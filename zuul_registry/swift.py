# Copyright 2019 Red Hat, Inc.
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.

import logging
import openstack
import os
import keystoneauth1
import tempfile
import time
import json

import dateutil.parser

import storageutils

POST_ATTEMPTS = 3

def retry_function(func):
    for attempt in range(1, POST_ATTEMPTS + 1):
        try:
            return func()
        except keystoneauth1.exceptions.http.NotFound:
            raise
        except Exception:
            if attempt >= POST_ATTEMPTS:
                raise
            else:
                logging.exception("Error on attempt %d" % attempt)
                time.sleep(attempt * 10)

class SwiftDriver(storageutils.StorageDriver):
    log = logging.getLogger('registry.swift')

    def __init__(self, conf):
        self.cloud_name = conf['cloud']
        self.container_name = conf['container']
        self.conn = openstack.connect(cloud=self.cloud_name)
        container = retry_function(
            lambda: self.conn.get_container(self.container_name))
        if not container:
            self.log.info("Creating container %s", self.container_name)
            retry_function(
                lambda: self.conn.create_container(
                    name=self.container_name, public=False))
        endpoint = self.conn.object_store.get_endpoint()
        self.url = os.path.join(endpoint, self.container_name)

    def get_url(self, path):
        return os.path.join(self.url, path)

    def list_objects(self, path):
        self.log.debug("List objects %s", path)
        url = self.get_url('') + '?prefix=%s&delimiter=/&format=json' % (path,)
        ret = retry_function(
            lambda: self.conn.session.get(url).content.decode('utf8'))
        data = json.loads(ret)
        ret = []
        for obj in data:
            if 'subdir' in obj:
                objpath = obj['subdir']
                name = obj['subdir'].split('/')[-2]
                ctime = time.time()
                isdir = True
            else:
                objpath = obj['name']
                name = obj['name'].split('/')[-1]
                ctime = dateutil.parser.parse(obj['last_modified']+'Z').timestamp()
                isdir = False
            ret.append(storageutils.ObjectInfo(
                objpath, name, ctime, isdir))
        return ret

    def get_object_size(self, path):
        try:
            ret = retry_function(
                lambda: self.conn.session.head(self.get_url(path)))
        except keystoneauth1.exceptions.http.NotFound:
            return None
        return ret.headers['Content-Length']

    def put_object(self, path, data):
        name = None
        try:
            with tempfile.NamedTemporaryFile('wb', delete=False) as f:
                name = f.name
                if isinstance(data, bytes):
                    f.write(data)
                else:
                    for chunk in data:
                        f.write(chunk)
            retry_function(
                lambda: self.conn.object_store.upload_object(
                    self.container_name,
                    path,
                    filename=name))
        finally:
            if name:
                os.unlink(name)

    def get_object(self, path):
        try:
            ret = retry_function(
                lambda: self.conn.session.get(self.get_url(path)))
        except keystoneauth1.exceptions.http.NotFound:
            return None
        return ret.content

    def delete_object(self, path):
        retry_function(
            lambda: self.conn.session.delete(
                self.get_url(path)))

    def move_object(self, src_path, dst_path):
        dst = os.path.join(self.container_name, dst_path)
        retry_function(
            lambda: self.conn.session.request(
                self.get_url(src_path)+"?multipart-manfest=get",
                'COPY',
                headers={'Destination': dst}
            ))
        retry_function(
            lambda: self.conn.session.delete(
                self.get_url(src_path)))

    def cat_objects(self, path, chunks):
        manifest = []
        #TODO: Would it be better to move 1-chunk objects?
        for chunk_path in chunks:
            ret = retry_function(
                lambda: self.conn.session.head(self.get_url(chunk_path)))
            if int(ret.headers['Content-Length']) == 0:
                continue
            manifest.append({'path':
                             os.path.join(self.container_name, chunk_path),
                             'etag': ret.headers['Etag'],
                             'size_bytes': ret.headers['Content-Length']})
        retry_function(lambda:
                       self.conn.session.put(
                           self.get_url(path)+"?multipart-manifest=put",
                           data=json.dumps(manifest)))

Driver = SwiftDriver

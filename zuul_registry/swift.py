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

from . import storageutils

POST_ATTEMPTS = 3
SWIFT_CHUNK_SIZE = 64 * 1024


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
                ctime = dateutil.parser.parse(
                    obj['last_modified'] + 'Z').timestamp()
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

    def put_object(self, path, data, uuid=None):
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

            # Get the md5sum and size of the object, and make sure it
            # matches the upload.
            ret = retry_function(lambda: self.conn.session.head(
                self.get_url(path)))
            try:
                size = int(ret.headers.get('Content-Length', ''))
            except ValueError:
                size = None
            md5 = ret.headers.get('Etag', '')
            sdk_md5 = ret.headers.get('X-Object-Meta-X-Sdk-Md5', '')
            self.log.debug("[u: %s] Upload object %s "
                           "md5: %s sdkmd5: %s size: %s",
                           uuid, path, md5, sdk_md5, size)
            if md5 != sdk_md5:
                raise Exception("Swift and SDK md5s did not match (u: %s)" %
                                uuid)

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

    def stream_object(self, path):
        try:
            ret = retry_function(
                lambda: self.conn.session.get(self.get_url(path), stream=True))
        except keystoneauth1.exceptions.http.NotFound:
            return None, None
        try:
            size = int(ret.headers.get('Content-Length', ''))
        except ValueError:
            size = None
        return size, ret.iter_content(chunk_size=SWIFT_CHUNK_SIZE)

    def delete_object(self, path):
        retry_function(
            lambda: self.conn.session.delete(
                self.get_url(path)))

    def move_object(self, src_path, dst_path, uuid=None):
        dst = os.path.join(self.container_name, dst_path)

        # Get the md5sum and size of the object, and make sure it
        # matches on both sides of the copy.
        ret = retry_function(lambda: self.conn.session.head(
            self.get_url(src_path)))
        try:
            size = int(ret.headers.get('Content-Length', ''))
        except ValueError:
            size = None
        md5 = ret.headers.get('Etag', '')
        sdk_md5 = ret.headers.get('X-Object-Meta-X-Sdk-Md5', '')
        old_md = dict(md5=md5, sdk_md5=sdk_md5, size=size)
        self.log.debug("[u: %s] Move object %s %s %s",
                       uuid, src_path, dst_path, old_md)
        if md5 != sdk_md5:
            raise Exception("Swift and SDK md5s did not match at start "
                            "of copy (u: %s) %s" % (uuid, old_md))

        # FIXME: The multipart-manifest argument below means that in
        # the event this docker chunk is a large object, we intend to
        # copy the manifest but not the underlying large object
        # segments.  That seems incorrect, and we should actually just
        # recast the large object segments into docker chunks and
        # discard this manifest.  But first we should verify that's
        # what's happening -- it's not clear we ever hit a segment
        # limit in practice, so we may never have a large object
        # chunk.
        retry_function(
            lambda: self.conn.session.request(
                self.get_url(src_path) + "?multipart-manfest=get",
                'COPY',
                headers={'Destination': dst}
            ))

        # Get the md5sum and size of the object, and make sure it
        # matches on both sides of the copy.
        ret = retry_function(lambda: self.conn.session.head(
            self.get_url(dst_path)))
        try:
            size = int(ret.headers.get('Content-Length', ''))
        except ValueError:
            size = None
        md5 = ret.headers.get('Etag', '')
        sdk_md5 = ret.headers.get('X-Object-Meta-X-Sdk-Md5', '')
        new_md = dict(md5=md5, sdk_md5=sdk_md5, size=size)
        self.log.debug("[u: %s] Moved object %s %s %s",
                       uuid, src_path, dst_path, new_md)
        if md5 != sdk_md5:
            raise Exception("Swift and SDK md5s did not match at end of copy "
                            "(u: %s) %s" % (uuid, new_md))
        if old_md != new_md:
            raise Exception("Object metadata did not match after copy "
                            "(u: %s) old: %s new: %s" % (uuid, old_md, new_md))

        retry_function(
            lambda: self.conn.session.delete(
                self.get_url(src_path)))

    def cat_objects(self, path, chunks, uuid=None):
        manifest = []
        # TODO: Would it be better to move 1-chunk objects?
        for chunk in chunks:
            ret = retry_function(
                lambda: self.conn.session.head(self.get_url(chunk['path'])))
            size = int(ret.headers['Content-Length'])
            if size == 0:
                continue
            etag = ret.headers['Etag']
            sdk_md5 = ret.headers['X-Object-Meta-X-Sdk-Md5']
            if not (sdk_md5 == etag == chunk['md5']):
                raise Exception("Object metadata did not match during cat "
                                "(u: %s) orig: %s sdk: %s etag: %s" % (
                                    uuid, chunk['md5'], sdk_md5, etag))
            if not (size == chunk['size']):
                raise Exception("Object metadata did not match during cat "
                                "(u: %s) orig: %s size: %s" % (
                                    uuid, chunk['size'], size))
            manifest.append({'path':
                             os.path.join(self.container_name, chunk['path']),
                             'etag': ret.headers['Etag'],
                             'size_bytes': ret.headers['Content-Length']})
        retry_function(lambda:
                       self.conn.session.put(
                           self.get_url(path) + "?multipart-manifest=put",
                           data=json.dumps(manifest)))


Driver = SwiftDriver

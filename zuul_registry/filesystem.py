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

import os

from . import storageutils


class FilesystemDriver(storageutils.StorageDriver):
    def __init__(self, conf):
        self.root = conf['root']

    def list_objects(self, path):
        path = os.path.join(self.root, path)
        if not os.path.isdir(path):
            return []
        ret = []
        for f in os.listdir(path):
            obj_path = os.path.join(path, f)
            ret.append(storageutils.ObjectInfo(
                obj_path, f, os.stat(obj_path).st_ctime,
                os.path.isdir(obj_path)))
        return ret

    def get_object_size(self, path):
        path = os.path.join(self.root, path)
        if not os.path.exists(path):
            return None
        return os.stat(path).st_size

    def put_object(self, path, data):
        path = os.path.join(self.root, path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            if isinstance(data, bytes):
                f.write(data)
            else:
                for chunk in data:
                    f.write(chunk)

    def get_object(self, path):
        path = os.path.join(self.root, path)
        if not os.path.exists(path):
            return None
        with open(path, 'rb') as f:
            return f.read()

    def delete_object(self, path):
        path = os.path.join(self.root, path)
        if os.path.exists(path):
            if os.path.isdir(path):
                os.rmdir(path)
            else:
                os.unlink(path)

    def move_object(self, src_path, dst_path):
        src_path = os.path.join(self.root, src_path)
        dst_path = os.path.join(self.root, dst_path)
        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
        os.rename(src_path, dst_path)

    def cat_objects(self, path, chunks):
        path = os.path.join(self.root, path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as outf:
            for chunk_path in chunks:
                chunk_path = os.path.join(self.root, chunk_path)
                with open(chunk_path, 'rb') as inf:
                    while True:
                        d = inf.read(4096)
                        if not d:
                            break
                        outf.write(d)
        for chunk_path in chunks:
            chunk_path = os.path.join(self.root, chunk_path)
            os.unlink(chunk_path)


Driver = FilesystemDriver

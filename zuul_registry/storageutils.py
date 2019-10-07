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

from abc import ABCMeta, abstractmethod


class ObjectInfo:
    def __init__(self, path, name, ctime, isdir):
        self.path = path
        self.name = name
        self.ctime = ctime
        self.isdir = isdir


class StorageDriver(metaclass=ABCMeta):
    """Base class for storage drivers.

    Storage drivers should implement all of the methods in this class.
    This is a low-level API with no knowledge of the intended use as
    an image registry.  This makes it easy to add backend drivers
    since the storage abstraction layer is designed to deal with the
    lowest common denominator.
    """

    @abstractmethod
    def __init__(self, conf):
        """Initialize a driver.

        :arg dict conf: The 'storage' section from the config file.
        """
        pass

    @abstractmethod
    def list_objects(self, path):
        """List objects at path.

        Returns a list of objects rooted at `path`, one level deep.

        :arg str path: The object path.

        :returns: A list of ObjectInfo objects, one for each object.
        :rtype: ObjectInfo
        """
        pass

    @abstractmethod
    def get_object_size(self, path):
        """Return the size of object at path.

        :arg str path: The object path.

        :returns: The size of the object in bytes.
        :rtype: int
        """
        pass

    @abstractmethod
    def put_object(self, path, data):
        """Store an object.

        Store the contents of `data` at `path`.  The `data` parameter
        may be a bytearray or a generator which produces bytearrays.

        :arg str path: The object path.
        :arg bytearray data: The data to store.
        """
        pass

    @abstractmethod
    def get_object(self, path):
        """Retrieve an object.

        Return the contents of the object at `path`.

        :arg str path: The object path.

        :returns: The contents of the object.
        :rtype: bytearray
        """
        pass

    @abstractmethod
    def stream_object(self, path):
        """Retrieve an object, streaming.

        Return a generator with the content of the object at `path`.

        :arg str path: The object path.

        :returns: The size and contents of the object.
        :rtype: tuple of (int or None, generator-of-bytearray or None)
        """
        pass

    @abstractmethod
    def delete_object(self, path):
        """Delete an object.

        Delete the object stored at `path`.

        :arg str path: The object path.
        """
        pass

    @abstractmethod
    def move_object(self, src_path, dst_path):
        """Move an object.

        Move the object from `src_path` to `dst_path`.

        :arg str src_path: The original path.
        :arg str dst_path: The new path.
        """
        pass

    @abstractmethod
    def cat_objects(self, path, chunks):
        """Concatenate objects.

        Concatenate one or more objects to create a new object.
        The original objects are deleted.

        :arg str path: The new path.
        :arg list chunks: A list of paths of objects to concatenate.
        """
        pass

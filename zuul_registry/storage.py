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

import base64
import json
import logging
import os
import queue
import rehash
import hashlib
import threading
import time
from uuid import uuid4


class UploadRecord:
    """Information about an upload.

    This class holds information about an upload in progress.  It is
    designed to be serialized into object storage and stored along
    with the data of the upload so that as each new chunk is uploaded,
    this is updated.

    The registry protocol guarantees that upload chunks are
    sequential, so this does not need to be locked for use by multiple
    writers.

    The most important part of this (that which could not otherwise be
    constructed from a simple object listing) is the resumable hash of
    the contents.  We need to calculate the hash of the complete
    upload, but we would like to support chunks being written by
    different writers (for example, in a simple round-robin load
    balancer).  If we store the state of the hash algorithm after each
    chunk is uploaded, we can avoid having to download the entire data
    again at the end merely to calculate the hash.
    """

    def __init__(self):
        self.chunks = []
        self.hasher = rehash.sha256()

    @property
    def count(self):
        return len(self.chunks)

    @property
    def size(self):
        return sum([x['size'] for x in self.chunks])

    @property
    def digest(self):
        return 'sha256:' + self.hasher.hexdigest()

    def load(self, data):
        data = json.loads(data.decode('utf8'))
        self.chunks = data['chunks']
        hash_state = data['hash_state']
        hash_state['md_data'] = base64.decodebytes(
            hash_state['md_data'].encode('ascii'))
        self.hasher.__setstate__(hash_state)

    def dump(self):
        hash_state = self.hasher.__getstate__()
        hash_state['md_data'] = base64.encodebytes(
            hash_state['md_data']).decode('ascii')
        data = dict(chunks=self.chunks,
                    hash_state=hash_state)
        return json.dumps(data).encode('utf8')


class UploadStreamer:
    """Stream an upload to the object storage.

    This returns data from an internal buffer as a generator.  Pass
    this to the `put_object` method to supply streaming data to it in
    one thread, while another adds data to the buffer using the
    `write` method.
    """
    def __init__(self):
        self.queue = queue.Queue()

    def write(self, data):
        self.queue.put(data)

    def __iter__(self):
        while True:
            d = self.queue.get()
            if d is None:
                break
            yield d


class Storage:
    """Storage abstraction layer.

    This class abstracts different storage backends, providing a
    convenience API to the registry.

    Most of these methods take a namespace argument.  The namespace
    is, essentially, an entire registry isolated from the other
    namespaces.  They may even have duplicate object data.  This
    allows us to support serving multiple registries from the same
    process (without confusing the contents of them).

    """

    # Clients have 1 hour to complete an upload before we start
    # deleting stale objects.
    upload_exp = 60 * 60
    log = logging.getLogger('registry.storage')

    def __init__(self, backend, conf):
        self.backend = backend
        if 'expiration' in conf:
            self.manifest_exp = conf['expiration']
        else:
            self.manifest_exp = None

    def blob_size(self, namespace, digest):
        path = os.path.join(namespace, 'blobs', digest, 'data')
        return self.backend.get_object_size(path)

    def put_blob(self, namespace, digest, data):
        path = os.path.join(namespace, 'blobs', digest, 'data')
        return self.backend.put_object(path, data)

    def get_blob(self, namespace, digest):
        path = os.path.join(namespace, 'blobs', digest, 'data')
        return self.backend.get_object(path)

    def stream_blob(self, namespace, digest):
        path = os.path.join(namespace, 'blobs', digest, 'data')
        return self.backend.stream_object(path)

    def start_upload(self, namespace):
        """Start an upload.

        Create an empty UploadRecord and store it.  Later methods will
        add to it.  The uuid attribute of the UploadRecord uniquely
        identifies the upload.

        Uploads have one or more chunks.  See `upload_chunk`.

        """
        uuid = uuid4().hex
        upload = UploadRecord()
        self._update_upload(namespace, uuid, upload)
        return uuid

    def _get_upload(self, namespace, uuid):
        path = os.path.join(namespace, 'uploads', uuid, 'metadata')
        data = self.backend.get_object(path)
        upload = UploadRecord()
        upload.load(data)
        return upload

    def _update_upload(self, namespace, uuid, upload):
        path = os.path.join(namespace, 'uploads', uuid, 'metadata')
        self.log.debug("[u: %s] Update upload metadata chunks: %s",
                       uuid, upload.chunks)
        self.backend.put_object(path, upload.dump(), uuid)

    def upload_chunk(self, namespace, uuid, fp):
        """Add a chunk to an upload.

        Uploads contain one or more chunk of data which are ultimately
        concatenated into one blob.

        This streams the data from `fp` and writes it into the
        registry.

        :arg namespace str: The registry namespace.
        :arg uuid str: The UUID of the upload.
        :arg file fp: An open file pointer to the source data.

        """

        upload = self._get_upload(namespace, uuid)
        path = os.path.join(namespace, 'uploads', uuid, str(upload.count + 1))
        streamer = UploadStreamer()
        t = threading.Thread(target=self.backend.put_object,
                             args=(path, streamer, uuid))
        t.start()
        size = 0
        # This calculates the md5 of just this chunk for internal
        # integrity checking; it is not the overall hash of the layer
        # (that's a running calculation in the upload record).
        chunk_hasher = hashlib.md5()
        while True:
            try:
                d = fp.read(4096)
            except ValueError:
                # We get this on an empty body
                d = b''
            if not d:
                break
            upload.hasher.update(d)
            chunk_hasher.update(d)
            size += len(d)
            streamer.write(d)
        streamer.write(None)
        t.join()
        upload.chunks.append(dict(size=size, md5=chunk_hasher.hexdigest()))
        self._update_upload(namespace, uuid, upload)
        return upload.size - size, upload.size

    def store_upload(self, namespace, uuid, digest):
        """Complete an upload.

        Verify the supplied digest matches the uploaded data, and if
        so, stores the uploaded data as a blob in the registry.  Until
        this is called, the upload is incomplete and the data blob is
        not addressible.
        """
        upload = self._get_upload(namespace, uuid)
        if digest != upload.digest:
            raise Exception('Digest does not match %s %s' %
                            (digest, upload.digest))
        # Move the chunks into the blob dir to get them out of the
        # uploads dir.
        chunks = []
        for i, chunk in enumerate(upload.chunks):
            src_path = os.path.join(namespace, 'uploads', uuid, str(i + 1))
            dst_path = os.path.join(namespace, 'blobs', digest, str(i + 1))
            chunks.append(dict(path=dst_path,
                               md5=chunk['md5'], size=chunk['size']))
            self.backend.move_object(src_path, dst_path, uuid)
        # Concatenate the chunks into one blob.
        path = os.path.join(namespace, 'blobs', digest, 'data')
        self.backend.cat_objects(path, chunks, uuid)
        path = os.path.join(namespace, 'uploads', uuid, 'metadata')
        self.backend.delete_object(path)

    def put_manifest(self, namespace, repo, tag, data):
        path = os.path.join(namespace, 'repos', repo, 'manifests', tag)
        self.backend.put_object(path, data)

    def get_manifest(self, namespace, repo, tag):
        path = os.path.join(namespace, 'repos', repo, 'manifests', tag)
        return self.backend.get_object(path)

    def prune(self):
        """Prune the registry

        Prune all namespaces in the registry according to configured
        expiration times.
        """
        now = time.time()
        upload_target = now - self.upload_exp
        if self.manifest_exp:
            manifest_target = now - self.manifest_exp
        else:
            manifest_target = None
        for namespace in self.backend.list_objects(''):
            uploadpath = os.path.join(namespace.path, 'uploads/')
            for upload in self.backend.list_objects(uploadpath):
                self._prune(upload, upload_target)
            if not manifest_target:
                continue
            repopath = os.path.join(namespace.path, 'repos/')
            for repo in self.backend.list_objects(repopath):
                kept_manifests = self._prune(repo, manifest_target)
            # mark/sweep manifest blobs
            layers = set()
            for manifest in kept_manifests:
                if manifest.isdir:
                    continue
                layers.update(self._get_layers_from_manifest(
                    namespace.name, manifest.path))
            blobpath = os.path.join(namespace.path, 'blobs/')
            for blob in self.backend.list_objects(blobpath):
                if blob.name not in layers:
                    self._prune(blob, upload_target)

    def _get_layers_from_manifest(self, namespace, path):
        self.log.debug('Get layers %s', path)
        data = self.backend.get_object(path)
        manifest = json.loads(data)
        target = manifest.get(
            'application/vnd.docker.distribution.manifest.v2+json')
        layers = []
        if not target:
            self.log.debug('Unknown manifest %s', path)
            return layers
        layers.append(target)
        data = self.get_blob(namespace, target)
        manifest = json.loads(data)
        layers.append(manifest['config']['digest'])
        for layer in manifest['layers']:
            layers.append(layer['digest'])
        return layers

    def _prune(self, root_obj, target):
        kept = []
        if root_obj.isdir:
            for obj in self.backend.list_objects(root_obj.path):
                kept.extend(self._prune(obj, target))
        if not kept and root_obj.ctime < target:
            self.log.debug('Prune %s', root_obj.path)
            self.backend.delete_object(root_obj.path)
        else:
            self.log.debug('Keep %s', root_obj.path)
            kept.append(root_obj)
        return kept

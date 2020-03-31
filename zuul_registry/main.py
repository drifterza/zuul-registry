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

import argparse
import base64
import os
import sys
import logging
import cherrypy
import hashlib
import json
import yaml

from . import filesystem
from . import storage
from . import swift

import jwt

DRIVERS = {
    'filesystem': filesystem.Driver,
    'swift': swift.Driver,
}


class Authorization(cherrypy.Tool):
    log = logging.getLogger("registry.authz")
    READ = 'read'
    WRITE = 'write'
    AUTH = 'auth'

    def __init__(self, secret, users, public_url):
        self.secret = secret
        self.public_url = public_url
        self.rw = {}

        for user in users:
            if user['access'] == self.WRITE:
                self.rw[user['name']] = user['pass']

        cherrypy.Tool.__init__(self, 'before_handler',
                               self.check_auth,
                               priority=1)

    def check(self, store, user, password):
        if user not in store:
            return False
        return store[user] == password

    def unauthorized(self):
        cherrypy.response.headers['www-authenticate'] = (
            'Bearer realm="%s/auth/token"' % (self.public_url,)
        )
        raise cherrypy.HTTPError(401, 'Authentication required')

    def check_auth(self, level=READ):
        auth_header = cherrypy.request.headers.get('authorization')
        if auth_header and 'Bearer' in auth_header:
            token = auth_header.split()[1]
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
            if payload.get('level') in [level, self.WRITE]:
                self.log.debug('Auth ok %s', level)
                return
        self.log.debug('Unauthorized %s', level)
        self.unauthorized()

    def _get_level(self, scope):
        level = None
        if not isinstance(scope, list):
            scope = scope.split(' ')
        for resource_scope in scope:
            parts = resource_scope.split(':')
            if parts[0] == 'repository' and 'push' in parts[2]:
                level = self.WRITE
            if (parts[0] == 'repository' and 'pull' in parts[2]
                and level is None):
                level = self.READ
        if level is None:
            # No scope was provided, so this is an authentication
            # request; treat it as requesting 'write' access so that
            # we validate the password.
            level = self.WRITE
        return level

    @cherrypy.expose
    @cherrypy.tools.json_out(content_type='application/json; charset=utf-8')
    def token(self, **kw):
        # If the scope of the token requested is for pushing an image,
        # that corresponds to 'write' level access, so we verify the
        # password.
        #
        # If the scope of the token is not specified, we treat it as
        # 'write' since it probably means the client is performing
        # login validation.  The _get_level method takes care of that.
        #
        # If the scope requested is for pulling an image, we always
        # grant a read-level token.  This covers the case where no
        # authentication credentials are supplied, and also an
        # interesting edge case: the docker client, when configured
        # with a registry mirror, will, bless it's little heart, send
        # the *docker hub* credentials to that mirror.  In order for
        # us to act as a a stand-in for docker hub, we need to accept
        # those credentials.
        auth_header = cherrypy.request.headers.get('authorization')
        level = self._get_level(kw.get('scope', ''))
        self.log.info('Authenticate level %s', level)
        if level == self.WRITE:
            if auth_header and 'Basic' in auth_header:
                cred = auth_header.split()[1]
                cred = base64.decodebytes(cred.encode('utf8')).decode('utf8')
                user, pw = cred.split(':', 1)
                if not self.check(self.rw, user, pw):
                    self.unauthorized()
            else:
                self.unauthorized()
        self.log.debug('Generate %s token', level)
        token = jwt.encode({'level': level}, 'secret',
                           algorithm='HS256').decode('utf8')
        return {'token': token,
                'access_token': token}


class RegistryAPI:
    """Registry API server.

    Implements the container registry protocol as documented in
    https://docs.docker.com/registry/spec/api/
    """
    log = logging.getLogger("registry.api")
    DEFAULT_NAMESPACE = '_local'

    def __init__(self, store, namespaced, authz):
        self.storage = store
        self.authz = authz
        self.namespaced = namespaced

    def get_namespace(self, repository):
        if not self.namespaced:
            return (self.DEFAULT_NAMESPACE, repository)
        parts = repository.split('/')
        return (parts[0], '/'.join(parts[1:]))

    def not_found(self):
        raise cherrypy.HTTPError(404)

    @cherrypy.expose
    @cherrypy.tools.json_out(content_type='application/json; charset=utf-8')
    def version_check(self):
        self.log.info('Version check')
        return {'version': '1.0'}
        res = cherrypy.response
        res.headers['Distribution-API-Version'] = 'registry/2.0'

    @cherrypy.expose
    def head_blob(self, repository, digest):
        namespace, repository = self.get_namespace(repository)
        self.log.info('Head blob %s %s %s', namespace, repository, digest)
        size = self.storage.blob_size(namespace, digest)
        if size is None:
            return self.not_found()
        res = cherrypy.response
        res.headers['Docker-Content-Digest'] = digest
        res.headers['Content-Length'] = str(size)
        return {}

    @cherrypy.expose
    @cherrypy.config(**{'response.stream': True})
    def get_blob(self, repository, digest):
        namespace, repository = self.get_namespace(repository)
        self.log.info('Get blob %s %s %s', namespace, repository, digest)
        size, data_iter = self.storage.stream_blob(namespace, digest)
        if data_iter is None:
            return self.not_found()
        res = cherrypy.response
        res.headers['Docker-Content-Digest'] = digest
        if size is not None:
            res.headers['Content-Length'] = str(size)
        return data_iter

    @cherrypy.expose
    @cherrypy.config(**{'tools.check_auth.level': Authorization.WRITE})
    def start_upload(self, repository, digest=None):
        orig_repository = repository
        namespace, repository = self.get_namespace(repository)
        method = cherrypy.request.method
        uuid = self.storage.start_upload(namespace)
        self.log.info('[u: %s] Start upload %s %s %s digest %s',
                      uuid, method, namespace, repository, digest)
        res = cherrypy.response
        res.headers['Location'] = '/v2/%s/blobs/uploads/%s' % (
            orig_repository, uuid)
        res.headers['Docker-Upload-UUID'] = uuid
        res.headers['Range'] = '0-0'
        res.status = '202 Accepted'

    @cherrypy.expose
    @cherrypy.config(**{'tools.check_auth.level': Authorization.WRITE})
    def upload_chunk(self, repository, uuid):
        orig_repository = repository
        namespace, repository = self.get_namespace(repository)
        self.log.info('[u: %s] Upload chunk %s %s',
                      uuid, namespace, repository)
        old_length, new_length = self.storage.upload_chunk(
            namespace, uuid, cherrypy.request.body)
        res = cherrypy.response
        res.headers['Location'] = '/v2/%s/blobs/uploads/%s' % (
            orig_repository, uuid)
        res.headers['Docker-Upload-UUID'] = uuid
        res.headers['Range'] = '0-%s' % (new_length,)
        res.status = '204 No Content'
        self.log.info(
            '[u: %s] Finish Upload chunk %s %s', uuid, repository, new_length)

    @cherrypy.expose
    @cherrypy.config(**{'tools.check_auth.level': Authorization.WRITE})
    def finish_upload(self, repository, uuid, digest):
        orig_repository = repository
        namespace, repository = self.get_namespace(repository)
        self.log.info('[u: %s] Upload final chunk %s %s',
                      uuid, namespace, repository)
        old_length, new_length = self.storage.upload_chunk(
            namespace, uuid, cherrypy.request.body)
        self.log.debug('[u: %s] Store upload %s %s',
                       uuid, namespace, repository)
        self.storage.store_upload(namespace, uuid, digest)
        self.log.info('[u: %s] Upload complete %s %s',
                      uuid, namespace, repository)
        res = cherrypy.response
        res.headers['Location'] = '/v2/%s/blobs/%s' % (orig_repository, digest)
        res.headers['Docker-Content-Digest'] = digest
        res.headers['Content-Range'] = '%s-%s' % (old_length, new_length)
        res.status = '201 Created'

    @cherrypy.expose
    @cherrypy.config(**{'tools.check_auth.level': Authorization.WRITE})
    def put_manifest(self, repository, ref):
        namespace, repository = self.get_namespace(repository)
        body = cherrypy.request.body.read()
        hasher = hashlib.sha256()
        hasher.update(body)
        digest = 'sha256:' + hasher.hexdigest()
        self.log.info('Put manifest %s %s %s digest %s',
                      namespace, repository, ref, digest)
        self.storage.put_blob(namespace, digest, body)
        manifest = self.storage.get_manifest(namespace, repository, ref)
        if manifest is None:
            manifest = {}
        else:
            manifest = json.loads(manifest)
        manifest[cherrypy.request.headers['Content-Type']] = digest
        self.storage.put_manifest(
            namespace, repository, ref, json.dumps(manifest).encode('utf8'))
        res = cherrypy.response
        res.headers['Location'] = '/v2/%s/manifests/%s' % (repository, ref)
        res.headers['Docker-Content-Digest'] = digest
        res.status = '201 Created'

    @cherrypy.expose
    def get_manifest(self, repository, ref):
        namespace, repository = self.get_namespace(repository)
        headers = cherrypy.request.headers
        res = cherrypy.response
        self.log.info('Get manifest %s %s %s', namespace, repository, ref)
        if ref.startswith('sha256:'):
            manifest = self.storage.get_blob(namespace, ref)
            if manifest is None:
                self.log.error('Manifest %s %s not found', repository, ref)
                return self.not_found()
            res.headers['Content-Type'] = json.loads(manifest)['mediaType']
            res.headers['Docker-Content-Digest'] = ref
            return manifest
        manifest = self.storage.get_manifest(namespace, repository, ref)
        if manifest is None:
            manifest = {}
        else:
            manifest = json.loads(manifest)
        for ct in [x.strip() for x in headers['Accept'].split(',')]:
            if ct in manifest:
                self.log.debug('Manifest %s %s digest found %s',
                               repository, ref, manifest[ct])
                data = self.storage.get_blob(namespace, manifest[ct])
                if not data:
                    self.log.error(
                        'Blob %s %s not found', namespace, manifest[ct])
                    return self.not_found()
                res.headers['Content-Type'] = ct
                res.headers['Docker-Content-Digest'] = manifest[ct]
                hasher = hashlib.sha256()
                hasher.update(data)
                self.log.debug('Retrieved sha256 %s', hasher.hexdigest())
                return data
        self.log.error('Manifest %s %s not found', repository, ref)
        return self.not_found()


class RegistryServer:
    log = logging.getLogger("registry.server")

    def __init__(self, config_path):
        self.log.info("Loading config from %s", config_path)
        self._load_config(config_path)

        # TODO: pyopenssl?
        cherrypy.server.ssl_module = 'builtin'
        cherrypy.server.ssl_certificate = self.conf['tls-cert']
        cherrypy.server.ssl_private_key = self.conf['tls-key']

        driver = self.conf['storage']['driver']
        backend = DRIVERS[driver](self.conf['storage'])
        self.store = storage.Storage(backend, self.conf['storage'])

        authz = Authorization(self.conf['secret'], self.conf['users'],
                              self.conf['public-url'])

        route_map = cherrypy.dispatch.RoutesDispatcher()
        api = RegistryAPI(self.store,
                          False,
                          authz)
        cherrypy.tools.check_auth = authz

        route_map.connect('api', '/v2/',
                          controller=api, action='version_check')
        route_map.connect('api', '/v2/{repository:.*}/blobs/uploads/',
                          controller=api, action='start_upload')
        route_map.connect('api', '/v2/{repository:.*}/blobs/uploads/{uuid}',
                          conditions=dict(method=['PATCH']),
                          controller=api, action='upload_chunk')
        route_map.connect('api', '/v2/{repository:.*}/blobs/uploads/{uuid}',
                          conditions=dict(method=['PUT']),
                          controller=api, action='finish_upload')
        route_map.connect('api', '/v2/{repository:.*}/manifests/{ref}',
                          conditions=dict(method=['PUT']),
                          controller=api, action='put_manifest')
        route_map.connect('api', '/v2/{repository:.*}/manifests/{ref}',
                          conditions=dict(method=['GET']),
                          controller=api, action='get_manifest')
        route_map.connect('api', '/v2/{repository:.*}/blobs/{digest}',
                          conditions=dict(method=['HEAD']),
                          controller=api, action='head_blob')
        route_map.connect('api', '/v2/{repository:.*}/blobs/{digest}',
                          conditions=dict(method=['GET']),
                          controller=api, action='get_blob')
        route_map.connect('authz', '/auth/token',
                          controller=authz, action='token')

        conf = {
            '/': {
                'request.dispatch': route_map,
                'tools.check_auth.on': True,
            },
            '/auth': {
                'tools.check_auth.on': False,
            }
        }

        cherrypy.config.update({
            'global': {
                'environment': 'production',
                'server.max_request_body_size': 1e12,
                'server.socket_host': self.conf['address'],
                'server.socket_port': self.conf['port'],
            },
        })

        cherrypy.tree.mount(api, '/', config=conf)

    def _load_config(self, path):
        with open(path) as f:
            conf = yaml.safe_load(f.read())
        self.conf = conf['registry']

    @property
    def port(self):
        return cherrypy.server.bound_addr[1]

    def start(self):
        self.log.info("Registry starting")
        cherrypy.engine.start()

    def stop(self):
        self.log.info("Registry stopping")
        cherrypy.engine.exit()
        # Not strictly necessary, but without this, if the server is
        # started again (e.g., in the unit tests) it will reuse the
        # same host/port settings.
        cherrypy.server.httpserver = None

    def prune(self):
        self.store.prune()


def main():
    parser = argparse.ArgumentParser(
        description='Zuul registry server')
    parser.add_argument('-c', dest='config',
                        help='Config file path',
                        default='/conf/registry.yaml')
    parser.add_argument('-d', dest='debug',
                        help='Debug log level',
                        action='store_true')
    parser.add_argument('command',
                        nargs='?',
                        help='Command: serve, prune',
                        default='serve')
    args = parser.parse_args()
    logformat = '%(asctime)s %(levelname)s %(name)s: %(message)s'
    if args.debug or os.environ.get('DEBUG') == '1':
        logging.basicConfig(level=logging.DEBUG, format=logformat)
        logging.getLogger("openstack").setLevel(logging.DEBUG)
        logging.getLogger("urllib3").setLevel(logging.DEBUG)
        logging.getLogger("requests").setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO, format=logformat)
        logging.getLogger("openstack").setLevel(logging.INFO)
        logging.getLogger("urllib3").setLevel(logging.ERROR)
        logging.getLogger("requests").setLevel(logging.ERROR)
        cherrypy.log.access_log.propagate = False
    logging.getLogger("keystoneauth").setLevel(logging.ERROR)
    logging.getLogger("stevedore").setLevel(logging.ERROR)

    s = RegistryServer(args.config)
    if args.command == 'serve':
        s.start()
        cherrypy.engine.block()
    elif args.command == 'prune':
        s.prune()
    else:
        print("Unknown command: %s", args.command)
        sys.exit(1)

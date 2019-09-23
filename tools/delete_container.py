#!/usr/bin/env python3
#
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
import openstack
import requests
import logging
import os

logging.basicConfig(level=logging.INFO)
# logging.getLogger("requests").setLevel(logging.DEBUG)
# logging.getLogger("keystoneauth").setLevel(logging.INFO)
# logging.getLogger("stevedore").setLevel(logging.INFO)
logging.captureWarnings(True)


def main():
    parser = argparse.ArgumentParser(
        description="Delete a swift container"
    )
    parser.add_argument('cloud',
                        help='Name of the cloud to use when uploading')
    parser.add_argument('container',
                        help='Name of the container to use when uploading')

    args = parser.parse_args()

    cloud = openstack.connect(cloud=args.cloud)

    sess = cloud.config.get_session()
    adapter = requests.adapters.HTTPAdapter(pool_maxsize=100)
    sess.mount('https://', adapter)

    container = cloud.get_container(args.container)
    print('Found container', container)
    print()
    for x in cloud.object_store.objects(args.container):
        print('Delete object', x.name)
        if x.name == '/':
            endpoint = cloud.object_store.get_endpoint()
            container = os.path.join(endpoint, args.container)
            cloud.session.delete(container + '//')
        else:
            cloud.object_store.delete_object(x)

    print()
    print('Delete container', container)
    cloud.object_store.delete_container(args.container)


if __name__ == "__main__":
    main()

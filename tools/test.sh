#!/bin/bash
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

rm -fr /tmp/storage
docker rmi localhost:9000/test/registry
docker image prune -f
docker load <registry.img
docker image push localhost:9000/test/registry
docker rmi localhost:9000/test/registry
docker image prune -f
docker image pull localhost:9000/test/registry

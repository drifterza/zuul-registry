# Copyright 2020 Red Hat, Inc.
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

import testtools

from zuul_registry.main import RegistryServer


class TestRegistryConfig(testtools.TestCase):
    def test_config_env(self):
        conf = RegistryServer.load_config("tests/fixtures/registry.yaml", {})
        self.assertEqual(conf["registry"]["secret"], "%(ZUUL_REGISTRY_SECRET)")
        conf = RegistryServer.load_config(
            "tests/fixtures/registry.yaml", dict(ZUUL_REGISTRY_SECRET="42"))
        self.assertEqual(conf["registry"]["secret"], "42")

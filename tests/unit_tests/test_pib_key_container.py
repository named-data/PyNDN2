# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx unit tests:
# https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/pib/key-container.t.cpp
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU Lesser General Public License is in the file COPYING.

import unittest as ut
from pyndn.security.pib.pib_memory import PibMemory
from pyndn import Name
from pyndn.security.pib.pib_key_container import PibKeyContainer
from pyndn.security.pib.pib_key import PibKey
from pyndn.security.pib.pib import Pib
from .pib_data_fixture import PibDataFixture

class TestPibKeyContainer(ut.TestCase):
    def setUp(self):
        self.fixture = PibDataFixture()

    def test_basic(self):
        fixture = self.fixture
        pibImpl = PibMemory()

        # Start with an empty container.
        container = PibKeyContainer(fixture.id1, pibImpl)
        self.assertEquals(0, container.size())
        self.assertEquals(0, len(container._keys))

        # Add the first key.
        key11 = container.add(fixture.id1Key1.buf(), fixture.id1Key1Name)
        self.assertTrue(fixture.id1Key1Name.equals(key11.getName()))
        self.assertTrue(key11.getPublicKey().equals(fixture.id1Key1))
        self.assertEquals(1, container.size())
        self.assertEquals(1, len(container._keys))
        self.assertTrue(fixture.id1Key1Name in container._keys)

        # Add the same key again.
        key12 = container.add(fixture.id1Key1.buf(), fixture.id1Key1Name)
        self.assertTrue(fixture.id1Key1Name.equals(key12.getName()))
        self.assertTrue(key12.getPublicKey().equals(fixture.id1Key1))
        self.assertEquals(1, container.size())
        self.assertEquals(1, len(container._keys))
        self.assertTrue(fixture.id1Key1Name in container._keys)

        # Add the second key.
        key21 = container.add(fixture.id1Key2.buf(), fixture.id1Key2Name)
        self.assertTrue(fixture.id1Key2Name.equals(key21.getName()))
        self.assertTrue(key21.getPublicKey().equals(fixture.id1Key2))
        self.assertEquals(2, container.size())
        self.assertEquals(2, len(container._keys))
        self.assertTrue(fixture.id1Key1Name in container._keys)
        self.assertTrue(fixture.id1Key2Name in container._keys)

        # Get keys.
        try:
            container.get(fixture.id1Key1Name)
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))
        try:
            container.get(fixture.id1Key2Name)
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))
        id1Key3Name = PibKey.constructKeyName(
          fixture.id1, Name.Component("non-existing-id"))
        try:
            container.get(id1Key3Name)
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        # Get and check keys.
        key1 = container.get(fixture.id1Key1Name)
        key2 = container.get(fixture.id1Key2Name)
        self.assertTrue(fixture.id1Key1Name.equals(key1.getName()))
        self.assertTrue(key1.getPublicKey().equals(fixture.id1Key1))
        self.assertEquals(fixture.id1Key2Name, key2.getName())
        self.assertTrue(key2.getPublicKey().equals(fixture.id1Key2))

        # Create another container using the same PibImpl. The cache should be empty.
        container2 = PibKeyContainer(fixture.id1, pibImpl)
        self.assertEquals(2, container2.size())
        self.assertEquals(0, len(container2._keys))

        # Get a key. The cache should be filled.
        try:
            container2.get(fixture.id1Key1Name)
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))
        self.assertEquals(2, container2.size())
        self.assertEquals(1, len(container2._keys))

        try:
            container2.get(fixture.id1Key2Name)
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))
        self.assertEquals(2, container2.size())
        self.assertEquals(2, len(container2._keys))

        # Remove a key.
        container2.remove(fixture.id1Key1Name)
        self.assertEquals(1, container2.size())
        self.assertEquals(1, len(container2._keys))
        self.assertTrue(not (fixture.id1Key1Name in container2._keys))
        self.assertTrue(fixture.id1Key2Name in container2._keys)

        # Remove another key.
        container2.remove(fixture.id1Key2Name)
        self.assertEquals(0, container2.size())
        self.assertEquals(0, len(container2._keys))
        self.assertTrue(not (fixture.id1Key2Name in container2._keys))

    def test_errors(self):
        fixture = self.fixture
        pibImpl = PibMemory()

        container = PibKeyContainer(fixture.id1, pibImpl)

        try:
            container.add(fixture.id2Key1.toBytes(), fixture.id2Key1Name)
            self.fail("Did not throw the expected exception")
        except ValueError:
            pass
        else:
            self.fail("Did not throw the expected exception")

        try:
            container.remove(fixture.id2Key1Name)
            self.fail("Did not throw the expected exception")
        except ValueError:
            pass
        else:
            self.fail("Did not throw the expected exception")

        try:
            container.get(fixture.id2Key1Name)
            self.fail("Did not throw the expected exception")
        except ValueError:
            pass
        else:
            self.fail("Did not throw the expected exception")

if __name__ == '__main__':
    ut.main(verbosity=2)

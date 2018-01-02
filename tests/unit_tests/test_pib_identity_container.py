# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx unit tests:
# https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/pib/identity-container.t.cpp
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
from pyndn.security.pib.pib_identity_container import PibIdentityContainer
from pyndn.security.pib.pib import Pib
from .pib_data_fixture import PibDataFixture

class TestPibIdentityContainer(ut.TestCase):
    def setUp(self):
        self.fixture = PibDataFixture()

    def test_basic(self):
        fixture = self.fixture
        pibImpl = PibMemory()

        # Start with an empty container.
        container = PibIdentityContainer(pibImpl)
        self.assertEquals(0, container.size())
        self.assertEquals(0, len(container._identities))

        # Add the first identity.
        identity11 = container.add(fixture.id1)
        self.assertTrue(fixture.id1.equals(identity11.getName()))
        self.assertEquals(1, container.size())
        self.assertEquals(1, len(container._identities))
        self.assertTrue(fixture.id1 in container._identities)

        # Add the same identity again.
        identity12 = container.add(fixture.id1)
        self.assertTrue(fixture.id1.equals(identity12.getName()))
        self.assertEquals(1, container.size())
        self.assertEquals(1, len(container._identities))
        self.assertTrue(fixture.id1 in container._identities)

        # Add the second identity.
        identity21 = container.add(fixture.id2)
        self.assertTrue(fixture.id2.equals(identity21.getName()))
        self.assertEquals(2, container.size())
        self.assertEquals(2, len(container._identities))
        self.assertTrue(fixture.id1 in container._identities)
        self.assertTrue(fixture.id2 in container._identities)

        # Get identities.
        try:
            container.get(fixture.id1)
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))
        try:
            container.get(fixture.id2)
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))
        try:
            container.get(Name("/non-existing"))
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        # Check the identity.
        identity1 = container.get(fixture.id1)
        identity2 = container.get(fixture.id2)
        self.assertTrue(fixture.id1.equals(identity1.getName()))
        self.assertTrue(fixture.id2.equals(identity2.getName()))

        # Create another container from the same PibImpl. The cache should be empty.
        container2 = PibIdentityContainer(pibImpl)
        self.assertEquals(2, container2.size())
        self.assertEquals(0, len(container2._identities))

        # Get keys. The cache should be filled.
        try:
            container2.get(fixture.id1)
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))
        self.assertEquals(2, container2.size())
        self.assertEquals(1, len(container2._identities))

        try:
            container2.get(fixture.id2)
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))
        self.assertEquals(2, container2.size())
        self.assertEquals(2, len(container2._identities))

        # Remove a key.
        container2.remove(fixture.id1)
        self.assertEquals(1, container2.size())
        self.assertEquals(1, len(container2._identities))
        self.assertTrue(not (fixture.id1 in container2._identities))
        self.assertTrue(fixture.id2 in container2._identities)

        # Remove another key.
        container2.remove(fixture.id2)
        self.assertEquals(0, container2.size())
        self.assertEquals(0, len(container2._identities))
        self.assertTrue(not (fixture.id2 in container2._identities))

if __name__ == '__main__':
    ut.main(verbosity=2)

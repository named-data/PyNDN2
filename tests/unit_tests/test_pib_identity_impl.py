# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx unit tests:
# https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/pib/detail/identity-impl.t.cpp
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
from pyndn.security.pib.pib import Pib
from pyndn.security.pib.detail.pib_identity_impl import PibIdentityImpl
from .pib_data_fixture import PibDataFixture

class TestPibIdentityImpl(ut.TestCase):
    def setUp(self):
        self.fixture = PibDataFixture()

    def test_basic(self):
        fixture = self.fixture
        pibImpl = PibMemory()
        identity1 = PibIdentityImpl(fixture.id1, pibImpl, True)

        self.assertTrue(fixture.id1.equals(identity1.getName()))

    def test_key_operation(self):
        fixture = self.fixture
        pibImpl = PibMemory()
        identity1 = PibIdentityImpl(fixture.id1, pibImpl, True)
        try:
            PibIdentityImpl(fixture.id1, pibImpl, False)
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        # The identity should not have any key.
        self.assertEquals(0, identity1._keys.size())

        # Getting non-existing key should throw Pib.Error.
        try:
            identity1.getKey(fixture.id1Key1Name)
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        # Getting the default key should throw Pib.Error.
        try:
            identity1.getDefaultKey()
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        # Setting a non-existing key as the default key should throw Pib.Error.
        try:
            identity1.setDefaultKey(fixture.id1Key1Name)
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        # Add a key.
        identity1.addKey(fixture.id1Key1.toBytes(), fixture.id1Key1Name)
        try:
          identity1.getKey(fixture.id1Key1Name)
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        # A new key should become the default key when there is no default.
        try:
            identity1.getDefaultKey()
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))
        defaultKey0 = identity1.getDefaultKey()
        self.assertTrue(fixture.id1Key1Name.equals(defaultKey0.getName()))
        self.assertTrue(defaultKey0.getPublicKey().equals(fixture.id1Key1))

        # Remove a key.
        identity1.removeKey(fixture.id1Key1Name)
        try:
            identity1.setDefaultKey(fixture.id1Key1Name)
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        try:
            identity1.getDefaultKey()
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        # Set the default key directly.
        try:
            identity1.setDefaultKey(fixture.id1Key1.toBytes(), fixture.id1Key1Name)
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))
        try:
            identity1.getDefaultKey()
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))
        try:
          identity1.getKey(fixture.id1Key1Name)
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        # Check for a default key.
        defaultKey1 = identity1.getDefaultKey()
        self.assertTrue(fixture.id1Key1Name.equals(defaultKey1.getName()))
        self.assertTrue(defaultKey1.getPublicKey().equals(fixture.id1Key1))

        # Add another key.
        identity1.addKey(fixture.id1Key2.toBytes(), fixture.id1Key2Name)
        self.assertEquals(2, identity1._keys.size())

        # Set the default key using a name.
        try:
            identity1.setDefaultKey(fixture.id1Key2Name)
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))
        try:
          identity1.getDefaultKey()
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))
        defaultKey2 = identity1.getDefaultKey()
        self.assertTrue(fixture.id1Key2Name.equals(defaultKey2.getName()))
        self.assertTrue(defaultKey2.getPublicKey().equals(fixture.id1Key2))

        # Remove a key.
        identity1.removeKey(fixture.id1Key1Name)
        try:
            identity1.getKey(fixture.id1Key1Name)
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        self.assertEquals(1, identity1._keys.size())

        # Seting the default key directly again should change the default.
        try:
            identity1.setDefaultKey(fixture.id1Key1.toBytes(), fixture.id1Key1Name)
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))
        defaultKey3 = identity1.getDefaultKey()
        self.assertTrue(fixture.id1Key1Name.equals(defaultKey3.getName()))
        self.assertTrue(defaultKey3.getPublicKey().equals(fixture.id1Key1))
        self.assertEquals(2, identity1._keys.size())

        # Remove all keys.
        identity1.removeKey(fixture.id1Key1Name)
        try:
            identity1.getKey(fixture.id1Key1Name)
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        self.assertEquals(1, identity1._keys.size())
        identity1.removeKey(fixture.id1Key2Name)
        try:
            identity1.getKey(fixture.id1Key2Name)
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        self.assertEquals(0, identity1._keys.size())
        try:
            identity1.getDefaultKey()
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

    def test_overwrite(self):
        fixture = self.fixture
        pibImpl = PibMemory()
        identity1 = PibIdentityImpl(fixture.id1, pibImpl, True)

        identity1.addKey(fixture.id1Key1.toBytes(), fixture.id1Key1Name)
        self.assertTrue(identity1.getKey(fixture.id1Key1Name).getPublicKey()
          .equals(fixture.id1Key1))

        # Overwriting the key should work.
        identity1.addKey(fixture.id1Key2.toBytes(), fixture.id1Key1Name)
        self.assertTrue(identity1.getKey(fixture.id1Key1Name).getPublicKey()
          .equals(fixture.id1Key2))

    def test_errors(self):
        fixture = self.fixture
        pibImpl = PibMemory()

        try:
            PibIdentityImpl(fixture.id1, pibImpl, False)
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        identity1 = PibIdentityImpl(fixture.id1, pibImpl, True)

        identity1.addKey(fixture.id1Key1.buf(), fixture.id1Key1Name)
        try:
            identity1.addKey(fixture.id2Key1.buf(), fixture.id2Key1Name)
            self.fail("Did not throw the expected exception")
        except ValueError:
            pass
        else:
            self.fail("Did not throw the expected exception")

        identity1.addKey(fixture.id1Key1.buf(), fixture.id1Key1Name)
        try:
            identity1.removeKey(fixture.id2Key1Name)
            self.fail("Did not throw the expected exception")
        except ValueError:
            pass
        else:
            self.fail("Did not throw the expected exception")

        identity1.addKey(fixture.id1Key1.buf(), fixture.id1Key1Name)
        try:
            identity1.getKey(fixture.id2Key1Name)
            self.fail("Did not throw the expected exception")
        except ValueError:
            pass
        else:
            self.fail("Did not throw the expected exception")

        identity1.addKey(fixture.id1Key1.buf(), fixture.id1Key1Name)
        try:
            identity1.setDefaultKey(fixture.id2Key1.buf(), fixture.id2Key1Name)
            self.fail("Did not throw the expected exception")
        except ValueError:
            pass
        else:
            self.fail("Did not throw the expected exception")

        identity1.addKey(fixture.id1Key1.buf(), fixture.id1Key1Name)
        try:
            identity1.setDefaultKey(fixture.id2Key1Name)
            self.fail("Did not throw the expected exception")
        except ValueError:
            pass
        else:
            self.fail("Did not throw the expected exception")

if __name__ == '__main__':
    ut.main(verbosity=2)

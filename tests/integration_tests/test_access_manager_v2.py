# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt unit tests
# https://github.com/named-data/name-based-access-control/blob/new/tests/tests/access-manager.t.cpp
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
from pyndn import Name, Interest, Data
from pyndn.security import RsaKeyParams
from pyndn.encrypt.encryptor_v2 import EncryptorV2 # Debug: Should import without encryptor_v2
from pyndn.encrypt.access_manager_v2 import AccessManagerV2 # Debug: Should import without access_manager_v2
from pyndn.in_memory_storage import InMemoryStorageRetaining
from .identity_management_fixture import IdentityManagementFixture
from .in_memory_storage_face import InMemoryStorageFace

class AccessManagerFixture(IdentityManagementFixture):
    def __init__(self):
        super(AccessManagerFixture, self).__init__()

        self._userIdentities = []

        self._face = InMemoryStorageFace(InMemoryStorageRetaining())
        self._accessIdentity = self.addIdentity(Name("/access/policy/identity"))
        # This is a hack to get access to the KEK key-id.
        self._nacIdentity = self.addIdentity(
          Name("/access/policy/identity/NAC/dataset"), RsaKeyParams())
        self._userIdentities.append(self.addIdentity
          (Name("/first/user"), RsaKeyParams()))
        self._userIdentities.append(self.addIdentity
          (Name("/second/user"), RsaKeyParams()))
        self._manager = AccessManagerV2(
          self._accessIdentity, Name("/dataset"), self._keyChain, self._face)

        for  user in self._userIdentities:
            self._manager.addMember(user.getDefaultKey().getDefaultCertificate())

class TestAccessManagerV2(ut.TestCase):
    def setUp(self):
        self._fixture = AccessManagerFixture()

    def test_published_kek(self):
        self._fixture._face.receive(Interest
          (Name("/access/policy/identity/NAC/dataset/KEK"))
           .setCanBePrefix(True).setMustBeFresh(True))

        self.assertTrue(self._fixture._face._sentData[0].getName().getPrefix(-1).equals
          (Name("/access/policy/identity/NAC/dataset/KEK")))
        self.assertTrue(self._fixture._face._sentData[0].getName().get(-1).equals
          (self._fixture._nacIdentity.getDefaultKey().getName().get(-1)))

    def test_published_kdks(self):
        for user in self._fixture._userIdentities:
            kdkName = Name("/access/policy/identity/NAC/dataset/KDK")
            kdkName.append(
              self._fixture._nacIdentity.getDefaultKey().getName().get(-1)).append(
              "ENCRYPTED-BY").append(
              user.getDefaultKey().getName())

            self._fixture._face.receive(
              Interest(kdkName).setCanBePrefix(True).setMustBeFresh(True))

            self.assertTrue(
              self._fixture._face._sentData[0].getName().equals(kdkName),
              "Sent Data does not have the KDK name " + kdkName.toUri())
            self._fixture._face._sentData = []

    def test_enumerate_data_from_in_memory_storage(self):
        self.assertEqual(3, self._fixture._manager.size())

        nKek = 0
        nKdk = 0
        for name, data in self._fixture._manager._storage._cache.items():
            if data.getName().get(5).equals(EncryptorV2.NAME_COMPONENT_KEK):
                nKek += 1
            if data.getName().get(5).equals(EncryptorV2.NAME_COMPONENT_KDK):
                nKdk += 1

        self.assertEqual(1, nKek)
        self.assertEqual(2, nKdk)

if __name__ == '__main__':
    ut.main(verbosity=2)

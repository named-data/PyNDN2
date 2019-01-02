# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt unit tests
# https://github.com/named-data/name-based-access-control/blob/new/tests/tests/decryptor.t.cpp
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
from pyndn import Name, Data
from pyndn.util.blob import Blob
from pyndn.security import SafeBag, ValidatorNull
from pyndn.in_memory_storage import InMemoryStorageRetaining
from pyndn.encrypt import EncryptedContent
from pyndn.encrypt.decryptor_v2 import DecryptorV2 # Debug: Should import without decryptor_v2
from .identity_management_fixture import IdentityManagementFixture
from .in_memory_storage_face import InMemoryStorageFace
from .encrypt_static_data import EncryptStaticData

class DecryptorFixture(IdentityManagementFixture):
    def __init__(self, identityName):
        super(DecryptorFixture, self).__init__()

        # Include the code here from the NAC unit-tests class
        # DecryptorStaticDataEnvironment instead of making it a base class.
        self._storage = InMemoryStorageRetaining()
        for array in EncryptStaticData.managerPackets:
            data = Data()
            data.wireDecode(array)
            self._storage.insert(data)

        for array in EncryptStaticData.encryptorPackets:
            data = Data()
            data.wireDecode(array)
            self._storage.insert(data)

        # Import the "/first/user" identity.
        self._keyChain.importSafeBag(
          SafeBag(EncryptStaticData.userIdentity),
          Blob("password").buf())

        self.addIdentity(Name("/not/authorized"))

        self._face = InMemoryStorageFace(self._storage)
        self._validator = ValidatorNull()
        self._decryptor = DecryptorV2(
          self._keyChain.getPib().getIdentity(identityName).getDefaultKey(),
          self._validator, self._keyChain, self._face)

class TestDecryptorV2(ut.TestCase):
    def test_decrypt_valid(self):
        fixture = DecryptorFixture(Name("/first/user"))

        encryptedContent = EncryptedContent()
        encryptedContent.wireDecodeV2(EncryptStaticData.encryptedBlobs[0])

        nSuccesses = [0]
        nFailures = [0]

        def onSuccess(plainData):
            nSuccesses[0] += 1
            self.assertEqual(15, plainData.size())
            self.assertTrue(plainData.equals(Blob("Data to encrypt")))

        def onError(errorCode, message):
            nFailures[0] += 1

        fixture._decryptor.decrypt(encryptedContent, onSuccess, onError)

        self.assertEqual(1, nSuccesses[0])
        self.assertEqual(0, nFailures[0])

    def test_decrypt_invalid(self):
        fixture = DecryptorFixture(Name("/not/authorized"))

        encryptedContent = EncryptedContent()
        encryptedContent.wireDecodeV2(EncryptStaticData.encryptedBlobs[0])

        nSuccesses = [0]
        nFailures = [0]

        def onSuccess(plainData):
            nSuccesses[0] += 1

        def onError(errorCode, message):
            nFailures[0] += 1

        fixture._decryptor.decrypt(encryptedContent, onSuccess, onError)

        self.assertEqual(0, nSuccesses[0])
        self.assertEqual(1, nFailures[0])

if __name__ == '__main__':
    ut.main(verbosity=2)

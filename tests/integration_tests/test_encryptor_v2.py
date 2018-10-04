# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt unit tests
# https://github.com/named-data/name-based-access-control/blob/new/tests/tests/encryptor.t.cpp
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

import time
import unittest as ut
from pyndn import Name, Interest, Data
from pyndn.util.blob import Blob
from pyndn.security import SigningInfo, ValidatorNull
from pyndn.in_memory_storage import InMemoryStorageRetaining
from pyndn.encrypt.encryptor_v2 import EncryptorV2 # Debug: Should import without encryptor_v2
from .identity_management_fixture import IdentityManagementFixture
from .in_memory_storage_face import InMemoryStorageFace
from .encrypt_static_data import EncryptStaticData

class EncryptorFixture(IdentityManagementFixture):
    def __init__(self, shouldPublishData, onError):
        super(EncryptorFixture, self).__init__()

        # Include the code here from the NAC unit-tests class
        # EncryptorStaticDataEnvironment instead of making it a base class.
        self._storage = InMemoryStorageRetaining()
        if shouldPublishData:
            self.publishData()

        self._face = InMemoryStorageFace(self._storage)
        self._validator = ValidatorNull()
        self._encryptor = EncryptorV2(
          Name("/access/policy/identity/NAC/dataset"),
          Name("/some/ck/prefix"),
          SigningInfo(SigningInfo.SignerType.SHA256),
          onError, self._validator, self._keyChain, self._face)

    def publishData(self):
        for buffer in EncryptStaticData.managerPackets:
            data = Data()
            data.wireDecode(buffer)
            self._storage.insert(data)

class TestEncryptorV2(ut.TestCase):
    def setUp(self):
        self._fixture = EncryptorFixture(True,
          lambda code, message: self.fail("onError: " + message))

    def test_encrypt_and_publish_ck(self):
        self._fixture._encryptor._kekData = None
        self.assertEqual(False, self._fixture._encryptor._isKekRetrievalInProgress)
        self._fixture._encryptor.regenerateCk()
        # Unlike the ndn-group-encrypt unit tests, we don't check
        # isKekRetrievalInProgress_ true because we use a synchronous face which
        # finishes immediately.

        plainText = Blob("Data to encrypt")
        encryptedContent = self._fixture._encryptor.encrypt(plainText)

        ckPrefix = encryptedContent.getKeyLocatorName()
        self.assertTrue(Name("/some/ck/prefix/CK").equals(ckPrefix.getPrefix(-1)))

        self.assertTrue(encryptedContent.hasInitialVector())
        self.assertTrue(not encryptedContent.getPayload().equals(plainText))

        # Check that the KEK Interest has been sent.
        self.assertTrue(
          self._fixture._face._sentInterests[0].getName().getPrefix(6).equals
          (Name("/access/policy/identity/NAC/dataset/KEK")))

        kekData = self._fixture._face._sentData[0]
        self.assertTrue(kekData.getName().getPrefix(6).equals
          (Name("/access/policy/identity/NAC/dataset/KEK")))
        self.assertEqual(7, kekData.getName().size())

        self._fixture._face._sentData = []
        self._fixture._face._sentInterests = []

        self._fixture._face.receive(
          Interest(ckPrefix).setCanBePrefix(True).setMustBeFresh(True))

        ckName = self._fixture._face._sentData[0].getName()
        self.assertTrue(ckName.getPrefix(4).equals(Name("/some/ck/prefix/CK")))
        self.assertTrue(ckName.get(5).equals(Name.Component("ENCRYPTED-BY")))

        extractedKek = ckName.getSubName(6)
        self.assertTrue(extractedKek.equals(kekData.getName()))

        self.assertEqual(False, self._fixture._encryptor._isKekRetrievalInProgress)

    def test_kek_retrieval_failure(self):
        # Replace the default fixture.
        nErrors = [0]
        def onError(errorCode, message):
           nErrors[0] += 1
        self._fixture = EncryptorFixture(False, onError)

        plainText = Blob("Data to encrypt")
        encryptedContent = self._fixture._encryptor.encrypt(plainText)

        # Check that KEK interests has been sent.
        self.assertTrue(
          self._fixture._face._sentInterests[0].getName().getPrefix(6).equals
          (Name("/access/policy/identity/NAC/dataset/KEK")))

        # ... and failed to retrieve.
        self.assertEqual(0, len(self._fixture._face._sentData))

        self.assertEqual(1, nErrors[0])
        self.assertEqual(0, len(self._fixture._face._sentData))

        # Check recovery.
        self._fixture.publishData()

        self._fixture._face._delayedCallTable._setNowOffsetMilliseconds(73000)
        self._fixture._face.processEvents()

        kekData = self._fixture._face._sentData[0]
        self.assertTrue(kekData.getName().getPrefix(6).equals
          (Name("/access/policy/identity/NAC/dataset/KEK")))
        self.assertEqual(7, kekData.getName().size())

    def test_enumerate_data_from_in_memory_storage(self):
        time.sleep(0.2)
        self._fixture._encryptor.regenerateCk()
        time.sleep(0.2)
        self._fixture._encryptor.regenerateCk()

        self.assertEqual(3, self._fixture._encryptor.size())
        nCk = 0
        for name, data in self._fixture._encryptor._storage._cache.items():
            if data.getName().getPrefix(4).equals(Name("/some/ck/prefix/CK")):
                nCk += 1

        self.assertEqual(3, nCk)

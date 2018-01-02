# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt unit tests
# https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/producer.t.cpp
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
import os
from pyndn import Name, Data, Link
from pyndn.util import Blob
from pyndn.encrypt import Producer, Schedule, Sqlite3ProducerDb, EncryptedContent
from pyndn.encrypt.algo import Encryptor, AesAlgorithm, RsaAlgorithm
from pyndn.encrypt.algo import EncryptParams, EncryptAlgorithmType
from pyndn.security import KeyChain, RsaKeyParams
from pyndn.security.identity import IdentityManager
from pyndn.security.identity import MemoryIdentityStorage, MemoryPrivateKeyStorage
from pyndn.security.policy import NoVerifyPolicyManager

DATA_CONTENT = bytearray([
    0xcb, 0xe5, 0x6a, 0x80, 0x41, 0x24, 0x58, 0x23,
    0x84, 0x14, 0x15, 0x61, 0x80, 0xb9, 0x5e, 0xbd,
    0xce, 0x32, 0xb4, 0xbe, 0xbc, 0x91, 0x31, 0xd6,
    0x19, 0x00, 0x80, 0x8b, 0xfa, 0x00, 0x05, 0x9c
])

class TestProducer(ut.TestCase):
    def setUp(self):
        self.decryptionKeys = {} # key: Name, value: Blob
        self.encryptionKeys = {} # key: Name, value: Data

        # Reuse the policy_config subdirectory for the temporary SQLite files.
        self.databaseFilePath = "policy_config/test.db"
        try:
            os.remove(self.databaseFilePath)
        except OSError:
            # no such file
            pass

        # Set up the keyChain.
        identityStorage = MemoryIdentityStorage()
        privateKeyStorage = MemoryPrivateKeyStorage()
        self.keyChain = KeyChain(
          IdentityManager(identityStorage, privateKeyStorage),
          NoVerifyPolicyManager())
        identityName = Name("TestProducer")
        self.certificateName = self.keyChain.createIdentityAndCertificate(identityName)
        self.keyChain.getIdentityManager().setDefaultIdentity(identityName)

    def tearDown(self):
        try:
            os.remove(self.databaseFilePath)
        except OSError:
            pass

    def createEncryptionKey(self, eKeyName, timeMarker):
        params = RsaKeyParams()
        eKeyName = Name(eKeyName)
        eKeyName.append(timeMarker)

        dKeyBlob = RsaAlgorithm.generateKey(params).getKeyBits()
        eKeyBlob = RsaAlgorithm.deriveEncryptKey(dKeyBlob).getKeyBits()
        self.decryptionKeys[eKeyName] = dKeyBlob

        keyData = Data(eKeyName)
        keyData.setContent(eKeyBlob)
        self.keyChain.sign(keyData, self.certificateName)
        self.encryptionKeys[eKeyName] = keyData

    def test_content_key_request(self):
        prefix = Name("/prefix")
        suffix = Name("/a/b/c")
        expectedInterest = Name(prefix)
        expectedInterest.append(Encryptor.NAME_COMPONENT_READ)
        expectedInterest.append(suffix)
        expectedInterest.append(Encryptor.NAME_COMPONENT_E_KEY)

        cKeyName = Name(prefix)
        cKeyName.append(Encryptor.NAME_COMPONENT_SAMPLE)
        cKeyName.append(suffix)
        cKeyName.append(Encryptor.NAME_COMPONENT_C_KEY)

        timeMarker = Name("20150101T100000/20150101T120000")
        testTime1 = Schedule.fromIsoString("20150101T100001")
        testTime2 = Schedule.fromIsoString("20150101T110001")
        testTimeRounded1 = Name.Component("20150101T100000")
        testTimeRounded2 = Name.Component("20150101T110000")
        testTimeComponent2 = Name.Component("20150101T110001")

        # Create content keys required for this test case:
        for i in range(suffix.size()):
          self.createEncryptionKey(expectedInterest, timeMarker)
          expectedInterest = expectedInterest.getPrefix(-2).append(
            Encryptor.NAME_COMPONENT_E_KEY)

        expressInterestCallCount = [0]

        # Prepare a TestFace to instantly answer calls to expressInterest.
        class TestFace(object):
            def __init__(self, handleExpressInterest):
                self.handleExpressInterest = handleExpressInterest
            def expressInterest(self, interest, onData, onTimeout, onNetworkNack):
                return self.handleExpressInterest(
                  interest, onData, onTimeout, onNetworkNack)

        def handleExpressInterest(interest, onData, onTimeout, onNetworkNack):
            expressInterestCallCount[0] += 1

            interestName = Name(interest.getName())
            interestName.append(timeMarker)
            self.assertTrue(interestName in self.encryptionKeys)
            onData(interest, self.encryptionKeys[interestName])

            return 0
        face = TestFace(handleExpressInterest)

        # Verify that the content key is correctly encrypted for each domain, and
        # the produce method encrypts the provided data with the same content key.
        testDb = Sqlite3ProducerDb(self.databaseFilePath)
        producer = Producer(prefix, suffix, face, self.keyChain, testDb)
        contentKey = [None] # Blob

        def checkEncryptionKeys(
          result, testTime, roundedTime, expectedExpressInterestCallCount):
            self.assertEqual(expectedExpressInterestCallCount,
                             expressInterestCallCount[0])

            self.assertEqual(True, testDb.hasContentKey(testTime))
            contentKey[0] = testDb.getContentKey(testTime)

            params = EncryptParams(EncryptAlgorithmType.RsaOaep)
            for i in range(len(result)):
                key = result[i]
                keyName = key.getName()
                self.assertEqual(cKeyName, keyName.getSubName(0, 6))
                self.assertEqual(keyName.get(6), roundedTime)
                self.assertEqual(keyName.get(7), Encryptor.NAME_COMPONENT_FOR)
                self.assertEqual(
                  True, keyName.getSubName(8) in self.decryptionKeys)

                decryptionKey = self.decryptionKeys[keyName.getSubName(8)]
                self.assertEqual(True, decryptionKey.size() != 0)
                encryptedKeyEncoding = key.getContent()

                content = EncryptedContent()
                content.wireDecode(encryptedKeyEncoding)
                encryptedKey = content.getPayload()
                retrievedKey = RsaAlgorithm.decrypt(
                  decryptionKey, encryptedKey, params)

                self.assertTrue(contentKey[0].equals(retrievedKey))

            self.assertEqual(3, len(result))

        # An initial test to confirm that keys are created for this time slot.
        contentKeyName1 = producer.createContentKey(
          testTime1,
          lambda keys: checkEncryptionKeys(keys, testTime1, testTimeRounded1, 3))

        # Verify that we do not repeat the search for e-keys. The total
        #   expressInterestCallCount should be the same.
        contentKeyName2 = producer.createContentKey(
          testTime2,
          lambda keys: checkEncryptionKeys(keys, testTime2, testTimeRounded2, 3))

        # Confirm content key names are correct
        self.assertEqual(cKeyName, contentKeyName1.getPrefix(-1))
        self.assertEqual(testTimeRounded1, contentKeyName1.get(6))
        self.assertEqual(cKeyName, contentKeyName2.getPrefix(-1))
        self.assertEqual(testTimeRounded2, contentKeyName2.get(6))

        # Confirm that produce encrypts with the correct key and has the right name.
        testData = Data()
        producer.produce(testData, testTime2, Blob(DATA_CONTENT, False))

        producedName = testData.getName()
        self.assertEqual(cKeyName.getPrefix(-1), producedName.getSubName(0, 5))
        self.assertEqual(testTimeComponent2, producedName.get(5))
        self.assertEqual(Encryptor.NAME_COMPONENT_FOR, producedName.get(6))
        self.assertEqual(cKeyName, producedName.getSubName(7, 6))
        self.assertEqual(testTimeRounded2, producedName.get(13))

        dataBlob = testData.getContent()

        dataContent = EncryptedContent()
        dataContent.wireDecode(dataBlob)
        encryptedData = dataContent.getPayload()
        initialVector = dataContent.getInitialVector()

        params = EncryptParams(EncryptAlgorithmType.AesCbc, 16)
        params.setInitialVector(initialVector)
        decryptTest = AesAlgorithm.decrypt(contentKey[0], encryptedData, params)
        self.assertTrue(decryptTest.equals(Blob(DATA_CONTENT, False)))

    def test_content_key_search(self):
        timeMarkerFirstHop = Name("20150101T070000/20150101T080000")
        timeMarkerSecondHop = Name("20150101T080000/20150101T090000")
        timeMarkerThirdHop = Name("20150101T100000/20150101T110000")

        prefix = Name("/prefix")
        suffix = Name("/suffix")
        expectedInterest = Name(prefix)
        expectedInterest.append(Encryptor.NAME_COMPONENT_READ)
        expectedInterest.append(suffix)
        expectedInterest.append(Encryptor.NAME_COMPONENT_E_KEY)

        cKeyName = Name(prefix)
        cKeyName.append(Encryptor.NAME_COMPONENT_SAMPLE)
        cKeyName.append(suffix)
        cKeyName.append(Encryptor.NAME_COMPONENT_C_KEY)

        testTime = Schedule.fromIsoString("20150101T100001")

        # Create content keys required for this test case:
        self.createEncryptionKey(expectedInterest, timeMarkerFirstHop)
        self.createEncryptionKey(expectedInterest, timeMarkerSecondHop)
        self.createEncryptionKey(expectedInterest, timeMarkerThirdHop)

        requestCount = [0]

        # Prepare a TestFace to instantly answer calls to expressInterest.
        class TestFace(object):
            def __init__(self, handleExpressInterest):
                self.handleExpressInterest = handleExpressInterest
            def expressInterest(self, interest, onData, onTimeout, onNetworkNack):
                return self.handleExpressInterest(
                  interest, onData, onTimeout, onNetworkNack)

        def handleExpressInterest(interest, onData, onTimeout, onNetworkNack):
            self.assertEqual(expectedInterest, interest.getName())

            gotInterestName = False
            for i in range(3):
              interestName = Name(interest.getName())
              if i == 0:
                interestName.append(timeMarkerFirstHop)
              elif i == 1:
                interestName.append(timeMarkerSecondHop)
              elif i == 2:
                interestName.append(timeMarkerThirdHop)

              # matchesName will check the Exclude.
              if interest.matchesName(interestName):
                gotInterestName = True
                requestCount[0] += 1
                break

            if gotInterestName:
              onData(interest, self.encryptionKeys[interestName])

            return 0
        face = TestFace(handleExpressInterest)

        # Verify that if a key is found, but not within the right time slot, the
        # search is refined until a valid time slot is found.
        testDb = Sqlite3ProducerDb(self.databaseFilePath)
        producer = Producer(prefix, suffix, face, self.keyChain, testDb)
        def onEncryptedKeys(result):
            self.assertEqual(3, requestCount[0])
            self.assertEqual(1, len(result))

            keyData = result[0]
            keyName = keyData.getName()
            self.assertEqual(cKeyName, keyName.getSubName(0, 4))
            self.assertEqual(timeMarkerThirdHop.get(0), keyName.get(4))
            self.assertEqual(Encryptor.NAME_COMPONENT_FOR, keyName.get(5))
            self.assertEqual(expectedInterest.append(timeMarkerThirdHop),
                             keyName.getSubName(6))
        producer.createContentKey(testTime, onEncryptedKeys)

    def test_content_key_timeout(self):
        prefix = Name("/prefix")
        suffix = Name("/suffix")
        expectedInterest = Name(prefix)
        expectedInterest.append(Encryptor.NAME_COMPONENT_READ)
        expectedInterest.append(suffix)
        expectedInterest.append(Encryptor.NAME_COMPONENT_E_KEY)

        testTime = Schedule.fromIsoString("20150101T100001")

        timeoutCount = [0]

        # Prepare a TestFace to instantly answer calls to expressInterest.
        class TestFace(object):
            def __init__(self, handleExpressInterest):
                self.handleExpressInterest = handleExpressInterest
            def expressInterest(self, interest, onData, onTimeout, onNetworkNack):
                return self.handleExpressInterest(
                  interest, onData, onTimeout, onNetworkNack)

        def handleExpressInterest(interest, onData, onTimeout, onNetworkNack):
            self.assertEqual(expectedInterest, interest.getName())
            timeoutCount[0] += 1
            onTimeout(interest)

            return 0
        face = TestFace(handleExpressInterest)

        # Verify that if no response is received, the producer appropriately times
        # out. The result vector should not contain elements that have timed out.
        testDb = Sqlite3ProducerDb(self.databaseFilePath)
        producer = Producer(prefix, suffix, face, self.keyChain, testDb)
        def onEncryptedKeys(result):
            self.assertEqual(4, timeoutCount[0])
            self.assertEqual(0, len(result))
        producer.createContentKey(testTime, onEncryptedKeys)

    def test_producer_with_link(self):
        prefix = Name("/prefix")
        suffix = Name("/suffix")
        expectedInterest = Name(prefix)
        expectedInterest.append(Encryptor.NAME_COMPONENT_READ)
        expectedInterest.append(suffix)
        expectedInterest.append(Encryptor.NAME_COMPONENT_E_KEY)

        testTime = Schedule.fromIsoString("20150101T100001")

        timeoutCount = [0]

        # Prepare a TestFace to instantly answer calls to expressInterest.
        class TestFace(object):
            def __init__(self, handleExpressInterest):
                self.handleExpressInterest = handleExpressInterest
            def expressInterest(self, interest, onData, onTimeout, onNetworkNack):
                return self.handleExpressInterest(
                  interest, onData, onTimeout, onNetworkNack)

        def handleExpressInterest(interest, onData, onTimeout, onNetworkNack):
            self.assertEqual(expectedInterest, interest.getName())
            self.assertEqual(3, interest.getLink().getDelegations().size())
            timeoutCount[0] += 1
            onTimeout(interest)

            return 0
        face = TestFace(handleExpressInterest)

        # Verify that if no response is received, the producer appropriately times
        # out. The result vector should not contain elements that have timed out.
        link = Link()
        link.addDelegation(10,  Name("/test1"))
        link.addDelegation(20,  Name("/test2"))
        link.addDelegation(100, Name("/test3"))
        self.keyChain.sign(link, self.certificateName)
        testDb = Sqlite3ProducerDb(self.databaseFilePath)
        producer = Producer(prefix, suffix, face, self.keyChain, testDb, 3, link)
        def onEncryptedKeys(result):
            self.assertEqual(4, timeoutCount[0])
            self.assertEqual(0, len(result))
        producer.createContentKey(testTime, onEncryptedKeys)

if __name__ == '__main__':
    ut.main(verbosity=2)

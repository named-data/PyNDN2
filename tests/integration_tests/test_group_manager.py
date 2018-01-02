# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt unit tests
# https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/group-manager.t.cpp
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
from pyndn import Name, Data
from pyndn.util import Blob
from pyndn.encoding import TlvWireFormat
from pyndn.encrypt import GroupManager, Sqlite3GroupManagerDb, EncryptedContent
from pyndn.encrypt import Schedule, RepetitiveInterval, DecryptKey, EncryptKey
from pyndn.encrypt.algo import AesAlgorithm, RsaAlgorithm
from pyndn.encrypt.algo import EncryptParams, EncryptAlgorithmType
from pyndn.security import KeyChain, RsaKeyParams
from pyndn.security.certificate import IdentityCertificate, PublicKey
from pyndn.security.identity import IdentityManager
from pyndn.security.identity import MemoryIdentityStorage, MemoryPrivateKeyStorage
from pyndn.security.policy import NoVerifyPolicyManager

SIG_INFO = bytearray([
  0x16, 0x1b, # SignatureInfo
      0x1b, 0x01, # SignatureType
          0x01,
      0x1c, 0x16, # KeyLocator
          0x07, 0x14, # Name
              0x08, 0x04,
                  0x74, 0x65, 0x73, 0x74,
              0x08, 0x03,
                  0x6b, 0x65, 0x79,
              0x08, 0x07,
                  0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72
])

SIG_VALUE = bytearray([
  0x17, 0x80, # SignatureValue
      0x2f, 0xd6, 0xf1, 0x6e, 0x80, 0x6f, 0x10, 0xbe, 0xb1, 0x6f, 0x3e, 0x31, 0xec,
      0xe3, 0xb9, 0xea, 0x83, 0x30, 0x40, 0x03, 0xfc, 0xa0, 0x13, 0xd9, 0xb3, 0xc6,
      0x25, 0x16, 0x2d, 0xa6, 0x58, 0x41, 0x69, 0x62, 0x56, 0xd8, 0xb3, 0x6a, 0x38,
      0x76, 0x56, 0xea, 0x61, 0xb2, 0x32, 0x70, 0x1c, 0xb6, 0x4d, 0x10, 0x1d, 0xdc,
      0x92, 0x8e, 0x52, 0xa5, 0x8a, 0x1d, 0xd9, 0x96, 0x5e, 0xc0, 0x62, 0x0b, 0xcf,
      0x3a, 0x9d, 0x7f, 0xca, 0xbe, 0xa1, 0x41, 0x71, 0x85, 0x7a, 0x8b, 0x5d, 0xa9,
      0x64, 0xd6, 0x66, 0xb4, 0xe9, 0x8d, 0x0c, 0x28, 0x43, 0xee, 0xa6, 0x64, 0xe8,
      0x55, 0xf6, 0x1c, 0x19, 0x0b, 0xef, 0x99, 0x25, 0x1e, 0xdc, 0x78, 0xb3, 0xa7,
      0xaa, 0x0d, 0x14, 0x58, 0x30, 0xe5, 0x37, 0x6a, 0x6d, 0xdb, 0x56, 0xac, 0xa3,
      0xfc, 0x90, 0x7a, 0xb8, 0x66, 0x9c, 0x0e, 0xf6, 0xb7, 0x64, 0xd1
])

class TestGroupManager(ut.TestCase):
    def setUp(self):
        # Reuse the policy_config subdirectory for the temporary SQLite files.
        self.dKeyDatabaseFilePath = "policy_config/manager-d-key-test.db"
        try:
            os.remove(self.dKeyDatabaseFilePath)
        except OSError:
            # no such file
            pass

        self.eKeyDatabaseFilePath = "policy_config/manager-e-key-test.db"
        try:
            os.remove(self.eKeyDatabaseFilePath)
        except OSError:
            # no such file
            pass

        self.intervalDatabaseFilePath = "policy_config/manager-interval-test.db"
        try:
            os.remove(self.intervalDatabaseFilePath)
        except OSError:
            # no such file
            pass

        self.groupKeyDatabaseFilePath = "policy_config/manager-group-key-test.db"
        try:
            os.remove(self.groupKeyDatabaseFilePath)
        except OSError:
            # no such file
            pass

        params = RsaKeyParams()
        memberDecryptKey = RsaAlgorithm.generateKey(params)
        self.decryptKeyBlob = memberDecryptKey.getKeyBits()
        memberEncryptKey = RsaAlgorithm.deriveEncryptKey(self.decryptKeyBlob)
        self.encryptKeyBlob = memberEncryptKey.getKeyBits()

        # Generate the certificate.
        self.certificate = IdentityCertificate()
        self.certificate.setName(Name("/ndn/memberA/KEY/ksk-123/ID-CERT/123"))
        contentPublicKey = PublicKey(self.encryptKeyBlob)
        self.certificate.setPublicKeyInfo(contentPublicKey)
        self.certificate.setNotBefore(0)
        self.certificate.setNotAfter(0)
        self.certificate.encode()

        signatureInfoBlob = Blob(SIG_INFO, False)
        signatureValueBlob = Blob(SIG_VALUE, False)

        signature = TlvWireFormat.get().decodeSignatureInfoAndValue(
          signatureInfoBlob.buf(), signatureValueBlob.buf())
        self.certificate.setSignature(signature)

        self.certificate.wireEncode()

        # Set up the keyChain.
        identityStorage = MemoryIdentityStorage()
        privateKeyStorage = MemoryPrivateKeyStorage()
        self.keyChain = KeyChain(
          IdentityManager(identityStorage, privateKeyStorage),
          NoVerifyPolicyManager())
        identityName = Name("TestGroupManager")
        self.keyChain.createIdentityAndCertificate(identityName)
        self.keyChain.getIdentityManager().setDefaultIdentity(identityName)

    def tearDown(self):
        try:
            os.remove(self.dKeyDatabaseFilePath)
        except OSError:
            pass
        try:
            os.remove(self.eKeyDatabaseFilePath)
        except OSError:
            pass
        try:
            os.remove(self.intervalDatabaseFilePath)
        except OSError:
            pass
        try:
            os.remove(self.groupKeyDatabaseFilePath)
        except OSError:
            pass

    def setManager(self, manager):
        # Set up the first schedule.
        schedule1 = Schedule()
        interval11 = RepetitiveInterval(
          Schedule.fromIsoString("20150825T000000"),
          Schedule.fromIsoString("20150827T000000"), 5, 10, 2,
          RepetitiveInterval.RepeatUnit.DAY)
        interval12 = RepetitiveInterval(
          Schedule.fromIsoString("20150825T000000"),
          Schedule.fromIsoString("20150827T000000"), 6, 8, 1,
          RepetitiveInterval.RepeatUnit.DAY)
        interval13 = RepetitiveInterval(
          Schedule.fromIsoString("20150827T000000"),
          Schedule.fromIsoString("20150827T000000"), 7, 8)
        schedule1.addWhiteInterval(interval11)
        schedule1.addWhiteInterval(interval12)
        schedule1.addBlackInterval(interval13)

        # Set up the second schedule.
        schedule2 = Schedule()
        interval21 = RepetitiveInterval(
          Schedule.fromIsoString("20150825T000000"),
          Schedule.fromIsoString("20150827T000000"), 9, 12, 1,
          RepetitiveInterval.RepeatUnit.DAY)
        interval22 = RepetitiveInterval(
          Schedule.fromIsoString("20150827T000000"),
          Schedule.fromIsoString("20150827T000000"), 6, 8)
        interval23 = RepetitiveInterval(
          Schedule.fromIsoString("20150827T000000"),
          Schedule.fromIsoString("20150827T000000"), 2, 4)
        schedule2.addWhiteInterval(interval21)
        schedule2.addWhiteInterval(interval22)
        schedule2.addBlackInterval(interval23)

        # Add them to the group manager database.
        manager.addSchedule("schedule1", schedule1)
        manager.addSchedule("schedule2", schedule2)

        # Make some adaptions to certificate.
        dataBlob = self.certificate.wireEncode()

        memberA = Data()
        memberA.wireDecode(dataBlob, TlvWireFormat.get())
        memberA.setName(Name("/ndn/memberA/KEY/ksk-123/ID-CERT/123"))
        memberB = Data()
        memberB.wireDecode(dataBlob, TlvWireFormat.get())
        memberB.setName(Name("/ndn/memberB/KEY/ksk-123/ID-CERT/123"))
        memberC = Data()
        memberC.wireDecode(dataBlob, TlvWireFormat.get())
        memberC.setName(Name("/ndn/memberC/KEY/ksk-123/ID-CERT/123"))

        # Add the members to the database.
        manager.addMember("schedule1", memberA)
        manager.addMember("schedule1", memberB)
        manager.addMember("schedule2", memberC)

    def test_create_d_key_data(self):
        # Create the group manager.
        manager = GroupManager(
          Name("Alice"), Name("data_type"),
          Sqlite3GroupManagerDb(self.dKeyDatabaseFilePath), 2048, 1,
          self.keyChain)

        newCertificateBlob = self.certificate.wireEncode()
        newCertificate = IdentityCertificate()
        newCertificate.wireDecode(newCertificateBlob)

        # Encrypt the D-KEY.
        data = manager._createDKeyData(
          "20150825T000000", "20150827T000000", Name("/ndn/memberA/KEY"),
          self.decryptKeyBlob, newCertificate.getPublicKeyInfo().getKeyDer())

        # Verify the encrypted D-KEY.
        dataContent = data.getContent()

        # Get the nonce key.
        # dataContent is a sequence of the two EncryptedContent.
        encryptedNonce = EncryptedContent()
        encryptedNonce.wireDecode(dataContent)
        self.assertEqual(0, encryptedNonce.getInitialVector().size())
        self.assertEqual(EncryptAlgorithmType.RsaOaep, encryptedNonce.getAlgorithmType())

        blobNonce = encryptedNonce.getPayload()
        decryptParams = EncryptParams(EncryptAlgorithmType.RsaOaep)
        nonce = RsaAlgorithm.decrypt(self.decryptKeyBlob, blobNonce, decryptParams)

        # Get the D-KEY.
        # Use the size of encryptedNonce to find the start of encryptedPayload.
        payloadContent = dataContent.buf()[encryptedNonce.wireEncode().size():]
        encryptedPayload = EncryptedContent()
        encryptedPayload.wireDecode(payloadContent)
        self.assertEqual(16, encryptedPayload.getInitialVector().size())
        self.assertEqual(EncryptAlgorithmType.AesCbc, encryptedPayload.getAlgorithmType())

        decryptParams.setAlgorithmType(EncryptAlgorithmType.AesCbc)
        decryptParams.setInitialVector(encryptedPayload.getInitialVector())
        blobPayload = encryptedPayload.getPayload()
        largePayload = AesAlgorithm.decrypt(nonce, blobPayload, decryptParams)

        self.assertTrue(largePayload.equals(self.decryptKeyBlob))

    def test_create_e_key_data(self):
        # Create the group manager.
        manager = GroupManager(
          Name("Alice"), Name("data_type"),
          Sqlite3GroupManagerDb(self.eKeyDatabaseFilePath), 1024, 1,
          self.keyChain)
        self.setManager(manager)

        data = manager._createEKeyData(
          "20150825T090000", "20150825T110000", self.encryptKeyBlob)
        self.assertEqual("/Alice/READ/data_type/E-KEY/20150825T090000/20150825T110000",
                         data.getName().toUri())

        contentBlob = data.getContent()
        self.assertTrue(self.encryptKeyBlob.equals(contentBlob))

    def test_calculate_interval(self):
        # Create the group manager.
        manager = GroupManager(
          Name("Alice"), Name("data_type"),
          Sqlite3GroupManagerDb(self.intervalDatabaseFilePath), 1024, 1,
          self.keyChain)
        self.setManager(manager)

        memberKeys = {}

        timePoint1 = Schedule.fromIsoString("20150825T093000")
        result = manager._calculateInterval(timePoint1, memberKeys)
        self.assertEqual("20150825T090000", Schedule.toIsoString(result.getStartTime()))
        self.assertEqual("20150825T100000", Schedule.toIsoString(result.getEndTime()))

        timePoint2 = Schedule.fromIsoString("20150827T073000")
        result = manager._calculateInterval(timePoint2, memberKeys)
        self.assertEqual("20150827T070000", Schedule.toIsoString(result.getStartTime()))
        self.assertEqual("20150827T080000", Schedule.toIsoString(result.getEndTime()))

        timePoint3 = Schedule.fromIsoString("20150827T043000")
        result = manager._calculateInterval(timePoint3, memberKeys)
        self.assertEqual(False, result.isValid())

        timePoint4 = Schedule.fromIsoString("20150827T053000")
        result = manager._calculateInterval(timePoint4, memberKeys)
        self.assertEqual("20150827T050000", Schedule.toIsoString(result.getStartTime()))
        self.assertEqual("20150827T060000", Schedule.toIsoString(result.getEndTime()))

    def test_get_group_key(self):
        # Create the group manager.
        manager = GroupManager(
          Name("Alice"), Name("data_type"),
          Sqlite3GroupManagerDb(self.groupKeyDatabaseFilePath), 1024, 1,
          self.keyChain)
        self.setManager(manager)

        # Get the data list from the group manager.
        timePoint1 = Schedule.fromIsoString("20150825T093000")
        result = manager.getGroupKey(timePoint1)

        self.assertEqual(4, len(result))

        # The first data packet contains the group's encryption key (public key).
        data = result[0]
        self.assertEqual(
          "/Alice/READ/data_type/E-KEY/20150825T090000/20150825T100000",
          data.getName().toUri())
        groupEKey = EncryptKey(data.getContent())

        # Get the second data packet and decrypt.
        data = result[1]
        self.assertEqual(
          "/Alice/READ/data_type/D-KEY/20150825T090000/20150825T100000/FOR/ndn/memberA/ksk-123",
          data.getName().toUri())

        ####################################################### Start decryption.
        dataContent = data.getContent()

        # Get the nonce key.
        # dataContent is a sequence of the two EncryptedContent.
        encryptedNonce = EncryptedContent()
        encryptedNonce.wireDecode(dataContent)
        self.assertEqual(0, encryptedNonce.getInitialVector().size())
        self.assertEqual(EncryptAlgorithmType.RsaOaep, encryptedNonce.getAlgorithmType())

        decryptParams = EncryptParams(EncryptAlgorithmType.RsaOaep)
        blobNonce = encryptedNonce.getPayload()
        nonce = RsaAlgorithm.decrypt(self.decryptKeyBlob, blobNonce, decryptParams)

        # Get the payload.
        # Use the size of encryptedNonce to find the start of encryptedPayload.
        payloadContent = dataContent.buf()[encryptedNonce.wireEncode().size():]
        encryptedPayload = EncryptedContent()
        encryptedPayload.wireDecode(payloadContent)
        self.assertEqual(16, encryptedPayload.getInitialVector().size())
        self.assertEqual(EncryptAlgorithmType.AesCbc, encryptedPayload.getAlgorithmType())

        decryptParams.setAlgorithmType(EncryptAlgorithmType.AesCbc)
        decryptParams.setInitialVector(encryptedPayload.getInitialVector())
        blobPayload = encryptedPayload.getPayload()
        largePayload = AesAlgorithm.decrypt(nonce, blobPayload, decryptParams)

        # Get the group D-KEY.
        groupDKey = DecryptKey(largePayload)

        ####################################################### End decryption.

        # Check the D-KEY.
        derivedGroupEKey = RsaAlgorithm.deriveEncryptKey(groupDKey.getKeyBits())
        self.assertTrue(groupEKey.getKeyBits().equals(derivedGroupEKey.getKeyBits()))

        # Check the third data packet.
        data = result[2]
        self.assertEqual(
          "/Alice/READ/data_type/D-KEY/20150825T090000/20150825T100000/FOR/ndn/memberB/ksk-123",
          data.getName().toUri())

        # Check the fourth data packet.
        data = result[3]
        self.assertEqual(
          "/Alice/READ/data_type/D-KEY/20150825T090000/20150825T100000/FOR/ndn/memberC/ksk-123",
          data.getName().toUri())

        # Check invalid time stamps for getting the group key.
        timePoint2 = Schedule.fromIsoString("20150826T083000")
        self.assertEqual(0, len(manager.getGroupKey(timePoint2)))

        timePoint3 = Schedule.fromIsoString("20150827T023000")
        self.assertEqual(0, len(manager.getGroupKey(timePoint3)))

    def test_get_group_key_without_regeneration(self):
        # Create the group manager.
        manager = GroupManager(
          Name("Alice"), Name("data_type"),
          Sqlite3GroupManagerDb(self.groupKeyDatabaseFilePath), 1024, 1,
          self.keyChain)
        self.setManager(manager)

        # Get the data list from the group manager.
        timePoint1 = Schedule.fromIsoString("20150825T093000")
        result = manager.getGroupKey(timePoint1)

        self.assertEqual(4, len(result))

        # The first data packet contains the group's encryption key (public key).
        data1 = result[0]
        self.assertEqual(
          "/Alice/READ/data_type/E-KEY/20150825T090000/20150825T100000",
          data1.getName().toUri())
        groupEKey1 = EncryptKey(data1.getContent())

        # Get the second data packet and decrypt.
        data = result[1]
        self.assertEqual(
          "/Alice/READ/data_type/D-KEY/20150825T090000/20150825T100000/FOR/ndn/memberA/ksk-123",
          data.getName().toUri())

        # Add new members to the database.
        dataBlob = self.certificate.wireEncode()
        memberD = Data()
        memberD.wireDecode(dataBlob)
        memberD.setName(Name("/ndn/memberD/KEY/ksk-123/ID-CERT/123"))
        manager.addMember("schedule1", memberD)

        result2 = manager.getGroupKey(timePoint1, False)
        self.assertEqual(5, len(result2))

        # Check that the new EKey is the same as the previous one.
        data2 = result2[0]
        self.assertEqual(
          "/Alice/READ/data_type/E-KEY/20150825T090000/20150825T100000",
           data2.getName().toUri())
        groupEKey2 = EncryptKey(data2.getContent())
        self.assertTrue(groupEKey1.getKeyBits().equals(groupEKey2.getKeyBits()));

        # Check the second data packet.
        data2 = result2[1]
        self.assertEqual(
          "/Alice/READ/data_type/D-KEY/20150825T090000/20150825T100000/FOR/ndn/memberA/ksk-123",
          data2.getName().toUri())

if __name__ == '__main__':
    ut.main(verbosity=2)

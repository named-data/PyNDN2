# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx unit tests:
# https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/tpm/back-end.t.cpp
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
import sys
from pyndn.util import Blob
from pyndn.name import Name
from pyndn.encrypt.algo.encrypt_params import EncryptParams, EncryptAlgorithmType
from pyndn.encrypt.algo.rsa_algorithm import RsaAlgorithm
from pyndn.security.security_types import DigestAlgorithm
from pyndn.security.key_params import RsaKeyParams, EcKeyParams
from pyndn.security.verification_helpers import VerificationHelpers
from pyndn.security.pib.pib_key import PibKey
from pyndn.security.tpm.tpm import Tpm
from pyndn.security.tpm.tpm_back_end_memory import TpmBackEndMemory
from pyndn.security.tpm.tpm_back_end_file import TpmBackEndFile
from pyndn.security.tpm.tpm_back_end_osx import TpmBackEndOsx

class TestTpmBackEnds(ut.TestCase):
    def setUp(self):
        self.backEndMemory = TpmBackEndMemory()

        locationPath = os.path.abspath("policy_config/ndnsec-key-file")
        if os.path.exists(locationPath):
            # Delete files from a previous test.
            for fileName in os.listdir(locationPath):
                filePath = os.path.join(locationPath, fileName)
                if os.path.isfile(filePath):
                    os.remove(filePath)
        self.backEndFile = TpmBackEndFile(locationPath)

        self.backEndOsx = TpmBackEndOsx()

        self.backEndList = []
        self.backEndList.append(self.backEndMemory)
        self.backEndList.append(self.backEndFile)
        if sys.platform == 'darwin':
            self.backEndList.append(self.backEndOsx)

    def test_key_management(self):
        for tpm in self.backEndList:
            identityName = Name("/Test/KeyName")
            keyId = Name.Component("1")
            keyName = PibKey.constructKeyName(identityName, keyId)

            # The key should not exist.
            self.assertEquals(False, tpm.hasKey(keyName))
            self.assertTrue(tpm.getKeyHandle(keyName) == None)

            # Create a key, which should exist.
            self.assertTrue(
              tpm.createKey(identityName, RsaKeyParams(keyId)) != None)
            self.assertTrue(tpm.hasKey(keyName))
            self.assertTrue(tpm.getKeyHandle(keyName) != None)

            # Create a key with the same name, which should throw an error.
            try:
                tpm.createKey(identityName, RsaKeyParams(keyId))
                self.fail("Did not throw the expected exception")
            except Tpm.Error:
                pass
            else:
                self.fail("Did not throw the expected exception")

            # Delete the key, then it should not exist.
            tpm.deleteKey(keyName)
            self.assertEquals(False, tpm.hasKey(keyName))
            self.assertTrue(tpm.getKeyHandle(keyName) == None)

    def test_rsa_signing(self):
        for tpm in self.backEndList:
            # Create an RSA key.
            identityName = Name("/Test/KeyName")

            key = tpm.createKey(identityName, RsaKeyParams())
            keyName = key.getKeyName()

            content = Blob([0x01, 0x02, 0x03, 0x04])
            signature = key.sign(DigestAlgorithm.SHA256, content.toBytes())

            publicKey = key.derivePublicKey()

            result = VerificationHelpers.verifySignature(
              content, signature, publicKey)
            self.assertEquals(True, result)

            tpm.deleteKey(keyName)
            self.assertEquals(False, tpm.hasKey(keyName))

    def test_rsa_decryption(self):
        for tpm in self.backEndList:
            # Create an rsa key.
            identityName = Name("/Test/KeyName")

            key = tpm.createKey(identityName, RsaKeyParams())
            keyName = key.getKeyName()

            content = Blob([0x01, 0x02, 0x03, 0x04])

            publicKey = key.derivePublicKey()

            # TODO: Move encrypt to PublicKey?
            cipherText = RsaAlgorithm.encrypt(
              publicKey, content, EncryptParams(EncryptAlgorithmType.RsaOaep))

            plainText = key.decrypt(cipherText.toBytes())

            self.assertTrue(plainText.equals(content))

            tpm.deleteKey(keyName)
            self.assertEquals(False, tpm.hasKey(keyName))

    def test_ecdsa_signing(self):
        for tpm in self.backEndList:
            # Create an EC key.
            identityName = Name("/Test/Ec/KeyName")

            key = tpm.createKey(identityName, EcKeyParams())
            keyName = key.getKeyName()

            content = Blob([0x01, 0x02, 0x03, 0x04])
            signature = key.sign(DigestAlgorithm.SHA256, content.toBytes())

            publicKey = key.derivePublicKey()

            result = VerificationHelpers.verifySignature(
              content, signature, publicKey)
            self.assertEquals(True, result)

            tpm.deleteKey(keyName)
            self.assertEquals(False, tpm.hasKey(keyName))

    def test_random_key_id(self):
        tpm = self.backEndMemory

        identityName = Name("/Test/KeyName");

        keyNames = set()
        for i in range(100):
            key = tpm.createKey(identityName, RsaKeyParams())
            keyName = key.getKeyName()

            saveSize = len(keyNames)
            keyNames.add(keyName)
            self.assertTrue(len(keyNames) > saveSize)

if __name__ == '__main__':
    ut.main(verbosity=2)

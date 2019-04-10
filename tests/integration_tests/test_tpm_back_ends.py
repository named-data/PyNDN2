# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
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
import base64
from pyndn.util import Blob
from pyndn.name import Name
from pyndn.encrypt.algo.encrypt_params import EncryptParams, EncryptAlgorithmType
from pyndn.encrypt.algo.rsa_algorithm import RsaAlgorithm
from pyndn.security.security_types import DigestAlgorithm
from pyndn.security.key_params import RsaKeyParams, EcKeyParams
from pyndn.security.verification_helpers import VerificationHelpers
from pyndn.security.pib.pib_key import PibKey
from pyndn.security.tpm.tpm import Tpm
from pyndn.security.tpm.tpm_private_key import TpmPrivateKey
from pyndn.security.tpm.tpm_back_end import TpmBackEnd
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
            self.assertEqual(False, tpm.hasKey(keyName))
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
            self.assertEqual(False, tpm.hasKey(keyName))
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
            self.assertEqual(True, result)

            tpm.deleteKey(keyName)
            self.assertEqual(False, tpm.hasKey(keyName))

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
            self.assertEqual(False, tpm.hasKey(keyName))

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
            self.assertEqual(True, result)

            tpm.deleteKey(keyName)
            self.assertEqual(False, tpm.hasKey(keyName))

    def test_import_export(self):
        privateKeyPkcs1Base64 = (
          "MIIEpAIBAAKCAQEAw0WM1/WhAxyLtEqsiAJgWDZWuzkYpeYVdeeZcqRZzzfRgBQT\n" +
          "sNozS5t4HnwTZhwwXbH7k3QN0kRTV826Xobws3iigohnM9yTK+KKiayPhIAm/+5H\n" +
          "GT6SgFJhYhqo1/upWdueojil6RP4/AgavHhopxlAVbk6G9VdVnlQcQ5Zv0OcGi73\n" +
          "c+EnYD/YgURYGSngUi/Ynsh779p2U69/te9gZwIL5PuE9BiO6I39cL9z7EK1SfZh\n" +
          "OWvDe/qH7YhD/BHwcWit8FjRww1glwRVTJsA9rH58ynaAix0tcR/nBMRLUX+e3rU\n" +
          "RHg6UbSjJbdb9qmKM1fTGHKUzL/5pMG6uBU0ywIDAQABAoIBADQkckOIl4IZMUTn\n" +
          "W8LFv6xOdkJwMKC8G6bsPRFbyY+HvC2TLt7epSvfS+f4AcYWaOPcDu2E49vt2sNr\n" +
          "cASly8hgwiRRAB3dHH9vcsboiTo8bi2RFvMqvjv9w3tK2yMxVDtmZamzrrnaV3YV\n" +
          "Q+5nyKo2F/PMDjQ4eUAKDOzjhBuKHsZBTFnA1MFNI+UKj5X4Yp64DFmKlxTX/U2b\n" +
          "wzVywo5hzx2Uhw51jmoLls4YUvMJXD0wW5ZtYRuPogXvXb/of9ef/20/wU11WFKg\n" +
          "Xb4gfR8zUXaXS1sXcnVm3+24vIs9dApUwykuoyjOqxWqcHRec2QT2FxVGkFEraze\n" +
          "CPa4rMECgYEA5Y8CywomIcTgerFGFCeMHJr8nQGqY2V/owFb3k9maczPnC9p4a9R\n" +
          "c5szLxA9FMYFxurQZMBWSEG2JS1HR2mnjigx8UKjYML/A+rvvjZOMe4M6Sy2ggh4\n" +
          "SkLZKpWTzjTe07ByM/j5v/SjNZhWAG7sw4/LmPGRQkwJv+KZhGojuOkCgYEA2cOF\n" +
          "T6cJRv6kvzTz9S0COZOVm+euJh/BXp7oAsAmbNfOpckPMzqHXy8/wpdKl6AAcB57\n" +
          "OuztlNfV1D7qvbz7JuRlYwQ0cEfBgbZPcz1p18HHDXhwn57ZPb8G33Yh9Omg0HNA\n" +
          "Imb4LsVuSqxA6NwSj7cpRekgTedrhLFPJ+Ydb5MCgYEAsM3Q7OjILcIg0t6uht9e\n" +
          "vrlwTsz1mtCV2co2I6crzdj9HeI2vqf1KAElDt6G7PUHhglcr/yjd8uEqmWRPKNX\n" +
          "ddnnfVZB10jYeP/93pac6z/Zmc3iU4yKeUe7U10ZFf0KkiiYDQd59CpLef/2XScS\n" +
          "HB0oRofnxRQjfjLc4muNT+ECgYEAlcDk06MOOTly+F8lCc1bA1dgAmgwFd2usDBd\n" +
          "Y07a3e0HGnGLN3Kfl7C5i0tZq64HvxLnMd2vgLVxQlXGPpdQrC1TH+XLXg+qnlZO\n" +
          "ivSH7i0/gx75bHvj75eH1XK65V8pDVDEoSPottllAIs21CxLw3N1ObOZWJm2EfmR\n" +
          "cuHICmsCgYAtFJ1idqMoHxES3mlRpf2JxyQudP3SCm2WpGmqVzhRYInqeatY5sUd\n" +
          "lPLHm/p77RT7EyxQHTlwn8FJPuM/4ZH1rQd/vB+Y8qAtYJCexDMsbvLW+Js+VOvk\n" +
          "jweEC0nrcL31j9mF0vz5E6tfRu4hhJ6L4yfWs0gSejskeVB/w8QY4g==\n")

        for tpm in self.backEndList:
            if tpm is self.backEndOsx:
                # TODO: Implement TpmBackEndOsx import/export.
                continue

            keyName = Name("/Test/KeyName/KEY/1")
            tpm.deleteKey(keyName)
            self.assertEqual(False, tpm.hasKey(keyName))

            privateKey = TpmPrivateKey()
            privateKeyPkcs1Encoding = Blob(base64.b64decode(privateKeyPkcs1Base64))
            privateKey.loadPkcs1(privateKeyPkcs1Encoding.buf())

            password = Blob("password").toBytes()
            encryptedPkcs8 = privateKey.toEncryptedPkcs8(password)

            tpm.importKey(keyName, encryptedPkcs8.buf(), password)
            self.assertEqual(True, tpm.hasKey(keyName))
            try:
                # Can't import the same keyName again.
                tpm.importKey(keyName, encryptedPkcs8.buf(), password)
                self.fail("Did not throw the expected exception")
            except TpmBackEnd.Error:
                pass
            else:
                self.fail("Did not throw the expected exception")

            exportedKey = tpm.exportKey(keyName, password)
            self.assertEqual(True, tpm.hasKey(keyName))

            privateKey2 = TpmPrivateKey()
            privateKey2.loadEncryptedPkcs8(exportedKey.buf(), password)
            privateKey2Pkcs1Encoding = privateKey2.toPkcs1()
            self.assertTrue(privateKeyPkcs1Encoding.equals(privateKey2Pkcs1Encoding))

            tpm.deleteKey(keyName)
            self.assertEqual(False, tpm.hasKey(keyName))
            try:
                tpm.exportKey(keyName, password)
                self.fail("Did not throw the expected exception")
            except TpmBackEnd.Error:
                pass
            else:
                self.fail("Did not throw the expected exception")

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

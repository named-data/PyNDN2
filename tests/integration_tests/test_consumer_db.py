# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt unit tests
# https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/consumer-db.t.cpp
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

from pyndn import Name
from pyndn.encrypt import Schedule, ConsumerDb, Sqlite3ConsumerDb
from pyndn.encrypt.algo import AesAlgorithm, RsaAlgorithm
from pyndn.security.key_params import AesKeyParams, RsaKeyParams

def generateRsaKeys():
    params = RsaKeyParams()
    decryptKey = RsaAlgorithm.generateKey(params)
    decryptionKeyBlob = decryptKey.getKeyBits()
    encryptKey = RsaAlgorithm.deriveEncryptKey(decryptionKeyBlob)
    encryptionKeyBlob = encryptKey.getKeyBits()

    return (encryptionKeyBlob, decryptionKeyBlob)

def generateAesKeys():
    params = AesKeyParams()
    memberDecryptKey = AesAlgorithm.generateKey(params)
    decryptionKeyBlob = memberDecryptKey.getKeyBits()
    memberEncryptKey = AesAlgorithm.deriveEncryptKey(decryptionKeyBlob)
    encryptionKeyBlob = memberEncryptKey.getKeyBits()

    return (encryptionKeyBlob, decryptionKeyBlob)

class TestConsumerDb(ut.TestCase):
    def setUp(self):
        # Reuse the policy_config subdirectory for the temporary SQLite file.
        self.databaseFilePath = "policy_config/test.db"
        try:
            os.remove(self.databaseFilePath)
        except OSError:
            # no such file
            pass

    def tearDown(self):
        try:
            os.remove(self.databaseFilePath)
        except OSError:
            pass

    def test_operate_aes_decryption_key(self):
        # Test construction.
        database = Sqlite3ConsumerDb(self.databaseFilePath)

        # Generate key blobs.
        (encryptionKeyBlob, decryptionKeyBlob) = generateAesKeys()

        keyName = Name(
          "/alice/health/samples/activity/steps/C-KEY/20150928080000/20150928090000!")
        keyName.append(Name("FOR/alice/health/read/activity!"))
        database.addKey(keyName, decryptionKeyBlob)
        resultBlob = database.getKey(keyName)

        self.assertTrue(decryptionKeyBlob.equals(resultBlob))

        database.deleteKey(keyName)
        resultBlob = database.getKey(keyName)

        self.assertEqual(0, resultBlob.size())

    def test_operate_rsa_decryption_key(self):
        # Test construction.
        database = Sqlite3ConsumerDb(self.databaseFilePath)

        # Generate key blobs.
        (encryptionKeyBlob, decryptionKeyBlob) = generateRsaKeys()

        keyName = Name(
          "/alice/health/samples/activity/steps/D-KEY/20150928080000/20150928090000!")
        keyName.append(Name("FOR/test/member/KEY/123!"))
        database.addKey(keyName, decryptionKeyBlob)
        resultBlob = database.getKey(keyName)

        self.assertTrue(decryptionKeyBlob.equals(resultBlob))

        database.deleteKey(keyName)
        resultBlob = database.getKey(keyName)

        self.assertEqual(0, resultBlob.size())

if __name__ == '__main__':
    ut.main(verbosity=2)

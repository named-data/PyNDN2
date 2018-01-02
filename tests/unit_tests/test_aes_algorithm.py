# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt unit tests
# https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/aes.t.cpp
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
from pyndn.util import Blob
from pyndn.encrypt.algo import EncryptParams, EncryptAlgorithmType
from pyndn.encrypt.algo import AesAlgorithm
from pyndn.encrypt import DecryptKey
from pyndn.security import AesKeyParams

KEY = bytearray([
    0xdd, 0x60, 0x77, 0xec, 0xa9, 0x6b, 0x23, 0x1b,
    0x40, 0x6b, 0x5a, 0xf8, 0x7d, 0x3d, 0x55, 0x32
])

# plaintext: AES-Encrypt-Test
PLAINTEXT = bytearray([
    0x41, 0x45, 0x53, 0x2d, 0x45, 0x6e, 0x63, 0x72,
    0x79, 0x70, 0x74, 0x2d, 0x54, 0x65, 0x73, 0x74
])

CIPHERTEXT_ECB = bytearray([
    0xcb, 0xe5, 0x6a, 0x80, 0x41, 0x24, 0x58, 0x23,
    0x84, 0x14, 0x15, 0x61, 0x80, 0xb9, 0x5e, 0xbd,
    0xce, 0x32, 0xb4, 0xbe, 0xbc, 0x91, 0x31, 0xd6,
    0x19, 0x00, 0x80, 0x8b, 0xfa, 0x00, 0x05, 0x9c
])

INITIAL_VECTOR = bytearray([
    0x6f, 0x53, 0x7a, 0x65, 0x58, 0x6c, 0x65, 0x75,
    0x44, 0x4c, 0x77, 0x35, 0x58, 0x63, 0x78, 0x6e
])

CIPHERTEXT_CBC_IV = bytearray([
    0xb7, 0x19, 0x5a, 0xbb, 0x23, 0xbf, 0x92, 0xb0,
    0x95, 0xae, 0x74, 0xe9, 0xad, 0x72, 0x7c, 0x28,
    0x6e, 0xc6, 0x73, 0xb5, 0x0b, 0x1a, 0x9e, 0xb9,
    0x4d, 0xc5, 0xbd, 0x8b, 0x47, 0x1f, 0x43, 0x00
])

class TestAesAlgorithm(ut.TestCase):
    def test_encryption_decryption(self):
        encryptParams = EncryptParams(EncryptAlgorithmType.AesEcb, 16)

        key = Blob(KEY, False)
        decryptKey = DecryptKey(key)
        encryptKey = AesAlgorithm.deriveEncryptKey(decryptKey.getKeyBits())

        # Check key loading and key derivation.
        self.assertTrue(encryptKey.getKeyBits().equals(key))
        self.assertTrue(decryptKey.getKeyBits().equals(key))

        plainBlob = Blob(PLAINTEXT, False)

        # Encrypt data in AES_ECB.
        cipherBlob = AesAlgorithm.encrypt(
          encryptKey.getKeyBits(), plainBlob, encryptParams)
        self.assertTrue(cipherBlob.equals(Blob(CIPHERTEXT_ECB, False)))

        # Decrypt data in AES_ECB.
        receivedBlob = AesAlgorithm.decrypt(
          decryptKey.getKeyBits(), cipherBlob, encryptParams)
        self.assertTrue(receivedBlob.equals(plainBlob))

        # Encrypt/decrypt data in AES_CBC with auto-generated IV.
        encryptParams.setAlgorithmType(EncryptAlgorithmType.AesCbc)
        cipherBlob = AesAlgorithm.encrypt(
          encryptKey.getKeyBits(), plainBlob, encryptParams)
        receivedBlob = AesAlgorithm.decrypt(
          decryptKey.getKeyBits(), cipherBlob, encryptParams)
        self.assertTrue(receivedBlob.equals(plainBlob))

        # Encrypt data in AES_CBC with specified IV.
        initialVector = Blob(INITIAL_VECTOR, False)
        encryptParams.setInitialVector(initialVector)
        cipherBlob = AesAlgorithm.encrypt(
          encryptKey.getKeyBits(), plainBlob, encryptParams)
        self.assertTrue(cipherBlob.equals(Blob(CIPHERTEXT_CBC_IV, False)))

        # Decrypt data in AES_CBC with specified IV.
        receivedBlob = AesAlgorithm.decrypt(
          decryptKey.getKeyBits(), cipherBlob, encryptParams)
        self.assertTrue(receivedBlob.equals(plainBlob))

    def test_key_generation(self):
        keyParams = AesKeyParams(128)
        decryptKey = AesAlgorithm.generateKey(keyParams)
        encryptKey = AesAlgorithm.deriveEncryptKey(decryptKey.getKeyBits())

        plainBlob = Blob(PLAINTEXT, False)

        # Encrypt/decrypt data in AES_CBC with auto-generated IV.
        encryptParams = EncryptParams(EncryptAlgorithmType.AesCbc, 16)
        cipherBlob = AesAlgorithm.encrypt(
          encryptKey.getKeyBits(), plainBlob, encryptParams)
        receivedBlob = AesAlgorithm.decrypt(
          decryptKey.getKeyBits(), cipherBlob, encryptParams)
        self.assertTrue(receivedBlob.equals(plainBlob))

if __name__ == '__main__':
    ut.main(verbosity=2)

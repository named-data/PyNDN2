# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt src/algo/aes https://github.com/named-data/ndn-group-encrypt
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

"""
This module defines the AesAlgorithm class which provides static methods to
manipulate keys, encrypt and decrypt using the AES symmetric key cipher.
Note: This class is an experimental feature. The API may change.
"""

# (This is ported from ndn::gep::algo::Aes, and named AesAlgorithm because
# "Aes" is very short and not all the Common Client Libraries have namespaces.)

import sys
from random import SystemRandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pyndn.util.blob import Blob
from pyndn.encrypt.algo.encrypt_params import EncryptAlgorithmType
from pyndn.encrypt.decrypt_key import DecryptKey
from pyndn.encrypt.encrypt_key import EncryptKey

# The Python documentation says "Use SystemRandom if you require a
#   cryptographically secure pseudo-random number generator."
# http://docs.python.org/2/library/random.html
_systemRandom = SystemRandom()

class AesAlgorithm(object):
    @staticmethod
    def generateKey(params):
        """
        Generate a new random decrypt key for AES based on the given params.

        :param AesKeyParams params: The key params with the key size (in bits).
        :return: The new decrypt key.
        :rtype: DecryptKey
        """
        # Convert the key bit size to bytes.
        nBytes = int(round(params.getKeySize() / 8))
        key = bytearray(nBytes)
        for i in range(nBytes):
            key[i] = _systemRandom.randint(0, 0xff)

        decryptKey = DecryptKey(Blob(key, False))
        return decryptKey

    @staticmethod
    def deriveEncryptKey(keyBits):
        """
        Derive a new encrypt key from the given decrypt key value.

        :param Blob keyBits: The key value of the decrypt key.
        :return: The new encrypt key.
        :rtype: EncryptKey
        """
        return EncryptKey(keyBits)

    @staticmethod
    def decrypt(keyBits, encryptedData, params):
        """
        Decrypt the encryptedData using the keyBits according the encrypt params.

        :param Blob keyBits: The key value.
        :param Blob encryptedData: The data to decrypt.
        :param EncryptParams params: This decrypts according to
          params.getAlgorithmType() and other params as needed such as
          params.getInitialVector().
        :return: The decrypted data.
        :rtype: Blob
        """
        if params.getAlgorithmType() == EncryptAlgorithmType.AesEcb:
            cipher = Cipher(algorithms.AES(
              keyBits.toBytes()), modes.ECB(), backend = default_backend())
        elif params.getAlgorithmType() == EncryptAlgorithmType.AesCbc:
            cipher = Cipher(algorithms.AES(
              keyBits.toBytes()), modes.CBC(params.getInitialVector().toBytes()),
              backend = default_backend())
        else:
            raise RuntimeError("unsupported encryption mode")

        # For the cryptography package, we have to remove the padding.
        decryptor = cipher.decryptor()
        resultWithPad = decryptor.update(encryptedData.toBytes()) + decryptor.finalize()
        if sys.version_info[0] <= 2:
            padLength = ord(resultWithPad[-1])
        else:
            padLength = resultWithPad[-1]

        return Blob(resultWithPad[:-padLength], False)

    @staticmethod
    def encrypt(keyBits, plainData, params):
        """
        Encrypt the plainData using the keyBits according the encrypt params.

        :param Blob keyBits: The key value.
        :param Blob plainData: The data to encrypt.
        :param EncryptParams params: This encrypts according to
          params.getAlgorithmType() and other params as needed such as
          params.getInitialVector().
        :return: The encrypted data.
        :rtype: Blob
        """
        # For the cryptography package, we have to do the padding.
        padLength = 16 - (plainData.size() % 16)
        if sys.version_info[0] <= 2:
            pad = chr(padLength) * padLength
        else:
            pad = bytes([padLength]) * padLength

        if params.getAlgorithmType() == EncryptAlgorithmType.AesEcb:
            cipher = Cipher(algorithms.AES(
              keyBits.toBytes()), modes.ECB(), backend = default_backend())
        elif params.getAlgorithmType() == EncryptAlgorithmType.AesCbc:
            cipher = Cipher(algorithms.AES(
              keyBits.toBytes()), modes.CBC(params.getInitialVector().toBytes()),
              backend = default_backend())
        else:
            raise RuntimeError("unsupported encryption mode")

        encryptor = cipher.encryptor()
        return Blob(
          encryptor.update(plainData.toBytes() + pad) + encryptor.finalize(),
          False)

    BLOCK_SIZE = 16

# Import this at the end of the file to avoid circular references.
from pyndn.encrypt.algo.encryptor import Encryptor

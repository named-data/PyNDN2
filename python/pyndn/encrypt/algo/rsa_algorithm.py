# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt src/algo/rsa https://github.com/named-data/ndn-group-encrypt
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
This module defines the RsaAlgorithm class which provides static methods to
manipulate keys, encrypt and decrypt using RSA.
"""

# (This is ported from ndn::gep::algo::Rsa, and named RsaAlgorithm because
# "Rsa" is very short and not all the Common Client Libraries have namespaces.)

from pyndn.encoding.der.der_node import *
from pyndn.security.certificate.public_key import PublicKey
from pyndn.encrypt.decrypt_key import DecryptKey
from pyndn.encrypt.encrypt_key import EncryptKey
from pyndn.security.tpm.tpm_private_key import TpmPrivateKey

class RsaAlgorithm(object):
    @staticmethod
    def generateKey(params):
        """
        Generate a new random decrypt key for RSA based on the given params.

        :param RsaKeyParams params: The key params with the key size (in bits).
        :return: The new decrypt key (PKCS8-encoded private key).
        :rtype: DecryptKey
        """
        privateKey = TpmPrivateKey.generatePrivateKey(params)
        return DecryptKey(privateKey.toPkcs8())

    @staticmethod
    def deriveEncryptKey(keyBits):
        """
        Derive a new encrypt key from the given decrypt key value.

        :param Blob keyBits: The key value of the decrypt key (PKCS8-encoded
          private key).
        :return: The new encrypt key (DER-encoded public key).
        :rtype: EncryptKey
        """
        privateKey = TpmPrivateKey()
        privateKey.loadPkcs8(keyBits.toBytes())
        return EncryptKey(privateKey.derivePublicKey())

    @staticmethod
    def decrypt(keyBits, encryptedData, params):
        """
        Decrypt the encryptedData using the keyBits according the encrypt params.

        :param Blob keyBits: The key value (PKCS8-encoded private key).
        :param Blob encryptedData: The data to decrypt.
        :param EncryptParams params: This decrypts according to
          params.getAlgorithmType().
        :return: The decrypted data.
        :rtype: Blob
        """
        privateKey = TpmPrivateKey()
        privateKey.loadPkcs8(keyBits.toBytes())
        return privateKey.decrypt(
          encryptedData.toBytes(), params.getAlgorithmType())

    @staticmethod
    def encrypt(keyBits, plainData, params):
        """
        Encrypt the plainData using the keyBits according the encrypt params.

        :param Blob keyBits: The key value (DER-encoded public key).
        :param Blob plainData: The data to encrypt.
        :param EncryptParams params: This encrypts according to
          params.getAlgorithmType().
        :return: The encrypted data.
        :rtype: Blob
        """
        return PublicKey(keyBits).encrypt(plainData, params.getAlgorithmType())

    RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1"

# Import this at the end of the file to avoid circular references.
from pyndn.encrypt.algo.encryptor import Encryptor

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015 Regents of the University of California.
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

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long
from pyndn.util.blob import Blob
from pyndn.encoding.der.der_node import *
from pyndn.encoding.oid import OID
from pyndn.encrypt.algo.encrypt_params import EncryptAlgorithmType
from pyndn.encrypt.decrypt_key import DecryptKey
from pyndn.encrypt.encrypt_key import EncryptKey

class RsaAlgorithm(object):
    @staticmethod
    def generateKey(params):
        """
        Generate a new random decrypt key for RSA based on the given params.

        :param RsaKeyParams params: The key params with the key size (in bits).
        :return: The new decrypt key (PKCS8-encoded private key).
        :rtype: DecryptKey
        """
        key = RSA.generate(params.getKeySize())
        pkcs1PrivateKeyDer = Blob(key.exportKey('DER'), False)
        privateKey = RsaAlgorithm._encodePkcs8PrivateKey(
          pkcs1PrivateKeyDer, OID(RsaAlgorithm.RSA_ENCRYPTION_OID),
          DerNull())
        return DecryptKey(privateKey)
          
    @staticmethod
    def deriveEncryptKey(keyBits):
        """
        Derive a new encrypt key from the given decrypt key value.

        :param Blob keyBits: The key value of the decrypt key (PKCS8-encoded
          private key).
        :return: The new encrypt key (DER-encoded public key).
        :rtype: EncryptKey
        """
        # Decode the PKCS #8 private key. (We don't use RSAPrivateCrtKey because
        # the Android library doesn't have an easy way to decode into it.)
        parsedNode = DerNode.parse(keyBits.buf(), 0)
        pkcs8Children = parsedNode.getChildren()
        algorithmIdChildren = DerNode.getSequence(pkcs8Children, 1).getChildren()
        oidString = algorithmIdChildren[0].toVal()
        rsaPrivateKeyDer = pkcs8Children[2].getPayload()

        if oidString != RsaAlgorithm.RSA_ENCRYPTION_OID:
          raise RuntimeException("The PKCS #8 private key is not RSA_ENCRYPTION")

        # Decode the PKCS #1 RSAPrivateKey.
        parsedNode = DerNode.parse(rsaPrivateKeyDer.buf(), 0)
        rsaPrivateKeyChildren = parsedNode.getChildren()
        modulus = rsaPrivateKeyChildren[1].getPayload()
        publicExponent = rsaPrivateKeyChildren[2].getPayload()

        publicKey = RSA.construct((
          bytes_to_long(Encryptor.toPyCrypto(modulus)),
          bytes_to_long(Encryptor.toPyCrypto(publicExponent))))
        return EncryptKey(Blob(publicKey.exportKey(format = 'DER'), False))

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
        privateKey = RSA.importKey(Encryptor.toPyCrypto(keyBits))

        # TODO: Support EncryptAlgorithmType.RsaPkcs. (not really using it now.)
        if params.getAlgorithmType() == EncryptAlgorithmType.RsaOaep:
            cipher = PKCS1_OAEP.new(privateKey)
            result = cipher.decrypt(Encryptor.toPyCrypto(encryptedData))
        else:
            raise RuntimeError("unsupported encryption mode")

        return Blob(result, False)

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
        publicKey = RSA.importKey(Encryptor.toPyCrypto(keyBits))

        # TODO: Support EncryptAlgorithmType.RsaPkcs. (not really using it now.)
        if params.getAlgorithmType() == EncryptAlgorithmType.RsaOaep:
            cipher = PKCS1_OAEP.new(publicKey)
            result = cipher.encrypt(Encryptor.toPyCrypto(plainData))
        else:
            raise RuntimeError("unsupported encryption mode")

        return Blob(result, False)

    @staticmethod
    def _encodePkcs8PrivateKey(privateKeyDer, oid, parameters):
        """
        Encode the private key to a PKCS #8 private key.

        :param privateKeyDer: The input private key DER.
        :type privateKeyDer: Blob or bytearray
        :param OID oid: The OID of the privateKey.
        :param DerNode parameters: The DerNode of the parameters for the OID.
        :return: The PKCS #8 private key DER.
        :rtype: Blob
        """
        algorithmIdentifier = DerSequence()
        algorithmIdentifier.addChild(DerOid(oid))
        algorithmIdentifier.addChild(parameters)

        result = DerSequence()
        result.addChild(DerInteger(0))
        result.addChild(algorithmIdentifier)
        result.addChild(DerOctetString(privateKeyDer))

        return result.encode()

    RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1"

# Import this at the end of the file to avoid circular references.
from pyndn.encrypt.algo.encryptor import Encryptor

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From https://github.com/named-data/ndn-cxx/blob/master/src/security/transform/private-key.cpp
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
This module defines the TpmPrivateKey class which holds an in-memory private key
and provides cryptographic operations such as for signing by the in-memory TPM.
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from pyndn.security.security_types import DigestAlgorithm
from pyndn.security.security_types import KeyType
from pyndn.util.blob import Blob
from pyndn.encoding.der.der_node import DerNode, DerInteger
from pyndn.encoding.der.der_exceptions import DerDecodingException

class TpmPrivateKey(object):
    """
    Create an uninitialized TpmPrivateKey. You must call a load method to
    initialize it, such as loadPkcs1.
    """
    def __init__(self):
        self._keyType = None
        self._privateKey = None

    class Error(Exception):
        """
        Create a TpmPrivateKey.Error to represents an error in private key
        processing.

        :param str message: The error message.
        """
        def __init__(self, message):
            super(TpmPrivateKey.Error, self).__init__(message)

    def loadPkcs1(self, encoding, keyType = None):
        """
        Load the unencrypted private key from a buffer with the PKCS #1 encoding.
        This replaces any existing private key in this object.

        :param encoding: The byte buffer with the private key encoding.
        :type encoding: str, or an array type with int elements which is
          converted to str
        :param KeyType keyType: (optional) The KeyType, such as KeyType.RSA.
          If omitted or None, then partially decode the private key to determine
          the key type.
        :raises TpmPrivateKey.Error: For errors decoding the key.
        """
        if keyType == None:
            # Try to determine the key type.
            try:
                parsedNode = DerNode.parse(Blob(encoding, False).buf())
                children = parsedNode.getChildren()

                # An RsaPrivateKey has integer version 0 and 8 integers.
                if (len(children) == 9 and
                    isinstance(children[0], DerInteger) and
                    children[0].toVal() == 0 and
                    isinstance(children[1], DerInteger) and
                    isinstance(children[2], DerInteger) and
                    isinstance(children[3], DerInteger) and
                    isinstance(children[4], DerInteger) and
                    isinstance(children[5], DerInteger) and
                    isinstance(children[6], DerInteger) and
                    isinstance(children[7], DerInteger) and
                    isinstance( children[8], DerInteger)):
                    keyType = KeyType.RSA
                else:
                    # Assume it is an EC key. Try decoding it below.
                    keyType = KeyType.ECDSA
            except DerDecodingException:
                # Assume it is an EC key. Try decoding it below.
                keyType =  KeyType.ECDSA

        if keyType == KeyType.ECDSA or keyType == KeyType.RSA:
            # serialization can load PKCS #1 directly.
            self._privateKey = serialization.load_der_private_key(
              Blob(encoding, False).toBytes(), password = None, backend = default_backend())
        else:
            raise TpmPrivateKey.Error(
              "loadPkcs1: Unrecognized keyType: " + str(keyType))

        self._keyType = keyType

    def loadPkcs8(self, encoding, keyType = None):
        """
        Load the unencrypted private key from a buffer with the PKCS #8 encoding.
        This replaces any existing private key in this object.

        :param encoding: The byte buffer with the private key encoding.
        :type encoding: str, or an array type with int elements which is
          converted to str
        :param KeyType keyType: (optional) The KeyType, such as KeyType.RSA.
          If omitted or None, then partially decode the private key to determine
          the key type.
        :raises TpmPrivateKey.Error: For errors decoding the key.
        """
        if keyType == None:
            # Decode the PKCS #8 DER to find the algorithm OID.
            oidString = None
            try:
                parsedNode = DerNode.parse(Blob(encoding, False).buf())
                pkcs8Children = parsedNode.getChildren()
                algorithmIdChildren = DerNode.getSequence(
                  pkcs8Children, 1).getChildren()
                oidString = "" + algorithmIdChildren[0].toVal()
            except Exception as ex:
                raise TpmPrivateKey.Error(
                  "Cannot decode the PKCS #8 private key: " + str(ex))

            if oidString == TpmPrivateKey.EC_ENCRYPTION_OID:
                keyType = KeyType.ECDSA
            elif oidString == TpmPrivateKey.RSA_ENCRYPTION_OID:
                keyType = KeyType.RSA
            else:
                raise TpmPrivateKey.Error(
                  "loadPkcs8: Unrecognized private key OID: " + oidString)

        if keyType == KeyType.ECDSA or keyType == KeyType.RSA:
            self._privateKey = serialization.load_der_private_key(
              Blob(encoding, False).toBytes(), password = None, backend = default_backend())
        else:
            raise TpmPrivateKey.Error(
              "loadPkcs8: Unrecognized keyType: " + str(keyType))

        self._keyType = keyType

    def derivePublicKey(self):
        """
        Get the encoded public key for this private key.

        :return: The public key encoding Blob.
        :rtype: Blob
        :raises TpmPrivateKey.Error: If no private key is loaded, or error
          converting to a public key.
        """
        if (self._keyType == KeyType.ECDSA or
            self._keyType == KeyType.RSA):
            publicKeyDer = self._privateKey.public_key().public_bytes(
              encoding = serialization.Encoding.DER,
              format = serialization.PublicFormat.SubjectPublicKeyInfo)
            return Blob(publicKeyDer, False)
        else:
            raise TpmPrivateKey.Error(
              "derivePublicKey: The private key is not loaded")

    def decrypt(self, cipherText, algorithmType = None):
        """
        Decrypt the cipherText using this private key according the encryption
        algorithmType. Only RSA encryption is supported for now.

        :param cipherText: The cipher text byte buffer.
        :type cipherText: an array which implements the buffer protocol
        :param EncryptAlgorithmType algorithmType: (optional) This decrypts
          according to algorithmType. If omitted, use RsaOaep.
        :return: The decrypted data.
        :rtype: Blob
        :raises TpmPrivateKey.Error: If the private key is not loaded, if
          decryption is not supported for this key type, or for error decrypting.
        """
        # TODO: Fix import loops and import at load time.
        from pyndn.encrypt.algo.encrypt_params import EncryptAlgorithmType

        if algorithmType == None:
            algorithmType = EncryptAlgorithmType.RsaOaep

        if self._keyType == None:
            raise TpmPrivateKey.Error("decrypt: The private key is not loaded")

        if algorithmType == EncryptAlgorithmType.RsaOaep:
            try:
                paddingObject = padding.OAEP(
                  mgf = padding.MGF1(algorithm = hashes.SHA1()),
                  algorithm = hashes.SHA1(), label = None)
                result = self._privateKey.decrypt(cipherText, paddingObject)
            except Exception as ex:
                raise TpmPrivateKey.Error("Error in decrypt: " + str(ex))
        elif algorithmType == EncryptAlgorithmType.RsaPkcs:
            try:
                paddingObject = padding.PKCS1v15()
                result = self._privateKey.decrypt(cipherText, paddingObject)
            except Exception as ex:
                raise TpmPrivateKey.Error("Error in decrypt: " + str(ex))
        else:
            raise TpmPrivateKey.Error("unsupported padding scheme")

        return Blob(result, False)

    def sign(self, data, digestAlgorithm):
        """
        Sign the data with this private key, returning a signature Blob.

        :param data: The input byte buffer.
        :type data: an array which implements the buffer protocol
        :param digestAlgorithm: The digest algorithm.
        :type digestAlgorithm: int from DigestAlgorithm
        :return: The signature Blob, or an isNull Blob if this private key is
          not initialized.
        :rtype: Blob
        :raises TpmPrivateKey.Error: For unrecognized digestAlgorithm or an
          error in signing.
        """
        if digestAlgorithm != DigestAlgorithm.SHA256:
            raise TpmPrivateKey.Error(
              "TpmPrivateKey.sign: Unsupported digest algorithm")

        if self._keyType == KeyType.RSA:
            signer = self._privateKey.signer(padding.PKCS1v15(), hashes.SHA256())
        elif self._keyType == KeyType.ECDSA:
            signer = self._privateKey.signer(ec.ECDSA(hashes.SHA256()))
        else:
            return Blob()

        signer.update(data)
        return Blob(bytearray(signer.finalize()), False)

    def toPkcs1(self):
        """
        Get the encoded unencrypted private key in PKCS #1.

        :return: The private key encoding Blob.
        :rtype: Blob
        :raises TpmPrivateKey.Error: If no private key is loaded, or error
          encoding.
        """
        if self._keyType == None:
            raise TpmPrivateKey.Error("toPkcs1: The private key is not loaded")

        # Decode the PKCS #8 private key.
        try:
            parsedNode = DerNode.parse(self.toPkcs8().buf(), 0)
            pkcs8Children = parsedNode.getChildren()
            return pkcs8Children[2].getPayload()
        except Exception as ex:
            raise TpmPrivateKey.Error(
              "Error decoding PKCS #8 private key: " + str(ex))

    def toPkcs8(self):
        """
        Get the encoded unencrypted private key in PKCS #8.

        :return: The private key encoding Blob.
        :rtype: Blob
        :raises TpmPrivateKey.Error: If no private key is loaded, or error
          encoding.
        """
        if self._keyType == None:
            raise TpmPrivateKey.Error("toPkcs8: The private key is not loaded")

        privateKeyDer = self._privateKey.private_bytes(
          encoding = serialization.Encoding.DER,
          format = serialization.PrivateFormat.PKCS8,
          encryption_algorithm = serialization.NoEncryption())
        return Blob(privateKeyDer, False)

    @staticmethod
    def generatePrivateKey(keyParams):
        """
        Generate a key pair according to keyParams and return a new
        TpmPrivateKey with the private key. You can get the public key with
        derivePublicKey.

        :param KeyParams keyParams: The parameters of the key.
        :return: A new TpmPrivateKey.
        :rtype: TpmPrivateKey
        :raises ValueError: If the key type is not supported.
        :raises TpmPrivateKey.Error: For an invalid key size, or an error
          generating.
        """
        if (keyParams.getKeyType() == KeyType.RSA or
            keyParams.getKeyType() == KeyType.ECDSA):
            if keyParams.getKeyType() == KeyType.RSA:
                privateKey = rsa.generate_private_key(
                  public_exponent = 65537, key_size = keyParams.getKeySize(),
                  backend = default_backend())
            else:
                privateKey = ec.generate_private_key(
                  TpmPrivateKey._getEcCurve(keyParams.getKeySize()),
                  default_backend())
        else:
            raise ValueError(
              "Cannot generate a key pair of type " + str(keyParams.getKeyType()))

        result = TpmPrivateKey()
        result._privateKey = privateKey
        result._keyType = keyParams.getKeyType()

        return result

    @staticmethod
    def _getEcCurve(keySize):
        """
        Get the Elliptic Curve algorithm object for the key size.

        :param int keySize: The key size.
        :raises TpmPrivateKey.Error: If the key size is not supported.
        """
        if keySize == 256:
            return ec.SECP256R1()
        elif keySize == 384:
            return ec.SECP384R1()
        elif keySize == 521:
            return ec.SECP521R1()
        else:
            raise TpmPrivateKey.Error("Unsupported EC key size: " + str(keySize))

    RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1"
    EC_ENCRYPTION_OID = "1.2.840.10045.2.1"

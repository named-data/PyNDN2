# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/transform/private-key.cpp
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

import sys
from random import SystemRandom
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pyndn.security.security_types import DigestAlgorithm
from pyndn.security.security_types import KeyType
from pyndn.util.blob import Blob
from pyndn.encoding.der.der_node import DerNode, DerInteger
from pyndn.encoding.der.der_node import DerSequence, DerOctetString, DerOid
from pyndn.encoding.der.der_exceptions import DerDecodingException

# The Python documentation says "Use SystemRandom if you require a
#   cryptographically secure pseudo-random number generator."
# http://docs.python.org/2/library/random.html
_systemRandom = SystemRandom()

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
                    keyType = KeyType.EC
            except DerDecodingException:
                # Assume it is an EC key. Try decoding it below.
                keyType =  KeyType.EC

        if keyType == KeyType.EC or keyType == KeyType.RSA:
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
                keyType = KeyType.EC
            elif oidString == TpmPrivateKey.RSA_ENCRYPTION_OID:
                keyType = KeyType.RSA
            else:
                raise TpmPrivateKey.Error(
                  "loadPkcs8: Unrecognized private key OID: " + oidString)

        if keyType == KeyType.EC or keyType == KeyType.RSA:
            self._privateKey = serialization.load_der_private_key(
              Blob(encoding, False).toBytes(), password = None, backend = default_backend())
        else:
            raise TpmPrivateKey.Error(
              "loadPkcs8: Unrecognized keyType: " + str(keyType))

        self._keyType = keyType

    def loadEncryptedPkcs8(self, encoding, password):
        """
        Load the encrypted private key from a buffer with the PKCS #8 encoding
        of the EncryptedPrivateKeyInfo. This replaces any existing private key
        in this object. This partially decodes the private key to determine the
        key type.

        :param encoding: The byte buffer with the private key encoding.
        :type encoding: str, or an array type with int elements which is
          converted to str
        :param password: The password for decrypting the private key, which
          should have characters in the range of 1 to 127..
        :type password: an array which implements the buffer protocol
        :raises TpmPrivateKey.Error: For errors decoding the key.
        """
        # Decode the PKCS #8 EncryptedPrivateKeyInfo.
        # See https://tools.ietf.org/html/rfc5208.
        oidString = None
        parameters = None
        encryptedKey = None
        try:
            parsedNode = DerNode.parse(Blob(encoding, False).buf())
            encryptedPkcs8Children = parsedNode.getChildren()
            algorithmIdChildren = DerNode.getSequence(
              encryptedPkcs8Children, 0).getChildren()
            oidString = algorithmIdChildren[0].toVal()
            parameters = algorithmIdChildren[1]

            encryptedKey = encryptedPkcs8Children[1].toVal()
        except Exception as ex:
            raise TpmPrivateKey.Error(
              "Cannot decode the PKCS #8 EncryptedPrivateKeyInfo: " + str(ex))

        if oidString == TpmPrivateKey.PBES2_OID:
            # Decode the PBES2 parameters. See https://www.ietf.org/rfc/rfc2898.txt .
            keyDerivationOidString = None
            keyDerivationParameters = None
            encryptionSchemeOidString = None
            encryptionSchemeParameters = None
            try:
                parametersChildren = parameters.getChildren()

                keyDerivationAlgorithmIdChildren = DerNode.getSequence(
                  parametersChildren, 0).getChildren()
                keyDerivationOidString = keyDerivationAlgorithmIdChildren[0].toVal()
                keyDerivationParameters = keyDerivationAlgorithmIdChildren[1]

                encryptionSchemeAlgorithmIdChildren = DerNode.getSequence(
                  parametersChildren, 1).getChildren()
                encryptionSchemeOidString = encryptionSchemeAlgorithmIdChildren[0].toVal()
                encryptionSchemeParameters = encryptionSchemeAlgorithmIdChildren[1]
            except Exception as ex:
                raise TpmPrivateKey.Error(
                  "Cannot decode the PBES2 parameters: " + str(ex))

            # Get the derived key from the password.
            derivedKey = None
            if keyDerivationOidString == TpmPrivateKey.PBKDF2_OID:
                # Decode the PBKDF2 parameters.
                salt = None
                nIterations = None
                try:
                  pbkdf2ParametersChildren = keyDerivationParameters.getChildren()
                  salt = pbkdf2ParametersChildren[0].toVal()
                  nIterations = pbkdf2ParametersChildren[1].toVal()
                except Exception as ex:
                    raise TpmPrivateKey.Error(
                      "Cannot decode the PBES2 parameters: " + str(ex))

                # Check the encryption scheme here to get the needed result length.
                resultLength = None
                if encryptionSchemeOidString == TpmPrivateKey.DES_EDE3_CBC_OID:
                  resultLength = TpmPrivateKey.DES_EDE3_KEY_LENGTH
                else:
                    raise TpmPrivateKey.Error(
                      "Unrecognized PBES2 encryption scheme OID: " +
                      encryptionSchemeOidString)

            else:
                raise TpmPrivateKey.Error(
                  "Unrecognized PBES2 key derivation OID: " + keyDerivationOidString)

            pbkdf2 = PBKDF2HMAC(algorithm = hashes.SHA1(), length = resultLength,
              salt = Blob(salt, False).toBytes(), iterations = nIterations,
              backend = default_backend())
            derivedKey = pbkdf2.derive(Blob(password, False).toBytes())

            # Use the derived key to get the unencrypted pkcs8Encoding.
            if encryptionSchemeOidString == TpmPrivateKey.DES_EDE3_CBC_OID:
                # Decode the DES-EDE3-CBC parameters.
                initialVector = None
                try:
                    initialVector = encryptionSchemeParameters.toVal()
                except Exception as ex:
                    raise TpmPrivateKey.Error(
                      "Cannot decode the DES-EDE3-CBC parameters: " + str(ex))

                try:
                    cipher = Cipher(algorithms.TripleDES(
                      Blob(derivedKey, False).toBytes()),
                      modes.CBC(Blob(initialVector, False).toBytes()),
                      backend = default_backend())

                    # For the cryptography package, we have to remove the padding.
                    decryptor = cipher.decryptor()
                    resultWithPad = decryptor.update(
                      Blob(encryptedKey, False).toBytes()) + decryptor.finalize()
                    if sys.version_info[0] <= 2:
                        padLength = ord(resultWithPad[-1])
                    else:
                        padLength = resultWithPad[-1]

                    pkcs8Encoding = resultWithPad[:-padLength]
                except Exception as ex:
                    raise TpmPrivateKey.Error(
                      "Error decrypting the PKCS #8 key with DES-EDE3-CBC: " + str(ex))
            else:
                raise TpmPrivateKey.Error(
                  "Unrecognized PBES2 encryption scheme OID: " +
                  encryptionSchemeOidString)

        else:
            raise TpmPrivateKey.Error(
              "Unrecognized PKCS #8 EncryptedPrivateKeyInfo OID: " + oidString)

        self.loadPkcs8(pkcs8Encoding)

    def derivePublicKey(self):
        """
        Get the encoded public key for this private key.

        :return: The public key encoding Blob.
        :rtype: Blob
        :raises TpmPrivateKey.Error: If no private key is loaded, or error
          converting to a public key.
        """
        if (self._keyType == KeyType.EC or
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
            signature = self._privateKey.sign(
              data, padding.PKCS1v15(), hashes.SHA256())
        elif self._keyType == KeyType.EC:
            signature = self._privateKey.sign(data, ec.ECDSA(hashes.SHA256()))
        else:
            return Blob()

        return Blob(bytearray(signature), False)

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

    def toEncryptedPkcs8(self, password):
        """
        Get the encoded encrypted private key in PKCS #8.

        :param password: The password for encrypting the private key, which
          should have characters in the range of 1 to 127..
        :type password: an array which implements the buffer protocol
        :return: The encoding Blob of the EncryptedPrivateKeyInfo.
        :rtype: Blob
        :raises TpmPrivateKey.Error: If no private key is loaded, or error
          encoding.
        """
        if self._keyType == None:
            raise TpmPrivateKey.Error(
              "toEncryptedPkcs8: The private key is not loaded")

        # Create the derivedKey from the password.
        nIterations = 2048
        salt = bytearray(8)
        for i in range(len(salt)):
            salt[i] = _systemRandom.randint(0, 0xff)
        pbkdf2 = PBKDF2HMAC(algorithm = hashes.SHA1(),
          length = TpmPrivateKey.DES_EDE3_KEY_LENGTH,
          salt = Blob(salt, False).toBytes(), iterations = nIterations,
          backend = default_backend())
        derivedKey = pbkdf2.derive(Blob(password, False).toBytes())

        pkcs8Encoding = self.toPkcs8()

        # Use the derived key to get the encrypted pkcs8Encoding.
        encryptedEncoding = None
        initialVector = bytearray(8)
        for i in range(len(initialVector)):
            initialVector[i] = _systemRandom.randint(0, 0xff)
        try:
            # For the cryptography package, we have to do the padding.
            padLength = 16 - (pkcs8Encoding.size() % 16)
            if sys.version_info[0] <= 2:
                pad = chr(padLength) * padLength
            else:
                pad = bytes([padLength]) * padLength

            cipher = Cipher(algorithms.TripleDES(
              Blob(derivedKey, False).toBytes()),
              modes.CBC(Blob(initialVector, False).toBytes()),
              backend = default_backend())

            encryptor = cipher.encryptor()
            encryptedEncoding = encryptor.update(
              pkcs8Encoding.toBytes() + pad) + encryptor.finalize()
        except Exception as ex:
            raise TpmPrivateKey.Error(
              "Error encrypting the PKCS #8 key with DES-EDE3-CBC: " + str(ex))

        try:
            # Encode the PBES2 parameters. See https://www.ietf.org/rfc/rfc2898.txt .
            keyDerivationParameters = DerSequence()
            keyDerivationParameters.addChild(DerOctetString(Blob(salt, False)))
            keyDerivationParameters.addChild(DerInteger(nIterations))
            keyDerivationAlgorithmIdentifier = DerSequence()
            keyDerivationAlgorithmIdentifier.addChild(
              DerOid(TpmPrivateKey.PBKDF2_OID))
            keyDerivationAlgorithmIdentifier.addChild(keyDerivationParameters)

            encryptionSchemeAlgorithmIdentifier = DerSequence()
            encryptionSchemeAlgorithmIdentifier.addChild(
              DerOid(TpmPrivateKey.DES_EDE3_CBC_OID))
            encryptionSchemeAlgorithmIdentifier.addChild(
              DerOctetString(Blob(initialVector, False)))

            encryptedKeyParameters = DerSequence()
            encryptedKeyParameters.addChild(keyDerivationAlgorithmIdentifier)
            encryptedKeyParameters.addChild(encryptionSchemeAlgorithmIdentifier)
            encryptedKeyAlgorithmIdentifier = DerSequence()
            encryptedKeyAlgorithmIdentifier.addChild(
              DerOid(TpmPrivateKey.PBES2_OID))
            encryptedKeyAlgorithmIdentifier.addChild(encryptedKeyParameters)

            # Encode the PKCS #8 EncryptedPrivateKeyInfo.
            # See https://tools.ietf.org/html/rfc5208.
            encryptedKey = DerSequence()
            encryptedKey.addChild(encryptedKeyAlgorithmIdentifier)
            encryptedKey.addChild(DerOctetString(Blob(encryptedEncoding, False)))

            return encryptedKey.encode()
        except Exception as ex:
            raise TpmPrivateKey.Error(
              "Error encoding the encryped PKCS #8 private key: " + str(ex))

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
            keyParams.getKeyType() == KeyType.EC):
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
    PBES2_OID = "1.2.840.113549.1.5.13"
    PBKDF2_OID = "1.2.840.113549.1.5.12"
    DES_EDE3_CBC_OID = "1.2.840.113549.3.7"
    DES_EDE3_KEY_LENGTH = 24

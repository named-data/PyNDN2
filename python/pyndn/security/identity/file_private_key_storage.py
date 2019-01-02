# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
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
This module defines the FilePrivateKeyStorage class which extends
PrivateKeyStorage to implement private key storage using files.
"""

import os
import stat
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from pyndn.util.blob import Blob
from pyndn.security.security_types import DigestAlgorithm
from pyndn.security.security_types import KeyClass
from pyndn.security.security_exception import SecurityException
from pyndn.security.certificate.public_key import PublicKey
from pyndn.security.identity.private_key_storage import PrivateKeyStorage
from pyndn.util.common import Common
from pyndn.security.tpm.tpm_private_key import TpmPrivateKey

class FilePrivateKeyStorage(PrivateKeyStorage):
    """
    Create a new FilePrivateKeyStorage to connect to the default directory.
    """
    def __init__(self):
        super(FilePrivateKeyStorage, self).__init__()

        if not "HOME" in os.environ:
            # Don't expect this to happen
            home = "."
        else:
            home = os.environ["HOME"]

        self._keyStorePath = os.path.join(home, ".ndn", "ndnsec-tpm-file")
        if not os.path.exists(self._keyStorePath):
            os.makedirs(self._keyStorePath)

    def generateKeyPair(self, keyName, params):
        """
        Generate a pair of asymmetric keys.

        :param Name keyName: The name of the key pair.
        :param KeyParams params: The parameters of the key.
        """
        if self.doesKeyExist(keyName, KeyClass.PUBLIC):
            raise SecurityException("Public key already exists")
        if self.doesKeyExist(keyName, KeyClass.PRIVATE):
            raise SecurityException("Private key already exists")

        try:
            privateKey = TpmPrivateKey.generatePrivateKey(params)
            privateKeyDer = privateKey.toPkcs8().toBytes()
            publicKeyDer = privateKey.derivePublicKey().toBytes()
        except Exception as ex:
            raise SecurityException("Error in generatePrivateKey: " + str(ex))

        keyUri = keyName.toUri()
        keyFilePathNoExtension = self.maintainMapping(keyUri)
        publicKeyFilePath = keyFilePathNoExtension + ".pub"
        privateKeyFilePath = keyFilePathNoExtension + ".pri"

        with open(publicKeyFilePath, 'w') as keyFile:
            keyFile.write(Common.base64Encode(publicKeyDer, True))
        with open(privateKeyFilePath, 'w') as keyFile:
            keyFile.write(Common.base64Encode(privateKeyDer, True))

        os.chmod(publicKeyFilePath,  stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        os.chmod(privateKeyFilePath, stat.S_IRUSR)

    def deleteKeyPair(self, keyName):
        """
        Delete a pair of asymmetric keys. If the key doesn't exist, do nothing.

        :param Name keyName: The name of the key pair.
        """
        keyUri = keyName.toUri()

        if self.doesKeyExist(keyName, KeyClass.PUBLIC):
            os.remove(self.nameTransform(keyUri, ".pub"))
        if self.doesKeyExist(keyName, KeyClass.PRIVATE):
            os.remove(self.nameTransform(keyUri, ".pri"))

    def getPublicKey(self, keyName):
        """
        Get the public key with the keyName.

        :param Name keyName: The name of public key.
        :return: The public key.
        :rtype: PublicKey
        """
        keyURI = keyName.toUri()

        if not self.doesKeyExist(keyName, KeyClass.PUBLIC):
            raise SecurityException(
              "Public key doesn't exist")

        base64Content = None
        with open(self.nameTransform(keyURI, ".pub")) as keyFile:
            base64Content = keyFile.read()
        der = base64.b64decode(base64Content)

        return PublicKey(Blob(der, False))

    def sign(self, data, keyName, digestAlgorithm = DigestAlgorithm.SHA256):
        """
        Fetch the private key for keyName and sign the data, returning a
        signature Blob.

        :param data: Pointer the input byte buffer to sign.
        :type data: An array type with int elements
        :param Name keyName: The name of the signing key.
        :param digestAlgorithm: (optional) the digest algorithm. If omitted,
          use DigestAlgorithm.SHA256.
        :type digestAlgorithm: int from DigestAlgorithm
        :return: The signature Blob.
        :rtype: Blob
        """
        keyURI = keyName.toUri()

        if not self.doesKeyExist(keyName, KeyClass.PRIVATE):
            raise SecurityException(
              "FilePrivateKeyStorage.sign: private key doesn't exist")

        # Read the private key.
        base64Content = None
        with open(self.nameTransform(keyURI, ".pri")) as keyFile:
            base64Content = keyFile.read()
        pkcs8Der = base64.b64decode(base64Content)

        privateKey = TpmPrivateKey()
        try:
            privateKey.loadPkcs8(pkcs8Der)
            return privateKey.sign(Blob(data, False).toBytes(), digestAlgorithm)
        except Exception as ex:
            raise SecurityException("Error in sign: " + str(ex))

    def decrypt(self, keyName, data, isSymmetric = False):
        """
        Decrypt data.

        :param Name keyName: The name of the decrypting key.
        :param data: The byte buffer to be decrypted.
        :type data: An array type with int elements
        :param bool isSymmetric: (optional) If True symmetric encryption is
          used, otherwise asymmetric encryption is used. If omitted, use
          asymmetric encryption.
        :return: The decrypted data.
        :rtype: Blob
        """
        raise RuntimeError("decrypt is not implemented")

    def encrypt(self, keyName, data, isSymmetric = False):
        """
        Encrypt data.

        :param Name keyName: The name of the encrypting key.
        :param data: The byte buffer to be encrypted.
        :type data: An array type with int elements
        :param bool isSymmetric: (optional) If True symmetric encryption is
          used, otherwise asymmetric encryption is used. If omitted, use
          asymmetric encryption.
        :return: The encrypted data.
        :rtype: Blob
        """
        raise RuntimeError("encrypt is not implemented")

    def generateKey(self, keyName, params):
        """
        Generate a symmetric key.

        :param Name keyName: The name of the key.
        :param KeyParams params: The parameters of the key.
        :param int keySize: (optional) The size of the key. If omitted, use 256.
        """
        raise RuntimeError("generateKey is not implemented")

    def doesKeyExist(self, keyName, keyClass):
        """
        Check if a particular key exists.

        :param Name keyName: The name of the key.
        :param keyClass: The class of the key, e.g. KeyClass.PUBLIC,
           KeyClass.PRIVATE, or KeyClass.SYMMETRIC.
        :type keyClass: int from KeyClass
        :return: True if the key exists, otherwise false.
        :rtype: bool
        """
        keyURI = keyName.toUri()
        if keyClass == KeyClass.PUBLIC:
            return os.path.isfile(self.nameTransform(keyURI, ".pub"))
        elif keyClass == KeyClass.PRIVATE:
            return os.path.isfile(self.nameTransform(keyURI, ".pri"))
        elif keyClass == KeyClass.SYMMETRIC:
            return os.path.isfile(self.nameTransform(keyURI, ".key").c_str())
        else:
            return False

    def nameTransform(self, keyName, extension):
        """
        Create a file path from keyName and the extension

        :param str keyName: The key name URI.
        :param str extension: The desired file name extension, e.g. ".pri".
        :return: The file path.
        :rtype: str
        """
        sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
        sha256.update(Blob(keyName, False).toBytes())
        hash = sha256.finalize()

        digest = Common.base64Encode(hash)
        digest = digest.strip()
        digest = digest.replace('/', '%')

        return os.path.join(self._keyStorePath, digest + extension)

    def maintainMapping(self, keyName):
        """
        Use nameTransform to get the file path for keyName (without the
        extension) and also add to the mapping.txt file.

        :param str keyName: The key name URI.
        :return: The key file path without the extension.
        :rtype: str
        """
        keyFilePathNoExtension = self.nameTransform(keyName, "")

        mappingFilePath = os.path.join(self._keyStorePath, "mapping.txt")
        with open(mappingFilePath, 'a') as mappingFile:
            mappingFile.write(keyName + ' ' + keyFilePathNoExtension + '\n')

        return keyFilePathNoExtension

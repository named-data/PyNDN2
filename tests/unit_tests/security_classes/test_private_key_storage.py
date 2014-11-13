# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Adeola Bannis <abannis@ucla.edu>
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
This module defines the TestPrivateKeyStorage class which extends
FilePrivateKeyStorage to implement private key storage using files.
"""

import os
import sys
import base64
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from pyndn.util import Blob
from pyndn.security.security_types import DigestAlgorithm
from pyndn.security.security_types import KeyClass
from pyndn.security.security_types import KeyType
from pyndn.security.security_exception import SecurityException
from pyndn.security.identity.file_private_key_storage import FilePrivateKeyStorage

class TestPrivateKeyStorage(FilePrivateKeyStorage):

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
        :return: The signature, or an isNull() Blob pointer if signing fails.
        :rtype: Blob
        """
        if digestAlgorithm != DigestAlgorithm.SHA256:
            raise SecurityException(
              "FilePrivateKeyStorage.sign: Unsupported digest algorithm")

        der = self.getPrivateKey(keyName)
        privateKey = RSA.importKey(der.toRawStr())

        # Sign the hash of the data.
        if sys.version_info[0] == 2:
            # In Python 2.x, we need a str.  Use Blob to convert data.
            data = Blob(data, False).toRawStr()
        signature = PKCS1_v1_5.new(privateKey).sign(SHA256.new(data))
        # Convert the string to a Blob.
        return Blob(bytearray(signature), False)

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
        try:
            return os.path.isfile(self._getTransformedName(keyName, keyClass))
        except (AttributeError, SecurityException):
            return False

    def _getTransformedName(self, keyName, keyClass):
        """
        Apply the name transformation and append the correct extension
        according to key class.

        :param Name keyName: The name of the key
        :param int keyClass: A value from KeyClass
        :return: The transformed name with extension
        :rtype: str
        """
        if keyClass == KeyClass.PUBLIC:
            ext = ".pub"
        elif keyClass == KeyClass.PRIVATE:
            ext = ".pri"
        elif keyClass == KeyClass.SYMMETRIC:
            ext = ".key"
        try:
            return self.nameTransform(keyName.toUri(), ext)
        except NameError:
            # an invalid keyClass was given
            raise SecurityException('Invalid key type given')

    def _getNewRsaKeyBits(self, keySize):
        # returns public and private key DER in blobs
        key = RSA.generate(keySize)
        publicDer = key.publickey().exportKey(format='DER')
        privateDer = key.exportKey(format='DER', pkcs=8)
        return (Blob(publicDer, False), Blob(privateDer, False))

    def generateKeyPair(self, keyName, keyType=KeyType.RSA, keySize=2048):
        """
        Generate a pair of asymmetric keys.
        Your derived class should override.

        :param Name keyName: The name of the key pair.
        :param keyType: (optional) The type of the key pair.  If omitted, use
          KeyType.RSA
        :type keyType: int from KeyType
        :param int keySize: (optional) The size of the key pair.  If omitted,
          use 2048.
        """
        # TODO: different generator for DSA
        public, private = self._getNewRsaKeyBits(keySize)
        self.addPublicKey(keyName, public)
        self.addPrivateKey(keyName, private)

    def deleteKeyPair(self, keyName):
        try:
            self._deleteKey(keyName, KeyClass.PRIVATE)
        except SecurityException:
            pass # I don't care if it doesn't exist
        try:
            self._deleteKey(keyName, KeyClass.PUBLIC)
        except SecurityException:
            pass # I don't care if it doesn't exist

    def addPublicKey(self, keyName, keyDer):
        """
        Add a private key to the store.
        :param Name keyName: The name of the key
        :param Blob keyDer: The private key DER
        """
        self._saveKey(keyName, keyDer, KeyClass.PUBLIC)

    def addPrivateKey(self, keyName, keyDer):
        """
        Add a private key to the store.
        :param Name keyName: The name of the key
        :param Blob keyDer: The private key DER
        """
        self._saveKey(keyName, keyDer, KeyClass.PRIVATE)

    def getPrivateKey(self, keyName):
        """
        Fetch a private key from the store.
        :param Name keyName: The name of the private key to look up.
        :return: The binary DER encoding of the private key bits
        :rtype: Blob
        """
        return self._loadKey(keyName, KeyClass.PRIVATE)

    def getPublicKey(self, keyName):
        """
        Fetch a public key from the store.
        :param Name keyName: The name of the public key to look up.
        :return: The binary DER encoding of the public key bits
        :rtype: Blob
        """
        return self._loadKey(keyName, KeyClass.PUBLIC)

    def _loadKey(self, keyName, keyClass):
        if not self.doesKeyExist(keyName, keyClass):
            raise SecurityException("Key doesn't exist")

        # Read the key data.
        base64Content = None
        keyPath = self._getTransformedName(keyName, keyClass)
        with open(keyPath, 'r') as keyFile:
            base64Content = keyFile.read()
        bits  = base64.b64decode(base64Content)

        return Blob(bits)

    def _saveKey(self, keyName, keyBits, keyClass):
        """
        Save key data to the store
        :param Name keyName: The name of the key
        :param Blob keyBits: The key bits, e.g. private key DER
        :param int keyClass: A value from KeyClass
        """
        if self.doesKeyExist(keyName, keyClass):
            raise SecurityException("The key already exists!")
        keyUri = keyName.toUri()
        newPath = self._getTransformedName(keyName, keyClass)

        encodedBits = base64.b64encode(keyBits.toRawStr())
        with open(newPath, 'w') as keyFile:
            keyFile.write(encodedBits)

    def _deleteKey(self, keyName, keyBits, keyClass):
        """
        Remove key data from the store.
        :param Name keyName: The name of the key
        :param int keyClass: A value from KeyClass
        """
        if not self.doesKeyExist(keyName, keyClass):
            raise SecurityException("Key doesn't exist")

        # Read the key data.
        keyPath = self._getTransformedName(keyName, keyClass)
        os.remove(keyPath)

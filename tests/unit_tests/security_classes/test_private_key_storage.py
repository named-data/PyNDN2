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

    def _deleteKey(self, keyName, keyClass):
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

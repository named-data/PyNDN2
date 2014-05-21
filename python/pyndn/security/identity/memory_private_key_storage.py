# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU General Public License is in the file COPYING.

"""
This module defines the MemoryPrivateKeyStorage class which extends
PrivateKeyStorage to implement private key storage in memory.
"""

import sys
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from pyndn.util import Blob
from pyndn.security.security_types import DigestAlgorithm
from pyndn.security.security_types import KeyClass
from pyndn.security.security_exception import SecurityException
from pyndn.security.identity.private_key_storage import PrivateKeyStorage

class MemoryPrivateKeyStorage(PrivateKeyStorage):
    def __init__(self):
        super(MemoryPrivateKeyStorage, self).__init__()
        # The key is the keyName.toUri()
        self._publicKeyStore = {}
        # The key is the keyName.toUri()
        self._privateKeyStore = {}
        
    def setPublicKeyForKeyName(self, keyName, publicKeyDer):
        """
        Set the public key for the keyName.
        
        :param Name keyName: The key name.
        :param publicKeyDer: The public key DER byte array.
        :type publicKeyDer: str, or an array type with int elements which is
          converted to str
        """
        if not type(publicKeyDer) is str:
            publicKeyDer = "".join(map(chr, publicKeyDer))
        self._publicKeyStore[keyName.toUri()] = RSA.importKey(publicKeyDer)
        
    def setPrivateKeyForKeyName(self, keyName, privateKeyDer):
        """
        Set the private key for the keyName.
        
        :param Name keyName: The key name.
        :param privateKeyDer: The private key DER byte array.
        :type privateKeyDer: str, or an array type with int elements which is
          converted to str
        """
        if not type(privateKeyDer) is str:
            privateKeyDer = "".join(map(chr, privateKeyDer))
        self._privateKeyStore[keyName.toUri()] = RSA.importKey(privateKeyDer)
        
    def setKeyPairForKeyName(self, keyName, publicKeyDer, privateKeyDer):
        """
        Set the public and private key for the keyName.
        
        :param Name keyName: The key name.
        :param publicKeyDer: The public key DER byte array.
        :type publicKeyDer: str, or an array type with int elements which is
          converted to str
        :param privateKeyDer: The private key DER byte array.
        :type privateKeyDer: str, or an array type with int elements which is
          converted to str
        """
        self.setPublicKeyForKeyName(keyName, publicKeyDer)
        self.setPrivateKeyForKeyName(keyName, privateKeyDer)
        
    def getPublicKey(self, keyName):
        """
        Get the public key with the keyName.
        
        :param Name keyName: The name of public key.
        :return: The public key.
        :rtype: PublicKey
        """
        keyNameUri = keyName.toUri()
        if not (keyNameUri in self._publicKeyStore):
            raise SecurityException(
              "MemoryPrivateKeyStorage: Cannot find public key " + 
              keyName.toUri())
              
        return self._publicKeyStore[keyNameUri]

    def sign(self, data, keyName, digestAlgorithm = DigestAlgorithm.SHA256):
        """
        Fetch the private key for keyName and sign the data, returning a 
        signature Blob.

        :param data: The input byte buffer to sign.
        :type data: an array which implements the buffer protocol
        :param Name keyName: The name of the signing key.
        :param digestAlgorithm: (optional) the digest algorithm. If omitted,
          use DigestAlgorithm.SHA256.
        :type digestAlgorithm: int from DigestAlgorithm
        :return: The signature, or an isNull() Blob pointer if signing fails.
        :rtype: Blob
        :raises SecurityException: if can't find the private key with keyName.
        """
        if digestAlgorithm != DigestAlgorithm.SHA256:
          return Blob()

        # Find the private key.
        keyUri = keyName.toUri()
        if not keyUri in self._privateKeyStore:
          raise SecurityException(
            "MemoryPrivateKeyStorage: Cannot find private key " + keyUri)
        privateKey = self._privateKeyStore[keyUri]
        
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
        keyUri = keyName.toUri()
        if keyClass == KeyClass.PUBLIC:
          return keyUri in self._publicKeyStore
        elif keyClass == KeyClass.PRIVATE:
          return keyUri in self._privateKeyStore
        else:
          # KeyClass.SYMMETRIC not implemented yet.
          return False 

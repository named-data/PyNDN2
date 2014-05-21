# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# This uses cocoapy in pyglet http://www.pyglet.org/. See contrib/cocoapy/LICENSE
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
This module defines the OSXPrivateKeyStorage class which extends
PrivateKeyStorage to implement private key storage using the OS X Keychain.
"""

import sys
if sys.platform == 'darwin':
    from pyndn.contrib.cocoapy import *
from pyndn.util import Blob
from pyndn.security.security_types import DigestAlgorithm
from pyndn.security.security_types import KeyClass
from pyndn.security.security_types import KeyType
from pyndn.security.security_exception import SecurityException
from pyndn.security.identity.private_key_storage import PrivateKeyStorage

class OSXPrivateKeyStorage(PrivateKeyStorage):
    def __init__(self):
        super(OSXPrivateKeyStorage, self).__init__()

        self._kCFBooleanTrue = c_void_p.in_dll(cf, "kCFBooleanTrue")
        
        self._security = cdll.LoadLibrary(
          "/System/Library/Frameworks/Security.framework/Versions/Current/Security")
        self._security.SecItemCopyMatching.restype = c_void_p
        self._security.SecItemCopyMatching.argtypes = [c_void_p, POINTER(c_void_p)]
        
        self._security.SecSignTransformCreate.restype = c_void_p
        self._security.SecSignTransformCreate.argtypes = [c_void_p, POINTER(c_void_p)]
        
        self._security.SecTransformSetAttribute.restype = c_void_p
        self._security.SecTransformSetAttribute.argtypes = [c_void_p, c_void_p, c_void_p, POINTER(c_void_p)]
        
        self._security.SecTransformExecute.restype = c_void_p
        self._security.SecTransformExecute.argtypes = [c_void_p, POINTER(c_void_p)]
          
        self._kSecClass = c_void_p.in_dll(self._security, "kSecClass")
        self._kSecClassKey = c_void_p.in_dll(self._security, "kSecClassKey")
        self._kSecAttrLabel = c_void_p.in_dll(self._security, "kSecAttrLabel")
        self._kSecAttrKeyClass = c_void_p.in_dll(self._security, "kSecAttrKeyClass")
        self._kSecReturnRef = c_void_p.in_dll(self._security, "kSecReturnRef")
        
        self._kSecAttrKeyTypeAES = c_void_p.in_dll(self._security, "kSecAttrKeyTypeAES")
        self._kSecAttrKeyTypeRSA = c_void_p.in_dll(self._security, "kSecAttrKeyTypeRSA")
        self._kSecAttrKeyClassPrivate = c_void_p.in_dll(self._security, "kSecAttrKeyClassPrivate")
        self._kSecAttrKeyClassPublic = c_void_p.in_dll(self._security, "kSecAttrKeyClassPublic")
        self._kSecAttrKeyClassSymmetric = c_void_p.in_dll(self._security, "kSecAttrKeyClassSymmetric")
        self._kSecDigestSHA2 = c_void_p.in_dll(self._security, "kSecDigestSHA2")
        
        self._kSecTransformInputAttributeName = c_void_p.in_dll(self._security, "kSecTransformInputAttributeName")
        self._kSecDigestTypeAttribute = c_void_p.in_dll(self._security, "kSecDigestTypeAttribute")
        self._kSecDigestLengthAttribute = c_void_p.in_dll(self._security, "kSecDigestLengthAttribute")

    def generateKeyPair(self, keyName, keyType = KeyType.RSA, keySize = 2048):
        """
        Generate a pair of asymmetric keys.

        :param Name keyName: The name of the key pair.
        :param keyType: (optional) The type of the key pair.  If omitted, use
          KeyType.RSA
        :type keyType: int from KeyType
        :param int keySize: (optional) The size of the key pair.  If omitted,
          use 2048.
        """
        raise RuntimeError("generateKeyPair is not implemented")

    def getPublicKey(self, keyName):
        """
        Get the public key with the keyName.

        :param Name keyName: The name of public key.
        :return: The public key.
        :rtype: PublicKey
        """
        raise RuntimeError("getPublicKey is not implemented")

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
        #_LOG_TRACE("OSXPrivateKeyStorage::Sign")

        privateKey = self._getKey(keyName, KeyClass.PRIVATE)
        if privateKey == None:
            raise SecurityException("private key not found")
        
        signer = None
        dataRef = None
        digestSizeRef = None

        try:    
            error = c_void_p()
            signer = self._security.SecSignTransformCreate(
              privateKey, pointer(error))
            if error.value != None:
                raise SecurityException("Failed to create the signer")

            # we need a str. Use Blob to convert data.
            dataStr = Blob(data, False).toRawStr()
            dataRef = c_void_p(cf.CFDataCreate(None, dataStr, len(data)))

            self._security.SecTransformSetAttribute(
              signer, self._kSecTransformInputAttributeName, dataRef, 
              pointer(error))
            if error.value != None:
                raise SecurityException("Failed to configure the input of the signer")

            self._security.SecTransformSetAttribute(
              signer, self._kSecDigestTypeAttribute, 
              self._getDigestAlgorithm(digestAlgorithm), pointer(error))
            if error.value != None:
                raise SecurityException("Fail to configure the digest algorithm of the signer")

            digestSizeRef = c_void_p(cf.CFNumberCreate(
              None, kCFNumberLongType, 
              byref(c_long(self._getDigestSize(digestAlgorithm)))))

            self._security.SecTransformSetAttribute(
              signer, self._kSecDigestLengthAttribute, digestSizeRef, 
              pointer(error))
            if error.value != None:
                raise SecurityException("Failed to configure the digest size of the signer")

            signature = self._security.SecTransformExecute(
              signer, pointer(error))
            if error.value != None:
                raise SecurityException("Failed to sign the data")
            
            if signature == None:
                raise SecurityException("Signature is NULL!")
            
            signatureLength = cf.CFDataGetLength(signature)
            signatureBytes = (c_byte * signatureLength)()
            cf.CFDataGetBytes(
              signature, CFRange(0, signatureLength), signatureBytes)

            return Blob(signatureBytes, False)
        finally:
            if privateKey != None:
                cf.CFRelease(privateKey)
            if signer != None:
                cf.CFRelease(signer)
            if dataRef != None:
                cf.CFRelease(dataRef)
            if digestSizeRef != None:
                cf.CFRelease(digestSizeRef)
            if signature != None:
                cf.CFRelease(signature)

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

    def generateKey(self, keyName, keyType = KeyType.AES, keySize = 256):
        """
        Generate a symmetric key.

        :param Name keyName: The name of the key.
        :param keyType: (optional) The type of the key. If omitted, use
          KeyType.AES .
        :type keyType: int from KeyType
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
        raise RuntimeError("doesKeyExist is not implemented")

    @staticmethod
    def _toInternalKeyName(keyName, keyClass):
        """
        Convert an NDN name of a key to an internal name of the key base on
        the keyClass.

        :param Name keyName: The NDN name of the key.
        :param keyClass: The class of the key, e.g. KeyClass.PUBLIC,
           KeyClass.PRIVATE, or KeyClass.SYMMETRIC.
        :type keyClass: int from KeyClass
        :return: The internal key name.
        :rtype: str
        """
        keyUri = keyName.toUri()

        if KeyClass.SYMMETRIC == keyClass:
            return keyUri + "/symmetric"
        else:
            return keyUri

    def _getKey(self, keyName, keyClass):
        """
        Get a key from the Keychain.

        :param Name keyName: The name of the key.
        :param keyClass: The class of the key, e.g. KeyClass.PUBLIC,
           KeyClass.PRIVATE, or KeyClass.SYMMETRIC.
        :return: None if not found, otherwise a Keychain ref to the key. You 
          must use cf.CFRelease to free it.
        :rtype: c_void_p
        """
        keyLabel = None
        attrDict = None
        
        try:
            keyNameUri = self._toInternalKeyName(keyName, keyClass)

            keyLabel = CFSTR(keyNameUri)

            attrDict = c_void_p(cf.CFDictionaryCreateMutable(
              None, 5, cf.kCFTypeDictionaryKeyCallBacks, None))

            cf.CFDictionaryAddValue(
              attrDict, self._kSecClass, self._kSecClassKey)
            cf.CFDictionaryAddValue(
              attrDict, self._kSecAttrLabel, keyLabel)
            cf.CFDictionaryAddValue(
              attrDict, self._kSecAttrKeyClass, self._getKeyClass(keyClass))
            cf.CFDictionaryAddValue(
              attrDict, self._kSecReturnRef, self._kCFBooleanTrue)

            keyItem = c_void_p()
            res = self._security.SecItemCopyMatching(attrDict, pointer(keyItem))

            if res != None:
                #_LOG_DEBUG("Fail to find the key!");
                return None
            else:
                return keyItem
        finally:
            if keyLabel != None:
                cf.CFRelease(keyLabel)
            if attrDict != None:
                cf.CFRelease(attrDict)

    def _getSymmetricKeyType(self, keyType):
        """
        Convert keyType to the MAC OS symmetric key key type.

        :param keyType: The type of the key.
        :type keyType: int from KeyType
        :return: The MAC OS key type.
        :rtype: c_void_p
        """
        if keyType == KeyType.AES:
          return self._kSecAttrKeyTypeAES
        else:
          #_LOG_DEBUG("Unrecognized key type!")
          return None

    def _getAsymmetricKeyType(self, keyType):
        """
        Convert keyType to the MAC OS asymmetric key key type.

        :param keyType: The type of the key.
        :type keyType: int from KeyType
        :return: The MAC OS key type.
        :rtype: c_void_p
        """
        if keyType == KeyType.RSA:
          return self._kSecAttrKeyTypeRSA
        else:
          #_LOG_DEBUG("Unrecognized key type!")
          return None

    def _getKeyClass(self, keyClass):
        """
        Convert keyClass to the Mac OS key class.

        :param keyClass: The class of the key, e.g. KeyClass.PUBLIC,
           KeyClass.PRIVATE, or KeyClass.SYMMETRIC.
        :type keyClass: int from KeyClass
        :return: The MAC OS key class.
        :rtype: c_void_p
        """
        if keyClass == KeyClass.PRIVATE:
          return self._kSecAttrKeyClassPrivate
        elif keyClass == KeyClass.PUBLIC:
          return self._kSecAttrKeyClassPublic
        elif keyClass == KeyClass.SYMMETRIC:
          return self._kSecAttrKeyClassSymmetric
        else:
          #_LOG_DEBUG("Unrecognized key class!")
          return None

    def _getDigestAlgorithm(self, digestAlgorithm):
        """
        Convert digestAlgorithm to the MAC OS algorithm in.

        :param digestAlgorithm: The digest algorithm.
        :type digestAlgorithm: int from DigestAlgorithm
        :return: The MAC OS algorithm id.
        :rtype: c_void_p
        """
        if digestAlgorithm == DigestAlgorithm.SHA256:
          return self._kSecDigestSHA2
        else:
          #_LOG_DEBUG("Unrecognized digest algorithm!")
          return None

    def _getDigestSize(self, digestAlgorithm):
        """
        Get the digest size of the corresponding algorithm

        :param digestAlgorithm: The digest algorithm.
        :type digestAlgorithm: int from DigestAlgorithm
        :return: The digest size.
        :rtype: int
        """
        if digestAlgorithm == DigestAlgorithm.SHA256:
          return 256
        else:
          #_LOG_DEBUG("Unrecognized digest algorithm!")
          return -1


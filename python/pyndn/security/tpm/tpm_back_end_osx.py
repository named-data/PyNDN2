# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/tpm/back-end-osx.cpp
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
This module defines the TpmBackEndOsx class which extends TpmBackEnd to
implement a TPM back-end using the macOS Keychain services.
"""

import sys
from ctypes import *
if sys.platform == 'darwin':
    from pyndn.contrib.cocoapy import *
from pyndn.util.blob import Blob
from pyndn.security.security_types import KeyType
from pyndn.security.security_types import DigestAlgorithm
from pyndn.security.tpm.tpm_private_key import TpmPrivateKey
from pyndn.security.tpm.tpm_back_end import TpmBackEnd

class TpmBackEndOsx(TpmBackEnd):
    def __init__(self):
        super(TpmBackEndOsx, self).__init__()

        self._isTerminalMode = False

    class Error(TpmBackEnd.Error):
        """
        Create a TpmBackEndOsx.Error which extends TpmBackEnd.Error and
        represents a non-semantic error in the backend TPM for the macOS
        Keychain services.

        :param str message: The error message.
        """
        def __init__(self, message):
            super(TpmBackEndOsx.Error, self).__init__(message)

    @staticmethod
    def getScheme():
        return "tpm-osxkeychain"

    # Management

    def isTerminalMode(self):
        """
        Check if the TPM is in terminal mode.

        :return: True if in terminal mode.
        :rtype: bool
        """
        return self._isTerminalMode

    def setTerminalMode(self, isTerminal):
        """
        Set the terminal mode of the TPM. In terminal mode, the TPM will not ask
        for a password from the GUI.

        :param bool isTerminal: True to enable terminal mode.
        """
        osx = Osx.get()

        self._isTerminalMode = isTerminal
        osx._security.SecKeychainSetUserInteractionAllowed(not isTerminal)

    # TODO: isTpmLocked
    # TODO: unlockTpm

    # Cryptographic transformation

    @staticmethod
    def sign(key, digestAlgorithm, data):
        """
        Use the macOS Keychain key to sign.

        :param c_void_p key: The macOS Keychain private key.
        :param digestAlgorithm: The digest algorithm.
        :type digestAlgorithm: int from DigestAlgorithm
        :param data: The input byte buffer.
        :type data: an array which implements the buffer protocol
        :return: The signature Blob, or an isNull Blob for an unrecognized
          digestAlgorithm.
        :rtype: Blob
        """
        osx = Osx.get()
        signer = None
        dataRef = None
        digestSizeRef = None
        signature = None

        try:
            # We need a str (Python 2) or bytes (Python 3). Use Blob to convert data.
            dataStr = Blob(data, False).toBytes()
            dataRef = c_void_p(cf.CFDataCreate(None, dataStr, len(data)))

            error = c_void_p()
            signer = osx._security.SecSignTransformCreate(key, pointer(error))
            if error.value != None:
                raise TpmBackEndOsx.Error("Failed to create the signer")

            # Set the input.
            osx._security.SecTransformSetAttribute(
              signer, osx._kSecTransformInputAttributeName, dataRef,
              pointer(error))
            if error.value != None:
                raise TpmBackEndOsx.Error(
                  "Failed to configure the input of the signer")

            # Set the padding type.
            osx._security.SecTransformSetAttribute(
              signer, osx._kSecPaddingKey, osx._kSecPaddingPKCS1Key,
              pointer(error))
            if error.value != None:
                raise TpmBackEndOsx.Error(
                  "Failed to configure the padding algorithm of the signer")

            # Set the digest attribute.
            osx._security.SecTransformSetAttribute(
              signer, osx._kSecDigestTypeAttribute,
              TpmBackEndOsx._getDigestAlgorithm(digestAlgorithm), pointer(error))
            if error.value != None:
                raise TpmBackEndOsx.Error(
                  "Fail to configure the digest algorithm of the signer")

            # Set the digest size attribute.
            digestSizeRef = c_void_p(cf.CFNumberCreate(
              None, kCFNumberLongType,
              byref(c_long(TpmBackEndOsx._getDigestSize(digestAlgorithm)))))
            osx._security.SecTransformSetAttribute(
              signer, osx._kSecDigestLengthAttribute, digestSizeRef,
              pointer(error))
            if error.value != None:
                raise TpmBackEndOsx.Error(
                  "Failed to configure the digest size of the signer")

            # Actually sign.
            signature = osx._security.SecTransformExecute(
              signer, pointer(error))
            if error.value != None:
                raise TpmBackEndOsx.Error(
"Failed to sign the data. Try using the Keychain Access application to set the access control of the private key to \"Allow all applications to access this item\".")

            if signature == None:
                raise TpmBackEndOsx.Error("Signature is NULL!")

            return TpmBackEndOsx._CFDataToBlob(signature)
        finally:
            if signer != None:
                cf.CFRelease(signer)
            if dataRef != None:
                cf.CFRelease(dataRef)
            if digestSizeRef != None:
                cf.CFRelease(digestSizeRef)
            if signature != None:
                cf.CFRelease(signature)

    @staticmethod
    def decrypt(key, cipherText):
        """
        Use the macOS Keychain key to decrypt.

        :param c_void_p key: The macOS Keychain private key.
        :param cipherText: The cipher text byte buffer.
        :type cipherText: an array which implements the buffer protocol
        :return: The decrypted data.
        :rtype: Blob
        """
        osx = Osx.get()
        dataRef = None
        decryptor = None
        output = None

        try:
            # We need a str (Python 2) or bytes (Python 3). Use Blob to convert data.
            dataStr = Blob(cipherText, False).toBytes()
            dataRef = c_void_p(cf.CFDataCreate(None, dataStr, len(cipherText)))

            error = c_void_p()
            decryptor = osx._security.SecDecryptTransformCreate(key, pointer(error))
            if error.value != None:
                raise TpmBackEndOsx.Error("Failed to create the decryptor")

            osx._security.SecTransformSetAttribute(
              decryptor, osx._kSecTransformInputAttributeName, dataRef,
              pointer(error))
            if error.value != None:
                raise TpmBackEndOsx.Error("Failed to configure the decryptor")

            osx._security.SecTransformSetAttribute(
              decryptor, osx._kSecPaddingKey, osx._kSecPaddingOAEPKey,
              pointer(error))
            if error.value != None:
                raise TpmBackEndOsx.Error("Failed to configure the decryptor #2")

            output = osx._security.SecTransformExecute(decryptor, pointer(error))
            if error.value != None:
                raise TpmBackEndOsx.Error(
"Failed to decrypt the cipherText. Try using the Keychain Access application to set the access control of the private key to \"Allow all applications to access this item\".")

            if output == None:
                raise TpmBackEndOsx.Error("The output is NULL")

            return TpmBackEndOsx._CFDataToBlob(output)
        finally:
            if dataRef != None:
                cf.CFRelease(dataRef)
            if decryptor != None:
                cf.CFRelease(decryptor)
            if output != None:
                cf.CFRelease(output)

    @staticmethod
    def derivePublicKey(key):
        """
        Use the macOS Keychain key to derive the public key.

        :param c_void_p key: The macOS Keychain private key.
        :return: The public key encoding Blob.
        :rtype: Blob
        """
        osx = Osx.get()
        exportedKey = None

        try:
            exportedKey = c_void_p()
            res = osx._security.SecItemExport(
              key, osx._kSecFormatOpenSSL, 0, None, pointer(exportedKey))
            if res != None:
                # TODO: check for errSecAuthFailed
                raise TpmBackEndOsx.Error(
                  "Failed to export the private key")

            privateKey = TpmPrivateKey()
            privateKey.loadPkcs1(TpmBackEndOsx._CFDataToBlob(exportedKey))
            return privateKey.derivePublicKey()
        finally:
            if exportedKey != None:
                cf.CFRelease(exportedKey)

    def _doHasKey(self, keyName):
        """
        A protected method to check if the key with name keyName exists in the
        TPM.

        :param Name keyName: The name of the key.
        :return: True if the key exists.
        :rtype: bool
        """
        osx = Osx.get()
        keyLabel = None
        attrDict = None
        itemRef = None

        try:
            keyLabel = CFSTR(keyName.toUri())

            attrDict = c_void_p(cf.CFDictionaryCreateMutable(
              None, 4, cf.kCFTypeDictionaryKeyCallBacks, None))

            cf.CFDictionaryAddValue(
              attrDict, osx._kSecClass, osx._kSecClassKey)
            cf.CFDictionaryAddValue(
              attrDict, osx._kSecAttrLabel, keyLabel)
            cf.CFDictionaryAddValue(
              attrDict, osx._kSecReturnRef, osx._kCFBooleanTrue)

            itemRef = c_void_p()
            res = osx._security.SecItemCopyMatching(attrDict, pointer(itemRef))

            return res == None
        finally:
            if keyLabel != None:
                cf.CFRelease(keyLabel)
            if attrDict != None:
                cf.CFRelease(attrDict)

    def _doGetKeyHandle(self, keyName):
        """
        A protected method to get the handle of the key with name keyName.

        :param Name keyName: The name of the key.
        :return: The handle of the key, or None if the key does not exist.
        :rtype: TpmKeyHandle
        """
        keyItem = self._getKey(keyName)
        if keyItem == None:
            return None

        return TpmKeyHandleOsx(keyItem)

    def _doCreateKey(self, identityName, params):
        """
        A protected method to create a key for identityName according to params.
        The created key is named as: /<identityName>/[keyId]/KEY . The key name
        is set in the returned TpmKeyHandle.

        :param Name identityName: The name if the identity.
        :param KeyParams params: The KeyParams for creating the key.
        :return: The handle of the created key.
        :rtype: TpmKeyHandle
        :raises TpmBackEnd.Error: If the key cannot be created.
        """
        osx = Osx.get()
        keyLabel = None
        attrDict = None
        cfKeySize = None
        publicKey = None

        try:
            keyType = params.getKeyType()
            if keyType == KeyType.RSA:
                keySize = params.getKeySize()
            elif keyType == KeyType.EC:
                keySize = params.getKeySize()
            else:
                raise TpmBackEndOsx.Error(
                  "Failed to create a key pair: Unsupported key type")
            cfKeySize = c_void_p(cf.CFNumberCreate(
              None, kCFNumberIntType, byref(c_int(keySize))))

            attrDict = c_void_p(cf.CFDictionaryCreateMutable(
              None, 2, cf.kCFTypeDictionaryKeyCallBacks, None))
            cf.CFDictionaryAddValue(
              attrDict, osx._kSecAttrKeyType,
              TpmBackEndOsx._getAsymmetricKeyType(keyType))
            cf.CFDictionaryAddValue(
              attrDict, osx._kSecAttrKeySizeInBits, cfKeySize)

            publicKey = c_void_p()
            privateKey = c_void_p()
            res = osx._security.SecKeyGeneratePair(
              attrDict, pointer(publicKey), pointer(privateKey))

            if res != 0:
                # TODO: check for errSecAuthFailed
                raise TpmBackEndOsx.Error("Failed to create a key pair")

            keyHandle = TpmKeyHandleOsx(privateKey)
            TpmBackEnd.setKeyName(keyHandle, identityName, params)

            keyUri = keyHandle.getKeyName().toUri()
            # There is only one attr, so we don't need to make a C array.
            attr = SecKeychainAttribute(
              osx._kSecKeyPrintName, len(keyUri), keyUri.encode('utf-8'))
            attrList = SecKeychainAttributeList(1, pointer(attr))

            osx._security.SecKeychainItemModifyAttributesAndData(
              privateKey, byref(attrList), 0, None)
            osx._security.SecKeychainItemModifyAttributesAndData(
              publicKey, byref(attrList), 0, None)

            return keyHandle
        finally:
            if keyLabel != None:
                cf.CFRelease(keyLabel)
            if attrDict != None:
                cf.CFRelease(attrDict)
            if cfKeySize != None:
                cf.CFRelease(cfKeySize)
            if publicKey != None:
                cf.CFRelease(publicKey)

    def _doDeleteKey(self, keyName):
        """
        A protected method to delete the key with name keyName. If the key
        doesn't exist, do nothing.

        :param Name keyName: The name of the key to delete.
        :raises TpmBackEnd.Error: If the deletion fails.
        """
        osx = Osx.get()
        keyLabel = None
        searchDict = None

        try:
            keyLabel = CFSTR(keyName.toUri())

            searchDict = c_void_p(cf.CFDictionaryCreateMutable(
              None, 5, cf.kCFTypeDictionaryKeyCallBacks, None))

            cf.CFDictionaryAddValue(
              searchDict, osx._kSecClass, osx._kSecClassKey)
            cf.CFDictionaryAddValue(
              searchDict, osx._kSecAttrLabel, keyLabel)
            cf.CFDictionaryAddValue(
              searchDict, osx._kSecMatchLimit, osx._kSecMatchLimitAll)

            res = osx._security.SecItemDelete(searchDict)
            # TODO: check for errSecAuthFailed
            # TODO: check for errSecItemNotFound
        finally:
            if keyLabel != None:
                cf.CFRelease(keyLabel)
            if searchDict != None:
                cf.CFRelease(searchDict)

    def _getKey(self, keyName):
        """
        Get a key from the Keychain.

        :param Name keyName: The name of the key.
        :return: None if not found, otherwise a Keychain ref to the key. You
          must use cf.CFRelease to free it.
        :rtype: c_void_p
        """
        osx = Osx.get()
        keyLabel = None
        attrDict = None

        try:
            keyLabel = CFSTR(keyName.toUri())

            attrDict = c_void_p(cf.CFDictionaryCreateMutable(
              None, 5, cf.kCFTypeDictionaryKeyCallBacks, None))

            cf.CFDictionaryAddValue(
              attrDict, osx._kSecClass, osx._kSecClassKey)
            cf.CFDictionaryAddValue(
              attrDict, osx._kSecAttrLabel, keyLabel)
            cf.CFDictionaryAddValue(
              attrDict, osx._kSecAttrKeyClass, osx._kSecAttrKeyClassPrivate)
            cf.CFDictionaryAddValue(
              attrDict, osx._kSecReturnRef, osx._kCFBooleanTrue)

            keyItem = c_void_p()
            res = osx._security.SecItemCopyMatching(attrDict, pointer(keyItem))

            if res != None:
                # TODO: check for errSecAuthFailed
                return None

            return keyItem
        finally:
            if keyLabel != None:
                cf.CFRelease(keyLabel)
            if attrDict != None:
                cf.CFRelease(attrDict)

    @staticmethod
    def _getAsymmetricKeyType(keyType):
        """
        Convert keyType to the MAC OS asymmetric key key type.

        :param keyType: The type of the key.
        :type keyType: int from KeyType
        :return: The MAC OS key type.
        :rtype: c_void_p
        """
        osx = Osx.get()

        if keyType == KeyType.RSA:
          return osx._kSecAttrKeyTypeRSA
        elif keyType == KeyType.EC:
          return osx._kSecAttrKeyTypeECDSA
        else:
          return None

    @staticmethod
    def _getDigestAlgorithm(digestAlgorithm):
        """
        Convert digestAlgorithm to the MAC OS algorithm in.

        :param digestAlgorithm: The digest algorithm.
        :type digestAlgorithm: int from DigestAlgorithm
        :return: The MAC OS algorithm id.
        :rtype: c_void_p
        """
        osx = Osx.get()

        if digestAlgorithm == DigestAlgorithm.SHA256:
          return osx._kSecDigestSHA2
        else:
          return None

    @staticmethod
    def _getDigestSize(digestAlgorithm):
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
          return -1

    @staticmethod
    def _CFDataToBlob(cfData):
        length = cf.CFDataGetLength(cfData)
        array = (c_byte * length)()
        cf.CFDataGetBytes(cfData, CFRange(0, length), array)

        # Convert from signed byte to unsigned byte.
        unsignedArray = [(x if x >= 0 else x + 256) for x in array]
        return Blob(unsignedArray, False)

class SecKeychainAttribute(Structure):
    _fields_ = [("tag", c_uint32),
                ("length", c_uint32),
                ("data", c_char_p)]

class SecKeychainAttributeList(Structure):
    _fields_ = [("count", c_int),
                ("attr", POINTER(SecKeychainAttribute))]

class Osx(object):
    _instance = None

    def __init__(self):
#pylint: disable=E1103
        self._kCFBooleanTrue = c_void_p.in_dll(cf, "kCFBooleanTrue")

        self._security = cdll.LoadLibrary(
          "/System/Library/Frameworks/Security.framework/Versions/Current/Security")
        self._security.SecItemCopyMatching.restype = c_void_p
        self._security.SecItemCopyMatching.argtypes = [c_void_p, POINTER(c_void_p)]

        self._security.SecSignTransformCreate.restype = c_void_p
        self._security.SecSignTransformCreate.argtypes = [c_void_p, POINTER(c_void_p)]

        self._security.SecDecryptTransformCreate.restype = c_void_p
        self._security.SecDecryptTransformCreate.argtypes = [c_void_p, POINTER(c_void_p)]

        self._security.SecTransformSetAttribute.restype = c_void_p
        self._security.SecTransformSetAttribute.argtypes = [c_void_p, c_void_p, c_void_p, POINTER(c_void_p)]

        self._security.SecTransformExecute.restype = c_void_p
        self._security.SecTransformExecute.argtypes = [c_void_p, POINTER(c_void_p)]

        self._security.SecItemExport.restype = c_void_p
        self._security.SecItemExport.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p, POINTER(c_void_p)]

        self._security.SecKeychainSetUserInteractionAllowed.restype = c_void_p
        self._security.SecKeychainSetUserInteractionAllowed.argtypes = [c_void_p]

        self._security.SecKeychainItemModifyAttributesAndData.restype = c_void_p
        self._security.SecKeychainItemModifyAttributesAndData.argtypes = [
          c_void_p, POINTER(SecKeychainAttributeList), c_uint32, c_void_p]

        self._kSecClass = c_void_p.in_dll(self._security, "kSecClass")
        self._kSecClassKey = c_void_p.in_dll(self._security, "kSecClassKey")
        self._kSecAttrKeyType = c_void_p.in_dll(self._security, "kSecAttrKeyType")
        self._kSecAttrKeySizeInBits = c_void_p.in_dll(self._security, "kSecAttrKeySizeInBits")
        self._kSecAttrLabel = c_void_p.in_dll(self._security, "kSecAttrLabel")
        self._kSecAttrKeyClass = c_void_p.in_dll(self._security, "kSecAttrKeyClass")
        self._kSecReturnRef = c_void_p.in_dll(self._security, "kSecReturnRef")
        self._kSecMatchLimit = c_void_p.in_dll(self._security, "kSecMatchLimit")
        self._kSecMatchLimitAll = c_void_p.in_dll(self._security, "kSecMatchLimitAll")

        self._kSecAttrKeyTypeAES = c_void_p.in_dll(self._security, "kSecAttrKeyTypeAES")
        self._kSecAttrKeyTypeRSA = c_void_p.in_dll(self._security, "kSecAttrKeyTypeRSA")
        self._kSecAttrKeyTypeECDSA = c_void_p.in_dll(self._security, "kSecAttrKeyTypeECDSA")
        self._kSecAttrKeyClassPrivate = c_void_p.in_dll(self._security, "kSecAttrKeyClassPrivate")
        self._kSecAttrKeyClassPublic = c_void_p.in_dll(self._security, "kSecAttrKeyClassPublic")
        self._kSecAttrKeyClassSymmetric = c_void_p.in_dll(self._security, "kSecAttrKeyClassSymmetric")
        self._kSecDigestSHA2 = c_void_p.in_dll(self._security, "kSecDigestSHA2")

        self._kSecTransformInputAttributeName = c_void_p.in_dll(self._security, "kSecTransformInputAttributeName")
        self._kSecDigestTypeAttribute = c_void_p.in_dll(self._security, "kSecDigestTypeAttribute")
        self._kSecDigestLengthAttribute = c_void_p.in_dll(self._security, "kSecDigestLengthAttribute")

        self._kSecPaddingKey = c_void_p.in_dll(self._security, "kSecPaddingKey")
        self._kSecPaddingPKCS1Key = c_void_p.in_dll(self._security, "kSecPaddingPKCS1Key")
        self._kSecPaddingOAEPKey = c_void_p.in_dll(self._security, "kSecPaddingOAEPKey")

        self._kSecKeyPrintName = 1
#pylint: enable=E1103

        # enum values:
        self._kSecFormatOpenSSL = 1

    @staticmethod
    def get():
        """
        Get the static instance of Osx, creating it only when needed.
        """
        if Osx._instance == None:
            Osx._instance = Osx()
        return Osx._instance

# Put this last to avoid an import loop.
from pyndn.security.tpm.tpm_key_handle_osx import TpmKeyHandleOsx

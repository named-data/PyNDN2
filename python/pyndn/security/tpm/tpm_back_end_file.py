# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/tpm/back-end-file.hpp
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
This module defines the TpmBackEndFile class which extends TpmBackEnd to
implement a TPM back-end using on-disk file storage. In this TPM, each private
key is stored in a separate file with permission 0400, i.e., owner read-only.
The key is stored in PKCS #1 format in base64 encoding.
"""

import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from pyndn.util.blob import Blob
from pyndn.util.common import Common
from pyndn.security.tpm.tpm_private_key import TpmPrivateKey
from pyndn.security.tpm.tpm_key_handle_memory import TpmKeyHandleMemory
from pyndn.security.tpm.tpm_back_end import TpmBackEnd

class TpmBackEndFile(TpmBackEnd):
    """
    Create a TpmBackEndFile to use the given path to store files (of provided)
    or to the default location.

    :param str locationPath: (optional) The full path of the directory to store
      private keys. If omitted or None or "", use the default location
      ~/.ndn/ndnsec-key-file. This creates the directory if it doesn't exist.
    """
    def __init__(self, locationPath = None):
        super(TpmBackEndFile, self).__init__()

        if locationPath == None or locationPath == "":
            if not "HOME" in os.environ:
                # Don't expect this to happen
                home = "."
            else:
                home = os.environ["HOME"]

            locationPath = os.path.join(home, ".ndn", "ndnsec-key-file")

        self._keyStorePath = locationPath
        if not os.path.exists(self._keyStorePath):
            os.makedirs(self._keyStorePath)

    class Error(TpmBackEnd.Error):
        """
        Create a TpmBackEndFile.Error which extends TpmBackEnd.Error and
        represents a non-semantic error in backend TPM file processing.

        :param str message: The error message.
        """
        def __init__(self, message):
            super(TpmBackEndFile.Error, self).__init__(message)

    @staticmethod
    def getScheme():
        return "tpm-file"

    def _doHasKey(self, keyName):
        """
        A protected method to check if the key with name keyName exists in the
        TPM.

        :param Name keyName: The name of the key.
        :return: True if the key exists.
        :rtype: bool
        """
        if not os.path.isfile(self._toFilePath(keyName)):
            return False

        try:
            self._loadKey(keyName)
            return True
        except TpmBackEnd.Error:
            return False

    def _doGetKeyHandle(self, keyName):
        """
        Get the handle of the key with name keyName.

        :param Name keyName: The name of the key.
        :return: The handle of the key, or None if the key does not exist.
        :rtype: TpmKeyHandle
        """
        if not self._doHasKey(keyName):
            return None

        return TpmKeyHandleMemory(self._loadKey(keyName))

    def _doCreateKey(self, identityName, params):
        """
        Create a key for identityName according to params. The created key is
        named as: /<identityName>/[keyId]/KEY . The key name is set in the
        returned TpmKeyHandle.

        :param Name identityName: The name if the identity.
        :param KeyParams params: The KeyParams for creating the key.
        :return: The handle of the created key.
        :rtype: TpmKeyHandle
        :raises TpmBackEnd.Error: If the key cannot be created.
        """
        try:
            key = TpmPrivateKey.generatePrivateKey(params)
        except Exception as ex:
            raise TpmBackEndFile.Error(
              "Error in TpmPrivateKey.generatePrivateKey: " + str(ex))
        keyHandle = TpmKeyHandleMemory(key)

        TpmBackEnd.setKeyName(keyHandle, identityName, params)

        self._saveKey(keyHandle.getKeyName(), key)
        return keyHandle

    def _doDeleteKey(self, keyName):
        """
        Delete the key with name keyName. If the key doesn't exist, do nothing.

        :param Name keyName: The name of the key to delete.
        :raise TpmBackEnd.Error: If the deletion fails.
        """
        filePath = self._toFilePath(keyName)
        if os.path.isfile(filePath):
            os.remove(filePath)

    def _doExportKey(self, keyName, password):
        """
        A protected method to get the encoded private key with name keyName in
        PKCS #8 format, possibly password-encrypted.

        :param Name keyName: The name of the key in the TPM.
        :param password: The password for encrypting the private key, which
          should have characters in the range of 1 to 127. If the password is
          supplied, use it to return a PKCS #8 EncryptedPrivateKeyInfo. If the
          password is None, return an unencrypted PKCS #8 PrivateKeyInfo.
        :type password: an array which implements the buffer protocol
        :return: The encoded private key.
        :rtype: Blob
        :raises TpmBackEnd.Error: If the key does not exist or if the key cannot
          be exported, e.g., insufficient privileges.
        """
        try:
            key = self._loadKey(keyName)
        except TpmBackEnd.Error as ex:
            raise TpmBackEnd.Error("Cannot export private key: " + str(ex))

        try:
            if password != None:
                return key.toEncryptedPkcs8(password)
            else:
                return key.toPkcs8()
        except TpmPrivateKey.Error as ex:
            raise TpmBackEnd.Error(
              "Error PKCS#8 encoding private key: " + str(ex))

    def _doImportKey(self, keyName, pkcs8, password):
        """
        A protected method to import an encoded private key with name keyName in
          PKCS #8 format, possibly password-encrypted.

        :param Name keyName: The name of the key to use in the TPM.
        :param pkcs8: The input byte buffer. If the password is supplied, this
          is a PKCS #8 EncryptedPrivateKeyInfo. If the password is none, this is
          an unencrypted PKCS #8 PrivateKeyInfo.
        :type pkcs8: an array which implements the buffer protocol
        :param password: The password for decrypting the private key, which
          should have characters in the range of 1 to 127. If the password is
          supplied, use it to decrypt the PKCS #8 EncryptedPrivateKeyInfo. If
          the password is None, import an unencrypted PKCS #8 PrivateKeyInfo.
        :type password: an array which implements the buffer protocol
        :raises TpmBackEnd.Error: For an error importing the key.
        """
        try:
            key = TpmPrivateKey()
            if password != None:
                key.loadEncryptedPkcs8(pkcs8, password)
            else:
                key.loadPkcs8(pkcs8)
        except TpmPrivateKey.Error as ex:
            raise TpmBackEnd.Error("Cannot import private key: " + str(ex))

        self._saveKey(keyName, key)

    def _loadKey(self, keyName):
        """
        Load the private key with name keyName from the key file directory.

        :param Name keyName: The name of the key.
        :return: The key loaded into a TpmPrivateKey.
        :rtype: TpmPrivateKey
        """
        key = TpmPrivateKey()
        base64Content = None
        try:
            with open(self._toFilePath(keyName)) as keyFile:
                base64Content = keyFile.read()
        except Exception as ex:
            raise TpmBackEndFile.Error(
              "Error reading private key file: " + str(ex))

        pkcs = base64.b64decode(base64Content)

        try:
            key.loadPkcs1(pkcs, None)
        except Exception as ex:
            raise TpmBackEndFile.Error(
              "Error decoding private key file: " + str(ex))

        return key

    def _saveKey(self, keyName, key):
        """
        Save the private key using keyName into the key file directory.

        :param Name keyName: The name of the key.
        :param TpmPrivateKey key: The private key to save.
        """
        filePath = self._toFilePath(keyName)
        try:
            base64 = Common.base64Encode(key.toPkcs1().toBytes(), True)
        except Exception as ex:
            raise TpmBackEndFile.Error(
              "Error encoding private key file: " + str(ex))

        try:
            with open(filePath, 'w') as keyFile:
                keyFile.write(base64)
        except Exception as ex:
            raise TpmBackEndFile.Error(
              "Error writing private key file: " + str(ex))

    def _toFilePath(self, keyName):
        """
        Get the file path for the keyName, which is keyStorePath_ + "/" +
        hex(sha256(keyName-wire-encoding)) + ".privkey" .

        :param Name keyName: The name of the key.
        :return: The file path for the key.
        :rtype: str
        """
        keyEncoding = keyName.wireEncode()
        sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
        sha256.update(keyEncoding.toBytes())
        digest = sha256.finalize()

        return os.path.join(self._keyStorePath, Blob(digest, False).toHex() +
          ".privkey")

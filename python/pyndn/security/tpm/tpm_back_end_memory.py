# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/tpm/back-end-mem.cpp
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
This module defines the TpmBackEndMemory class which extends TpmBackEnd to
implement a TPM back-end using in-memory storage.
"""

from pyndn.name import Name
from pyndn.security.tpm.tpm_private_key import TpmPrivateKey
from pyndn.security.tpm.tpm_key_handle_memory import TpmKeyHandleMemory
from pyndn.security.tpm.tpm_back_end import TpmBackEnd

class TpmBackEndMemory(TpmBackEnd):
    def __init__(self):
        super(TpmBackEndMemory, self).__init__()

        # keyName => TpmPrivateKey.
        self._keys = {}

    @staticmethod
    def getScheme():
        return "tpm-memory"

    def _doHasKey(self, keyName):
        """
        A protected method to check if the key with name keyName exists in the
        TPM.

        :param Name keyName: The name of the key.
        :return: True if the key exists.
        :rtype: bool
        """
        return keyName in self._keys

    def _doGetKeyHandle(self, keyName):
        """
        A protected method to get the handle of the key with name keyName.

        :param Name keyName: The name of the key.
        :return: The handle of the key, or None if the key does not exist.
        :rtype: TpmKeyHandle
        """
        try:
            key = self._keys[keyName]
        except KeyError:
            return None

        return TpmKeyHandleMemory(key)

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
        try:
            key = TpmPrivateKey.generatePrivateKey(params)
        except TpmPrivateKey.Error as ex:
            raise TpmBackEnd.Error(
              "Error in TpmPrivateKey.generatePrivateKey: " + str(ex))

        keyHandle = TpmKeyHandleMemory(key)

        TpmBackEnd.setKeyName(keyHandle, identityName, params)

        self._keys[keyHandle.getKeyName()] = key
        return keyHandle

    def _doDeleteKey(self, keyName):
        """
        A protected method to delete the key with name keyName. If the key
        doesn't exist, do nothing.

        :param Name keyName: The name of the key to delete.
        :raises TpmBackEnd.Error: If the deletion fails.
        """
        try:
            del self._keys[keyName]
        except KeyError:
            # Do nothing if it doesn't exist.
            pass

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
        if not self.hasKey(keyName):
            raise TpmBackEnd.Error("exportKey: The key does not exist")

        try:
            if password != None:
                return self._keys[keyName].toEncryptedPkcs8(password)
            else:
                return self._keys[keyName].toPkcs8()
        except TpmPrivateKey.Error as ex:
            raise TpmBackEnd.Error(
              "Error in TpmPrivateKey.toPkcs8: " + str(ex))

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
            # Copy the Name.
            self._keys[Name(keyName)] = key
        except TpmPrivateKey.Error as ex:
            raise TpmBackEnd.Error("Cannot import private key: " + str(ex))

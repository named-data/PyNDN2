# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/tpm/back-end.cpp
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
This module defines the TpmBackEnd class which is an abstract base class for a
TPM backend implementation which provides a TpmKeyHandle to the TPM front end.
This class defines the interface that an actual TPM backend implementation
should provide, for example TpmBackEndMemory.
"""

from random import SystemRandom
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from pyndn.name import Name
from pyndn.util.blob import Blob
from pyndn.security.key_id_type import KeyIdType
from pyndn.security.pib.pib_key import PibKey

# The Python documentation says "Use SystemRandom if you require a
#   cryptographically secure pseudo-random number generator."
# http://docs.python.org/2/library/random.html
_systemRandom = SystemRandom()

class TpmBackEnd(object):
    class Error(Exception):
        """
        Create a TpmBackEnd.Error which represents a non-semantic error in
        backend TPM processing.

        :param str message: The error message.
        """
        def __init__(self, message):
            super(TpmBackEnd.Error, self).__init__(message)

    def hasKey(self, keyName):
        """
        Check if the key with name keyName exists in the TPM.

        :param Name keyName: The name of the key.
        :return: True if the key exists.
        :rtype: bool
        """
        return self._doHasKey(keyName)

    def getKeyHandle(self, keyName):
        """
        Get the handle of the key with name keyName. Calling getKeyHandle
        multiple times with the same keyName will return different TpmKeyHandle
        objects that all refer to the same key.

        :param Name keyName: The name of the key.
        :return: The handle of the key, or None if the key does not exist.
        :rtype: TpmKeyHandle
        """
        return self._doGetKeyHandle(keyName)

    def createKey(self, identityName, params):
        """
        Create a key for the identityName according to params.

        :param Name identityName: The name if the identity.
        :param KeyParams params: The KeyParams for creating the key.
        :return: The handle of the created key.
        :rtype: TpmKeyHandle
        :raises TpmBackEnd.Error: If the key cannot be created.
        """
        # Do key name checking.
        if params.getKeyIdType() == KeyIdType.USER_SPECIFIED:
            # The keyId is pre-set.
            keyName = PibKey.constructKeyName(identityName, params.getKeyId())
            if self.hasKey(keyName):
                raise Tpm.Error("Key `" + keyName.toUri() + "` already exists")
        elif params.getKeyIdType() == KeyIdType.SHA256:
            # The key name will be assigned in setKeyName after the key is generated.
            pass
        elif params.getKeyIdType() == KeyIdType.RANDOM:
            random = bytearray(8)
            while True:
                for i in range(len(random)):
                    random[i] = _systemRandom.randint(0, 0xff)

                keyId = Name.Component(Blob(random, False))
                keyName = PibKey.constructKeyName(identityName, keyId)

                if not self.hasKey(keyName):
                    # We got a unique one.
                    break

            params.setKeyId(keyId)
        else:
            raise Tpm.Error("Unsupported key id type")

        return self._doCreateKey(identityName, params)

    def deleteKey(self, keyName):
        """
        Delete the key with name keyName. If the key doesn't exist, do nothing.
        Note: Continuing to use existing Key handles on a deleted key results in
        undefined behavior.

        :param Name keyName: The name of the key to delete.
        :raise TpmBackEnd.Error: If the deletion fails.
        """
        self._doDeleteKey(keyName)

    def exportKey(self, keyName, password):
        """
        Get the encoded private key with name keyName in PKCS #8 format,
        possibly password-encrypted.

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
            raise TpmBackEnd.Error("Key `" + keyName.toUri() + "` does not exist")

        return self._doExportKey(keyName, password)

    def importKey(self, keyName, pkcs8, password):
        """
        Import an encoded private key with name keyName in PKCS #8 format,
          possibly password-encrypted.

        :param Name keyName: The name of the key to use in the TPM.
        :param pkcs8: The input byte buffer. If the password is supplied, this
          is a PKCS #8 EncryptedPrivateKeyInfo. If the password is None, this is
          an unencrypted PKCS #8 PrivateKeyInfo.
        :type pkcs8: an array which implements the buffer protocol
        :param password: The password for decrypting the private key, which
          should have characters in the range of 1 to 127. If the password is
          supplied, use it to decrypt the PKCS #8 EncryptedPrivateKeyInfo. If
          the password is None, import an unencrypted PKCS #8 PrivateKeyInfo.
        :type password: an array which implements the buffer protocol
        :raises TpmBackEnd.Error: For an error importing the key.
        """
        if self.hasKey(keyName):
            raise TpmBackEnd.Error("Key `" + keyName.toUri() + "` already exists")

        self._doImportKey(keyName, pkcs8, password)

    def isTerminalMode(self):
        """
        Check if the TPM is in terminal mode. The default implementation always
          returns True.

        :return: True if in terminal mode.
        :rtype: bool
        """
        return True

    def setTerminalMode(self, isTerminal):
        """
        Set the terminal mode of the TPM. In terminal mode, the TPM will not ask
        for a password from the GUI. The default implementation does nothing.

        :param bool isTerminal: True to enable terminal mode.
        """
        pass

    def isTpmLocked(self):
        """
        Check if the TPM is locked. The default implementation returns false.

        :return: True if the TPM is locked, otherwise False.
        :rtype: bool
        """
        return False

    def unlockTpm(self, password):
        """
        Unlock the TPM. If !isTerminalMode(), prompt for a password from the GUI.
        The default implementation does nothing and returns not isTpmLocked().

        :param password: The password to unlock TPM.
        :type password: an array which implements the buffer protocol
        :return: True if the TPM was unlocked.
        :rtype: bool
        """
        return not self.isTpmLocked()

    @staticmethod
    def setKeyName(keyHandle, identityName, params):
        """
        Set the key name in keyHandle according to identityName and params.

        :param TpmKeyHandle keyHandle:
        :param Name identityName:
        :param KeyParams params:
        """
        if params.getKeyIdType() == KeyIdType.USER_SPECIFIED:
            keyId = params.getKeyId()
        elif params.getKeyIdType() == KeyIdType.SHA256:
            sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
            sha256.update(keyHandle.derivePublicKey().toBytes())
            digest = sha256.finalize()
            keyId = Name.Component(digest)
        elif params.getKeyIdType() == KeyIdType.RANDOM:
            if params.getKeyId().getValue().size() == 0:
                raise TpmBackEnd.Error(
                  "setKeyName: The keyId is empty for type RANDOM")
            keyId = params.getKeyId()
        else:
            raise TpmBackEnd.Error(
              "setKeyName: unrecognized params.getKeyIdType()")

        keyHandle.setKeyName(PibKey.constructKeyName(identityName, keyId))

    def _doHasKey(self, keyName):
        """
        A protected method to check if the key with name keyName exists in the
        TPM.
        Your subclass must implement it.

        :param Name keyName: The name of the key.
        :return: True if the key exists.
        :rtype: bool
        """
        raise RuntimeError("TpmBackEnd._doHasKey is not implemented")

    def _doGetKeyHandle(self, keyName):
        """
        A protected method to get the handle of the key with name keyName.
        Your subclass must implement it.

        :param Name keyName: The name of the key.
        :return: The handle of the key, or None if the key does not exist.
        :rtype: TpmKeyHandle
        """
        raise RuntimeError("TpmBackEnd._doGetKeyHandle is not implemented")

    def _doCreateKey(self, identityName, params):
        """
        A protected method to create a key for identityName according to params.
        The created key is named as: /<identityName>/[keyId]/KEY . The key name
        is set in the returned TpmKeyHandle.
        Your subclass must implement it.

        :param Name identityName: The name if the identity.
        :param KeyParams params: The KeyParams for creating the key.
        :return: The handle of the created key.
        :rtype: TpmKeyHandle
        :raises TpmBackEnd.Error: If the key cannot be created.
        """
        raise RuntimeError("TpmBackEnd._doCreateKey is not implemented")

    def _doDeleteKey(self, keyName):
        """
        A protected method to delete the key with name keyName. If the key
        doesn't exist, do nothing.
        Your subclass must implement it.

        :param Name keyName: The name of the key to delete.
        :raises TpmBackEnd.Error: If the deletion fails.
        """
        raise RuntimeError("TpmBackEnd._doDeleteKey is not implemented")

    def _doExportKey(self, keyName, password):
        """
        A protected method to get the encoded private key with name keyName in
        PKCS #8 format, possibly password-encrypted.
        Your subclass must implement it.

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
        raise RuntimeError("TpmBackEnd._doExportKey is not implemented")

    def _doImportKey(self, keyName, pkcs8, password):
        """
        A protected method to import an encoded private key with name keyName in
          PKCS #8 format, possibly password-encrypted.
        Your subclass must implement it.

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
        :raises TpmBackEnd.Error: if a key with name keyName already exists, or
          for an error importing the key.
        """
        raise RuntimeError("TpmBackEnd._doImportKey is not implemented")

# Put this last to avoid an import loop.
from pyndn.security.tpm.tpm import Tpm

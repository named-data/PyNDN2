# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/tpm/tpm.cpp
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
The TPM (Trusted Platform Module) stores the private portion of a user's
cryptography keys. The format and location of stored information is indicated by
the TPM locator. The TPM is designed to work with a PIB (Public Information
Base) which stores public keys and related information such as certificates.

The TPM also provides functionalities of cryptographic transformation, such as
signing and decryption.

A TPM consists of a unified front-end interface and a backend implementation.
The front-end caches the handles of private keys which are provided by the
backend implementation.

Note: A Tpm instance is created and managed only by the KeyChain. It is returned
by the KeyChain getTpm() method, through which it is possible to check for the
existence of private keys, get public keys for the private keys, sign, and
decrypt the supplied buffers using managed private keys.
"""

from pyndn.util.blob import Blob
from pyndn.name import Name
from pyndn.security.security_types import KeyType

class Tpm(object):
    def __init__(self, scheme, location, backEnd):
        """
        Create a new TPM instance with the specified location. This constructor
        should only be called by KeyChain.

        :param str scheme: The scheme for the TPM.
        :param str location: The location for the TPM.
        :param TpmBackEnd backEnd: The TPM back-end implementation.
        """
        # Name => TpmKeyHandle
        self._keys = {}

        self._scheme = scheme
        self._location = location
        self._backEnd = backEnd

    class Error(Exception):
        """
        Create a Tpm.Error which represents a semantic error in TPM processing.

        :param str message: The error message.
        """
        def __init__(self, message):
            super(Tpm.Error, self).__init__(message)

    def getTpmLocator(self):
        return self._scheme + ":" + self._location

    def hasKey(self, keyName):
        """
        Check if the key with name keyName exists in the TPM.

        :param Name keyName: The name of the key.
        :return: True if the key exists.
        :rtype: bool
        """
        return self._backEnd.hasKey(keyName)

    def getPublicKey(self, keyName):
        """
        Get the public portion of an asymmetric key pair with name keyName.

        :param Name keyName: The name of the key.
        :return: The encoded public key, or an isNull Blob if the key does not
          exist.
        :rtype: Blob
        """
        key = self._findKey(keyName)

        if key == None:
            return Blob()
        else:
            return key.derivePublicKey()

    def sign(self, data, keyName, digestAlgorithm):
        """
        Compute a digital signature from the byte buffer using the key with name
        keyName.

        :param data: The input byte buffer.
        :type data: an array which implements the buffer protocol
        :param Name keyName: The name of the key.
        :param digestAlgorithm: The digest algorithm for the signature.
        :type digestAlgorithm: int from DigestAlgorithm
        :return: The signature Blob, or an isNull Blob if the key does not
          exist, or for an unrecognized digestAlgorithm.
        :rtype: Blob
        """
        key = self._findKey(keyName)

        if key == None:
            return Blob()
        else:
            return key.sign(digestAlgorithm, data)

    def decrypt(self, cipherText, keyName):
        """
        Return the plain text which is decrypted from cipherText using the key
        with name keyName.

        :param cipherText: The cipher text byte buffer.
        :type cipherText: an array which implements the buffer protocol
        :param Name keyName: The name of the key.
        :return: The decrypted data, or an isNull Blob if the key does not exist.
        :rtype: Blob
        """
        key = self._findKey(keyName)

        if key == None:
            return Blob()
        else:
            return key.decrypt(cipherText)

    # TPM Management

    def isTerminalMode(self):
        """
        Check if the TPM is in terminal mode.

        :return: True if in terminal mode.
        :rtype: bool
        """
        return self._backEnd.isTerminalMode()

    def setTerminalMode(self, isTerminal):
        """
        Set the terminal mode of the TPM. In terminal mode, the TPM will not ask
        for a password from the GUI.

        :param bool isTerminal: True to enable terminal mode.
        """
        self._backEnd.setTerminalMode(isTerminal)

    def isTpmLocked(self):
        """
        Check if the TPM is locked.

        :return: True if the TPM is locked, otherwise False.
        :rtype: bool
        """
        return self._backEnd.isTpmLocked()

    def unlockTpm(self, password):
        """
        Unlock the TPM. If !isTerminalMode(), prompt for a password from the GUI.

        :param password: The password to unlock TPM.
        :type password: an array which implements the buffer protocol
        :return: True if the TPM was unlocked.
        :rtype: bool
        """
        return self._backEnd.unlockTpm(password)

    def _getBackEnd(self):
        """
        Get the TpmBackEnd. This should only be called by KeyChain.

        :rtype: TpmBackEnd
        """
        return self._backEnd

    def _createKey(self, identityName, params):
        """
        Create a key for the identityName according to params. The created key
        is named /<identityName>/[keyId]/KEY . This should only be called by
        KeyChain.

        :param Name identityName: The name if the identity.
        :param KeyParams params: The KeyParams for creating the key.
        :return: The name of the created key.
        :rtype: Name
        :raises Tpm.Error: If params is invalid or the key type is unsupported.
        :raises TpmBackEnd.Error: If the key already exists or cannot be created.
        """
        if (params.getKeyType() == KeyType.RSA or
            params.getKeyType() == KeyType.EC):
            keyHandle = self._backEnd.createKey(identityName, params)
            keyName = keyHandle.getKeyName()
            self._keys[keyName] = keyHandle
            return keyName
        else:
            raise Tpm.Error("createKey: Unsupported key type")

    def _deleteKey(self, keyName):
        """
        Delete the key with name keyName. If the key doesn't exist, do nothing.
        Note: Continuing to use existing Key handles on a deleted key results in
        undefined behavior. This should only be called by KeyChain.

        :param Name keyName: The name of the key.
        :raises TpmBackEnd.Error: If the deletion fails.
        """
        try:
            del self._keys[keyName]
        except KeyError:
            # Do nothing if it doesn't exist.
            pass

        self._backEnd.deleteKey(keyName)

    def _exportPrivateKey(self, keyName, password):
        """
        Get the encoded private key with name keyName in PKCS #8 format, possibly
        encrypted. This should only be called by KeyChain.

        :param Name keyName: The name of the key in the TPM.
        :param password: The password for encrypting the private key, which
          should have characters in the range of 1 to 127. If the password is
          supplied, use it to return a PKCS #8 EncryptedPrivateKeyInfo. If the
          password is None, return an unencrypted PKCS #8 PrivateKeyInfo.
        :type password: an array which implements the buffer protocol
        :return: The private key encoded in PKCS #8 format.
        :rtype: Blob
        :raises TpmBackEnd.Error: If the key does not exist or if the key cannot
          be exported, e.g., insufficient privileges.
        """
        return self._backEnd.exportKey(keyName, password)

    def _importPrivateKey(self, keyName, pkcs8, password):
        """
        Import an encoded private key with name keyName in PKCS #8 format,
        possibly password-encrypted. This should only be called by KeyChain.

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
        self._backEnd.importKey(keyName, pkcs8, password)

    def _findKey(self, keyName):
        """
        Get the TpmKeyHandle with name keyName, using _backEnd.getKeyHandle if
        it is not already cached in _keys.

        :param Name keyName: The name of the key, which is copied.
        :return: The key handle in the _keys cache, or None if no key exists
          with name keyName.
        :rtype: TpmKeyHandle
        """
        try:
            handle = self._keys[keyName]
        except KeyError:
            handle = None

        if handle != None:
            return handle

        handle = self._backEnd.getKeyHandle(keyName)

        if handle != None:
            # Copy the Name.
            self._keys[Name(keyName)] = handle
            return handle

        return None

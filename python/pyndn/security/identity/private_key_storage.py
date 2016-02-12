# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
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
This module defines the PrivateKeyStorage abstract class which declares
methods for working with a private key storage.  You should use a subclass.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from pyndn.security.security_exception import SecurityException
from pyndn.security.security_types import DigestAlgorithm

class PrivateKeyStorage(object):
    def generateKeyPair(self, keyName, params):
        """
        Generate a pair of asymmetric keys.
        Your derived class should override.

        :param Name keyName: The name of the key pair.
        :param KeyParams params: The parameters of the key.
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("generateKeyPair is not implemented")

    def deleteKeyPair(self, keyName):
        """
        Delete a pair of asymmetric keys. If the key doesn't exist, do nothing.
        Your derived class should override.

        :param Name keyName: The name of the key pair.
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("deleteKeyPair is not implemented")

    def getPublicKey(self, keyName):
        """
        Get the public key with the keyName.
        Your derived class should override.

        :param Name keyName: The name of public key.
        :return: The public key.
        :rtype: PublicKey
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("getPublicKey is not implemented")

    def sign(self, data, keyName, digestAlgorithm = DigestAlgorithm.SHA256):
        """
        Fetch the private key for keyName and sign the data, returning a
        signature Blob.
        Your derived class should override.

        :param data: Pointer the input byte buffer to sign.
        :type data: An array type with int elements
        :param Name keyName: The name of the signing key.
        :param digestAlgorithm: (optional) the digest algorithm. If omitted,
          use DigestAlgorithm.SHA256.
        :type digestAlgorithm: int from DigestAlgorithm
        :return: The signature Blob.
        :rtype: Blob
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("sign is not implemented")

    def decrypt(self, keyName, data, isSymmetric = False):
        """
        Decrypt data.
        Your derived class should override.

        :param Name keyName: The name of the decrypting key.
        :param data: The byte buffer to be decrypted.
        :type data: An array type with int elements
        :param bool isSymmetric: (optional) If True symmetric encryption is
          used, otherwise asymmetric encryption is used. If omitted, use
          asymmetric encryption.
        :return: The decrypted data.
        :rtype: Blob
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("decrypt is not implemented")

    def encrypt(self, keyName, data, isSymmetric = False):
        """
        Encrypt data.
        Your derived class should override.

        :param Name keyName: The name of the encrypting key.
        :param data: The byte buffer to be encrypted.
        :type data: An array type with int elements
        :param bool isSymmetric: (optional) If True symmetric encryption is
          used, otherwise asymmetric encryption is used. If omitted, use
          asymmetric encryption.
        :return: The encrypted data.
        :rtype: Blob
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("encrypt is not implemented")

    def generateKey(self, keyName, params):
        """
        Generate a symmetric key.
        Your derived class should override.

        :param Name keyName: The name of the key.
        :param KeyParams params: The parameters of the key.
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("generateKey is not implemented")

    def doesKeyExist(self, keyName, keyClass):
        """
        Check if a particular key exists.
        Your derived class should override.

        :param Name keyName: The name of the key.
        :param keyClass: The class of the key, e.g. KeyClass.PUBLIC,
           KeyClass.PRIVATE, or KeyClass.SYMMETRIC.
        :type keyClass: int from KeyClass
        :return: True if the key exists, otherwise false.
        :rtype: bool
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("doesKeyExist is not implemented")

    @staticmethod
    def getEcCurve(keySize):
        """
        Get the Elliptic Curve algorithm object for the key size.

        :param int keySize: The key size.
        :raises SecurityException: If the key size is not supported.
        """
        if keySize == 256:
            return ec.SECP256R1()
        elif keySize == 384:
            return ec.SECP384R1()
        elif keySize == 521:
            return ec.SECP521R1()
        else:
            raise SecurityException("Unsupported EC key size: " + str(keySize))

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
This module defines the MemoryIdentityStorage class which extends
IdentityStorage and implements its methods to store identity, public key and
certificate objects in memory. The application must get the objects through its
own means and add the objects to the MemoryIdentityStorage object.
To use permanent file-based storage, see BasicIdentityStorage.
"""

from pyndn.name import Name
from pyndn.util.blob import Blob
from pyndn.security.security_exception import SecurityException
from pyndn.security.identity.identity_storage import IdentityStorage
from pyndn.security.certificate import IdentityCertificate

class MemoryIdentityStorage(IdentityStorage):
    def __init__(self):
        super(MemoryIdentityStorage, self).__init__()
        # The key is the identityName.toUri(). The value is an _IdentityRecord.
        self._identityStore = {}
        # The default identity in identityStore_, or "" if not defined.
        self._defaultIdentity = ""
        # The key is the keyName.toUri(). The value is the tuple
        #  (KeyType keyType, Blob keyDer, Name defaultCertificate).
        self._keyStore = {}
        # The key is the certificateName.toUri(). The value is the encoded
        # certificate.
        self._certificateStore = {}

    def doesIdentityExist(self, identityName):
        """
        Check if the specified identity already exists.

        :param Name identityName: The identity name.
        :return: True if the identity exists, otherwise False.
        :rtype: bool
        """
        return identityName.toUri() in self._identityStore

    def addIdentity(self, identityName):
        """
        Add a new identity. Do nothing if the identity already exists.

        :param Name identityName: The identity name.
        """
        identityUri = identityName.toUri()
        if identityUri in self._identityStore:
            return

        self._identityStore[identityUri] = self._IdentityRecord()

    def revokeIdentity(self):
        """
        Revoke the identity.

        :return: True if the identity was revoked, False if not.
        :rtype: bool
        """
        raise RuntimeError(
          "MemoryIdentityStorage.doesIdentityExist is not implemented")

    def doesKeyExist(self, keyName):
        """
        Check if the specified key already exists.

        :param Name keyName: The name of the key.
        :return: True if the key exists, otherwise False.
        :rtype: bool
        """
        return keyName.toUri() in self._keyStore

    def addKey(self, keyName, keyType, publicKeyDer):
        """
        Add a public key to the identity storage. Also call addIdentity to ensure
        that the identityName for the key exists. However, if the key already
        exists, do nothing.

        :param Name keyName: The name of the public key to be added.
        :param keyType: Type of the public key to be added.
        :type keyType: int from KeyType
        :param Blob publicKeyDer: A blob of the public key DER to be added.
        """
        if keyName.size() == 0:
            return

        if self.doesKeyExist(keyName):
            return

        identityName = keyName.getSubName(0, keyName.size() - 1)

        self.addIdentity(identityName)

        self._keyStore[keyName.toUri()] = (keyType, Blob(publicKeyDer), None)

    def getKey(self, keyName):
        """
        Get the public key DER blob from the identity storage.

        :param Name keyName: The name of the requested public key.
        :return: The DER Blob.
        :rtype: Blob
        :raises SecurityException: if the key doesn't exist.
        """
        if keyName.size() == 0:
            raise SecurityException(
              "MemoryIdentityStorage::getKey: Empty keyName")

        keyNameUri = keyName.toUri()
        if not (keyNameUri in self._keyStore):
            raise SecurityException(
              "MemoryIdentityStorage::getKey: The key does not exist")

        (_, publicKeyDer, _) = self._keyStore[keyNameUri]
        return publicKeyDer

    def activateKey(self, keyName):
        """
        Activate a key. If a key is marked as inactive, its private part will
        not be used in packet signing.

        :param Name keyName: The name of the key.
        """
        raise RuntimeError(
          "MemoryIdentityStorage.activateKey is not implemented")

    def deactivateKey(self, keyName):
        """
        Deactivate a key. If a key is marked as inactive, its private part will
        not be used in packet signing.

        :param Name keyName: The name of the key.
        """
        raise RuntimeError(
         "MemoryIdentityStorage.deactivateKey is not implemented")

    def doesCertificateExist(self, certificateName):
        """
        Check if the specified certificate already exists.

        :param Name certificateName: The name of the certificate.
        :return: True if the certificate exists, otherwise False.
        :rtype: bool
        """
        return certificateName.toUri() in self._certificateStore

    def addCertificate(self, certificate):
        """
        Add a certificate to the identity storage. Also call addKey to ensure
        that the certificate key exists. If the certificate is already
        installed, don't replace it.

        :param IdentityCertificate certificate: The certificate to be added.
          This makes a copy of the certificate.
        """
        certificateName = certificate.getName()
        keyName = certificate.getPublicKeyName()

        self.addKey(keyName, certificate.getPublicKeyInfo().getKeyType(),
                    certificate.getPublicKeyInfo().getKeyDer())

        if self.doesCertificateExist(certificateName):
          return

        # Insert the certificate.
        # wireEncode returns the cached encoding if available.
        self._certificateStore[certificateName.toUri()] = (
           certificate.wireEncode())

    def getCertificate(self, certificateName):
        """
        Get a certificate from the identity storage.

        :param Name certificateName: The name of the requested certificate.
        :return: The requested certificate.
        :rtype: IdentityCertificate
        :raises SecurityException: if the certificate doesn't exist.
        """
        certificateNameUri = certificateName.toUri()
        if not (certificateNameUri in self._certificateStore):
            raise SecurityException(
              "MemoryIdentityStorage::getCertificate: The certificate does not exist")

        certificate = IdentityCertificate()
        try:
            certificate.wireDecode(self._certificateStore[certificateNameUri])
        except ValueError:
            raise SecurityException(
              "MemoryIdentityStorage::getCertificate: The certificate cannot be decoded")

        return certificate

    #
    # Get/Set Default
    #

    def getDefaultIdentity(self):
        """
        Get the default identity.

        :return: The name of default identity.
        :rtype: Name
        :raises SecurityException: if the default identity is not set.
        """
        if len(self._defaultIdentity) == 0:
            raise SecurityException(
          "MemoryIdentityStorage.getDefaultIdentity: The default identity is not defined")

        return Name(self._defaultIdentity)

    def getDefaultKeyNameForIdentity(self, identityName):
        """
        Get the default key name for the specified identity.

        :param Name identityName: The identity name.
        :return: The default key name.
        :rtype: Name
        :raises SecurityException: if the default key name for the identity is
          not set.
        """
        identityUri = identityName.toUri()
        if identityUri in self._identityStore:
            if self._identityStore[identityUri].hasDefaultKey():
                return self._identityStore[identityUri].getDefaultKey()
            else:
                raise SecurityException("No default key set.")
        else:
            raise SecurityException("Identity not found.")

    def getDefaultCertificateNameForKey(self, keyName):
        """
        Get the default certificate name for the specified key.

        :param Name keyName: The key name.
        :return: The default certificate name.
        :rtype: Name
        :raises SecurityException: if the default certificate name for the key
          name is not set.
        """
        keyNameUri = keyName.toUri()
        if keyNameUri in self._keyStore:
            (_, _, defaultCertificate) = self._keyStore[keyNameUri]
            if defaultCertificate != None:
                return defaultCertificate
            else:
                raise SecurityException("No default certificate set.")
        else:
            raise SecurityException("Key not found.")

    def setDefaultIdentity(self, identityName):
        """
        Set the default identity. If the identityName does not exist, then clear
        the default identity so that getDefaultIdentity() raises an exception.

        :param Name identityName: The default identity name.
        """
        identityUri = identityName.toUri()
        if identityUri in self._identityStore:
            self._defaultIdentity = identityUri
        else:
            # The identity doesn't exist, so clear the default.
            self._defaultIdentity = ""

    def setDefaultKeyNameForIdentity(self, keyName, identityNameCheck = None):
        """
        Set a key as the default key of an identity. The identity name is
        inferred from keyName.

        :param Name keyName: The name of the key.
        :param Name identityNameCheck: (optional) The identity name to check
          that the keyName contains the same identity name. If an empty name, it
          is ignored.
        """
        identityName = keyName.getPrefix(-1)

        if (identityNameCheck != None and identityNameCheck.size() > 0 and
              not identityNameCheck.equals(identityName)):
            raise SecurityException(
              "The specified identity name does not match the key name")

        identityUri = identityName.toUri()
        if identityUri in self._identityStore:
          self._identityStore[identityUri].setDefaultKey(Name(keyName))

    def setDefaultCertificateNameForKey(self, keyName, certificateName):
        """
        Set the default key name for the specified identity.

        :param Name keyName: The key name.
        :param Name certificateName: The certificate name.
        """
        keyNameUri = keyName.toUri()
        if keyNameUri in self._keyStore:
            # Replace the third element.
            self._keyStore[keyNameUri] = (
              self._keyStore[keyNameUri][0:2] + (Name(certificateName),) )

    class _IdentityRecord:
        def __init__(self):
            self._defaultKey = None

        def setDefaultKey(self, key):
            self._defaultKey = key

        def hasDefaultKey(self):
            return self._defaultKey != None

        def getDefaultKey(self):
            return self._defaultKey

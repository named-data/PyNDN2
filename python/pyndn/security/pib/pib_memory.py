# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/pib/pib-memory.cpp
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
This module defines the PibMemory class which  extends PibImpl and is used by
the Pib class as an in-memory implementation of a PIB. All the contents in the
PIB are stored in memory and have the same lifetime as the PibMemory instance.
"""

from pyndn.name import Name
from pyndn.util.blob import Blob
from pyndn.security.pib.pib import Pib
from pyndn.security.pib.pib_key import PibKey
from pyndn.security.v2.certificate_v2 import CertificateV2
from pyndn.security.pib.pib_impl import PibImpl

class PibMemory(PibImpl):
    """
    Create an empty PibMemory.
    """
    def __init__(self):
        super(PibMemory, self).__init__()

        self._tpmLocator = ""

        self._defaultIdentityName = None

        # Set of Name.
        self._identityNames = set()

        # identityName => default key Name.
        self._defaultKeyNames = {}

        # keyName => keyBits Blob.
        self._keys = {}

        # keyName => default certificate Name.
        self._defaultCertificateNames = {}

        # certificateName => CertificateV2.
        self._certificates = {}

    @staticmethod
    def getScheme():
        return "pib-memory"

    # TpmLocator management.

    def setTpmLocator(self, tpmLocator):
        """
        Set the corresponding TPM information to tpmLocator. This method does not
        reset the contents of the PIB.

        :param str tpmLocator: The TPM locator string.
        """
        self._tpmLocator = tpmLocator

    def getTpmLocator(self):
        """
        Get the TPM Locator.

        :return: The TPM locator string.
        :rtype: str
        """
        return self._tpmLocator

    # Identity management.

    def hasIdentity(self, identityName):
        """
        Check for the existence of an identity.

        :param Name identityName: The name of the identity.
        :return: True if the identity exists, otherwise False.
        :rtype: bool
        """
        return identityName in self._identityNames

    def addIdentity(self, identityName):
        """
        Add the identity. If the identity already exists, do nothing. If no
        default identity has been set, set the added identity as the default.

        :param Name identityName: The name of the identity to add. This copies
          the name.
        """
        identityNameCopy = Name(identityName)
        self._identityNames.add(identityNameCopy)

        if self._defaultIdentityName == None:
            self._defaultIdentityName = identityNameCopy

    def removeIdentity(self, identityName):
        """
        Remove the identity and its related keys and certificates. If the
        default identity is being removed, no default identity will be selected.
        If the identity does not exist, do nothing.

        :param Name identityName: The name of the identity to remove.
        """
        try:
            self._identityNames.remove(identityName)
        except KeyError:
            # Do nothing if it doesn't exist.
            pass
        if (self._defaultIdentityName != None and
            identityName.equals(self._defaultIdentityName)):
            self._defaultIdentityName = None

        for keyName in self.getKeysOfIdentity(identityName):
            self.removeKey(keyName)

    def clearIdentities(self):
        """
        Erase all certificates, keys, and identities.
        """
        self._defaultIdentityName = None
        self._identityNames = set()
        self._defaultKeyNames = {}
        self._keys = {}
        self._defaultCertificateNames = {}
        self._certificates = {}

    def getIdentities(self):
        """
        Get the names of all the identities.

        :return: A fresh set of identity names. The Name objects are fresh
          copies.
        :rtype: set of Name
        """
        # Copy the Name objects.
        result = set()
        for name in self._identityNames:
            result.add(Name(name))

        return result

    def setDefaultIdentity(self, identityName):
        """
        Set the identity with the identityName as the default identity. If the
        identity with identityName does not exist, then it will be created.

        :param Name identityName: The name for the default identity. This copies
          the name.
        """
        self.addIdentity(identityName)
        # Copy the name.
        self._defaultIdentityName = Name(identityName)

    def getDefaultIdentity(self):
        """
        Get the default identity.

        :return: The name of the default identity, as a fresh copy.
        :rtype: Name
        :raises Pib.Error: For no default identity.
        """
        if self._defaultIdentityName != None:
            # Copy the name.
            return Name(self._defaultIdentityName)

        raise Pib.Error("No default identity")

    # Key management.

    def hasKey(self, keyName):
        """
        Check for the existence of a key with keyName.

        :param Name keyName: The name of the key.
        :return: True if the key exists, otherwise False. Return False if the
          identity does not exist.
        :rtype: bool
        """
        return keyName in self._keys

    def addKey(self, identityName, keyName, key):
        """
        Add the key. If a key with the same name already exists, overwrite the
        key. If the identity does not exist, it will be created. If no default
        key for the identity has been set, then set the added key as the default
        for the identity.  If no default identity has been set, identity becomes
        the default.

        :param Name identityName: The name of the identity that the key belongs
          to. This copies the name.
        :param Name keyName:  The name of the key. This copies the name.
        :param key: The public key bits. This copies the array.
        :type key: an array which implements the buffer protocol
        """
        self.addIdentity(identityName)

        keyNameCopy = Name(keyName)
        self._keys[keyNameCopy] = Blob(key, True)

        if not identityName in self._defaultKeyNames:
            # Copy the identityName.
            self._defaultKeyNames[Name(identityName)] = keyNameCopy

    def removeKey(self, keyName):
        """
        Remove the key with keyName and its related certificates. If the key
        does not exist, do nothing.

        :param Name keyName: The name of the key.
        """
        identityName = PibKey.extractIdentityFromKeyName(keyName)

        try:
            del self._keys[keyName]
        except KeyError:
            # Do nothing if it doesn't exist.
            pass
        try:
            del self._defaultKeyNames[identityName]
        except KeyError:
            # Do nothing if it doesn't exist.
            pass

        for certificateName in self.getCertificatesOfKey(keyName):
            self.removeCertificate(certificateName)

    def getKeyBits(self, keyName):
        """
        Get the key bits of a key with name keyName.

        :param Name keyName: The name of the key.
        :return: The key bits.
        :rtype: Blob
        :raises Pib.Error: If the key does not exist.
        """
        if not self.hasKey(keyName):
            raise Pib.Error("Key `" + keyName.toUri() + "` not found")

        key = self._keys[keyName]
        return key

    def getKeysOfIdentity(self, identityName):
        """
        Get all the key names of the identity with the name identityName. The
        returned key names can be used to create a KeyContainer. With a key name
        and a backend implementation, one can create a Key front end instance.

        :param Name identityName: The name of the identity.
        :return: The set of key names. The Name objects are fresh copies. If the
          identity does not exist, return an empty set.
        :rtype: set of Name
        """
        ids = set()
        for keyName in self._keys:
            if identityName.equals(PibKey.extractIdentityFromKeyName(keyName)):
                # Copy the name.
                ids.add(Name(keyName))

        return ids

    def setDefaultKeyOfIdentity(self, identityName, keyName):
        """
        Set the key with keyName as the default key for the identity with name
        identityName.

        :param Name identityName: The name of the identity. This copies the name.
        :param Name keyName: The name of the key. This copies the name.
        :raises Pib.Error: If the key does not exist.
        """
        if not self.hasKey(keyName):
            raise Pib.Error("Key `" + keyName.toUri() + "` not found")

        # Copy the Names.
        self._defaultKeyNames[Name(identityName)] = Name(keyName)

    def getDefaultKeyOfIdentity(self, identityName):
        """
        Get the name of the default key for the identity with name identityName.

        :param Name identityName: The name of the identity.
        :return: The name of the default key, as a fresh copy.
        :rtype: Name
        :raises Pib.Error: If there is no default key or if the identity does
          not exist.
        """
        try:
            defaultKey = self._defaultKeyNames[identityName]
        except KeyError:
            raise Pib.Error(
              "No default key for identity `" + identityName.toUri() + "`")

        # Copy the name.
        return Name(defaultKey)

    # Certificate management.

    def hasCertificate(self, certificateName):
        """
        Check for the existence of a certificate with name certificateName.

        :param Name certificateName: The name of the certificate.
        :return: True if the certificate exists, otherwise False.
        :rtype: bool
        """
        return certificateName in self._certificates

    def addCertificate(self, certificate):
        """
        Add the certificate. If a certificate with the same name (without
        implicit digest) already exists, then overwrite the certificate. If the
        key or identity does not exist, they will be created. If no default
        certificate for the key has been set, then set the added certificate as
        the default for the key. If no default key was set for the identity, it
        will be set as the default key for the identity. If no default identity
        was selected, the certificate's identity becomes the default.

        :param CertificateV2 certificate: The certificate to add. This copies
          the object.
        """
        certificateNameCopy = Name(certificate.getName())
        # getKeyName already makes a new Name.
        keyNameCopy = certificate.getKeyName()
        identity = certificate.getIdentity()

        self.addKey(identity, keyNameCopy, certificate.getContent().toBytes())

        self._certificates[certificateNameCopy] = CertificateV2(certificate)
        if not (keyNameCopy in self._defaultCertificateNames):
            self._defaultCertificateNames[keyNameCopy] = certificateNameCopy

    def removeCertificate(self, certificateName):
        """
        Remove the certificate with name certificateName. If the certificate
        does not exist, do nothing.

        :param Name certificateName: The name of the certificate.
        """
        try:
            del self._certificates[certificateName]
        except KeyError:
            # Do nothing if it doesn't exist.
            pass

        keyName = CertificateV2.extractKeyNameFromCertName(certificateName)
        try:
            defaultCertificateName = self._defaultCertificateNames[keyName]
        except KeyError:
            defaultCertificateName = None

        if (defaultCertificateName != None and
            defaultCertificateName.equals(certificateName)):
            del self._defaultCertificateNames[keyName]

    def getCertificate(self, certificateName):
        """
        Get the certificate with name certificateName.

        :param Name certificateName: The name of the certificate.
        :return: A copy of the certificate.
        :rtype: CertificateV2
        :raises Pib.Error: If the certificate does not exist.
        """
        if not self.hasCertificate(certificateName):
            raise Pib.Error(
              "Certificate `" + certificateName.toUri() +  "` does not exist")

        return CertificateV2(self._certificates[certificateName])

    def getCertificatesOfKey(self, keyName):
        """
        Get a list of certificate names of the key with id keyName. The returned
        certificate names can be used to create a PibCertificateContainer. With a
        certificate name and a backend implementation, one can obtain the
        certificate.

        :param Name keyName: The name of the key.
        :return: The set of certificate names. The Name objects are fresh
          copies. If the key does not exist, return an empty set.
        :rtype: set of Name
        """
        certificateNames = set()
        for certificateName in self._certificates:
            if (CertificateV2.extractKeyNameFromCertName
                (self._certificates[certificateName].getName()).equals(keyName)):
                # Copy the Name.
                certificateNames.add(Name(certificateName))

        return certificateNames

    def setDefaultCertificateOfKey(self, keyName, certificateName):
        """
        Set the cert with name certificateName as the default for the key with
        keyName.

        :param Name keyName: The name of the key.
        :param Name certificateName: The name of the certificate. This copies
          the name.
        :raises Pib.Error: If the certificate with name certificateName does not
          exist.
        """
        if not self.hasCertificate(certificateName):
          raise Pib.Error(
            "Certificate `" + certificateName.toUri() +  "` does not exist")

        # Copy the Names.
        self._defaultCertificateNames[Name(keyName)] = Name(certificateName)

    def getDefaultCertificateOfKey(self, keyName):
        """
        Get the default certificate for the key with eyName.

        :param Name keyName: The name of the key.
        :return: A copy of the default certificate.
        :rtype: CertificateV2
        :raises Pib.Error: If the default certificate does not exist.
        """
        try:
            certificateName = self._defaultCertificateNames[keyName]
        except KeyError:
            raise Pib.Error(
              "No default certificate for key `" + keyName.toUri() + "`")

        certificate = self._certificates[certificateName]
        return CertificateV2(certificate)

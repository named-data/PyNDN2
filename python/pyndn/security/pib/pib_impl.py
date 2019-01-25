# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/pib/pib-impl.cpp
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
This module defines the PibImpl class which is an abstract base class for the
PIB implementation used by the Pib class. This class defines the interface that
an actual PIB implementation should provide, for example PibMemory.
"""

class PibImpl(object):
    class Error(Exception):
        """
        Create a PibImpl.Error which represents a non-semantic error in PIB
        implementation processing. A subclass of PibImpl may throw a subclass of
        this class when there's a non-semantic error, such as a storage problem.

        :param str message: The error message.
        """
        def __init__(self, message):
            super(PibImpl.Error, self).__init__(message)

    # TpmLocator management.

    def setTpmLocator(self, tpmLocator):
        """
        Set the corresponding TPM information to tpmLocator. This method does not
        reset the contents of the PIB.

        :param str tpmLocator: The TPM locator string.
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.setTpmLocator is not implemented")

    def getTpmLocator(self):
        """
        Get the TPM Locator.

        :return: The TPM locator string.
        :rtype: str
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.getTpmLocator is not implemented")

    # Identity management.

    def hasIdentity(self, identityName):
        """
        Check for the existence of an identity.

        :param Name identityName: The name of the identity.
        :return: True if the identity exists, otherwise False.
        :rtype: bool
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.hasIdentity is not implemented")

    def addIdentity(self, identityName):
        """
        Add the identity. If the identity already exists, do nothing. If no
        default identity has been set, set the added identity as the default.

        :param Name identityName: The name of the identity to add. This copies
          the name.
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.addIdentity is not implemented")

    def removeIdentity(self, identityName):
        """
        Remove the identity and its related keys and certificates. If the
        default identity is being removed, no default identity will be selected.
        If the identity does not exist, do nothing.

        :param Name identityName: The name of the identity to remove.
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.removeIdentity is not implemented")

    def clearIdentities(self):
        """
        Erase all certificates, keys, and identities.

        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.clearIdentities is not implemented")

    def getIdentities(self):
        """
        Get the names of all the identities.

        :return: The a fresh set of identity names. The Name objects are fresh
          copies.
        :rtype: set of Name
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.getIdentities is not implemented")

    def setDefaultIdentity(self, identityName):
        """
        Set the identity with the identityName as the default identity. If the
        identity with identityName does not exist, then it will be created.

        :param Name identityName: The name for the default identity. This copies
          the name.
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.setDefaultIdentity is not implemented")

    def getDefaultIdentity(self):
        """
        Get the default identity.

        :return: The name of the default identity, as a fresh copy.
        :rtype: Name
        :raises Pib.Error: For no default identity.
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.getDefaultIdentity is not implemented")

    # Key management.

    def hasKey(self, keyName):
        """
        Check for the existence of a key with keyName.

        :param Name keyName: The name of the key.
        :return: True if the key exists, otherwise False. Return False if the
          identity does not exist.
        :rtype: bool
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.hasKey is not implemented")

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
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.addKey is not implemented")

    def removeKey(self, keyName):
        """
        Remove the key with keyName and its related certificates. If the key
        does not exist, do nothing.

        :param Name keyName: The name of the key.
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.removeKey is not implemented")

    def getKeyBits(self, keyName):
        """
        Get the key bits of a key with name keyName.

        :param Name keyName: The name of the key.
        :return: The key bits.
        :rtype: Blob
        :raises Pib.Error: If the key does not exist.
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.getKeyBits is not implemented")

    def getKeysOfIdentity(self, identityName):
        """
        Get all the key names of the identity with the name identityName. The
        returned key names can be used to create a KeyContainer. With a key name
        and a backend implementation, one can create a Key front end instance.

        :param Name identityName: The name of the identity.
        :return: The set of key names. The Name objects are fresh copies. If the
          identity does not exist, return an empty set.
        :rtype: set of Name
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.getKeysOfIdentity is not implemented")

    def setDefaultKeyOfIdentity(self, identityName, keyName):
        """
        Set the key with keyName as the default key for the identity with name
        identityName.

        :param Name identityName: The name of the identity. This copies the name.
        :param Name keyName: The name of the key. This copies the name.
        :raises Pib.Error: If the key does not exist.
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.setDefaultKeyOfIdentity is not implemented")

    def getDefaultKeyOfIdentity(self, identityName):
        """
        Get the name of the default key for the identity with name identityName.

        :param Name identityName: The name of the identity.
        :return: The name of the default key, as a fresh copy.
        :rtype: Name
        :raises Pib.Error: If there is no default key or if the identity does
          not exist.
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.getDefaultKeyOfIdentity is not implemented")

    # Certificate management.

    def hasCertificate(self, certificateName):
        """
        Check for the existence of a certificate with name certificateName.

        :param Name certificateName: The name of the certificate.
        :return: True if the certificate exists, otherwise False.
        :rtype: bool
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.hasCertificate is not implemented")

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
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.addCertificate is not implemented")

    def removeCertificate(self, certificateName):
        """
        Remove the certificate with name certificateName. If the certificate
        does not exist, do nothing.

        :param Name certificateName: The name of the certificate.
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.removeCertificate is not implemented")

    def getCertificate(self, certificateName):
        """
        Get the certificate with name certificateName.

        :param Name certificateName: The name of the certificate.
        :return: A copy of the certificate.
        :rtype: CertificateV2
        :raises Pib.Error: If the certificate does not exist.
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.getCertificate is not implemented")

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
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.getCertificatesOfKey is not implemented")

    def setDefaultCertificateOfKey(self, keyName, certificateName):
        """
        Set the cert with name certificateName as the default for the key with
        keyName.

        :param Name keyName: The name of the key.
        :param Name certificateName: The name of the certificate. This copies
          the name.
        :raises Pib.Error: If the certificate with name certificateName does not
          exist.
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.setDefaultCertificateOfKey is not implemented")

    def getDefaultCertificateOfKey(self, keyName):
        """
        Get the default certificate for the key with eyName.

        :param Name keyName: The name of the key.
        :return: A copy of the default certificate.
        :rtype: CertificateV2
        :raises Pib.Error: If the default certificate does not exist.
        :raises PibImpl.Error: For a non-semantic (database access) error.
        """
        raise RuntimeError("PibImpl.getDefaultCertificateOfKey is not implemented")

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/key.cpp
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
This module defines the PibKey class which provides access to a key at the s
econd level in the PIB's Identity-Key-Certificate hierarchy. A PibKey object has
a Name (identity + "KEY" + keyId), and contains one or more CertificateV2
objects, one of which is set as the default certificate of this key. A
certificate can be directly accessed by getting a CertificateV2 object.
"""

from pyndn.name import Name
from pyndn.security.v2.certificate_v2 import CertificateV2

class PibKey(object):
    """
    Create a PibKey which uses the impl backend implementation. This constructor 
    should only be called by PibKeyContainer.

    :param PibKeyImpl impl: An object of a subclass of  PibKeyImpl.
    """
    def __init__(self, impl):
        self._impl = impl

    @staticmethod
    def constructKeyName(identityName, keyId):
        """
        Construct a key name based on the appropriate naming conventions.

        :param Name identityName: The name of the identity.
        :param Name.Component keyId: The key ID name component.
        :return: The constructed name as a new Name.
        :rtype: Name
        """
        keyName = Name(identityName)
        keyName.append(CertificateV2.KEY_COMPONENT).append(keyId)

        return keyName

    @staticmethod
    def isValidKeyName(keyName):
        """
        Check if keyName follows the naming conventions for a key name.

        :param Name keyName: The name of the key.
        :return: True if keyName follows the naming conventions, otherwise False.
        :rtype bool:
        """
        return (keyName.size() > CertificateV2.MIN_KEY_NAME_LENGTH and
                keyName.get(-CertificateV2.MIN_KEY_NAME_LENGTH).equals
                  (CertificateV2.KEY_COMPONENT))

    @staticmethod
    def extractIdentityFromKeyName(keyName):
        """
        Extract the identity namespace from keyName.

        :param Name keyName: The name of the key.
        :return: The identity name as a new Name.
        :rtype: Name
        """
        if not PibKey.isValidKeyName(keyName):
            raise ValueError("Key name `" + keyName.toUri() +
               "` does not follow the naming conventions")

        # Trim everything after and including "KEY".
        return keyName.getPrefix(-CertificateV2.MIN_KEY_NAME_LENGTH)

    def _addCertificate(self, certificate):
        """
        Add the certificate. If a certificate with the same name (without
        implicit digest) already exists, then overwrite the certificate. If no
        default certificate for the key has been set, then set the added
        certificate as default for the key. This should only be called by
        KeyChain.

        :param CertificateV2 certificate: The certificate to add. This copies
          the object.
        :raises ValueError: If the name of the certificate does not match the
          key name.
        """
        self._lockImpl().addCertificate(certificate)

    def _removeCertificate(self, certificateName):
        """
        Remove the certificate with name certificateName. If the certificate
        does not exist, do nothing. This should only be called by KeyChain.

        :param Name certificateName: The name of the certificate.
        :raises ValueError: If certificateName does not match the key name.
        """
        self._lockImpl().removeCertificate(certificateName)

    def _setDefaultCertificate(self, certificateName):
        """
        Set the existing certificate with name certificateName as the default
        certificate. This should only be called by KeyChain.

        :param Name certificateName: The name of the certificate.
        :return: The default certificate.
        :rtype: CertificateV2
        :raises ValueError: If certificateName does not match the key name.
        :raises Pib.Error: If the certificate does not exist.
        """
        return self._lockImpl().setDefaultCertificate(certificateName)

    def _lockImpl(self):
        """
        Check the validity of the _impl instance.

        :return: The PibKeyImpl when the instance is valid.
        :rtype: PibKeyImpl
        :raises ValueError: If the backend implementation instance is invalid.
        """
        if self._impl == None:
            raise ValueError("Invalid key instance")

        return self._impl

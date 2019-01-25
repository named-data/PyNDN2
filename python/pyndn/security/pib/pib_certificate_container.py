# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/pib/certificate-container.cpp
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
This modules defines the PibCertificateContainer class which is used to
search/enumerate the certificates of a key. (A PibCertificateContainer object
can only be created by PibKey.)
"""

from pyndn.name import Name
from pyndn.security.v2.certificate_v2 import CertificateV2

class PibCertificateContainer(object):
    """
    Create a PibCertificateContainer for a key with keyName. This constructor
    should only be called by PibKeyImpl.

    :param Name keyName: The name of the key, which is copied.
    :param PibImpl pibImpl: The PIB backend implementation.
    """
    def __init__(self,  keyName, pibImpl):
        # The cache of loaded certificates. certificateName => CertificateV2.
        self._certificates = {}
        self._keyName = Name(keyName)
        self._pibImpl = pibImpl

        if pibImpl == None:
            raise ValueError("The pibImpl is None")

        # A set of Name.
        self._certificateNames = self._pibImpl.getCertificatesOfKey(keyName)

    def size(self):
        """
        Get the number of certificates in the container.

        :return: The number of certificates.
        :rtype: int
        """
        return len(self._certificateNames)

    def add(self, certificate):
        """
        Add certificate into the container. If the certificate already exists,
        this replaces it.

        :param CertificateV2 certificate: The certificate to add. This copies
          the object.
        :raises ValueError: If the name of the certificate does not match the
          key name.
        """
        if not self._keyName.equals(certificate.getKeyName()):
            raise ValueError("The certificate name `" +
              certificate.getKeyName().toUri() + "` does not match the key name")

        certificateName = Name(certificate.getName())
        self._certificateNames.add(certificateName)
        # Copy the certificate.
        self._certificates[certificateName] = CertificateV2(certificate)
        self._pibImpl.addCertificate(certificate)

    def remove(self, certificateName):
        """
        Remove the certificate with name certificateName from the container. If
        the certificate does not exist, do nothing.

        :param Name certificateName: The name of the certificate.
        :raises ValueError: If certificateName does not match the key name.
        """
        if (not CertificateV2.isValidName(certificateName) or
            not CertificateV2.extractKeyNameFromCertName(certificateName).equals
              (self._keyName)):
            raise ValueError("Certificate name `" + certificateName.toUri() +
              "` is invalid or does not match key name")

        try:
            self._certificateNames.remove(certificateName)
        except KeyError:
            # Do nothing if it doesn't exist.
            pass

        try:
            del self._certificates[certificateName]
        except KeyError:
            # Do nothing if it doesn't exist.
            pass

        self._pibImpl.removeCertificate(certificateName)

    def get(self, certificateName):
        """
        Get the certificate with certificateName from the container.

        :param Name certificateName: The name of the certificate.
        :return: A copy of the certificate.
        :rtype: CertificateV2
        :raises ValueError: If certificateName does not match the key name
        :raises Pib.Error: If the certificate does not exist.
        """
        try:
            cachedCertificate = self._certificates[certificateName]
        except KeyError:
            cachedCertificate = None

        if cachedCertificate != None:
            # Make a copy.
            # TODO: Copy is expensive. Can we just tell the caller not to modify it?
            return CertificateV2(cachedCertificate)

        # Get from the PIB and cache.
        if (not CertificateV2.isValidName(certificateName) or
            not CertificateV2.extractKeyNameFromCertName(certificateName).equals
              (self._keyName)):
            raise ValueError("Certificate name `" + certificateName.toUri() +
               "` is invalid or does not match key name")

        certificate = self._pibImpl.getCertificate(certificateName)
        # Copy the certificate Name.
        self._certificates[Name(certificateName)] = certificate
        # Make a copy.
        # TODO: Copy is expensive. Can we just tell the caller not to modify it?
        return CertificateV2(certificate)

    def isConsistent(self):
        """
        Check if the container is consistent with the backend storage.

        :return: True if the container is consistent, False otherwise.
        :rtype: bool
        :note: This method is heavy-weight and should be used in a debugging
          mode only.
        """
        return (self._certificateNames ==
                self._pibImpl.getCertificatesOfKey(self._keyName))

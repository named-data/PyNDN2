# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/pib/detail/key-impl.cpp
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
This module defines the PibKeyImpl class which provides the backend
implementation for PibKey. A PibKey has only one backend instance, but may have
multiple frontend handles. Each frontend handle is associated with the only one
backend PibKeyImpl.
"""

from pyndn.name import Name
from pyndn.util.blob import Blob
from pyndn.security.certificate.public_key import PublicKey
from pyndn.security.pib.pib_certificate_container import PibCertificateContainer
from pyndn.security.pib.pib_key import PibKey
from pyndn.security.pib.pib import Pib

class PibKeyImpl(object):
    """
    The constructor has two forms:
    PibKeyImpl(keyName, keyEncoding, pibImpl) - Create a PibKeyImpl with
    keyName. If the key does not exist in the backend implementation, add it by
    creating it from the keyEncoding. If a key with keyName already exists,
    overwrite it.
    PibKeyImpl(keyName, pibImpl) - Create a PibKeyImpl with keyName. Initialize
    the cached key encoding with pibImpl.getKeyBits().

    :param Name keyName: The name of the key, which is copied.
    :param keyEncoding: The buffer of encoded key bytes, which is copied. (This
      is only used in the constructor form
      PibKeyImpl(keyName, keyEncoding, pibImpl) .)
    :type keyEncoding: an array which implements the buffer protocol
    :param PibImpl pibImpl: The Pib backend implementation.
    :raises Pib.Error: If the constructor is the form PibKeyImpl(keyName, pibImpl)
      (without the keyEncoding) and the key with keyName does not exist.
    """
    def __init__(self, keyName, arg2, arg3 = None):
        self._defaultCertificate = None

        if isinstance(arg2, PibImpl):
            # PibKeyImpl(keyName, pibImpl)
            pibImpl = arg2

            self._identityName = PibKey.extractIdentityFromKeyName(keyName)
            self._keyName = Name(keyName)
            self._certificates = PibCertificateContainer(keyName, pibImpl)
            self._pibImpl = pibImpl

            if pibImpl == None:
                raise ValueError("The pibImpl is None")

            self._keyEncoding = self._pibImpl.getKeyBits(self._keyName)

            try:
                publicKey = PublicKey(self._keyEncoding)
            except:
                # We don't expect this since we just fetched the encoding.
                raise Pib.Error("Error decoding public key")

            self._keyType = publicKey.getKeyType()
        else:
            # PibKeyImpl(keyName, keyEncoding, pibImpl)
            keyEncoding = arg2
            pibImpl = arg3

            self._identityName = PibKey.extractIdentityFromKeyName(keyName)
            self._keyName = Name(keyName)
            self._keyEncoding = Blob(keyEncoding, True)
            self._certificates = PibCertificateContainer(keyName, pibImpl)
            self._pibImpl = pibImpl

            if pibImpl == None:
                raise ValueError("The pibImpl is None")

            try:
                publicKey = PublicKey(self._keyEncoding)
                self._keyType = publicKey.getKeyType()
            except:
                raise ValueError("Invalid key encoding")

            self._pibImpl.addKey(self._identityName, self._keyName, keyEncoding)

    def getName(self):
        """
        Get the key name.

        :return: The key name. You must not change the object. If you need to
          change it, make a copy.
        :rtype: Name
        """
        return self._keyName

    def getIdentityName(self):
        """
        Get the name of the identity this key belongs to.

        :return: The name of the identity. You must not change the object. If
          you need to change it, make a copy.
        :rtype: Name
        """
        return self._identityName

    def getKeyType(self):
        """
        Get the key type.

        :return: The key type.
        :rtype: an int from the KeyType enum
        """
        return self._keyType

    def getPublicKey(self):
        """
        Get the public key encoding.

        :return: The public key encoding.
        :rtype: Blob
        """
        return self._keyEncoding

    def addCertificate(self, certificate):
        """
        Add the certificate. If a certificate with the same name (without
        implicit digest) already exists, then overwrite the certificate. If no
        default certificate for the key has been set, then set the added
        certificate as default for the key.

        :param CertificateV2 certificate: The certificate to add. This copies
          the object.
        :raises ValueError: If the name of the certificate does not match the
          key name.
        """
        # BOOST_ASSERT(self._certificates.isConsistent())
        self._certificates.add(certificate)

    def removeCertificate(self, certificateName):
        """
        Remove the certificate with name certificateName. If the certificate
        does not exist, do nothing.

        :param Name certificateName: The name of the certificate.
        :raises ValueError: If certificateName does not match the key name.
        """
        # BOOST_ASSERT(self._certificates.isConsistent())

        if (self._defaultCertificate != None and
            self._defaultCertificate.getName().equals(certificateName)):
            self._defaultCertificate = None

        self._certificates.remove(certificateName);

    def getCertificate(self, certificateName):
        """
        Get the certificate with name certificateName.

        :param Name certificateName: The name of the certificate.
        :return: A copy of the CertificateV2 object.
        :rtype: CertificateV2
        :raises ValueError: If certificateName does not match the key name.
        :raises Pib.Error: If the certificate does not exist.
        """
        # BOOST_ASSERT(self._certificates.isConsistent())
        return self._certificates.get(certificateName)

    def setDefaultCertificate(self, certificateOrCertificateName):
        """
        Set the existing certificate as the default certificate.

        :param certificateOrCertificateName: If certificateOrCertificateName is
          a Name, it is the name of the certificate, which must exist. Otherwise
          certificateOrCertificateName is the CertificateV2 to add (if
          necessary) and set as the default.
        :type certificateOrCertificateName: Name or CertificateV2
        :return: The default certificate.
        :rtype: CertificateV2
        :raises ValueError: If the certificate name does not match the key name.
        :raises Pib.Error: If certificateOrCertificateName is the
          certificate Name and the certificate does not exist.
        """
        # BOOST_ASSERT(self._certificates.isConsistent())

        if isinstance(certificateOrCertificateName, Name):
            certificateName = certificateOrCertificateName
        else:
            certificate = certificateOrCertificateName
            self.addCertificate(certificate)
            certificateName = certificate.getName()

        self._defaultCertificate = self._certificates.get(certificateName)
        self._pibImpl.setDefaultCertificateOfKey(self._keyName, certificateName)
        return self._defaultCertificate

    def getDefaultCertificate(self):
        """
        Get the default certificate for this Key.

        :return: The default certificate.
        :rtype: CertificateV2
        :raises Pib.Error: the default certificate does not exist.
        """
        # BOOST_ASSERT(self._certificates.isConsistent())

        if self._defaultCertificate == None:
            self._defaultCertificate = self._pibImpl.getDefaultCertificateOfKey(
              self._keyName)

        # BOOST_ASSERT(pibImpl_->getDefaultCertificateOfKey(keyName_)->wireEncode() == defaultCertificate_->wireEncode());

        return self._defaultCertificate

# Put this last to avoid an import loop.
from pyndn.security.pib.pib_impl import PibImpl

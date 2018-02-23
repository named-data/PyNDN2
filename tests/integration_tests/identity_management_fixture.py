# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx unit tests:
# https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/identity-management-fixture.cpp
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

from pyndn import Name
from pyndn.security import KeyChain
from pyndn.security.pib.pib import Pib
from pyndn.security.v2 import CertificateV2
from pyndn.security import SigningInfo
from pyndn import ValidityPeriod
from pyndn import ContentType
from pyndn.util.common import Common

class IdentityManagementFixture(object):
    def __init__(self):
        self._keyChain = KeyChain("pib-memory:", "tpm-memory:")
        self._identityNames = set()
        self._certificateFiles = set()

    def saveCertificateToFile(self, data, filePath):
        """
        :param Data data: The certificate to save.
        :param str filePath: The file path, which should be writable.
        :return: True if successful.
        :rtype: bool
        """
        self._certificateFiles.add(filePath)

        try:
            encoding = data.wireEncode()
            encodedCertificate = Common.base64Encode(encoding.toBytes(), True)

            with open(filePath, 'w') as keyFile:
                keyFile.write(encodedCertificate)

            return True
        except Exception:
            return False

    def addIdentity(self, identityName, params = None):
        """
        Add an identity for the identityName.

        :param Name identityName: The name of the identity.
        :param KeyParams params: (optional) The key parameters if a key needs to
          be generated for the identity. If omitted, use
          KeyChain.getDefaultKeyParams().
        :return: The created PibIdentity instance.
        :rtype: PibIdentity
        """
        if params == None:
            params = KeyChain.getDefaultKeyParams()

        identity = self._keyChain.createIdentityV2(identityName, params)
        self._identityNames.add(identityName)
        return identity

    def saveCertificate(identity, filePath):
        """
        Save the identity's certificate to a file.

        :param PibIdentity identity: The PibIdentity.
        :param str filePath: The file path, which should be writable.
        :return: True if successful.
        :rtype: str
        """
        try:
            certificate = identity.getDefaultKey().getDefaultCertificate()
            return self.saveCertificateToFile(certificate, filePath)
        except Pib.Error:
            return False

    def addSubCertificate(self, subIdentityName, issuer, params = None):
        """
        Issue a certificate for subIdentityName signed by issuer. If the
        identity does not exist, it is created. A new key is generated as the
        default key for the identity. A default certificate for the key is
        signed by the issuer using its default certificate.
        """
        if params == None:
            params = KeyChain.getDefaultKeyParams()

        subIdentity = self.addIdentity(subIdentityName, params)

        request = subIdentity.getDefaultKey().getDefaultCertificate()

        request.setName(request.getKeyName().append("parent").appendVersion(1))

        certificateParams = SigningInfo(issuer)
        # Validity period of 20 years.
        now = Common.getNowMilliseconds()
        certificateParams.setValidityPeriod(
          ValidityPeriod(now, now + 20 * 365 * 24 * 3600 * 1000.0))

        # Skip the AdditionalDescription.

        self._keyChain.sign(request, certificateParams)
        self._keyChain.setDefaultCertificate(subIdentity.getDefaultKey(), request)

        return subIdentity

    def addCertificate(self, key, issuerId):
        """
        Add a self-signed certificate made from the key and issuer ID.

        :param PibKey key: The key for the certificate.
        :param str issuerId: The issuer ID name component for the certificate
          name.
        :return: The new certificate.
        :rtype: CertificateV2
        """
        certificateName = Name(key.getName())
        certificateName.append(issuerId).appendVersion(3)
        certificate = CertificateV2()
        certificate.setName(certificateName)

        # Set the MetaInfo.
        certificate.getMetaInfo().setType(ContentType.KEY)
        # One hour.
        certificate.getMetaInfo().setFreshnessPeriod(3600 * 1000.0)

        # Set the content.
        certificate.setContent(key.getPublicKey())

        params = SigningInfo(key)
        # Validity period of 10 days.
        now = Common.getNowMilliseconds()
        params.setValidityPeriod(
          ValidityPeriod(now, now + 10 * 24 * 3600 * 1000.0))

        self._keyChain.sign(certificate, params)
        return certificate

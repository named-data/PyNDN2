# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx unit tests:
# https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/signing-info.t.cpp
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

import unittest as ut
from pyndn import Name
from pyndn.security.security_types import DigestAlgorithm
from pyndn.security import SigningInfo

class TestSigningInfo(ut.TestCase):
    def test_basic(self):
        identityName = Name("/my-identity")
        keyName = Name("/my-key")
        certificateName = Name("/my-cert")

        info = SigningInfo()

        self.assertEquals(SigningInfo.SignerType.NULL, info.getSignerType())
        self.assertTrue(Name().equals(info.getSignerName()))
        self.assertEquals(DigestAlgorithm.SHA256, info.getDigestAlgorithm())

        info.setSigningIdentity(identityName)
        self.assertEquals(SigningInfo.SignerType.ID, info.getSignerType())
        self.assertTrue(identityName.equals(info.getSignerName()))
        self.assertEquals(DigestAlgorithm.SHA256, info.getDigestAlgorithm())

        infoId = SigningInfo(SigningInfo.SignerType.ID, identityName)
        self.assertEquals(SigningInfo.SignerType.ID, infoId.getSignerType())
        self.assertTrue(identityName.equals(infoId.getSignerName()))
        self.assertEquals(DigestAlgorithm.SHA256, infoId.getDigestAlgorithm())

        info.setSigningKeyName(keyName)
        self.assertEquals(SigningInfo.SignerType.KEY, info.getSignerType())
        self.assertTrue(keyName.equals(info.getSignerName()))
        self.assertEquals(DigestAlgorithm.SHA256, info.getDigestAlgorithm())

        infoKey = SigningInfo(SigningInfo.SignerType.KEY, keyName)
        self.assertEquals(SigningInfo.SignerType.KEY, infoKey.getSignerType())
        self.assertTrue(keyName.equals(infoKey.getSignerName()))
        self.assertEquals(DigestAlgorithm.SHA256, infoKey.getDigestAlgorithm())

        info.setSigningCertificateName(certificateName)
        self.assertEquals(SigningInfo.SignerType.CERT, info.getSignerType())
        self.assertTrue(certificateName.equals(info.getSignerName()))
        self.assertEquals(DigestAlgorithm.SHA256, info.getDigestAlgorithm())

        infoCert = SigningInfo(SigningInfo.SignerType.CERT, certificateName)
        self.assertEquals(SigningInfo.SignerType.CERT, infoCert.getSignerType())
        self.assertTrue(certificateName.equals(infoCert.getSignerName()))
        self.assertEquals(DigestAlgorithm.SHA256, infoCert.getDigestAlgorithm())

        info.setSha256Signing()
        self.assertEquals(SigningInfo.SignerType.SHA256, info.getSignerType())
        self.assertTrue(Name().equals(info.getSignerName()))
        self.assertEquals(DigestAlgorithm.SHA256, info.getDigestAlgorithm())

        infoSha256 = SigningInfo(SigningInfo.SignerType.SHA256)
        self.assertEquals(SigningInfo.SignerType.SHA256, infoSha256.getSignerType())
        self.assertTrue(Name().equals(infoSha256.getSignerName()))
        self.assertEquals(DigestAlgorithm.SHA256, infoSha256.getDigestAlgorithm())

    def test_from_string(self):
        infoDefault = SigningInfo("")
        self.assertEquals(SigningInfo.SignerType.NULL, infoDefault.getSignerType())
        self.assertTrue(Name().equals(infoDefault.getSignerName()))
        self.assertEquals(DigestAlgorithm.SHA256, infoDefault.getDigestAlgorithm())

        infoId = SigningInfo("id:/my-identity")
        self.assertEquals(SigningInfo.SignerType.ID, infoId.getSignerType())
        self.assertTrue(Name("/my-identity").equals(infoId.getSignerName()))
        self.assertEquals(DigestAlgorithm.SHA256, infoId.getDigestAlgorithm())

        infoKey = SigningInfo("key:/my-key")
        self.assertEquals(SigningInfo.SignerType.KEY, infoKey.getSignerType())
        self.assertTrue(Name("/my-key").equals(infoKey.getSignerName()))
        self.assertEquals(DigestAlgorithm.SHA256, infoKey.getDigestAlgorithm())

        infoCert = SigningInfo("cert:/my-cert")
        self.assertEquals(SigningInfo.SignerType.CERT, infoCert.getSignerType())
        self.assertTrue(Name("/my-cert").equals(infoCert.getSignerName()))
        self.assertEquals(DigestAlgorithm.SHA256, infoCert.getDigestAlgorithm())

        infoSha = SigningInfo("id:/localhost/identity/digest-sha256")
        self.assertEquals(SigningInfo.SignerType.SHA256, infoSha.getSignerType())
        self.assertTrue(Name().equals(infoSha.getSignerName()))
        self.assertEquals(DigestAlgorithm.SHA256, infoSha.getDigestAlgorithm())

    def test_to_string(self):
        self.assertEquals("", str(SigningInfo()))

        self.assertEquals("id:/my-identity",
          str(SigningInfo(SigningInfo.SignerType.ID, Name("/my-identity"))))
        self.assertEquals("key:/my-key",
          str(SigningInfo(SigningInfo.SignerType.KEY, Name("/my-key"))))
        self.assertEquals("cert:/my-cert",
          str(SigningInfo(SigningInfo.SignerType.CERT, Name("/my-cert"))))
        self.assertEquals("id:/localhost/identity/digest-sha256",
          str(SigningInfo(SigningInfo.SignerType.SHA256)))

    def test_chaining(self):
        info = (SigningInfo()
          .setSigningIdentity(Name("/identity"))
          .setSigningKeyName(Name("/key/name"))
          .setSigningCertificateName(Name("/cert/name"))
          .setPibIdentity(None)
          .setPibKey(None)
          .setSha256Signing()
          .setDigestAlgorithm(DigestAlgorithm.SHA256))

        self.assertEquals("id:/localhost/identity/digest-sha256", str(info))

if __name__ == '__main__':
    ut.main(verbosity=2)

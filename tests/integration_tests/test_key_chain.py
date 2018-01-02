# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx unit tests:
# https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/v2/key-chain.t.cpp
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
from pyndn.security.pib.pib import Pib
from pyndn.security.v2 import CertificateV2
from pyndn.util.common import Common
from .identity_management_fixture import IdentityManagementFixture

class TestKeyChain(ut.TestCase):
    def setUp(self):
        self._fixture = IdentityManagementFixture()
        
    def test_management(self):
        identityName = Name("/test/id")
        identity2Name = Name("/test/id2")

        self.assertEqual(0, self._fixture._keyChain.getPib()._identities.size())
        try:
            self._fixture._keyChain.getPib().getDefaultIdentity()
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        # Create an identity.
        id = self._fixture._keyChain.createIdentityV2(identityName)
        self.assertTrue(id != None)
        self.assertTrue(identityName in
          self._fixture._keyChain.getPib()._identities._identities)

        # The first added identity becomes the default identity.
        try:
            self._fixture._keyChain.getPib().getDefaultIdentity()
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        # The default key of the added identity must exist.
        try:
            key = id.getDefaultKey()
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        # The default certificate of the default key must exist.
        try:
            key.getDefaultCertificate()
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        # Delete the key.
        key1Name = key.getName()
        try:
            id.getKey(key1Name)
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        self.assertEqual(1, id._getKeys().size())
        self._fixture._keyChain.deleteKey(id, key)
# TODO: Implement key validity.
#        # The key instance should not be valid anymore.
#        self.assertTrue(!key)

        try:
            id.getKey(key1Name)
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        self.assertEqual(0, id._getKeys().size())

        # Create another key.
        self._fixture._keyChain.createKey(id)
        # The added key becomes the default key.
        try:
            id.getDefaultKey()
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        key2 = id.getDefaultKey()
        self.assertTrue(key2 != None)
        self.assertTrue(not key2.getName().equals(key1Name))
        self.assertEqual(1, id._getKeys().size())
        try:
            key2.getDefaultCertificate()
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        # Create a third key.
        key3 = self._fixture._keyChain.createKey(id)
        self.assertTrue(not key3.getName().equals(key2.getName()))
        # The added key will not be the default key, because the default key already exists.
        self.assertTrue(id.getDefaultKey().getName().equals(key2.getName()))
        self.assertEqual(2, id._getKeys().size())
        try:
            key3.getDefaultCertificate()
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        # Delete the certificate.
        self.assertEqual(1, key3._getCertificates().size())
        key3Cert1 = list(key3._getCertificates()._certificates.values())[0]
        key3CertName = key3Cert1.getName()
        self._fixture._keyChain.deleteCertificate(key3, key3CertName)
        self.assertEqual(0, key3._getCertificates().size())
        try:
            key3.getDefaultCertificate()
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        # Add a certificate.
        self._fixture._keyChain.addCertificate(key3, key3Cert1)
        self.assertEqual(1, key3._getCertificates().size())
        try:
            key3.getDefaultCertificate()
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        # Overwriting the certificate should work.
        self._fixture._keyChain.addCertificate(key3, key3Cert1)
        self.assertEqual(1, key3._getCertificates().size())
        # Add another certificate.
        key3Cert2 = CertificateV2(key3Cert1)
        key3Cert2Name = Name(key3.getName())
        key3Cert2Name.append("Self")
        key3Cert2Name.appendVersion(1)
        key3Cert2.setName(key3Cert2Name)
        self._fixture._keyChain.addCertificate(key3, key3Cert2)
        self.assertEqual(2, key3._getCertificates().size())

        # Set the default certificate.
        self.assertTrue(key3.getDefaultCertificate().getName().equals(key3CertName))
        self._fixture._keyChain.setDefaultCertificate(key3, key3Cert2)
        self.assertTrue(key3.getDefaultCertificate().getName().equals(key3Cert2Name))

        # Set the default key.
        self.assertTrue(id.getDefaultKey().getName().equals(key2.getName()))
        self._fixture._keyChain.setDefaultKey(id, key3)
        self.assertTrue(id.getDefaultKey().getName().equals(key3.getName()))

        # Set the default identity.
        id2 = self._fixture._keyChain.createIdentityV2(identity2Name)
        self.assertTrue(self._fixture._keyChain.getPib().getDefaultIdentity().getName()
          .equals(id.getName()))
        self._fixture._keyChain.setDefaultIdentity(id2)
        self.assertTrue(self._fixture._keyChain.getPib().getDefaultIdentity().getName()
          .equals(id2.getName()))

        # Delete an identity.
        self._fixture._keyChain.deleteIdentity(id)
# TODO: Implement identity validity.
#        # The identity instance should not be valid anymore.
#        BOOST_CHECK(!id)
        try:
            self._fixture._keyChain.getPib().getIdentity(identityName)
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        self.assertTrue(not (identityName in
          self._fixture._keyChain.getPib()._identities._identities))

    def test_self_signed_cert_validity(self):
        certificate = (self._fixture.addIdentity
          (Name("/Security/V2/TestKeyChain/SelfSignedCertValidity"))
           .getDefaultKey().getDefaultCertificate())
        self.assertTrue(certificate.isValid())
        # Check 10 years from now.
        self.assertTrue(certificate.isValid
          (Common.getNowMilliseconds() + 10 * 365 * 24 * 3600 * 1000.0))
        # Check that notAfter is later than 10 years from now.
        self.assertTrue(certificate.getValidityPeriod().getNotAfter() >
          Common.getNowMilliseconds() + 10 * 365 * 24 * 3600 * 1000.0)

if __name__ == '__main__':
    ut.main(verbosity=2)

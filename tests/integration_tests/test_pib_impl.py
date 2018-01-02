# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx unit tests:
# https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/pib/pib-impl.t.cpp
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

import os
import unittest as ut
from pyndn.name import Name
from pyndn.security.pib.pib_memory import PibMemory
from pyndn.security.pib.pib_sqlite3 import PibSqlite3
from pyndn.security.pib.pib import Pib
from .pib_data_fixture import PibDataFixture

class PibMemoryFixture(PibDataFixture):
    def __init__(self):
        super(PibMemoryFixture, self).__init__()

        self._myPib = PibMemory()
        self.pib = self._myPib

class PibSqlite3Fixture(PibDataFixture):
    def __init__(self, databaseDirectoryPath, databaseFilename):
        super(PibSqlite3Fixture, self).__init__()

        self._myPib = PibSqlite3(databaseDirectoryPath, databaseFilename)
        self.pib = self._myPib

class TestPibImpl(ut.TestCase):
    def setUp(self):
        self.pibMemoryFixture = PibMemoryFixture()

        databaseDirectoryPath = os.path.abspath("policy_config")
        databaseFilename = "test-pib.db"
        self.databaseFilePath =  os.path.join(
          databaseDirectoryPath, databaseFilename)
        try:
            os.remove(self.databaseFilePath)
        except OSError:
            # no such file
            pass
        self.pibSqlite3Fixture = PibSqlite3Fixture(
          databaseDirectoryPath, databaseFilename)

        self.pibImpls = [None, None]
        self.pibImpls[0] = self.pibMemoryFixture
        self.pibImpls[1] = self.pibSqlite3Fixture

    def tearDown(self):
        try:
            os.remove(self.databaseFilePath)
        except OSError:
            pass

    def test_certificate_decoding(self):
        # Use pibMemoryFixture to test.
        fixture = self.pibMemoryFixture

        self.assertTrue(fixture.id1Key1Cert1.getPublicKey().equals
          (fixture.id1Key1Cert2.getPublicKey()))
        self.assertTrue(fixture.id1Key2Cert1.getPublicKey().equals
          (fixture.id1Key2Cert2.getPublicKey()))
        self.assertTrue(fixture.id2Key1Cert1.getPublicKey().equals
          (fixture.id2Key1Cert2.getPublicKey()))
        self.assertTrue(fixture.id2Key2Cert1.getPublicKey().equals
          (fixture.id2Key2Cert2.getPublicKey()))

        self.assertTrue(fixture.id1Key1Cert1.getPublicKey().equals(fixture.id1Key1))
        self.assertTrue(fixture.id1Key1Cert2.getPublicKey().equals(fixture.id1Key1))
        self.assertTrue(fixture.id1Key2Cert1.getPublicKey().equals(fixture.id1Key2))
        self.assertTrue(fixture.id1Key2Cert2.getPublicKey().equals(fixture.id1Key2))

        self.assertTrue(fixture.id2Key1Cert1.getPublicKey().equals(fixture.id2Key1))
        self.assertTrue(fixture.id2Key1Cert2.getPublicKey().equals(fixture.id2Key1))
        self.assertTrue(fixture.id2Key2Cert1.getPublicKey().equals(fixture.id2Key2))
        self.assertTrue(fixture.id2Key2Cert2.getPublicKey().equals(fixture.id2Key2))

        self.assertTrue(fixture.id1Key1Cert2.getIdentity().equals(fixture.id1))
        self.assertTrue(fixture.id1Key2Cert1.getIdentity().equals(fixture.id1))
        self.assertTrue(fixture.id1Key2Cert2.getIdentity().equals(fixture.id1))

        self.assertTrue(fixture.id2Key1Cert2.getIdentity().equals(fixture.id2))
        self.assertTrue(fixture.id2Key2Cert1.getIdentity().equals(fixture.id2))
        self.assertTrue(fixture.id2Key2Cert2.getIdentity().equals(fixture.id2))

        self.assertTrue(fixture.id1Key1Cert2.getKeyName().equals(fixture.id1Key1Name))
        self.assertTrue(fixture.id1Key2Cert2.getKeyName().equals(fixture.id1Key2Name))

        self.assertTrue(fixture.id2Key1Cert2.getKeyName().equals(fixture.id2Key1Name))
        self.assertTrue(fixture.id2Key2Cert2.getKeyName().equals(fixture.id2Key2Name))

    def test_tpm_locator(self):
        for fixture in self.pibImpls:
            pib = fixture.pib

            # Basic getting and setting
            try:
                pib.getTpmLocator()
            except Exception as ex:
                self.fail("Unexpected exception: " + str(ex))

            try:
                pib.setTpmLocator("tpmLocator")
            except Exception as ex:
                self.fail("Unexpected exception: " + str(ex))
            self.assertEqual(pib.getTpmLocator(), "tpmLocator")

            # Add a certificate, and do not change the TPM locator.
            pib.addCertificate(fixture.id1Key1Cert1)
            self.assertTrue(pib.hasIdentity(fixture.id1))
            self.assertTrue(pib.hasKey(fixture.id1Key1Name))
            self.assertTrue(pib.hasCertificate(fixture.id1Key1Cert1.getName()))

            # Set the TPM locator to the same value. Nothing should change.
            pib.setTpmLocator("tpmLocator")
            self.assertTrue(pib.hasIdentity(fixture.id1))
            self.assertTrue(pib.hasKey(fixture.id1Key1Name))
            self.assertTrue(pib.hasCertificate(fixture.id1Key1Cert1.getName()))

            # Change the TPM locator. (The contents of the PIB should not change.)
            pib.setTpmLocator("newTpmLocator")
            self.assertTrue(pib.hasIdentity(fixture.id1))
            self.assertTrue(pib.hasKey(fixture.id1Key1Name))
            self.assertTrue(pib.hasCertificate(fixture.id1Key1Cert1.getName()))

    def test_identity_management(self):
        for fixture in self.pibImpls:
            pib = fixture.pib

            # No default identity is set. This should throw an Error.
            try:
                pib.getDefaultIdentity()
                self.fail("Did not throw the expected exception")
            except Pib.Error:
                pass
            else:
                self.fail("Did not throw the expected exception")

            # Check for id1, which should not exist.
            self.assertEqual(False, pib.hasIdentity(fixture.id1))

            # Add id1, which should be the default.
            pib.addIdentity(fixture.id1)
            self.assertEqual(True, pib.hasIdentity(fixture.id1))
            try:
                pib.getDefaultIdentity()
            except Exception as ex:
                self.fail("Unexpected exception: " + str(ex))
            self.assertEqual(fixture.id1, pib.getDefaultIdentity())

            # Add id2, which should not be the default.
            pib.addIdentity(fixture.id2)
            self.assertEqual(True, pib.hasIdentity(fixture.id2))
            self.assertEqual(fixture.id1, pib.getDefaultIdentity())

            # Explicitly set id2 as the default.
            pib.setDefaultIdentity(fixture.id2)
            self.assertEqual(fixture.id2, pib.getDefaultIdentity())

            # Remove id2. The PIB should not have a default identity.
            pib.removeIdentity(fixture.id2)
            self.assertEqual(False, pib.hasIdentity(fixture.id2))
            try:
                pib.getDefaultIdentity()
                self.fail("Did not throw the expected exception")
            except Pib.Error:
                pass
            else:
                self.fail("Did not throw the expected exception")

            # Set id2 as the default. This should add id2 again.
            pib.setDefaultIdentity(fixture.id2)
            self.assertEqual(fixture.id2, pib.getDefaultIdentity())

            # Get all the identities, which should have id1 and id2.
            idNames = pib.getIdentities()
            self.assertEquals(2, len(idNames))
            self.assertTrue(fixture.id1 in idNames)
            self.assertTrue(fixture.id2 in idNames)

    def test_clear_identities(self):
        for fixture in self.pibImpls:
            pib = fixture.pib

            pib.setTpmLocator("tpmLocator")

            # Add id, key, and cert.
            pib.addCertificate(fixture.id1Key1Cert1)
            self.assertTrue(pib.hasIdentity(fixture.id1))
            self.assertTrue(pib.hasKey(fixture.id1Key1Name))
            self.assertTrue(pib.hasCertificate(fixture.id1Key1Cert1.getName()))

            # Clear identities.
            pib.clearIdentities()
            self.assertEquals(0, len(pib.getIdentities()))
            self.assertEquals(0, len(pib.getKeysOfIdentity(fixture.id1)))
            self.assertEquals(0, len(pib.getCertificatesOfKey(fixture.id1Key1Name)))
            self.assertEquals("tpmLocator", pib.getTpmLocator())

    def test_key_management(self):
        for fixture in self.pibImpls:
            pib = fixture.pib

            # There is no default setting. This should throw an Error.
            self.assertEquals(False, pib.hasIdentity(fixture.id2))
            try:
                pib.getDefaultKeyOfIdentity(fixture.id1)
                self.fail("Did not throw the expected exception")
            except Pib.Error:
                pass
            else:
                self.fail("Did not throw the expected exception")

            # Check for id1Key1, which should not exist. Neither should id1.
            self.assertEquals(False, pib.hasKey(fixture.id1Key1Name))
            self.assertEquals(False, pib.hasIdentity(fixture.id1))

            # Add id1Key1, which should be the default. id1 should be added implicitly.
            pib.addKey(fixture.id1, fixture.id1Key1Name, fixture.id1Key1.buf())
            self.assertEquals(True, pib.hasKey(fixture.id1Key1Name))
            self.assertEquals(True, pib.hasIdentity(fixture.id1))
            keyBits = pib.getKeyBits(fixture.id1Key1Name)
            self.assertTrue(keyBits.equals(fixture.id1Key1))
            try:
                pib.getDefaultKeyOfIdentity(fixture.id1)
            except Exception as ex:
                self.fail("Unexpected exception: " + str(ex))
            self.assertEquals(fixture.id1Key1Name,
                              pib.getDefaultKeyOfIdentity(fixture.id1))

            # Add id1Key2, which should not be the default.
            pib.addKey(fixture.id1, fixture.id1Key2Name, fixture.id1Key2.buf())
            self.assertEquals(True, pib.hasKey(fixture.id1Key2Name))
            self.assertEquals(fixture.id1Key1Name,
                              pib.getDefaultKeyOfIdentity(fixture.id1))

            # Explicitly Set id1Key2 as the default.
            pib.setDefaultKeyOfIdentity(fixture.id1, fixture.id1Key2Name)
            self.assertEquals(fixture.id1Key2Name,
                              pib.getDefaultKeyOfIdentity(fixture.id1))

            # Set a non-existing key as the default. This should throw an Error.
            try:
                pib.setDefaultKeyOfIdentity(fixture.id1, Name("/non-existing"))
                self.fail("Did not throw the expected exception")
            except Pib.Error:
                pass
            else:
                self.fail("Did not throw the expected exception")

            # Remove id1Key2. The PIB should not have a default key.
            pib.removeKey(fixture.id1Key2Name)
            self.assertEquals(False, pib.hasKey(fixture.id1Key2Name))
            try:
                pib.getKeyBits(fixture.id1Key2Name)
                self.fail("Did not throw the expected exception")
            except Pib.Error:
                pass
            else:
                self.fail("Did not throw the expected exception")

            try:
                pib.getDefaultKeyOfIdentity(fixture.id1)
                self.fail("Did not throw the expected exception")
            except Pib.Error:
                pass
            else:
                self.fail("Did not throw the expected exception")

            # Add id1Key2 back, which should be the default.
            pib.addKey(fixture.id1, fixture.id1Key2Name, fixture.id1Key2.buf())
            try:
                pib.getKeyBits(fixture.id1Key2Name)
            except Exception as ex:
                self.fail("Unexpected exception: " + str(ex))
            self.assertEquals(fixture.id1Key2Name,
                              pib.getDefaultKeyOfIdentity(fixture.id1))

            # Get all the keys, which should have id1Key1 and id1Key2.
            keyNames = pib.getKeysOfIdentity(fixture.id1)
            self.assertEquals(2, len(keyNames))
            self.assertTrue(fixture.id1Key1Name in keyNames)
            self.assertTrue(fixture.id1Key2Name in keyNames)

            # Remove id1, which should remove all the keys.
            pib.removeIdentity(fixture.id1)
            keyNames = pib.getKeysOfIdentity(fixture.id1)
            self.assertEquals(0, len(keyNames))

    def test_certificate_management(self):
        for fixture in self.pibImpls:
            pib = fixture.pib

            # There is no default setting. This should throw an Error.
            try:
                pib.getDefaultCertificateOfKey(fixture.id1Key1Name)
                self.fail("Did not throw the expected exception")
            except Pib.Error:
                pass
            else:
                self.fail("Did not throw the expected exception")

            # Check for id1Key1Cert1, which should not exist. Neither should
            #   id1 or id1Key1.
            self.assertEquals(False,
                              pib.hasCertificate(fixture.id1Key1Cert1.getName()))
            self.assertEquals(False, pib.hasIdentity(fixture.id1))
            self.assertEquals(False, pib.hasKey(fixture.id1Key1Name))

            # Add id1Key1Cert1, which should be the default.
            # id1 and id1Key1 should be added implicitly.
            pib.addCertificate(fixture.id1Key1Cert1)
            self.assertEquals(True,
                              pib.hasCertificate(fixture.id1Key1Cert1.getName()))
            self.assertEquals(True, pib.hasIdentity(fixture.id1))
            self.assertEquals(True, pib.hasKey(fixture.id1Key1Name))
            self.assertTrue(
              pib.getCertificate(fixture.id1Key1Cert1.getName()).wireEncode()
              .equals(fixture.id1Key1Cert1.wireEncode()))
            try:
                pib.getDefaultCertificateOfKey(fixture.id1Key1Name)
            except Exception as ex:
                self.fail("Unexpected exception: " + str(ex))
            # Use the wire encoding to check equivalence.
            self.assertTrue(fixture.id1Key1Cert1.wireEncode().equals
              (pib.getDefaultCertificateOfKey(fixture.id1Key1Name).wireEncode()))

            # Add id1Key1Cert2, which should not be the default.
            pib.addCertificate(fixture.id1Key1Cert2)
            self.assertEquals(True,
              pib.hasCertificate(fixture.id1Key1Cert2.getName()))
            self.assertTrue(fixture.id1Key1Cert1.wireEncode().equals
              (pib.getDefaultCertificateOfKey(fixture.id1Key1Name).wireEncode()))

            # Explicitly set id1Key1Cert2 as the default.
            pib.setDefaultCertificateOfKey(fixture.id1Key1Name,
              fixture.id1Key1Cert2.getName())
            self.assertTrue(fixture.id1Key1Cert2.wireEncode().equals
              (pib.getDefaultCertificateOfKey(fixture.id1Key1Name).wireEncode()))

            # Set a non-existing certificate as the default. This should throw an Error.
            try:
                pib.setDefaultCertificateOfKey(
                  fixture.id1Key1Name, Name("/non-existing"))
                self.fail("Did not throw the expected exception")
            except Pib.Error:
                pass
            else:
                self.fail("Did not throw the expected exception")

            # Remove id1Key1Cert2, which should not have a default certificate.
            pib.removeCertificate(fixture.id1Key1Cert2.getName())
            self.assertEquals(False,
              pib.hasCertificate(fixture.id1Key1Cert2.getName()))
            try:
                pib.getCertificate(fixture.id1Key1Cert2.getName())
                self.fail("Did not throw the expected exception")
            except Pib.Error:
                pass
            else:
                self.fail("Did not throw the expected exception")

            try:
                pib.getDefaultCertificateOfKey(fixture.id1Key1Name)
                self.fail("Did not throw the expected exception")
            except Pib.Error:
                pass
            else:
                self.fail("Did not throw the expected exception")

            # Add id1Key1Cert2, which should be the default.
            pib.addCertificate(fixture.id1Key1Cert2)
            try:
                pib.getCertificate(fixture.id1Key1Cert1.getName())
            except Exception as ex:
                self.fail("Unexpected exception: " + str(ex))
            self.assertTrue(fixture.id1Key1Cert2.wireEncode().equals
              (pib.getDefaultCertificateOfKey(fixture.id1Key1Name).wireEncode()))

            # Get all certificates, which should have id1Key1Cert1 and id1Key1Cert2.
            certNames = pib.getCertificatesOfKey(fixture.id1Key1Name)
            self.assertEquals(2, len(certNames))
            self.assertTrue(fixture.id1Key1Cert1.getName() in certNames)
            self.assertTrue(fixture.id1Key1Cert2.getName() in certNames)

            # Remove id1Key1, which should remove all the certificates.
            pib.removeKey(fixture.id1Key1Name)
            certNames = pib.getCertificatesOfKey(fixture.id1Key1Name)
            self.assertEquals(0, len(certNames))

    def test_defaults_management(self):
        for fixture in self.pibImpls:
            pib = fixture.pib

            pib.addIdentity(fixture.id1)
            self.assertEquals(fixture.id1, pib.getDefaultIdentity())

            pib.addIdentity(fixture.id2)
            self.assertEquals(fixture.id1, pib.getDefaultIdentity())

            pib.removeIdentity(fixture.id1)
            try:
                pib.getDefaultIdentity()
                self.fail("Did not throw the expected exception")
            except Pib.Error:
                pass
            else:
                self.fail("Did not throw the expected exception")

            pib.addKey(fixture.id2, fixture.id2Key1Name, fixture.id2Key1.buf())
            self.assertEquals(fixture.id2, pib.getDefaultIdentity())
            self.assertEquals(fixture.id2Key1Name,
              pib.getDefaultKeyOfIdentity(fixture.id2))

            pib.addKey(fixture.id2, fixture.id2Key2Name, fixture.id2Key2.buf())
            self.assertEquals(fixture.id2Key1Name,
              pib.getDefaultKeyOfIdentity(fixture.id2))

            pib.removeKey(fixture.id2Key1Name)
            try:
                pib.getDefaultKeyOfIdentity(fixture.id2)
                self.fail("Did not throw the expected exception")
            except Pib.Error:
                pass
            else:
                self.fail("Did not throw the expected exception")

            pib.addCertificate(fixture.id2Key2Cert1)
            self.assertEquals(fixture.id2Key2Name,
              pib.getDefaultKeyOfIdentity(fixture.id2))
            self.assertEquals(fixture.id2Key2Cert1.getName(),
              pib.getDefaultCertificateOfKey(fixture.id2Key2Name).getName())

            pib.addCertificate(fixture.id2Key2Cert2)
            self.assertEquals(fixture.id2Key2Cert1.getName(),
              pib.getDefaultCertificateOfKey(fixture.id2Key2Name).getName())

            pib.removeCertificate(fixture.id2Key2Cert2.getName())
            self.assertEquals(fixture.id2Key2Cert1.getName(),
              pib.getDefaultCertificateOfKey(fixture.id2Key2Name).getName())

    def test_overwrite(self):
        for fixture in self.pibImpls:
            pib = fixture.pib

            # Check for id1Key1, which should not exist.
            pib.removeIdentity(fixture.id1)
            self.assertEquals(False, pib.hasKey(fixture.id1Key1Name))

            # Add id1Key1.
            pib.addKey(fixture.id1, fixture.id1Key1Name, fixture.id1Key1.buf())
            self.assertEquals(True, pib.hasKey(fixture.id1Key1Name))
            keyBits = pib.getKeyBits(fixture.id1Key1Name)
            self.assertTrue(keyBits.equals(fixture.id1Key1))

            # To check overwrite, add a key with the same name.
            pib.addKey(fixture.id1, fixture.id1Key1Name, fixture.id1Key2.buf())
            keyBits2 = pib.getKeyBits(fixture.id1Key1Name)
            self.assertTrue(keyBits2.equals(fixture.id1Key2))

            # Check for id1Key1Cert1, which should not exist.
            pib.removeIdentity(fixture.id1)
            self.assertEquals(False,
              pib.hasCertificate(fixture.id1Key1Cert1.getName()))

            # Add id1Key1Cert1.
            pib.addKey(fixture.id1, fixture.id1Key1Name, fixture.id1Key1.buf())
            pib.addCertificate(fixture.id1Key1Cert1)
            self.assertEquals(True,
              pib.hasCertificate(fixture.id1Key1Cert1.getName()))

            cert = pib.getCertificate(fixture.id1Key1Cert1.getName())
            self.assertTrue(cert.wireEncode().equals
              (fixture.id1Key1Cert1.wireEncode()))

            # Create a fake certificate with the same name.
            cert2 = fixture.id1Key2Cert1
            cert2.setName(fixture.id1Key1Cert1.getName())
            cert2.setSignature(fixture.id1Key2Cert1.getSignature())
            pib.addCertificate(cert2)

            cert3 = pib.getCertificate(fixture.id1Key1Cert1.getName())
            self.assertTrue(cert3.wireEncode().equals(cert2.wireEncode()))

            # Check that both the key and certificate are overwritten.
            keyBits3 = pib.getKeyBits(fixture.id1Key1Name)
            self.assertTrue(keyBits3.equals(fixture.id1Key2))

if __name__ == '__main__':
    ut.main(verbosity=2)

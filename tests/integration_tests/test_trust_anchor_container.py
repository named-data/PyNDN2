# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx unit tests:
# https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/v2/trust-anchor-container.t.cpp
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
import os
import time
from pyndn import Name, Interest
from pyndn.security.v2.trust_anchor_container import TrustAnchorContainer
from pyndn.security.v2.static_trust_anchor_group import StaticTrustAnchorGroup
from pyndn.security.v2.certificate_v2 import CertificateV2
from .identity_management_fixture import IdentityManagementFixture

class TestTrustAnchorContainer(ut.TestCase):
    def setUp(self):
        self.anchorContainer = TrustAnchorContainer()
        self.fixture = IdentityManagementFixture()

        # Create a directory and prepare two certificates.
        self.certificateDirectoryPath = os.path.join(
          "policy_config", "test-cert-dir")
        if not os.path.exists(self.certificateDirectoryPath):
            os.makedirs(self.certificateDirectoryPath)

        self.certificatePath1 = os.path.join(
          self.certificateDirectoryPath, "trust-anchor-1.cert")
        self.certificatePath2 = os.path.join(
          self.certificateDirectoryPath, "trust-anchor-2.cert")

        self.identity1 = self.fixture.addIdentity(
          Name("/TestAnchorContainer/First"))
        self.certificate1 = self.identity1.getDefaultKey().getDefaultCertificate()
        self.fixture.saveCertificateToFile(self.certificate1, self.certificatePath1)

        self.identity2 = self.fixture.addIdentity(
          Name("/TestAnchorContainer/Second"))
        self.certificate2 = self.identity2.getDefaultKey().getDefaultCertificate()
        self.fixture.saveCertificateToFile(self.certificate2, self.certificatePath2)

    def tearDown(self):
        try:
            os.remove(self.certificatePath1)
        except OSError:
            pass

        try:
            os.remove(self.certificatePath2)
        except OSError:
            pass

    def test_insert(self):
        # Static
        self.anchorContainer.insert("group1", self.certificate1)
        self.assertTrue(self.anchorContainer.find(self.certificate1.getName()) != None)
        self.assertTrue(self.anchorContainer.find(self.identity1.getName()) != None)
        certificate = self.anchorContainer.find(self.certificate1.getName())
        try:
            # Re-inserting the same certificate should do nothing.
            self.anchorContainer.insert("group1", self.certificate1)
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        # It should still be the same instance of the certificate.
        self.assertTrue(certificate is
          self.anchorContainer.find(self.certificate1.getName()))
        # Cannot add a dynamic group when the static already exists.
        try:
            self.anchorContainer.insert("group1", self.certificatePath1, 400.0)
            self.fail("Did not throw the expected exception")
        except TrustAnchorContainer.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        self.assertTrue(1, self.anchorContainer.getGroup("group1").size())
        self.assertTrue(1, self.anchorContainer.size())

        # From file
        self.anchorContainer.insert("group2", self.certificatePath2, 400.0)
        self.assertTrue(self.anchorContainer.find(self.certificate2.getName()) != None)
        self.assertTrue(self.anchorContainer.find(self.identity2.getName()) != None)
        try:
            self.anchorContainer.insert("group2", self.certificate2)
            self.fail("Did not throw the expected exception")
        except TrustAnchorContainer.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        try:
            self.anchorContainer.insert("group2", self.certificatePath2, 400.0)
            self.fail("Did not throw the expected exception")
        except TrustAnchorContainer.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        self.assertTrue(1, self.anchorContainer.getGroup("group2").size())
        self.assertTrue(2, self.anchorContainer.size())

        try:
            os.remove(self.certificatePath2)
        except OSError:
            pass

        # Wait for the refresh period to expire.
        time.sleep(0.5)

        self.assertTrue(self.anchorContainer.find(self.identity2.getName()) == None)
        self.assertTrue(self.anchorContainer.find(self.certificate2.getName()) == None)
        self.assertEqual(0, self.anchorContainer.getGroup("group2").size())
        self.assertEqual(1, self.anchorContainer.size())

        staticGroup = self.anchorContainer.getGroup("group1")
        self.assertTrue(isinstance(staticGroup, StaticTrustAnchorGroup))
        self.assertEqual(1, staticGroup.size())
        staticGroup.remove(self.certificate1.getName())
        self.assertEqual(0, staticGroup.size())
        self.assertEqual(0, self.anchorContainer.size())

        try:
            self.anchorContainer.getGroup("non-existing-group")
            self.fail("Did not throw the expected exception")
        except TrustAnchorContainer.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

    def test_dynamic_anchor_from_directory(self):
        try:
            os.remove(self.certificatePath2)
        except OSError:
            pass

        self.anchorContainer.insert(
          "group", self.certificateDirectoryPath, 400.0, True)

        self.assertTrue(self.anchorContainer.find(self.identity1.getName()) != None)
        self.assertTrue(self.anchorContainer.find(self.identity2.getName()) == None)
        self.assertEqual(1, self.anchorContainer.getGroup("group").size())

        self.fixture.saveCertificateToFile(self.certificate2, self.certificatePath2)

        # Wait for the refresh period to expire. The dynamic anchors should remain.
        time.sleep(0.5)

        self.assertTrue(self.anchorContainer.find(self.identity1.getName()) != None)
        self.assertTrue(self.anchorContainer.find(self.identity2.getName()) != None)
        self.assertEqual(2, self.anchorContainer.getGroup("group").size())

        # Delete files from a previous test.
        allFiles = [f for f in os.listdir(self.certificateDirectoryPath)
          if os.path.isfile(os.path.join(self.certificateDirectoryPath, f))]
        for f in allFiles:
            try:
                os.remove(os.path.join(self.certificateDirectoryPath, f))
            except OSError:
                pass

        # Wait for the refresh period to expire. The dynamic anchors should be gone.
        time.sleep(0.5)

        self.assertTrue(self.anchorContainer.find(self.identity1.getName()) == None)
        self.assertTrue(self.anchorContainer.find(self.identity2.getName()) == None)
        self.assertEqual(0, self.anchorContainer.getGroup("group").size())

    def test_find_by_interest(self):
        self.anchorContainer.insert("group1", self.certificatePath1, 400.0)
        interest = Interest(self.identity1.getName())
        self.assertTrue(self.anchorContainer.find(interest) != None)
        interest1 = Interest(self.identity1.getName().getPrefix(-1))
        self.assertTrue(self.anchorContainer.find(interest1) != None)
        interest2 = Interest(Name(self.identity1.getName()).appendVersion(1))
        self.assertTrue(self.anchorContainer.find(interest2) == None)

        certificate3 = self.fixture.addCertificate(
          self.identity1.getDefaultKey(), "3")
        certificate4 = self.fixture.addCertificate(
          self.identity1.getDefaultKey(), "4")
        certificate5 = self.fixture.addCertificate(
          self.identity1.getDefaultKey(), "5")

        certificate3Copy = CertificateV2(certificate3)
        self.anchorContainer.insert("group2", certificate3Copy)
        self.anchorContainer.insert("group3", certificate4)
        self.anchorContainer.insert("group4", certificate5)

        interest3 = Interest(certificate3.getKeyName())
        foundCertificate = self.anchorContainer.find(interest3)
        self.assertTrue(foundCertificate != None)
        self.assertTrue(interest3.getName().isPrefixOf(foundCertificate.getName()))
        self.assertTrue(certificate3.getName().equals(foundCertificate.getName()))

        interest3.getExclude().appendComponent(
          certificate3.getName().get(CertificateV2.ISSUER_ID_OFFSET))
        foundCertificate = self.anchorContainer.find(interest3)
        self.assertTrue(foundCertificate != None)
        self.assertTrue(interest3.getName().isPrefixOf(foundCertificate.getName()))
        self.assertTrue(not foundCertificate.getName().equals(certificate3.getName()))

if __name__ == '__main__':
    ut.main(verbosity=2)

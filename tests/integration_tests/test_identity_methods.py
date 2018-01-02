# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2018 Regents of the University of California.
# Author: Adeola Bannis <thecodemaiden@gmail.com>
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

RSA_DER = b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuFoDcNtffwbfFix64fw0\
hI2tKMkFrc6Ex7yw0YLMK9vGE8lXOyBl/qXabow6RCz+GldmFN6E2Qhm1+AX3Zm5\
sj3H53/HPtzMefvMQ9X7U+lK8eNMWawpRzvBh4/36VrK/awlkNIVIQ9aXj6q6BVe\
zL+zWT/WYemLq/8A1/hHWiwCtfOH1xQhGqWHJzeSgwIgOOrzxTbRaCjhAb1u2TeV\
yx/I9H/DV+AqSHCaYbB92HDcDN0kqwSnUf5H1+osE9MR5DLBLhXdSiULSgxT3Or/\
y2QgsgUK59WrjhlVMPEiHHRs15NZJbL1uQFXjgScdEarohcY3dilqotineFZCeN8\
DwIDAQAB"

import time
import os
from pyndn.security import KeyChain, IdentityManager
from pyndn.security.security_types import KeyType
from pyndn.security.security_exception import SecurityException
from pyndn.security.identity import FilePrivateKeyStorage
from pyndn.security.identity import BasicIdentityStorage
from pyndn.security.certificate.identity_certificate import IdentityCertificate
from pyndn import Name
from pyndn.util import Blob
from pyndn.security.policy import SelfVerifyPolicyManager
import unittest as ut
import base64
import time

# use Python 3's mock library if it's available
try:
    from unittest.mock import Mock
except ImportError:
    from mock import Mock

class TestSqlIdentityStorage(ut.TestCase):
    def setUp(self):
        # Reuse the policy_config subdirectory for the temporary SQLite file.
        self.databaseFilePath = "policy_config/test-public-info.db"
        try:
            os.remove(self.databaseFilePath)
        except OSError:
            # no such file
            pass
        self.identityStorage = BasicIdentityStorage(self.databaseFilePath)

        self.identityManager = IdentityManager(self.identityStorage,
             FilePrivateKeyStorage())
        self.policyManager = SelfVerifyPolicyManager(self.identityStorage)
        self.keyChain = KeyChain(self.identityManager, self.policyManager)

    def tearDown(self):
        try:
            os.remove(self.databaseFilePath)
        except OSError:
            pass

    def test_identity_create_delete(self):
        identityName = Name('/TestIdentityStorage/Identity').appendVersion(
            int(time.time()))

        certificateName = self.keyChain.createIdentityAndCertificate(identityName)
        keyName = IdentityCertificate.certificateNameToPublicKeyName(certificateName)

        self.assertTrue(self.identityStorage.doesIdentityExist(identityName),
            "Identity was not added to IdentityStorage")
        self.assertIsNotNone(keyName, "New identity has no key")
        self.assertTrue(self.identityStorage.doesKeyExist(keyName),
            "Key was not added to IdentityStorage")
        self.assertIsNotNone(certificateName,
            "Certificate was not added to IdentityStorage")

        self.keyChain.deleteIdentity(identityName)
        self.assertFalse(self.identityStorage.doesIdentityExist(identityName),
            "Identity still in IdentityStorage after identity was deleted")
        self.assertFalse(self.identityStorage.doesKeyExist(keyName),
            "Key still in IdentityStorage after identity was deleted")
        self.assertFalse(self.identityStorage.doesCertificateExist(certificateName),
            "Certificate still in IdentityStorage after identity was deleted")

        with self.assertRaises(SecurityException):
            self.identityManager.getDefaultCertificateNameForIdentity(identityName)

    def test_key_create_delete(self):
        identityName = Name('/TestIdentityStorage/Identity').appendVersion(
            int(time.time()))

        keyName1 = self.keyChain.generateRSAKeyPair(identityName, True)
        self.keyChain.getIdentityManager().setDefaultKeyForIdentity(keyName1)

        keyName2 = self.keyChain.generateRSAKeyPair(identityName, False)
        self.assertEqual(self.identityManager.getDefaultKeyNameForIdentity(identityName),
            keyName1, "Default key name was changed without explicit request")
        self.assertNotEqual(self.identityManager.getDefaultKeyNameForIdentity(identityName),
            keyName2, "Newly created key replaced default key without explicit request")

        self.identityStorage.deletePublicKeyInfo(keyName2)

        self.assertFalse(self.identityStorage.doesKeyExist(keyName2))
        self.keyChain.deleteIdentity(identityName)

    def test_key_autocreate_identity(self):
        keyName1 = Name('/TestSqlIdentityStorage/KeyType/RSA/ksk-12345')
        identityName = keyName1[:-1]

        decodedKey = base64.b64decode(RSA_DER)
        self.identityStorage.addKey(keyName1, KeyType.RSA, Blob(decodedKey))
        self.identityStorage.setDefaultKeyNameForIdentity(keyName1)

        self.assertTrue(self.identityStorage.doesKeyExist(keyName1),
            "Key was not added")
        self.assertTrue(self.identityStorage.doesIdentityExist(identityName),
            "Identity for key was not automatically created")

        self.assertEqual(self.identityManager.getDefaultKeyNameForIdentity(identityName),
            keyName1, "Default key was not set on identity creation")

        with self.assertRaises(SecurityException):
            self.identityStorage.getDefaultCertificateNameForKey(keyName1)

        with self.assertRaises(SecurityException):
            # we have no private key for signing
            self.identityManager.selfSign(keyName1)

        with self.assertRaises(SecurityException):
            self.identityStorage.getDefaultCertificateNameForKey(keyName1)

        with self.assertRaises(SecurityException):
            self.identityManager.getDefaultCertificateNameForIdentity(identityName)

        keyName2 = self.identityManager.generateRSAKeyPairAsDefault(identityName)
        cert = self.identityManager.selfSign(keyName2)
        self.identityManager.addCertificateAsIdentityDefault(cert)

        certName1 = self.identityManager.getDefaultCertificateNameForIdentity(identityName)
        certName2 = self.identityStorage.getDefaultCertificateNameForKey(keyName2)

        self.assertEqual(certName1, certName2,
            "Key-certificate mapping and identity-certificate mapping are not consistent")

        self.keyChain.deleteIdentity(identityName)
        self.assertFalse(self.identityStorage.doesKeyExist(keyName1))

    def test_certificate_add_delete(self):
        identityName = Name('/TestIdentityStorage/Identity').appendVersion(
            int(time.time()))

        self.identityManager.createIdentityAndCertificate(
          identityName, KeyChain.getDefaultKeyParams())
        keyName1 = self.identityManager.getDefaultKeyNameForIdentity(identityName)
        cert2 = self.identityManager.selfSign(keyName1)
        self.identityStorage.addCertificate(cert2)
        certName2 = cert2.getName()

        certName1 = self.identityManager.getDefaultCertificateNameForIdentity(identityName)
        self.assertNotEqual(certName1, certName2,
            "New certificate was set as default without explicit request")

        self.identityStorage.deleteCertificateInfo(certName1)
        self.assertTrue(self.identityStorage.doesCertificateExist(certName2))
        self.assertFalse(self.identityStorage.doesCertificateExist(certName1))

        self.keyChain.deleteIdentity(identityName)
        self.assertFalse(self.identityStorage.doesCertificateExist(certName2))

    def test_stress(self):
        # ndn-cxx/tests/unit-tests/security/test-sec-public-info-sqlite3.cpp
        identityName = Name("/TestSecPublicInfoSqlite3/Delete").appendVersion(
            int(time.time()))

        # ndn-cxx returns the cert name, but the IndentityManager docstring
        # specifies a key
        certName1 = self.keyChain.createIdentityAndCertificate(identityName)
        keyName1 = IdentityCertificate.certificateNameToPublicKeyName(certName1)
        keyName2 = self.keyChain.generateRSAKeyPairAsDefault(identityName)

        cert2 = self.identityManager.selfSign(keyName2)
        certName2 = cert2.getName()
        self.identityManager.addCertificateAsDefault(cert2)

        keyName3 = self.keyChain.generateRSAKeyPairAsDefault(identityName)
        cert3 = self.identityManager.selfSign(keyName3)
        certName3 = cert3.getName()
        self.identityManager.addCertificateAsDefault(cert3)

        cert4 = self.identityManager.selfSign(keyName3)
        self.identityManager.addCertificateAsDefault(cert4)
        certName4 = cert4.getName()

        cert5 = self.identityManager.selfSign(keyName3)
        self.identityManager.addCertificateAsDefault(cert5)
        certName5 = cert5.getName()

        self.assertTrue(self.identityStorage.doesIdentityExist(identityName))
        self.assertTrue(self.identityStorage.doesKeyExist(keyName1))
        self.assertTrue(self.identityStorage.doesKeyExist(keyName2))
        self.assertTrue(self.identityStorage.doesKeyExist(keyName3))
        self.assertTrue(self.identityStorage.doesCertificateExist(certName1))
        self.assertTrue(self.identityStorage.doesCertificateExist(certName2))
        self.assertTrue(self.identityStorage.doesCertificateExist(certName3))
        self.assertTrue(self.identityStorage.doesCertificateExist(certName4))
        self.assertTrue(self.identityStorage.doesCertificateExist(certName5))

        self.identityStorage.deleteCertificateInfo(certName5)
        self.assertFalse(self.identityStorage.doesCertificateExist(certName5))
        self.assertTrue(self.identityStorage.doesCertificateExist(certName4))
        self.assertTrue(self.identityStorage.doesCertificateExist(certName3))
        self.assertTrue(self.identityStorage.doesKeyExist(keyName2))

        self.identityStorage.deletePublicKeyInfo(keyName3)
        self.assertFalse(self.identityStorage.doesCertificateExist(certName4))
        self.assertFalse(self.identityStorage.doesCertificateExist(certName3))
        self.assertFalse(self.identityStorage.doesKeyExist(keyName3))
        self.assertTrue(self.identityStorage.doesKeyExist(keyName2))
        self.assertTrue(self.identityStorage.doesKeyExist(keyName1))
        self.assertTrue(self.identityStorage.doesIdentityExist(identityName))

        self.keyChain.deleteIdentity(identityName)
        self.assertFalse(self.identityStorage.doesCertificateExist(certName2))
        self.assertFalse(self.identityStorage.doesKeyExist(keyName2))
        self.assertFalse(self.identityStorage.doesCertificateExist(certName1))
        self.assertFalse(self.identityStorage.doesKeyExist(keyName1))
        self.assertFalse(self.identityStorage.doesIdentityExist(identityName))

    def test_ecdsa_identity(self):
        identityName = Name("/TestSqlIdentityStorage/KeyType/ECDSA")
        keyName = self.identityManager.generateEcdsaKeyPairAsDefault(identityName)
        cert = self.identityManager.selfSign(keyName)
        self.identityManager.addCertificateAsIdentityDefault(cert)

        # Check the self-signature.
        failedCallback = Mock()
        verifiedCallback = Mock()
        self.keyChain.verifyData(cert, verifiedCallback, failedCallback)
        self.assertEqual(verifiedCallback.call_count, 1,
                         "Verification callback was not used.")

        self.keyChain.deleteIdentity(identityName)
        self.assertFalse(self.identityStorage.doesKeyExist(keyName))

if __name__ == '__main__':
    ut.main(verbosity=2)

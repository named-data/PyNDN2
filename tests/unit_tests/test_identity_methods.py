# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
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
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU General Public License is in the file COPYING.

RSA_DER = b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuFoDcNtffwbfFix64fw0\
hI2tKMkFrc6Ex7yw0YLMK9vGE8lXOyBl/qXabow6RCz+GldmFN6E2Qhm1+AX3Zm5\
sj3H53/HPtzMefvMQ9X7U+lK8eNMWawpRzvBh4/36VrK/awlkNIVIQ9aXj6q6BVe\
zL+zWT/WYemLq/8A1/hHWiwCtfOH1xQhGqWHJzeSgwIgOOrzxTbRaCjhAb1u2TeV\
yx/I9H/DV+AqSHCaYbB92HDcDN0kqwSnUf5H1+osE9MR5DLBLhXdSiULSgxT3Or/\
y2QgsgUK59WrjhlVMPEiHHRs15NZJbL1uQFXjgScdEarohcY3dilqotineFZCeN8\
DwIDAQAB"

from security_classes.test_identity_manager import TestIdentityManager 
from security_classes.test_identity_storage import TestIdentityStorage
from security_classes.test_private_key_storage import TestPrivateKeyStorage

from pyndn.security import KeyChain
from pyndn.security.security_types import KeyType
from pyndn.security.security_exception import SecurityException
from pyndn import Name, Data
from pyndn.util import Blob
from pyndn.security.policy import NoVerifyPolicyManager, SelfVerifyPolicyManager
from pyndn.security.certificate import IdentityCertificate
import unittest as ut

import base64

try:
    from unittest.mock import Mock 
except ImportError:
    from mock import Mock

import time

class TestSqlIdentityStorage(ut.TestCase):
    def setUp(self):
        self.identityStorage = TestIdentityStorage()
        self.identityManager = TestIdentityManager(self.identityStorage,
             TestPrivateKeyStorage())
        self.policyManager = SelfVerifyPolicyManager(self.identityStorage)
        self.keyChain = KeyChain(self.identityManager, self.policyManager)

        
    def test_identity_create_delete(self):
        identityName = Name('/TestIdentityStorage/Identity').appendVersion(
            int(time.time()))
        
        self.addCleanup(self.identityManager.deleteIdentity, identityName)
        keyName = self.keyChain.createIdentity(identityName)
        
        self.assertTrue(self.identityStorage.doesIdentityExist(identityName),
            "Identity was not added to IdentityStorage")
        self.assertIsNotNone(keyName, "New identity has no key")
        self.assertTrue(self.identityStorage.doesKeyExist(keyName), 
            "Key was not added to IdentityStorage")
        certificateName = self.identityManager.getDefaultCertificateNameForIdentity(
            identityName)
        self.assertIsNotNone(certificateName, 
            "Certificate was not added to IdentityStorage")

        self.identityManager.deleteIdentity(identityName)
        self.assertFalse(self.identityStorage.doesIdentityExist(identityName),
            "Identity still in IdentityStorage after revoking")
        self.assertFalse(self.identityStorage.doesKeyExist(keyName),
            "Key still in IdentityStorage after identity was deletedInfo")
        self.assertFalse(self.identityStorage.doesCertificateExist(certificateName),
            "Certificate still in IdentityStorage after identity was deletedInfo")

        with self.assertRaises(SecurityException):
            self.identityManager.getDefaultCertificateNameForIdentity(identityName)

    def test_key_create_delete(self):
        identityName = Name('/TestIdentityStorage/Identity').appendVersion(
            int(time.time()))
        self.addCleanup(self.identityManager.deleteIdentity, identityName)

        keyName1 = self.keyChain.generateRSAKeyPair(identityName, True)
        
        keyName2 = self.keyChain.generateRSAKeyPair(identityName, False)
        self.assertEqual(self.identityManager.getDefaultKeyNameForIdentity(identityName),
            keyName1, "Default key name was changed without explicit request")
        self.assertNotEqual(self.identityManager.getDefaultKeyNameForIdentity(identityName),
            keyName2, "Newly created key replaced default key without explicit request")

        self.identityStorage.deletePublicKeyInfo(keyName2)

        self.assertFalse(self.identityStorage.doesKeyExist(keyName2))
        self.identityManager.deleteIdentity(identityName)

    def test_key_autocreate_identity(self):
        keyName1 = Name('/TestSqlIdentityStorage/KeyType/RSA/ksk-12345')
        identityName = keyName1[:-1]
        self.addCleanup(self.identityManager.deleteIdentity, identityName)

        decodedKey = base64.b64decode(RSA_DER)
        self.identityStorage.addKey(keyName1, KeyType.RSA, Blob(decodedKey))
        
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

        self.identityManager.deleteIdentity(identityName)
        self.assertFalse(self.identityStorage.doesKeyExist(keyName1))

    def test_certificate_add_delete(self):
        identityName = Name('/TestIdentityStorage/Identity').appendVersion(
            int(time.time()))
        self.addCleanup(self.identityManager.deleteIdentity, identityName)
    
        self.identityManager.createIdentity(identityName)
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

        self.identityManager.deleteIdentity(identityName)
        self.assertFalse(self.identityStorage.doesCertificateExist(certName2))
    def test_stress(self):
        # ndn-cxx/tests/unit-tests/security/test-sec-public-info-sqlite3.cpp
        identityName = Name("/TestSecPublicInfoSqlite3/Delete").appendVersion(
            int(time.time()))
        
        self.addCleanup(self.identityManager.deleteIdentity, identityName)
        # ndn-cxx returns the cert name, but the IndentityManager docstring
        # specifies a key
        keyName1 = self.keyChain.createIdentity(identityName)
        certName1 = self.identityStorage.getDefaultCertificateNameForKey(keyName1)
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

        self.identityManager.deleteIdentity(identityName)
        self.assertFalse(self.identityStorage.doesCertificateExist(certName2))
        self.assertFalse(self.identityStorage.doesKeyExist(keyName2))
        self.assertFalse(self.identityStorage.doesCertificateExist(certName1))
        self.assertFalse(self.identityStorage.doesKeyExist(keyName1))
        self.assertFalse(self.identityStorage.doesIdentityExist(identityName))
        

if __name__ == '__main__':
    ut.main(verbosity=2)

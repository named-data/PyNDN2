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

from security_classes.test_identity_manager import TestIdentityManager 
from security_classes.test_identity_storage import TestIdentityStorage
from security_classes.test_private_key_storage import TestPrivateKeyStorage

from pyndn.security import KeyChain
from pyndn.security.certificate import IdentityCertificate
from pyndn.util import Blob
from pyndn import Name, Data, Interest, Face
from pyndn import Sha256WithRsaSignature
from pyndn.security.policy import NoVerifyPolicyManager, SelfVerifyPolicyManager, ConfigPolicyManager
import unittest as ut
import time
import os
from base64 import b64decode, b64encode
from collections import namedtuple

CERT_DUMP="Bv0C4AcxCAR0ZW1wCANLRVkIEWtzay0xNDE0MTk1Nzc5NjY1CAdJRC1DRVJUCAgA\
           AAFJRKMe3BQDGAECFf0BcDCCAWwwIhgPMjAxNDEwMjUwMDA5NDFaGA8yMDM0MTAy\
           MDAwMDk0MVowIDAeBgNVBCkTFy90ZW1wL2tzay0xNDE0MTk1Nzc5NjY1MIIBIjAN\
           BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA58yUcdGPsYx/+ZRwbrfdqeNyCIgJ\
           bZ7tsV3XC4awJEOwWsEp6KWcihAdfUfFGOvB+q4IAbg0GrpuRlD7/RjMMfOVrOj5\
           BmWvpW5unHUIZ4DNGsICH6f/e4DUvcCwxbXpJmtHRit2Pllep/4M62YZLKlaqQAJ\
           kfXseVEzKSIBmeHu5fPBGNizFoZTG2mocAya5grWzMX5boBjHddAGXC5VswviAHM\
           XcOUDre0+8Rg4BGl0Yt4DGuD2LcfijxCTGRJrT9M0ENKbxj8AMB6Grner0xN6thJ\
           LW4VLHBVkOTrjx/4USImgw9xQd0m+CshY+R6HXVDSGQ0ckno9MNWOZPjHQIDAQAB\
           Fi4bAQEcKQcnCAR0ZW1wCANLRVkIEWtzay0xNDE0MTk1Nzc5NjY1CAdJRC1DRVJU\
           F/0BADWC/f623e3XZSQe5sLHKlHMa1eWmvaBmQrVLa1BvhyVdjbdujXSh2cMv9Wi\
           qtVgALftzQpuhRA6wYX9PgP3A+0uGjjljKijuKDOWPPZodtWJqzDSt0UX4WU4hT5\
           is4g4VdZ/aRc8x/z17QmUOdrN6yidLGKzx814JDy+npqZVXYYkcLgUu6o+3rddId\
           DCp8sT/zjjGORj04Gh6qCp0QBEfNmZke8aI4DGor83AL5b9eDvWv3TtMNRzrWcF7\
           NgvRyxKNDIXJZym0qpHQQVjdQJezWNxf82swBV2S7nbJCI4djOwbRTnRFuwi4vHs\
           BmWVlUfyAg8noGdPRS8MGQs24vw="

try:
    from unittest.mock import Mock 
except ImportError:
    from mock import Mock

VerificationResult = namedtuple('VerificationResult', 
        'successCount failureCount hasFurtherSteps')
def doVerify(policyMan, toVerify):
    success = Mock()
    failure = Mock()
    result = policyMan.checkVerificationPolicy(toVerify, 0, success, failure)

    # a result of None means no more steps
    return VerificationResult(success.call_count, 
            failure.call_count, result is not None)

class TestSimplePolicyManager(ut.TestCase):
    def test_no_verify(self):
        identityStorage = TestIdentityStorage()
        identityManager = TestIdentityManager(identityStorage, TestPrivateKeyStorage())

        policyManager = NoVerifyPolicyManager()
        identityName = Name('TestValidator/Null').appendVersion(int(time.time()))
        
        self.addCleanup(identityStorage.deleteIdentityInfo ,identityName)

        keyChain = KeyChain(identityManager, policyManager)
        keyChain.createIdentity(identityName)
        data = Data(Name(identityName).append('data'))
        keyChain.signByIdentity(data, identityName)

        vr = doVerify(policyManager, data)

        self.assertFalse(vr.hasFurtherSteps, 
                "NoVerifyPolicyManager returned a ValidationRequest")

        self.assertEqual(vr.failureCount, 0, 
            "Verification failed with NoVerifyPolicyManager")
        self.assertEqual(vr.successCount, 1, 
            "Verification callback called {} times instead of 1".format( 
            vr.successCount))

    def test_self_verification(self):
        identityStorage = TestIdentityStorage()
        identityManager = TestIdentityManager(identityStorage, TestPrivateKeyStorage())
        policyManager = SelfVerifyPolicyManager(identityStorage)
        keyChain = KeyChain(identityManager, policyManager)
        
        identityName  = Name('TestValidator/RsaSignatureVerification')
        self.addCleanup(identityStorage.deleteIdentityInfo, identityName)
        keyChain.createIdentity(identityName)

        data = Data(Name('/TestData/1'))
        keyChain.signByIdentity(data, identityName)

        vr = doVerify(policyManager, data)
        
        self.assertFalse(vr.hasFurtherSteps, 
                "SelfVerifyPolicyManager returned a ValidationRequest")
        self.assertEqual(vr.failureCount, 0, 
            "Verification of identity-signed data failed")
        self.assertEqual(vr.successCount, 1,
            "Verification callback called {} times instead of 1".format(
            vr.successCount))

        data2 = Data(Name('/TestData/2'))

        vr = doVerify(policyManager, 
                data2)
        
        self.assertFalse(vr.hasFurtherSteps, 
                "SelfVerifyPolicyManager returned a ValidationRequest")
        self.assertEqual(vr.successCount, 0,
            "Verification of unsigned data succeeded")
        self.assertEqual(vr.failureCount, 1, 
            "Verification failure callback called {} times instead of 1".format(
            vr.failureCount))

class TestConfigPolicyManager(ut.TestCase):
    def setUp(self):
        testCertDirectory = 'policy_config/certs'
        self.testCertFile = os.path.join(testCertDirectory, 'test.cert')
        try:
            os.mkdir(testCertDirectory)
        except OSError:
            # already exists
            pass

        self.identityStorage = TestIdentityStorage()
        self.identityManager = TestIdentityManager(self.identityStorage,
                TestPrivateKeyStorage())
        self.policyManager = ConfigPolicyManager(self.identityStorage, 
                'policy_config/simple_rules.conf')

        self.identityName = Name('/TestConfigPolicyManager').appendVersion(
                int(time.time()))

        self.keyChain = KeyChain(self.identityManager, self.policyManager)
        self.keyChain.createIdentity(self.identityName)

        self.face = Face()

    def tearDown(self):
        self.identityStorage.deleteIdentityInfo(self.identityName)
        self.face.shutdown()

    def test_interest_timestamp(self):
        interestName = Name('/ndn/ucla/edu/something')
        certName = self.identityManager.getDefaultCertificateNameForIdentity(
                self.identityName)
        self.face.setCommandSigningInfo(self.keyChain, certName)
        
        oldInterest = Interest(interestName)
        self.face.makeCommandInterest(oldInterest)

        time.sleep(0.1) # make sure timestamps are different
        newInterest = Interest(interestName)
        self.face.makeCommandInterest(newInterest)

        vr  = doVerify(self.policyManager,
                newInterest)

        self.assertFalse(vr.hasFurtherSteps,
                "ConfigPolicyManager returned ValidationRequest but certificate is known")
        self.assertEqual(vr.failureCount, 0,
                "Verification of valid interest failed")
        self.assertEqual(vr.successCount, 1,
                "Verification callback called {} times instead of 1".format(
                      vr.successCount))

        vr  = doVerify(self.policyManager,
                oldInterest)

        self.assertFalse(vr.hasFurtherSteps,
                "ConfigPolicyManager returned ValidationRequest but certificate is known")
        self.assertEqual(vr.successCount, 0,
                "Verification of stale interest succeeded")
        self.assertEqual(vr.failureCount, 1,
                "Failure callback called {} times instead of 1".format(
                      vr.failureCount))

    def _removeFile(self, filename):
        try:
            os.remove(filename)
        except OSError:
            # no such file
            pass

    def test_refresh_10s(self):
        with open('policy_config/testData', 'r') as dataFile:
            encodedData = dataFile.read()
            data = Data()
            dataBlob = Blob(b64decode(encodedData))
            data.wireDecode(dataBlob)

        # needed, since the KeyChain will express interests in unknown 
        # certificates
        vr = doVerify(self.policyManager, data)

        self.assertTrue(vr.hasFurtherSteps, 
                "ConfigPolicyManager did not create ValidationRequest for unknown certificate")
        self.assertEqual(vr.successCount, 0,
                "ConfigPolicyManager called success callback with pending ValidationRequest")
        self.assertEqual(vr.failureCount, 0,
                "ConfigPolicyManager called failure callback with pending ValidationRequest")

        # now save the cert data to our anchor directory, and wait
        # we have to sign it with the current identity or the 
        # policy manager will create an interest for the signing certificate

        self.addCleanup(self._removeFile, self.testCertFile)
        self.addCleanup(self.identityStorage.deleteIdentityInfo, Name('/temp'))
        with open(self.testCertFile, 'w') as certFile:
            cert = IdentityCertificate()
            certData = b64decode(CERT_DUMP)
            cert.wireDecode(Blob(certData, False))
            self.keyChain.signByIdentity(cert, self.identityName)
            encodedCert = b64encode(str(cert.wireEncode()))
            certFile.write(encodedCert)

        # still too early for refresh to pick it up
        vr = doVerify(self.policyManager, data)

        self.assertTrue(vr.hasFurtherSteps, 
                "ConfigPolicyManager refresh occured sooner than specified")
        self.assertEqual(vr.successCount, 0,
                "ConfigPolicyManager called success callback with pending ValidationRequest")
        self.assertEqual(vr.failureCount, 0,
                "ConfigPolicyManager called failure callback with pending ValidationRequest")
        time.sleep(6)

        # now we should find it
        vr  = doVerify(self.policyManager, data)

        self.assertFalse(vr.hasFurtherSteps,
                "ConfigPolicyManager did not refresh certificate store")
        self.assertEqual(vr.successCount, 1,
                "Failure callback called {} times instead of 1".format(
                    vr.successCount))
        self.assertEqual(vr.failureCount, 0,
                "ConfigPolicyManager did not verify valid signed data")

if __name__ == '__main__':
    ut.main(verbosity=2)

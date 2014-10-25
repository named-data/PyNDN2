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
from pyndn.util import Blob
from pyndn import Name, Data, Interest, Face
from pyndn import Sha256WithRsaSignature
from pyndn.security.policy import NoVerifyPolicyManager, SelfVerifyPolicyManager, ConfigPolicyManager
import unittest as ut
import time
import os
from base64 import b64decode

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

def doVerify(method, toVerify):
    success = Mock()
    failure = Mock()
    method(toVerify, success, failure)
    return (success.call_count, failure.call_count)

class TestSimplePolicyManager(ut.TestCase):
    def test_no_verify(self):
        identityStorage = TestIdentityStorage()
        identityManager = TestIdentityManager(identityStorage, TestPrivateKeyStorage())

        policyManager = NoVerifyPolicyManager()
        identityName = Name('TestValidator/Null').appendVersion(int(time.time()))
        
        self.addCleanup(identityStorage.revokeIdentity ,identityName)

        keyChain = KeyChain(identityManager, policyManager)
        keyChain.createIdentity(identityName)
        data = Data(Name(identityName).append('data'))
        keyChain.signByIdentity(data, identityName)

        (success_count, fail_count) = doVerify(keyChain.verifyData, data)

        self.assertEqual(fail_count, 0, 
            "Verification failed with NoVerifyPolicyManager")
        self.assertEqual(success_count, 1, 
            "Verification callback called {} times instead of 1".format( 
            success_count))

    def test_self_verification(self):
        identityStorage = TestIdentityStorage()
        identityManager = TestIdentityManager(identityStorage, TestPrivateKeyStorage())
        policyManager = SelfVerifyPolicyManager(identityStorage)
        keyChain = KeyChain(identityManager, policyManager)
        
        identityName  = Name('TestValidator/RsaSignatureVerification')
        self.addCleanup(identityStorage.revokeIdentity, identityName)
        keyChain.createIdentity(identityName)

        data = Data(Name('/TestData/1'))
        keyChain.signByIdentity(data, identityName)

        (success_count, fail_count) = doVerify(keyChain.verifyData, data)
        
        self.assertEqual(fail_count, 0, 
            "Verification of identity-signed data failed")
        self.assertEqual(success_count, 1,
            "Verification callback called {} times instead of 1".format(
            success_count))

        data2 = Data(Name('/TestData/2'))

        (success_count, fail_count) = doVerify(keyChain.verifyData, 
                data2)
        
        self.assertEqual(success_count, 0,
            "Verification of unsigned data succeeded")
        self.assertEqual(fail_count, 1, 
            "Verification failure callback called {} times instead of 1".format(
            fail_count))

class TestConfigPolicyManager(ut.TestCase):
    def setUp(self):
        self.identityStorage = TestIdentityStorage()
        self.identityManager = TestIdentityManager(self.identityStorage,
                TestPrivateKeyStorage())
        self.policyManager = ConfigPolicyManager(self.identityStorage, 
                'policy_config/simple_rules.conf')

        self.identityName = Name('/TestConfigPolicyManager').appendVersion(
                int(time.time()))

        self.keyChain = KeyChain(self.identityManager, self.policyManager)
        self.keyChain.createIdentity(self.identityName)

    def tearDown(self):
        self.identityStorage.revokeIdentity(self.identityName)

    def test_interest_timestamp(self):
        interestName = Name('/ndn/ucla/edu/something')
        f = Face()
        certName = self.identityManager.getDefaultCertificateNameForIdentity(
                self.identityName)
        f.setCommandSigningInfo(self.keyChain, certName)
        self.addCleanup(f.shutdown)
        
        oldInterest = Interest(interestName)
        f.makeCommandInterest(oldInterest)

        time.sleep(0.1) # make sure timestamps are different
        newInterest = Interest(interestName)
        f.makeCommandInterest(newInterest)

        (success_count, fail_count) = doVerify(self.keyChain.verifyInterest,
                newInterest)

        self.assertEqual(fail_count, 0,
                "Verification of valid interest failed")
        self.assertEqual(success_count, 1,
                "Verification callback called {} times instead of 1".format(
                      success_count))

        (success_count, fail_count) = doVerify(self.keyChain.verifyInterest,
                oldInterest)

        self.assertEqual(success_count, 0,
                "Verification of stale interest succeeded")
        self.assertEqual(fail_count, 1,
                "Failure callback called {} times instead of 1".format(
                      fail_count))

    def _removeFile(self, filename):
        import pdb; pdb.set_trace()
        try:
            os.remove(filename)
        except OSError:
            pass

    def test_refresh_10s(self):
        with open('policy_config/testData', 'r') as dataFile:
            encodedData = dataFile.read()
            data = Data()
            dataBlob = Blob(b64decode(encodedData))
            data.wireDecode(dataBlob)

        (success_count, fail_count) = doVerify(self.keyChain.verifyData, data)

        self.assertEqual(success_count, 0,
                "Verification with unknown identity succeeded")
        self.assertEqual(fail_count, 1,
                "Failure callback called {} times instead of 1".format(
                      fail_count))

        # now save the cert data to our anchor directory, and wait
        testCertFile = 'policy_config/certs/test.cert'
        self.addCleanup(self._removeFile, testCertFile)
        with open(testCertFile, 'w') as certFile:
            certFile.write(CERT_DUMP)

        # still too early for refresh to pick it up
        (success_count, fail_count) = doVerify(self.keyChain.verifyData, data)

        self.assertEqual(success_count, 0,
                "Certificate store refreshed too soon")
        self.assertEqual(fail_count, 1,
                "Failure callback called {} times instead of 1".format(
                      fail_count))
        time.sleep(6)

        # now we should find it
        (success_count, fail_count) = doVerify(self.keyChain.verifyData, data)

        self.assertEqual(fail_count, 0,
                "Certificate store was not refreshed")
        self.assertEqual(success_count, 1,
                "Verification callback called {} times instead of 1".format(
                      success_count))

        
if __name__ == '__main__':
    ut.main(verbosity=2)

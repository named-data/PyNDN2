# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx unit tests:
# https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/validation-policy-command-interest.t.cpp
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
from pyndn import Name, Interest, Data, Sha256WithRsaSignature
from pyndn import KeyLocator, KeyLocatorType
from pyndn.util import Blob
from pyndn.encoding import TlvWireFormat
from pyndn.security import SigningInfo, CommandInterestSigner
from pyndn.security.v2 import ValidationPolicyCommandInterest
from pyndn.security.v2 import ValidationPolicySimpleHierarchy
from .hierarchical_validator_fixture import HierarchicalValidatorFixture

class ValidationPolicyCommandInterestFixture(HierarchicalValidatorFixture):
    """
    :param ValidationPolicyCommandInterest.Options options: (optional)
    """
    def __init__(self, options = None):
        super(ValidationPolicyCommandInterestFixture, self).__init__(
          ValidationPolicyCommandInterest(
            ValidationPolicySimpleHierarchy(), options))

        self._signer = CommandInterestSigner(self._keyChain)

    def makeCommandInterest(self, identity):
        """
        :param PibIdentity identity:
        :rtype: Interest
        """
        return self._signer.makeCommandInterest(
          Name(identity.getName()).append("CMD"), SigningInfo(identity))

    def setNowOffsetMilliseconds(self, nowOffsetMilliseconds):
        """
        Set the offset for the validation policy and signer.

        :param float nowOffsetMilliseconds: The offset in milliseconds.
        """
        self._validator.getPolicy()._setNowOffsetMilliseconds(nowOffsetMilliseconds)
        self._validator._setCacheNowOffsetMilliseconds(nowOffsetMilliseconds)
        self._signer._setNowOffsetMilliseconds(nowOffsetMilliseconds)

def setNameComponent(interest, index, component):
    """
    :param Interest interest:
    :param int index:
    :param component:
    :type component: Blob or Name.Component or value for Blob constructor
    """
    name = interest.getName().getPrefix(index)
    name.append(Name.Component(component))
    name.append(interest.getName().getSubName(name.size()))
    interest.setName(name)

class TestValidationPolicyCommandInterest(ut.TestCase):
    def setUp(self):
        self._fixture = ValidationPolicyCommandInterestFixture()

    def validateExpectSuccess(self, dataOrInterest, message):
        """
        Call _fixture._validator.validate and if it calls the failureCallback
        then fail the test with the given message.

        :param dataOrInterest: The Data or Interest to validate.
        :type dataOrInterest: Data or Interest
        :param str message: The message to show if the test fails.
        """
        successCount = [0]
        failureCount = [0]
        def successCallback(dataOrInterest):
            successCount[0] += 1
        def failureCallback(dataOrInterest, error):
            failureCount[0] += 1

        self._fixture._validator.validate(
          dataOrInterest, successCallback, failureCallback)
        self.assertTrue(failureCount[0] == 0, message)

    def validateExpectFailure(self, dataOrInterest, message):
        """
        Call _fixture._validator.validate and if it calls the successCallback
        then fail the test with the given message.

        :param dataOrInterest: The Data or Interest to validate.
        :type dataOrInterest: Data or Interest
        :param str message: The message to show if the test succeeds.
        """
        successCount = [0]
        failureCount = [0]
        def successCallback(dataOrInterest):
            successCount[0] += 1
        def failureCallback(dataOrInterest, error):
            failureCount[0] += 1

        self._fixture._validator.validate(
          dataOrInterest, successCallback, failureCallback)
        self.assertTrue(successCount[0] == 0, message)

    def test_basic(self):
        interest1 = self._fixture.makeCommandInterest(self._fixture._identity)
        self.validateExpectSuccess(interest1, "Should succeed (within grace period)")

        self._fixture.setNowOffsetMilliseconds(5 * 1000.0)
        interest2 = self._fixture.makeCommandInterest(self._fixture._identity)
        self.validateExpectSuccess(interest2,
          "Should succeed (timestamp larger than previous)")

    def test_data_passthrough(self):
        data1 = Data(Name("/Security/V2/ValidatorFixture/Sub1"))
        self._fixture._keyChain.sign(data1)
        self.validateExpectSuccess(data1,
          "Should succeed (fallback on inner validation policy for data)")

    def test_name_too_short(self):
        interest1 = Interest(Name("/name/too/short"))
        self.validateExpectFailure(interest1, "Should fail (name is too short)")

    def test_bad_signature_info(self):
        interest1 = self._fixture.makeCommandInterest(self._fixture._identity)
        setNameComponent(
          interest1, CommandInterestSigner.POS_SIGNATURE_INFO, "not-SignatureInfo")
        self.validateExpectFailure(interest1, "Should fail (missing signature info)")

    def test_missing_key_locator(self):
        interest1 = self._fixture.makeCommandInterest(self._fixture._identity)
        signatureInfo = Sha256WithRsaSignature()
        setNameComponent(
          interest1, CommandInterestSigner.POS_SIGNATURE_INFO,
          TlvWireFormat.get().encodeSignatureInfo(signatureInfo))
        self.validateExpectFailure(interest1, "Should fail (missing KeyLocator)")

    def test_bad_key_locator_type(self):
        interest1 = self._fixture.makeCommandInterest(self._fixture._identity)
        keyLocator = KeyLocator()
        keyLocator.setType(KeyLocatorType.KEY_LOCATOR_DIGEST)
        keyLocator.setKeyData(Blob
          ([ 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd ]))
        signatureInfo = Sha256WithRsaSignature()
        signatureInfo.setKeyLocator(keyLocator)

        setNameComponent(
          interest1, CommandInterestSigner.POS_SIGNATURE_INFO,
          TlvWireFormat.get().encodeSignatureInfo(signatureInfo))
        self.validateExpectFailure(interest1, "Should fail (bad KeyLocator type)")

    def test_bad_certificate_name(self):
        interest1 = self._fixture.makeCommandInterest(self._fixture._identity)
        keyLocator = KeyLocator()
        keyLocator.setType(KeyLocatorType.KEYNAME)
        keyLocator.setKeyName(Name("/bad/cert/name"))
        signatureInfo = Sha256WithRsaSignature()
        signatureInfo.setKeyLocator(keyLocator)

        setNameComponent(
          interest1, CommandInterestSigner.POS_SIGNATURE_INFO,
          TlvWireFormat.get().encodeSignatureInfo(signatureInfo))
        self.validateExpectFailure(interest1, "Should fail (bad certificate name)")

    def test_inner_policy_reject(self):
        interest1 = self._fixture.makeCommandInterest(self._fixture._otherIdentity)
        self.validateExpectFailure(interest1, "Should fail (inner policy should reject)")

    def test_timestamp_out_of_grace_positive(self):
        self._fixture = ValidationPolicyCommandInterestFixture(
          ValidationPolicyCommandInterest.Options(15 * 1000.0))

        # Signed at 0 seconds.
        interest1 = self._fixture.makeCommandInterest(self._fixture._identity)
        # Verifying at +16 seconds.
        self._fixture.setNowOffsetMilliseconds(16 * 1000.0)
        self.validateExpectFailure(interest1,
          "Should fail (timestamp outside the grace period)")

        # Signed at +16 seconds.
        interest2 = self._fixture.makeCommandInterest(self._fixture._identity)
        self.validateExpectSuccess(interest2, "Should succeed")

    def test_timestamp_out_of_grace_negative(self):
        self._fixture = ValidationPolicyCommandInterestFixture(
          ValidationPolicyCommandInterest.Options(15 * 1000.0))

        # Signed at 0 seconds.
        interest1 = self._fixture.makeCommandInterest(self._fixture._identity)
        # Signed at +1 seconds.
        self._fixture.setNowOffsetMilliseconds(1 * 1000.0)
        interest2 = self._fixture.makeCommandInterest(self._fixture._identity)
        # Signed at +2 seconds.
        self._fixture.setNowOffsetMilliseconds(2 * 1000.0)
        interest3 = self._fixture.makeCommandInterest(self._fixture._identity)

        # Verifying at -16 seconds.
        self._fixture.setNowOffsetMilliseconds(-16 * 1000.0)
        self.validateExpectFailure(interest1,
          "Should fail (timestamp outside the grace period)")

        # The CommandInterestValidator should not remember interest1's timestamp.
        self.validateExpectFailure(interest2,
          "Should fail (timestamp outside the grace period)")

        # The CommandInterestValidator should not remember interest2's timestamp, and
        # should treat interest3 as initial.
        # Verifying at +2 seconds.
        self._fixture.setNowOffsetMilliseconds(2 * 1000.0)
        self.validateExpectSuccess(interest3, "Should succeed")

    def test_timestamp_reorder_equal(self):
        # Signed at 0 seconds.
        interest1 = self._fixture.makeCommandInterest(self._fixture._identity)
        self.validateExpectSuccess(interest1, "Should succeed")

        # Signed at 0 seconds.
        interest2 = self._fixture.makeCommandInterest(self._fixture._identity)
        setNameComponent(
          interest2, CommandInterestSigner.POS_TIMESTAMP,
          interest1.getName().get(CommandInterestSigner.POS_TIMESTAMP))
        self.validateExpectFailure(interest2, "Should fail (timestamp reordered)")

        # Signed at +2 seconds.
        self._fixture.setNowOffsetMilliseconds(2 * 1000.0)
        interest3 = self._fixture.makeCommandInterest(self._fixture._identity)
        self.validateExpectSuccess(interest3, "Should succeed")

    def test_timestamp_reorder_negative(self):
        # Signed at 0 seconds.
        interest2 = self._fixture.makeCommandInterest(self._fixture._identity)
        # Signed at +200 milliseconds.
        self._fixture.setNowOffsetMilliseconds(200.0)
        interest3 = self._fixture.makeCommandInterest(self._fixture._identity)
        # Signed at +1100 milliseconds.
        self._fixture.setNowOffsetMilliseconds(1100.0)
        interest1 = self._fixture.makeCommandInterest(self._fixture._identity)
        # Signed at +1400 milliseconds.
        self._fixture.setNowOffsetMilliseconds(1400.0)
        interest4 = self._fixture.makeCommandInterest(self._fixture._identity)

        # Verifying at +1100 milliseconds.
        self._fixture.setNowOffsetMilliseconds(1100.0)
        self.validateExpectSuccess(interest1, "Should succeed")

        # Verifying at 0 milliseconds.
        self._fixture.setNowOffsetMilliseconds(0.0)
        self.validateExpectFailure(interest2, "Should fail (timestamp reordered)")

        # The CommandInterestValidator should not remember interest2's timestamp.
        # Verifying at +200 milliseconds.
        self._fixture.setNowOffsetMilliseconds(200.0)
        self.validateExpectFailure(interest3, "Should fail (timestamp reordered)")

        # Verifying at +1400 milliseconds.
        self._fixture.setNowOffsetMilliseconds(1400.0)
        self.validateExpectSuccess(interest4, "Should succeed")

    def test_limited_records(self):
        self._fixture = ValidationPolicyCommandInterestFixture(
          ValidationPolicyCommandInterest.Options(15 * 1000.0, 3))

        identity1 = self._fixture.addSubCertificate(
          Name("/Security/V2/ValidatorFixture/Sub1"), self._fixture._identity)
        self._fixture._cache.insert(identity1.getDefaultKey().getDefaultCertificate())
        identity2 = self._fixture.addSubCertificate(
          Name("/Security/V2/ValidatorFixture/Sub2"), self._fixture._identity)
        self._fixture._cache.insert(identity2.getDefaultKey().getDefaultCertificate())
        identity3 = self._fixture.addSubCertificate(
          Name("/Security/V2/ValidatorFixture/Sub3"), self._fixture._identity)
        self._fixture._cache.insert(identity3.getDefaultKey().getDefaultCertificate())
        identity4 = self._fixture.addSubCertificate(
          Name("/Security/V2/ValidatorFixture/Sub4"), self._fixture._identity)
        self._fixture._cache.insert(identity4.getDefaultKey().getDefaultCertificate())

        interest1 = self._fixture.makeCommandInterest(identity2)
        interest2 = self._fixture.makeCommandInterest(identity3)
        interest3 = self._fixture.makeCommandInterest(identity4)
        # Signed at 0 seconds.
        interest00 = self._fixture.makeCommandInterest(identity1)
        # Signed at +1 seconds.
        self._fixture.setNowOffsetMilliseconds(1 * 1000.0)
        interest01 = self._fixture.makeCommandInterest(identity1)
        # Signed at +2 seconds.
        self._fixture.setNowOffsetMilliseconds(2 * 1000.0)
        interest02 = self._fixture.makeCommandInterest(identity1)

        self.validateExpectSuccess(interest00, "Should succeed")

        self.validateExpectSuccess(interest02, "Should succeed")

        self.validateExpectSuccess(interest1, "Should succeed")

        self.validateExpectSuccess(interest2, "Should succeed")

        self.validateExpectSuccess(interest3, "Should succeed, forgets identity1")

        self.validateExpectSuccess(interest01,
          "Should succeed despite timestamp is reordered, because the record has been evicted")

    def test_unlimited_records(self):
        self._fixture = ValidationPolicyCommandInterestFixture(
          ValidationPolicyCommandInterest.Options(15 * 1000.0, -1))

        identities = []
        for i in range(20):
            identity = self._fixture.addSubCertificate(
              Name("/Security/V2/ValidatorFixture/Sub" + str(i)),
              self._fixture._identity)
            self._fixture._cache.insert(identity.getDefaultKey().getDefaultCertificate())
            identities.append(identity)

        # Signed at 0 seconds.
        interest1 = self._fixture.makeCommandInterest(identities[0])
        self._fixture.setNowOffsetMilliseconds(1 * 1000.0)
        for i in range(20):
            # Signed at +1 seconds.
            interest2 = self._fixture.makeCommandInterest(identities[i])

            self.validateExpectSuccess(interest2, "Should succeed")

        self.validateExpectFailure(interest1, "Should fail (timestamp reorder)")

    def test_zero_records(self):
        self._fixture = ValidationPolicyCommandInterestFixture(
          ValidationPolicyCommandInterest.Options(15 * 1000.0, 0))

        # Signed at 0 seconds.
        interest1 = self._fixture.makeCommandInterest(self._fixture._identity)
        # Signed at +1 seconds.
        self._fixture.setNowOffsetMilliseconds(1 * 1000.0)
        interest2 = self._fixture.makeCommandInterest(self._fixture._identity)
        self.validateExpectSuccess(interest2, "Should succeed")

        self.validateExpectSuccess(interest1,
          "Should succeed despite the timestamp being reordered, because the record isn't kept")

    def test_limited_record_lifetime(self):
        self._fixture = ValidationPolicyCommandInterestFixture(
          ValidationPolicyCommandInterest.Options(400 * 1000.0, 1000, 300 * 1000.0))

        # Signed at 0 seconds.
        interest1 = self._fixture.makeCommandInterest(self._fixture._identity)
        # Signed at +240 seconds.
        self._fixture.setNowOffsetMilliseconds(240 * 1000.0)
        interest2 = self._fixture.makeCommandInterest(self._fixture._identity)
        # Signed at +360 seconds.
        self._fixture.setNowOffsetMilliseconds(360 * 1000.0)
        interest3 = self._fixture.makeCommandInterest(self._fixture._identity)

        # Validate at 0 seconds.
        self._fixture.setNowOffsetMilliseconds(0.0)
        self.validateExpectSuccess(interest1, "Should succeed")

        self.validateExpectSuccess(interest3, "Should succeed")

        # Validate at +301 seconds.
        self._fixture.setNowOffsetMilliseconds(301 * 1000.0)
        self.validateExpectSuccess(interest2,
          "Should succeed despite the timestamp being reordered, because the record has expired")

    def test_zero_record_lifetime(self):
        self._fixture = ValidationPolicyCommandInterestFixture(
          ValidationPolicyCommandInterest.Options(15 * 1000.0, 1000, 0.0))

        # Signed at 0 seconds.
        interest1 = self._fixture.makeCommandInterest(self._fixture._identity)
        # Signed at +1 second.
        self._fixture.setNowOffsetMilliseconds(1 * 1000.0)
        interest2 = self._fixture.makeCommandInterest(self._fixture._identity)
        self.validateExpectSuccess(interest2, "Should succeed")

        self.validateExpectSuccess(interest1,
          "Should succeed despite the timestamp being reordered, because the record has expired")

if __name__ == '__main__':
    ut.main(verbosity=2)

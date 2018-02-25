# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx unit tests:
# https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/v2/validator.t.cpp
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
from pyndn import Name, Data, Interest, NetworkNack, ContentType, ValidityPeriod
from pyndn.security import SigningInfo, RsaKeyParams
from pyndn.security.v2 import CertificateV2, ValidationPolicySimpleHierarchy
from pyndn.util.common import Common
from .hierarchical_validator_fixture import HierarchicalValidatorFixture

class TestValidator(ut.TestCase):
    def setUp(self):
        self._fixture = HierarchicalValidatorFixture(
          ValidationPolicySimpleHierarchy())

    def validateExpectSuccess(self, data, message):
        """
        Call _fixture._validator.validate and if it calls the failureCallback
        then fail the test with the given message.

        :param Data data: The Data to validate.
        :param str message: The message to show if the test fails.
        """
        successCount = [0]
        failureCount = [0]
        def successCallback(data):
            successCount[0] += 1
        def failureCallback(data, error):
            failureCount[0] += 1

        self._fixture._validator.validate(data, successCallback, failureCallback)
        self.assertTrue(failureCount[0] == 0, message)

    def validateExpectFailure(self, data, message):
        """
        Call _fixture._validator.validate and if it calls the successCallback
        then fail the test with the given message.

        :param Data data: The Data to validate.
        :param str message: The message to show if the test succeeds.
        """
        successCount = [0]
        failureCount = [0]
        def successCallback(data):
            successCount[0] += 1
        def failureCallback(data, error):
            failureCount[0] += 1

        self._fixture._validator.validate(data, successCallback, failureCallback)
        self.assertTrue(successCount[0] == 0, message)

    def makeCertificate(self, key, signer):
        """
        Make a certificate and put it in the _fixture._cache .

        :type key: PibKey
        :type signer: PibKey
        """
        # Copy the default certificate.
        request = CertificateV2(key.getDefaultCertificate())
        request.setName(Name(key.getName()).append("looper").appendVersion(1))

        # Set SigningInfo.
        params = SigningInfo(signer)
        # Validity period from 100 days before to 100 days after now.
        now = Common.getNowMilliseconds()
        params.setValidityPeriod(ValidityPeriod
          (now - 100 * 24 * 3600 * 1000.0, now + 100 * 24 * 3600 * 1000.0))
        self._fixture._keyChain.sign(request, params)
        self._fixture._keyChain.addCertificate(key, request)

        self._fixture._cache.insert(request)

    def test_constructor_set_validator(self):
        validator = self._fixture._validator

        middlePolicy = ValidationPolicySimpleHierarchy()
        innerPolicy = ValidationPolicySimpleHierarchy()

        validator.getPolicy().setInnerPolicy(middlePolicy)
        validator.getPolicy().setInnerPolicy(innerPolicy)

        self.assertTrue(validator.getPolicy()._validator != None)
        self.assertTrue(validator.getPolicy().getInnerPolicy()._validator != None)
        self.assertTrue(
          validator.getPolicy().getInnerPolicy().getInnerPolicy()._validator != None)

    def test_timeouts(self):
        # Disable responses from the simulated Face.
        self._fixture._face._processInterest = None

        data = Data(Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"))
        self._fixture._keyChain.sign(data, SigningInfo(self._fixture._subIdentity))

        self.validateExpectFailure(data, "Should fail to retrieve certificate")
        # There should be multiple expressed interests due to retries.
        self.assertTrue(len(self._fixture._face._sentInterests) > 1)

    def test_nacked_interests(self):
        def processInterest(interest, onData, onTimeout, onNetworkNack):
            networkNack = NetworkNack()
            networkNack.setReason(NetworkNack.Reason.NO_ROUTE)

            onNetworkNack(interest, networkNack)
        self._fixture._face._processInterest = processInterest

        data = Data(Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"))
        self._fixture._keyChain.sign(data, SigningInfo(self._fixture._subIdentity))

        self.validateExpectFailure(data, "All interests should get NACKed")
        # There should be multiple expressed interests due to retries.
        self.assertTrue(len(self._fixture._face._sentInterests) > 1)

    def test_malformed_certificate(self):
        # Copy the default certificate.
        malformedCertificate = Data(
          self._fixture._subIdentity.getDefaultKey().getDefaultCertificate())
        malformedCertificate.getMetaInfo().setType(ContentType.BLOB)
        self._fixture._keyChain.sign(
          malformedCertificate, SigningInfo(self._fixture._identity))
        # It has the wrong content type and a missing ValidityPeriod.
        try:
            CertificateV2(malformedCertificate).wireEncode()
            self.fail("Did not throw the expected exception")
        except CertificateV2.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        originalProcessInterest = self._fixture._face._processInterest
        def processInterest(interest, onData, onTimeout, onNetworkNack):
            if interest.getName().isPrefixOf(malformedCertificate.getName()):
                onData(interest, malformedCertificate)
            else:
                originalProcessInterest.processInterest(
                  interest, onData, onTimeout, onNetworkNack)
        self._fixture._face._processInterest = processInterest

        data = Data(Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"))
        self._fixture._keyChain.sign(data, SigningInfo(self._fixture._subIdentity))

        self.validateExpectFailure(data, "Signed by a malformed certificate")
        self.assertEqual(1, len(self._fixture._face._sentInterests))

    def test_expired_certificate(self):
        # Copy the default certificate.
        expiredCertificate = Data(
          self._fixture._subIdentity.getDefaultKey().getDefaultCertificate())
        info = SigningInfo(self._fixture._identity)
        # Validity period from 2 hours ago do 1 hour ago.
        now = Common.getNowMilliseconds()
        info.setValidityPeriod(
          ValidityPeriod(now - 2 * 3600 * 1000, now - 3600 * 1000.0))
        self._fixture._keyChain.sign(expiredCertificate, info)
        try:
            CertificateV2(expiredCertificate).wireEncode()
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        originalProcessInterest = self._fixture._face._processInterest
        def processInterest(interest, onData, onTimeout, onNetworkNack):
            if interest.getName().isPrefixOf(expiredCertificate.getName()):
                onData(interest, expiredCertificate)
            else:
                originalProcessInterest.processInterest(
                  interest, onData, onTimeout, onNetworkNack)
        self._fixture._face._processInterest = processInterest

        data = Data(Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"))
        self._fixture._keyChain.sign(data, SigningInfo(self._fixture._subIdentity))

        self.validateExpectFailure(data, "Signed by an expired certificate")
        self.assertEqual(1, len(self._fixture._face._sentInterests))

    def test_reset_anchors(self):
        self._fixture._validator.resetAnchors()

        data = Data(Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"))
        self._fixture._keyChain.sign(data, SigningInfo(self._fixture._subIdentity))
        self.validateExpectFailure(data, "Should fail, as no anchors are configured")

    def test_trusted_certificate_caching(self):
        data = Data(Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"))
        self._fixture._keyChain.sign(data, SigningInfo(self._fixture._subIdentity))

        self.validateExpectSuccess(
          data, "Should get accepted, as signed by the policy-compliant certificate")
        self.assertEqual(1, len(self._fixture._face._sentInterests))
        self._fixture._face._sentInterests = []

        # Disable responses from the simulated Face.
        self._fixture._face._processInterest = None

        self.validateExpectSuccess(
          data, "Should get accepted, based on the cached trusted certificate")
        self.assertEqual(0, len(self._fixture._face._sentInterests))
        self._fixture._face._sentInterests = []

        # Make the trusted cache simulate a time 2 hours later, after expiration.
        self._fixture._validator._setCacheNowOffsetMilliseconds(2 * 3600 * 1000.0)

        self.validateExpectFailure(
          data, "Should try and fail to retrieve certificates")
        # There should be multiple expressed interests due to retries.
        self.assertTrue(len(self._fixture._face._sentInterests) > 1)
        self._fixture._face._sentInterests = []

    def test_infinite_certificate_chain(self):
        def processInterest(interest, onData, onTimeout, onNetworkNack):
            try:
                # Create another key for the same identity and sign it properly.
                parentKey = self._fixture._keyChain.createKey(
                  self._fixture._subIdentity)
                requestedKey = self._fixture._subIdentity.getKey(interest.getName())

                # Copy the Name.
                certificateName = Name(requestedKey.getName())
                certificateName.append("looper").appendVersion(1)
                certificate = CertificateV2()
                certificate.setName(certificateName)

                # Set the MetaInfo.
                certificate.getMetaInfo().setType(ContentType.KEY)
                # Set the freshness period to one hour.
                certificate.getMetaInfo().setFreshnessPeriod(3600 * 1000.0)

                # Set the content.
                certificate.setContent(requestedKey.getPublicKey())

                # Set SigningInfo.
                params = SigningInfo(parentKey)
                # Validity period from 10 days before to 10 days after now.
                now = Common.getNowMilliseconds()
                params.setValidityPeriod(ValidityPeriod(
                  now - 10 * 24 * 3600 * 1000.0, now + 10 * 24 * 3600 * 1000.0))

                self._fixture._keyChain.sign(certificate, params)
                onData(interest, certificate)
            except Exception as ex:
                self.fail("Error in InfiniteCertificateChain: " + repr(ex))

        self._fixture._face._processInterest = processInterest

        data = Data(Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"))
        self._fixture._keyChain.sign(data, SigningInfo(self._fixture._subIdentity))

        self._fixture._validator.setMaxDepth(40)
        self.assertEqual(40, self._fixture._validator.getMaxDepth())
        self.validateExpectFailure(data,
          "Should fail since the certificate should be looped")
        self.assertEqual(40, len(self._fixture._face._sentInterests))
        self._fixture._face._sentInterests = []

        # Make the trusted cache simulate a time 5 hours later, after expiration.
        self._fixture._validator._setCacheNowOffsetMilliseconds(5 * 3600 * 1000.0)

        self._fixture._validator.setMaxDepth(30)
        self.assertEqual(30, self._fixture._validator.getMaxDepth())
        self.validateExpectFailure(data,
          "Should fail since the certificate chain is infinite")
        self.assertEqual(30, len(self._fixture._face._sentInterests))

    def test_looped_certificate_chain(self):
        identity1 = self._fixture.addIdentity(Name("/loop"))
        key1 = self._fixture._keyChain.createKey(
          identity1, RsaKeyParams(Name.Component("key1")))
        key2 = self._fixture._keyChain.createKey(
          identity1, RsaKeyParams(Name.Component("key2")))
        key3 = self._fixture._keyChain.createKey(
          identity1, RsaKeyParams(Name.Component("key3")))

        self.makeCertificate(key1, key2)
        self.makeCertificate(key2, key3)
        self.makeCertificate(key3, key1)

        data = Data(Name("/loop/Data"))
        self._fixture._keyChain.sign(data, SigningInfo(key1))
        self.validateExpectFailure(data,
          "Should fail since the certificate chain loops")
        self.assertEqual(3, len(self._fixture._face._sentInterests))

class ValidationPolicySimpleHierarchyForInterestOnly(ValidationPolicySimpleHierarchy):
    def __init__(self):
        super(ValidationPolicySimpleHierarchyForInterestOnly, self).__init__()

    def checkPolicy(self, dataOrInterest, state, continueValidation):
        """
        :param dataOrInterest:
        :type dataOrInterest: Data or Interest
        :param ValidationState state:
        :param continueValidation:
        :type continueValidation: function object
        """
        if isinstance(dataOrInterest, Data):
            continueValidation(None, state)
        else:
            # Call the base method for the Interest.
            super(ValidationPolicySimpleHierarchyForInterestOnly, self).checkPolicy(
              dataOrInterest, state, continueValidation)

class TestValidatorInterestOnly(ut.TestCase):
    def setUp(self):
        self._fixture = HierarchicalValidatorFixture(
          ValidationPolicySimpleHierarchyForInterestOnly())

    def validateExpectSuccess(self, data, message):
        """
        Call _fixture._validator.validate and if it calls the failureCallback
        then fail the test with the given message.

        :param Data data: The Data to validate.
        :param str message: The message to show if the test fails.
        """
        successCount = [0]
        failureCount = [0]
        def successCallback(data):
            successCount[0] += 1
        def failureCallback(data, error):
            failureCount[0] += 1

        self._fixture._validator.validate(data, successCallback, failureCallback)
        self.assertTrue(failureCount[0] == 0, message)

    def validateExpectFailure(self, data, message):
        """
        Call _fixture._validator.validate and if it calls the successCallback
        then fail the test with the given message.

        :param Data data: The Data to validate.
        :param str message: The message to show if the test succeeds.
        """
        successCount = [0]
        failureCount = [0]
        def successCallback(data):
            successCount[0] += 1
        def failureCallback(data, error):
            failureCount[0] += 1

        self._fixture._validator.validate(data, successCallback, failureCallback)
        self.assertTrue(successCount[0] == 0, message)

    def test_validate_interests_but_bypass_for_data(self):
        interest = Interest(
          Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"))
        data = Data(
          Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"))

        self.validateExpectFailure(interest, "Unsigned")
        self.validateExpectSuccess(
          data, "The policy requests to bypass validation for all data")
        self.assertEqual(0, len(self._fixture._face._sentInterests))
        self._fixture._face._sentInterests = []

        interest = Interest(
          Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"))
        self._fixture._keyChain.sign(
          interest, SigningInfo(SigningInfo.SignerType.SHA256))
        self._fixture._keyChain.sign(
          data, SigningInfo(SigningInfo.SignerType.SHA256))
        self.validateExpectFailure(interest,
          "Required KeyLocator/Name is missing (not passed to the policy)")
        self.validateExpectSuccess(
          data, "The policy requests to bypass validation for all data")
        self.assertEqual(0, len(self._fixture._face._sentInterests))
        self._fixture._face._sentInterests = []

        interest = Interest(
          Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"))
        self._fixture._keyChain.sign(interest, SigningInfo(self._fixture._identity))
        self._fixture._keyChain.sign(data, SigningInfo(self._fixture._identity))
        self.validateExpectSuccess(interest,
          "Should be successful since it is signed by the anchor")
        self.validateExpectSuccess(
          data, "The policy requests to bypass validation for all data")
        self.assertEqual(0, len(self._fixture._face._sentInterests))
        self._fixture._face._sentInterests = []

        interest = Interest(
          Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"))
        self._fixture._keyChain.sign(interest, SigningInfo(self._fixture._subIdentity))
        self._fixture._keyChain.sign(data, SigningInfo(self._fixture._subIdentity))
        self.validateExpectFailure(interest,
          "Should fail since the policy is not allowed to create new trust anchors")
        self.validateExpectSuccess(
          data, "The policy requests to bypass validation for all data")
        self.assertEqual(1, len(self._fixture._face._sentInterests))
        self._fixture._face._sentInterests = []

        interest = Interest(
          Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"))
        self._fixture._keyChain.sign(interest, SigningInfo(self._fixture._otherIdentity))
        self._fixture._keyChain.sign(data, SigningInfo(self._fixture._otherIdentity))
        self.validateExpectFailure(interest,
          "Should fail since it is signed by a policy-violating certificate")
        self.validateExpectSuccess(
          data, "The policy requests to bypass validation for all data")
        # No network operations are expected since the certificate is not
        # validated by the policy.
        self.assertEqual(0, len(self._fixture._face._sentInterests))
        self._fixture._face._sentInterests = []

        # Make the trusted cache simulate a time 2 hours later, after expiration.
        self._fixture._validator._setCacheNowOffsetMilliseconds(2 * 3600 * 1000.0)

        interest = Interest(
          Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"))
        self._fixture._keyChain.sign(interest,
          SigningInfo(self._fixture._subSelfSignedIdentity))
        self._fixture._keyChain.sign(data,
          SigningInfo(self._fixture._subSelfSignedIdentity))
        self.validateExpectFailure(interest,
         "Should fail since the policy is not allowed to create new trust anchors")
        self.validateExpectSuccess(data,
          "The policy requests to bypass validation for all data")
        self.assertEqual(1, len(self._fixture._face._sentInterests))
        self._fixture._face._sentInterests = []

if __name__ == '__main__':
    ut.main(verbosity=2)

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From PyNDN unit-tests by Adeola Bannis.
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
from pyndn import Name, Data, KeyLocator, KeyLocatorType
from pyndn.security.v2 import CertificateFetcherOffline, DataValidationState
from pyndn.security import ValidatorConfig

class TestValidationResult(object):
    """
    Create a TestValidationResult whose state_ will reference the given Data.

    :param Data data: The Data packed for the state_, which must remain valid.
    """
    def __init__(self, data):
        self._data = data
        self.reset()

    def reset(self):
        """
        Reset all the results to false, to get ready for another result.
        """
        def successCallback(data):
            self._calledSuccess = True
        def failureCallback(data, error):
            self._calledFailure = True
        self._state = DataValidationState(
          self._data, successCallback, failureCallback)

        self._calledSuccess = False
        self._calledFailure = False
        self.calledContinue_ = False

    def checkPolicy(self, validator):
        """
        Call reset() then call validator.checkPolicy to set this object's
        results. When finished, you can check calledSuccess_, etc.

        :param ValidatorConfig validator: The ValidatorConfig for calling
          checkPolicy.
        """
        self.reset()

        def continueValidation(certificateRequest, state):
            self.calledContinue_ = True
        validator.getPolicy().checkPolicy(
          self._data, self._state, continueValidation)

class TestValidationPolicyConfig(ut.TestCase):
    def setUp(self):
        self._policyConfigDirectory = "policy_config"

    def test_name_relation(self):
        # Set up the validators.
        fetcher = CertificateFetcherOffline()
        validatorPrefix = ValidatorConfig(fetcher)
        validatorEqual = ValidatorConfig(fetcher)
        validatorStrict = ValidatorConfig(fetcher)

        validatorPrefix.load(
          os.path.join(self._policyConfigDirectory, "relation_ruleset_prefix.conf"))
        validatorEqual.load(
          os.path.join(self._policyConfigDirectory, "relation_ruleset_equal.conf"))
        validatorStrict.load(
          os.path.join(self._policyConfigDirectory, "relation_ruleset_strict.conf"))

        # Set up a Data packet and result object.
        data = Data()
        KeyLocator.getFromSignature(data.getSignature()).setType(
          KeyLocatorType.KEYNAME)
        KeyLocator.getFromSignature(data.getSignature()).setKeyName(
          Name("/SecurityTestSecRule/KEY/123"))
        result = TestValidationResult(data)

        data.setName(Name("/TestRule1"))
        result.checkPolicy(validatorPrefix)
        self.assertTrue(result.calledContinue_ and not result._calledFailure,
          "Prefix relation should match prefix name")
        result.checkPolicy(validatorEqual)
        self.assertTrue(result.calledContinue_ and not result._calledFailure,
          "Equal relation should match prefix name")
        result.checkPolicy(validatorStrict)
        self.assertTrue(result._calledFailure and not result.calledContinue_,
          "Strict-prefix relation should not match prefix name")

        data.setName(Name("/TestRule1/hi"))
        result.checkPolicy(validatorPrefix)
        self.assertTrue(result.calledContinue_ and not result._calledFailure,
          "Prefix relation should match longer name")
        result.checkPolicy(validatorEqual)
        self.assertTrue(result._calledFailure and not result.calledContinue_,
          "Equal relation should not match longer name")
        result.checkPolicy(validatorStrict)
        self.assertTrue(result.calledContinue_ and not result._calledFailure,
          "Strict-prefix relation should match longer name")

        data.setName(Name("/Bad/TestRule1/"))
        result.checkPolicy(validatorPrefix)
        self.assertTrue(result._calledFailure and not result.calledContinue_,
          "Prefix relation should not match inner components")
        result.checkPolicy(validatorEqual)
        self.assertTrue(result._calledFailure and not result.calledContinue_,
          "Equal relation should not match inner components")
        result.checkPolicy(validatorStrict)
        self.assertTrue(result._calledFailure and not result.calledContinue_,
          "Strict-prefix relation should  not match inner components")

    def test_simple_regex(self):
        # Set up the validator.
        fetcher = CertificateFetcherOffline()
        validator = ValidatorConfig(fetcher)
        validator.load(os.path.join(self._policyConfigDirectory, "regex_ruleset.conf"))

        # Set up a Data packet and result object.
        data = Data()
        KeyLocator.getFromSignature(data.getSignature()).setType(KeyLocatorType.KEYNAME)
        KeyLocator.getFromSignature(data.getSignature()).setKeyName(
          Name("/SecurityTestSecRule/KEY/123"))
        result = TestValidationResult(data)

        data.setName(Name("/SecurityTestSecRule/Basic"))
        result.checkPolicy(validator)
        self.assertTrue(result.calledContinue_ and not result._calledFailure)

        data.setName(Name("/SecurityTestSecRule/Basic/More"))
        result.checkPolicy(validator)
        self.assertTrue(result._calledFailure and not result.calledContinue_)

        data.setName(Name("/SecurityTestSecRule/"))
        result.checkPolicy(validator)
        self.assertTrue(result.calledContinue_ and not result._calledFailure)

        data.setName(Name("/SecurityTestSecRule/Other/TestData"))
        result.checkPolicy(validator)
        self.assertTrue(result.calledContinue_ and not result._calledFailure)

        data.setName(Name("/Basic/Data"))
        result.checkPolicy(validator)
        self.assertTrue(result._calledFailure and not result.calledContinue_)

    def test_hierarchical(self):
        # Set up the validator.
        fetcher = CertificateFetcherOffline()
        validator = ValidatorConfig(fetcher)
        validator.load(
          os.path.join(self._policyConfigDirectory, "hierarchical_ruleset.conf"))

        # Set up a Data packet and result object.
        data = Data()
        KeyLocator.getFromSignature(data.getSignature()).setType(KeyLocatorType.KEYNAME)
        KeyLocator.getFromSignature(data.getSignature()).setKeyName(
          Name("/SecurityTestSecRule/Basic/Longer/KEY/123"))
        result = TestValidationResult(data)

        data.setName(Name("/SecurityTestSecRule/Basic/Data1"))
        result.checkPolicy(validator)
        self.assertTrue(result._calledFailure and not result.calledContinue_)

        data.setName(Name("/SecurityTestSecRule/Basic/Longer/Data2"))
        result.checkPolicy(validator)
        self.assertTrue(result.calledContinue_ and not result._calledFailure)

        KeyLocator.getFromSignature(data.getSignature()).setKeyName(
          Name("/SecurityTestSecRule/Basic/KEY/123"))

        data.setName(Name("/SecurityTestSecRule/Basic/Data1"))
        result.checkPolicy(validator)
        self.assertTrue(result.calledContinue_ and not result._calledFailure)

        data.setName(Name("/SecurityTestSecRule/Basic/Longer/Data2"))
        result.checkPolicy(validator)
        self.assertTrue(result.calledContinue_ and not result._calledFailure)

    def test_hyper_relation(self):
        # Set up the validator.
        fetcher = CertificateFetcherOffline()
        validator = ValidatorConfig(fetcher)
        validator.load(
          os.path.join(self._policyConfigDirectory, "hyperrelation_ruleset.conf"))

        # Set up a Data packet and result object.
        data = Data()
        KeyLocator.getFromSignature(data.getSignature()).setType(KeyLocatorType.KEYNAME)
        result = TestValidationResult(data)

        data.setName(Name("/SecurityTestSecRule/Basic/Longer/Data2"))

        KeyLocator.getFromSignature(data.getSignature()).setKeyName(
          Name("/SecurityTestSecRule/Basic/Longer/KEY/123"))
        result.checkPolicy(validator)
        self.assertTrue(result._calledFailure and not result.calledContinue_)
        KeyLocator.getFromSignature(data.getSignature()).setKeyName(
          Name("/SecurityTestSecRule/Basic/KEY/123"))
        result.checkPolicy(validator)
        self.assertTrue(result._calledFailure and not result.calledContinue_)

        data.setName(Name("/SecurityTestSecRule/Basic/Other/Data1"))

        KeyLocator.getFromSignature(data.getSignature()).setKeyName(
          Name("/SecurityTestSecRule/Basic/Longer/KEY/123"))
        result.checkPolicy(validator)
        self.assertTrue(result._calledFailure and not result.calledContinue_)
        KeyLocator.getFromSignature(data.getSignature()).setKeyName(
          Name("/SecurityTestSecRule/Basic/KEY/123"))
        result.checkPolicy(validator)
        self.assertTrue(result._calledFailure and not result.calledContinue_)

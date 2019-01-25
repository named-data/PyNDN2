# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/validation-policy-config.cpp
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

"""
This module defines the ValidationPolicyConfig class which implements a
validator which can be set up via a configuration file. For command Interest
validation, this policy must be combined with ValidationPolicyCommandInterest in
order to guard against replay attacks.
Note: This policy does not support inner policies (a sole policy or a terminal
inner policy).
See https://named-data.net/doc/ndn-cxx/current/tutorials/security-validator-config.html
"""

import re
from base64 import b64decode
from pyndn.data import Data
from pyndn.interest import Interest
from pyndn.util.blob import Blob
from pyndn.util.boost_info_parser import BoostInfoParser
from pyndn.security.v2.certificate_v2 import CertificateV2
from pyndn.security.v2.certificate_request import CertificateRequest
from pyndn.security.v2.validation_error import ValidationError
from pyndn.security.validator_config_error import ValidatorConfigError
from pyndn.security.v2.validator_config.config_rule import ConfigRule
from pyndn.security.v2.validation_policy import ValidationPolicy

class ValidationPolicyConfig(ValidationPolicy):
    def __init__(self):
        super(ValidationPolicyConfig, self).__init__()

        self._shouldBypass = False
        self._isConfigured = False
        self._dataRules = []     # of ConfigRule
        self._interestRules = [] # of ConfigRule

    def load(self, filePathOrInputOrConfigSection, inputName = None):
        """
        There are three forms of load:
        load(filePath) - Load the configuration from the given config file.
        load(input, inputName) - Load the configuration from the given input
        string.
        load(configSection, inputName) - Load the configuration from the given
        configSection.
        Each of these forms of load replaces any existing configuration.

        :param str filePath: The The path of the config file.
        :param str input: The contents of the configuration rules, with lines
          separated by NL or CR/NL.
        :param BoostInfoTree configSection: The configuration section loaded
          from the config file. It should have one "validator" section.
        :param str inputName: Used for log messages, etc.
        """
        if type(filePathOrInputOrConfigSection) is str and inputName == None:
            filePath = filePathOrInputOrConfigSection

            parser = BoostInfoParser()
            parser.read(filePath)
            self.load(parser.getRoot(), filePath)
        elif (type(filePathOrInputOrConfigSection) is str and
              type(inputName) is str):
            input = filePathOrInputOrConfigSection

            parser = BoostInfoParser()
            parser.read(input, inputName)
            self.load(parser.getRoot(), inputName)
        else:
            configSection = filePathOrInputOrConfigSection

            if self._isConfigured:
                # Reset the previous configuration.
                self._shouldBypass = False
                self._dataRules = []
                self._interestRules = []

                self._validator.resetAnchors()
                self._validator.resetVerifiedCertificates()

            self._isConfigured = True

            validatorList = configSection["validator"]
            if len(validatorList) != 1:
                raise ValidatorConfigError(
                  "ValidationPolicyConfig: Expected one validator section")
            validatorSection = validatorList[0]

            # Get the rules.
            ruleList = validatorSection["rule"]
            for i in range(len(ruleList)):
                rule = ConfigRule.create(ruleList[i])
                if rule.getIsForInterest():
                    self._interestRules.append(rule)
                else:
                    self._dataRules.append(rule)

            # Get the trust anchors.
            trustAnchorList = validatorSection["trust-anchor"]
            for i in range(len(trustAnchorList)):
                self._processConfigTrustAnchor(trustAnchorList[i], inputName)

    def checkPolicy(self, dataOrInterest, state, continueValidation):
        """
        :param dataOrInterest:
        :type dataOrInterest: Data or Interest
        :param ValidationState state:
        :param continueValidation:
        :type continueValidation: function object
        """
        if self.hasInnerPolicy():
            raise ValidatorConfigError(
              "ValidationPolicyConfig must be a terminal inner policy")

        if self._shouldBypass:
            continueValidation(None, state)
            return

        keyLocatorName = ValidationPolicy.getKeyLocatorName(dataOrInterest, state)
        if state.isOutcomeFailed():
            # Already called state.fail() .
            return

        if isinstance(dataOrInterest, Data):
            data = dataOrInterest

            for i in range(len(self._dataRules)):
                rule = self._dataRules[i]

                if rule.match(False, data.getName()):
                    if rule.check(False, data.getName(), keyLocatorName, state):
                        continueValidation(
                          CertificateRequest(Interest(keyLocatorName)), state)
                        return
                    else:
                        # rule.check failed and already called state.fail() .
                        return

            state.fail(ValidationError(ValidationError.POLICY_ERROR,
              "No rule matched for data `" + data.getName().toUri() + "`"))
        else:
            interest = dataOrInterest

            for i in range(len(self._interestRules)):
                rule = self._interestRules[i]

                if rule.match(True, interest.getName()):
                    if rule.check(True, interest.getName(), keyLocatorName, state):
                        continueValidation(
                          CertificateRequest(Interest(keyLocatorName)), state)
                        return
                    else:
                        # rule.check failed and already called state.fail() .
                        return

            state.fail(ValidationError(ValidationError.POLICY_ERROR,
              "No rule matched for interest `" + interest.getName().toUri() + "`"))

    def _processConfigTrustAnchor(self, configSection, inputName):
        """
        Process the trust-anchor configuration section and call
        validator_.loadAnchor as needed.

        :param BoostInfoTree configSection: The section containing the
          definition of the trust anchor, e.g. one of "validator.trust-anchor".
        :param str inputName: Used for log messages, etc.
        """
        anchorType = configSection.getFirstValue("type")
        if anchorType == None:
            raise ValidatorConfigError("Expected <trust-anchor.type>")

        if anchorType.lower() == "file":
            # Get trust-anchor.file .
            fileName = configSection.getFirstValue("file-name")
            if fileName == None:
                raise ValidatorConfigError("Expected <trust-anchor.file-name>")

            refreshPeriod = ValidationPolicyConfig._getRefreshPeriod(configSection)
            self._validator.loadAnchor(fileName, fileName, refreshPeriod, False)

            return
        elif anchorType.lower() == "base64":
            # Get trust-anchor.base64-string .
            base64String = configSection.getFirstValue("base64-string")
            if base64String == None:
                raise ValidatorConfigError("Expected <trust-anchor.base64-string>")

            encoding = b64decode(base64String)
            certificate = CertificateV2()
            try:
                certificate.wireDecode(Blob(encoding, False))
            except Exception as ex:
                raise ValidatorConfigError(
                  "Cannot decode certificate from base64-string: " + repr(ex))

            self._validator.loadAnchor("", certificate)
            return
        elif anchorType.lower() == "dir":
            # Get trust-anchor.dir .
            dirString = configSection.getFirstValue("dir")
            if dirString == None:
                raise ValidatorConfigError("Expected <trust-anchor.dir>")

            refreshPeriod = ValidationPolicyConfig._getRefreshPeriod(configSection)
            self._validator.loadAnchor(dirString, dirString, refreshPeriod, True)

            return
        elif anchorType.lower() == "any":
            self._shouldBypass = True
        else:
            raise ValidatorConfigError("Unsupported trust-anchor.type")

    @staticmethod
    def _getRefreshPeriod(configSection):
        """
        Get the "refresh" value. If the value is 9, return a period of one hour.

        :param BoostInfoTree configSection: The section containing the
          definition of the trust anchor, e.g. one of "validator.trust-anchor".
        :return: The refresh period in milliseconds. However if there is no
          "refresh" value, return a large number (effectively no refresh).
        :rtype: float
        """
        refreshString = configSection.getFirstValue("refresh")
        if refreshString == None:
            # Return a large value (effectively no refresh).
            return 1e14

        refreshSeconds = 0.0
        refreshMatch = re.match('(\\d+)([hms])', refreshString)
        if refreshMatch:
            refreshSeconds = int(refreshMatch.group(1))
            if refreshMatch.group(2) != 's':
                refreshSeconds *= 60
                if refreshMatch.group(2) != 'm':
                    refreshSeconds *= 60

        if refreshSeconds == 0.0:
            # Use an hour instead of 0.
            return 3600 * 1000.0
        else:
            # Convert from seconds to milliseconds.
            return refreshSeconds * 1000.0

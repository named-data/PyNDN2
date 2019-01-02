# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
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
This module defines the ValidatorConfig class which extends Validator to
implement a validator which can be set up via a configuration file.
"""

from pyndn.security.v2.validator import Validator
from pyndn.security.v2.certificate_fetcher import CertificateFetcher
from pyndn.security.v2.certificate_fetcher_from_network import CertificateFetcherFromNetwork
from pyndn.security.v2.validation_policy_config import ValidationPolicyConfig

class ValidatorConfig(Validator):
    """
    The constructor has two forms:
    ValidatorConfig(fetcher) - Create a ValidatorConfig that uses the given
    certificate fetcher.
    ValidatorConfig(face) - Create a ValidatorConfig that uses a
    CertificateFetcherFromNetwork for the given Face.

    :param CertificateFetcher fetcher: the certificate fetcher to use.
    :param Face face: The face for the certificate fetcher to call
      expressInterest.
    """
    def __init__(self, fetcherOrFace):
        if isinstance(fetcherOrFace, CertificateFetcher):
            super(ValidatorConfig, self).__init__(
              ValidationPolicyConfig(), fetcherOrFace)
            # TODO: Use getInnerPolicy().
            self._policyConfig = self.getPolicy()
        else:
            super(ValidatorConfig, self).__init__(
              ValidationPolicyConfig(),
              CertificateFetcherFromNetwork(fetcherOrFace))
            # TODO: Use getInnerPolicy().
            self._policyConfig = self.getPolicy()

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
          separated by "\\n" or "\\r\\n".
        :param BoostInfoTree configSection: The configuration section loaded
          from the config file. It should have one "validator" section.
        :param str inputName: Used for log messages, etc.
        """
        self._policyConfig.load(filePathOrInputOrConfigSection, inputName)

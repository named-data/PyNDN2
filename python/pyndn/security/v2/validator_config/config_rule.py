# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/validator-config/rule.cpp
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
This module defines the ConfigRule class which represents a rule configuration
section, used by ConfigValidator.
"""

import logging
from pyndn.security.validator_config_error import ValidatorConfigError
from pyndn.security.v2.validator_config.config_filter import ConfigFilter
from pyndn.security.v2.validator_config.config_checker import ConfigChecker

class ConfigRule(object):
    """
    Create a ConfigRule with empty filters and checkers.

    :param str id: The rule ID from the configuration section.
    :param bool isForInterest: True if the rule is for an Interest packet,
      False if it is for a Data packet.
    """
    def __init__(self, id, isForInterest):
        self._id = id
        self._isForInterest = isForInterest
        self._filters = []  # of ConfigFilter
        self._checkers = [] # of ConfigChecker

    def getId(self):
        """
        Get the rule ID.

        :return: The rule ID.
        :rtype: bool
        """

    def getIsForInterest(self):
        """
        Get the isForInterest flag.

        :return: True if the rule is for an Interest packet, False if it is for
          a Data packet.
        :rtype: bool
        """
        return self._isForInterest

    def addFilter(self, filter):
        """
        Add the ConfigFilter to the list of filters.

        :param ConfigFilter filter: The ConfigFilter.
        """
        self._filters.append(filter)

    def addChecker(self, checker):
        """
        Add the ConfigChecker to the list of checkers.

        :param ConfigChecker checker: The ConfigChecker.
        """
        self._checkers.append(checker)

    def match(self, isForInterest, packetName):
        """
        Check if the packet name matches the rule's filter. If no filters were
        added, the rule matches everything.

        :param bool isForInterest: True if packetName is for an Interest, False
          if for a Data packet.
        :param Name packetName: The packet name. For a signed interest, the last
          two components are skipped but not removed.
        :return: True if at least one filter matches the packet name, False if
          none of the filters match the packet name.
        :rtype: bool
        :raises: ValidatorConfigError if the supplied isForInterest doesn't
          match the one for which the rule is designed.
        """
        logging.getLogger(__name__).info("Trying to match " + packetName.toUri())

        if isForInterest != self._isForInterest:
            raise ValidatorConfigError(
              ("Invalid packet type supplied ( " +
               ("interest" if isForInterest else "data") + " != " +
               ("interest" if self._isForInterest else "data") + ")"))

        if len(self._filters) == 0:
            return True

        result = False
        for i in range(len(self._filters)):
            result = (result or self._filters[i].match(isForInterest, packetName))
            if result:
                break

        return result

    def check(self, isForInterest, packetName, keyLocatorName, state):
        """
        Check if the packet satisfies the rule's condition.

        :param bool isForInterest: True if packetName is for an Interest, False
          if for a Data packet.
        :param Name packetName: The packet name. For a signed interest, the last
          two components are skipped but not removed.
        :param Name keyLocatorName: The KeyLocator's name.
        :param ValidationState state: This calls state.fail() if the packet is
          invalid.
        :return: True if further signature verification is needed, or False if
          the packet is immediately determined to be invalid in which case this
          calls state.fail() with the proper code and message.
        :rtype: bool
        :raises: ValidatorConfigError if the supplied isForInterest doesn't
          match the one for which the rule is designed.
        """
        logging.getLogger(__name__).info("Trying to check " +  packetName.toUri() +
          " with keyLocator " + keyLocatorName.toUri())

        if isForInterest != self._isForInterest:
            raise ValidatorConfigError(
              "Invalid packet type supplied ( " +
              ("interest" if isForInterest else "data") + " != " +
              ("interest" if self._isForInterest else "data") + ")")

        hasPendingResult = False
        for i in range(len(self._checkers)):
            result = self._checkers[i].check(
              isForInterest, packetName, keyLocatorName, state)
            if not result:
                return result
            hasPendingResult = True

        return hasPendingResult

    @staticmethod
    def create(configSection):
        """
        Create a rule from configuration section.

        :param BoostInfoTree configSection: The section containing the
          definition of the checker, e.g. one of "validator.rule".
        :return: A new ConfigRule created from the configuration.
        :rtype: ConfigRule
        """
        # Get rule.id .
        ruleId = configSection.getFirstValue("id")
        if ruleId == None:
            raise ValidatorConfigError("Expecting <rule.id>")

        # Get rule.for .
        usage = configSection.getFirstValue("for")
        if usage == None:
            raise ValidatorConfigError("Expecting <rule.for> in rule: " + ruleId)

        if usage.lower() == "data":
            isForInterest = False
        elif usage.lower() == "interest":
            isForInterest = True
        else:
            raise ValidatorConfigError(
              "Unrecognized <rule.for>: " + usage + " in rule: " + ruleId)

        rule = ConfigRule(ruleId, isForInterest)

        # Get rule.filter(s)
        filterList = configSection["filter"]
        for i in range(len(filterList)):
            rule.addFilter(ConfigFilter.create(filterList[i]))

        # Get rule.checker(s)
        checkerList = configSection["checker"]
        for i in range(len(checkerList)):
           rule.addChecker(ConfigChecker.create(checkerList[i]))

        # Check other stuff.
        if len(checkerList) == 0:
            raise ValidatorConfigError(
              "No <rule.checker> is specified in rule: " + ruleId)

        return rule

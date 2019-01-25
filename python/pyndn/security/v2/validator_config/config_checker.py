# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/validator-config/checker.cpp
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
This module defines the ConfigChecker class which is an abstract base class for
ConfigNameRelationChecker, etc. (also in this module) used by ValidatorConfig to
check if a packet name and KeyLocator satisfy the conditions in a configuration
section.
"""

from pyndn.name import Name
from pyndn.util.regex.ndn_regex_top_matcher import NdnRegexTopMatcher
from pyndn.security.pib.pib_key import PibKey
from pyndn.security.v2.validator_config.config_name_relation import ConfigNameRelation
from pyndn.security.validator_config_error import ValidatorConfigError
from pyndn.security.v2.validation_error import ValidationError

class ConfigChecker(object):
    def check(self, isForInterest, packetName, keyLocatorName, state):
        """
        Check if the packet name ane KeyLocator name satisfy this checker's
        conditions.

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
        """
        if isForInterest:
            signedInterestMinSize = 2

            if packetName.size() < signedInterestMinSize:
                return False

            return self.checkNames(
              packetName.getPrefix(-signedInterestMinSize), keyLocatorName, state)
        else:
            return self.checkNames(packetName, keyLocatorName, state)

    @staticmethod
    def create(configSection):
        """
        Create a checker from the configuration section.

        :param BoostInfoTree configSection: The section containing the
          definition of the checker, e.g. one of "validation.rule.checker".
        :return: A new checker created from the configuration section.
        :rtype: ConfigChecker
        """
        # Get checker.type.
        checkerType = configSection.getFirstValue("type")
        if checkerType == None:
            raise ValidatorConfigError("Expected <checker.type>")

        if checkerType.lower() == "customized":
            return ConfigChecker._createCustomizedChecker(configSection)
        elif checkerType.lower() == "hierarchical":
            return ConfigChecker._createHierarchicalChecker(configSection)
        else:
            raise ValidatorConfigError("Unsupported checker type: " + checkerType)

    def checkNames(self, packetName, keyLocatorName, state):
        """
        Check if the packet name ane KeyLocator name satisfy this checker's
        conditions.

        :param Name packetName: The packet name, which is already stripped of
          signature components if this is a signed Interest name.
        :param Name keyLocatorName: The KeyLocator's name.
        :param ValidationState state: This calls state.fail() if the packet is
          invalid.
        :return: True if further signature verification is needed, or False if
          the packet is immediately determined to be invalid in which case this
          calls state.fail() with the proper code and message.
        :rtype: bool
        """
        raise RuntimeError("ConfigChecker.checkNames is not implemented")

    @staticmethod
    def _createCustomizedChecker(configSection):
        """
        :param BoostInfoTree configSection:
        :rtype: ConfigChecker
        """
        # Ignore sig-type.
        # Get checker.key-locator .
        keyLocatorSection = configSection["key-locator"]
        if len(keyLocatorSection) != 1:
            raise ValidatorConfigError("Expected one <checker.key-locator>")

        return ConfigChecker._createKeyLocatorChecker(keyLocatorSection[0])

    @staticmethod
    def _createHierarchicalChecker(configSection):
        """
        :param BoostInfoTree configSection:
        :rtype: ConfigChecker
        """
        # Ignore sig-type.
        return ConfigHyperRelationChecker(
          "^(<>*)$",        "\\1",
          "^(<>*)<KEY><>$", "\\1",
          ConfigNameRelation.Relation.IS_PREFIX_OF)

    @staticmethod
    def _createKeyLocatorChecker(configSection):
        """
        :param BoostInfoTree configSection:
        :rtype: ConfigChecker
        """
        # Get checker.key-locator.type .
        keyLocatorType = configSection.getFirstValue("type")
        if keyLocatorType == None:
            raise ValidatorConfigError("Expected <checker.key-locator.type>")

        if keyLocatorType.lower() == "name":
            return ConfigChecker._createKeyLocatorNameChecker(configSection)
        else:
            raise ValidatorConfigError(
              "Unsupported checker.key-locator.type: " + keyLocatorType)

    @staticmethod
    def _createKeyLocatorNameChecker(configSection):
        """
        :param BoostInfoTree configSection:
        :rtype: ConfigChecker
        """
        nameUri = configSection.getFirstValue("name")
        if nameUri != None:
            name = Name(nameUri)

            relationValue = configSection.getFirstValue("relation")
            if relationValue == None:
                raise ValidatorConfigError(
                  "Expected <checker.key-locator.relation>")

            relation = ConfigNameRelation.getNameRelationFromString(relationValue)
            return ConfigNameRelationChecker(name, relation)

        regexString = configSection.getFirstValue("regex")
        if regexString != None:
            try:
                return ConfigRegexChecker(regexString)
            except:
                raise ValidatorConfigError(
                  "Invalid checker.key-locator.regex: " + regexString)

        hyperRelationList = configSection["hyper-relation"]
        if len(hyperRelationList) == 1:
            hyperRelation = hyperRelationList[0]

            # Get k-regex.
            keyRegex = hyperRelation.getFirstValue("k-regex")
            if keyRegex == None:
                raise ValidatorConfigError(
                  "Expected <checker.key-locator.hyper-relation.k-regex>")

            # Get k-expand.
            keyExpansion = hyperRelation.getFirstValue("k-expand")
            if keyExpansion == None:
                raise ValidatorConfigError(
                  "Expected <checker.key-locator.hyper-relation.k-expand")

            # Get h-relation.
            hyperRelationString = hyperRelation.getFirstValue("h-relation")
            if hyperRelationString == None:
                raise ValidatorConfigError(
                  "Expected <checker.key-locator.hyper-relation.h-relation>")

            # Get p-regex.
            packetNameRegex = hyperRelation.getFirstValue("p-regex")
            if packetNameRegex == None:
                raise ValidatorConfigError(
                  "Expected <checker.key-locator.hyper-relation.p-regex>")

            # Get p-expand.
            packetNameExpansion = hyperRelation.getFirstValue("p-expand")
            if packetNameExpansion == None:
                raise ValidatorConfigError(
                  "Expected <checker.key-locator.hyper-relation.p-expand>")

            relation = ConfigNameRelation.getNameRelationFromString(
              hyperRelationString)

            try:
                return ConfigHyperRelationChecker(
                  packetNameRegex, packetNameExpansion, keyRegex, keyExpansion,
                  relation)
            except:
                raise ValidatorConfigError(
                  "Invalid regex for key-locator.hyper-relation")

        raise ValidatorConfigError("Unsupported checker.key-locator")

class ConfigNameRelationChecker(ConfigChecker):
    """
    :param Name name:
    :param int relation: The value for the ConfigNameRelation.Relation enum.
    """
    def __init__(self, name, relation):
        super(ConfigNameRelationChecker, self).__init__()

        self._name = name
        self._relation = relation

    def checkNames(self, packetName, keyLocatorName, state):
        """
        :param Name packetName:
        :param Name keyLocatorName:
        :param ValidationState state:
        :rtype: bool
        """
        # packetName is not used in this check.

        identity = PibKey.extractIdentityFromKeyName(keyLocatorName)
        result = ConfigNameRelation.checkNameRelation(
          self._relation, self._name, identity)
        if not result:
            state.fail(ValidationError(ValidationError.POLICY_ERROR,
              "KeyLocator check failed: name relation " + self._name.toUri() + " " +
              ConfigNameRelation.toString(self._relation) + " for packet " +
              packetName.toUri() + " is invalid (KeyLocator=" +
              keyLocatorName.toUri() + ", identity=" + identity.toUri() + ")"))

        return result

class ConfigRegexChecker(ConfigChecker):
    """
    :param str regexString:
    """
    def __init__(self, regexString):
        super(ConfigRegexChecker, self).__init__()

        self._regex = NdnRegexTopMatcher(regexString)

    def checkNames(self, packetName, keyLocatorName, state):
        """
        :param Name packetName:
        :param Name keyLocatorName:
        :param ValidationState state:
        :rtype: bool
        """
        result = self._regex.match(keyLocatorName)
        if not result:
            state.fail(ValidationError(ValidationError.POLICY_ERROR,
              "KeyLocator check failed: regex " + self._regex.getExpr() +
              " for packet " + packetName.toUri() + " is invalid (KeyLocator=" +
              keyLocatorName.toUri() + ")"))

        return result

class ConfigHyperRelationChecker(ConfigChecker):
    """
    :param str packetNameRegexString:
    :param str packetNameExpansion:
    :param str keyNameRegexString:
    :param str keyNameExpansion:
    :param int hyperRelation: The value for the ConfigNameRelation.Relation enum.
    """
    def __init__(self, packetNameRegexString, packetNameExpansion,
          keyNameRegexString, keyNameExpansion, hyperRelation):
        super(ConfigHyperRelationChecker, self).__init__()

        self._packetNameRegex = NdnRegexTopMatcher(packetNameRegexString)
        self._packetNameExpansion = packetNameExpansion
        self._keyNameRegex = NdnRegexTopMatcher(keyNameRegexString)
        self._keyNameExpansion = keyNameExpansion
        self._hyperRelation = hyperRelation

    def checkNames(self, packetName, keyLocatorName, state):
        """
        :param Name packetName:
        :param Name keyLocatorName:
        :param ValidationState state:
        :rtype: bool
        """
        if not self._packetNameRegex.match(packetName):
            state.fail(ValidationError(ValidationError.POLICY_ERROR,
              "The packet " + packetName.toUri() + " (KeyLocator=" +
              keyLocatorName.toUri() +
              ") does not match the hyper relation packet name regex " +
              self._packetNameRegex.getExpr()))
            return False
        if not self._keyNameRegex.match(keyLocatorName):
            state.fail(ValidationError(ValidationError.POLICY_ERROR,
              "The packet " + packetName.toUri() + " (KeyLocator=" +
              keyLocatorName.toUri() +
              ") does not match the hyper relation key name regex " +
              self._keyNameRegex.getExpr()))
            return False

        keyNameMatchExpansion = self._keyNameRegex.expand(self._keyNameExpansion)
        packetNameMatchExpansion = self._packetNameRegex.expand(
          self._packetNameExpansion)
        result = ConfigNameRelation.checkNameRelation(
          self._hyperRelation, keyNameMatchExpansion, packetNameMatchExpansion)
        if not result:
            state.fail(ValidationError(ValidationError.POLICY_ERROR,
              "KeyLocator check failed: hyper relation " +
              ConfigNameRelation.toString(self._hyperRelation) +
              " packet name match=" + packetNameMatchExpansion.toUri() +
              ", key name match=" + keyNameMatchExpansion.toUri() + " of packet " +
              packetName.toUri() + " (KeyLocator=" + keyLocatorName.toUri() +
              ") is invalid"))

        return result

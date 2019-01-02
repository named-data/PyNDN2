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
This module defines the ConfigFilter class which is an abstract base class for
RegexNameFilter, etc. (also in this module) used by ValidatorConfig. The
ValidatorConfig class consists of a set of rules. The Filter class is a part of
a rule and is used to match a packet. Matched packets will be checked against
the checkers defined in the rule.
"""

from pyndn.name import Name
from pyndn.util.regex.ndn_regex_top_matcher import NdnRegexTopMatcher
from pyndn.security.v2.validator_config.config_name_relation import ConfigNameRelation
from pyndn.security.validator_config_error import ValidatorConfigError

class ConfigFilter(object):
    def match(self, isForInterest, packetName):
        """
        Call the virtual matchName method based on the packet type.

        :param bool isForInterest: True if packetName is for an Interest, False
          if for a Data packet.
        :param Name packetName: The packet name. For a signed interest, the last
          two components are skipped but not removed.
        :return: True for a match.
        :rtype: bool
        """
        if isForInterest:
            signedInterestMinSize = 2

            if packetName.size() < signedInterestMinSize:
                return False

            return self.matchName(packetName.getPrefix(-signedInterestMinSize))
        else:
            # Data packet.
            return self.matchName(packetName)

    @staticmethod
    def create(configSection):
        """
        Create a filter from the configuration section.

        :param BoostInfoTree configSection: The section containing the
          definition of the filter, e.g. one of "validator.rule.filter".
        :return: A new filter created from the configuration section.
        :rtype: ConfigFilter
        """
        filterType = configSection.getFirstValue("type")
        if filterType == None:
            raise ValidatorConfigError("Expected <filter.type>")

        if filterType.lower() == "name":
            return ConfigFilter._createNameFilter(configSection)
        else:
            raise ValidatorConfigError("Unsupported filter.type: " + filterType)

    def matchName(self, packetName):
        """
        Implementation of the check for match.

        :param Name packetName: The packet name, which is already stripped of
          signature components if this is a signed Interest name.
        :return: True for a match.
        :rtype: bool
        """
        raise RuntimeError("ConfigFilter.matchName is not implemented")

    @staticmethod
    def _createNameFilter(configSection):
        """
        This is a helper for create() to create a filter from the configuration
        section which is type "name".

        :param BoostInfoTree configSection: The section containing the
          definition of the filter.
        :return: A new filter created from the configuration section.
        :rtype: ConfigFilter
        """
        nameUri = configSection.getFirstValue("name")
        if nameUri != None:
            # Get the filter.name.
            name = Name(nameUri)

            # Get the filter.relation.
            relationValue = configSection.getFirstValue("relation")
            if relationValue == None:
                raise ValidatorConfigError("Expected <filter.relation>")

            relation = ConfigNameRelation.getNameRelationFromString(relationValue)

            return ConfigRelationNameFilter(name, relation)

        regexString = configSection.getFirstValue("regex")
        if regexString != None:
            try:
                return ConfigRegexNameFilter(regexString)
            except:
                raise ValidatorConfigError("Wrong filter.regex: " + regexString)

        raise ValidatorConfigError("Wrong filter(name) properties")

class ConfigRelationNameFilter(ConfigFilter):
    """
    ConfigRelationNameFilter extends ConfigFilter to check that the name is in
    the given relation to the packet name. The configuration
    "filter
    {
    type name
    name /example
    relation is-prefix-of
    }"
    creates ConfigRelationNameFilter("/example", ConfigNameRelation.Relation.IS_PREFIX_OF) .

    :param Name name: The relation name, which is copied.
    :param int relation: The relation type as a ConfigNameRelation.Relation enum.
    """
    def __init__(self, name, relation):
        super(ConfigRelationNameFilter, self).__init__()

        # Copy the Name.
        self._name = Name(name)
        self._relation = relation

    def matchName(self, packetName):
        """
        Implementation of the check for match.

        :param Name packetName: The packet name, which is already stripped of
          signature components if this is a signed Interest name.
        :return: True for a match.
        :rtype: bool
        """
        return ConfigNameRelation.checkNameRelation(
          self._relation, self._name, packetName)

class ConfigRegexNameFilter(ConfigFilter):
    """
    ConfigRegexNameFilter extends ConfigFilter to check that the packet name
    matches the specified regular expression. The configuration
    {@code
    "filter
    {
    type name
    regex ^[^<KEY>]*<KEY><>*<ksk-.*>$
    }"}
    creates
    {@code ConfigRegexNameFilter("^[^<KEY>]*<KEY><>*<ksk-.*>$") }.

    :param str regexString: The regex string.
    """
    def __init__(self, regexString):
        super(ConfigRegexNameFilter, self).__init__()

        self._regex = NdnRegexTopMatcher(regexString)

    def matchName(self, packetName):
        """
        Implementation of the check for match.

        :param Name packetName: The packet name, which is already stripped of
          signature components if this is a signed Interest name.
        :return: True for a match.
        :rtype: bool
        """
        return self._regex.match(packetName)

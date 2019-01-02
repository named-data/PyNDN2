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
This module defines the ConfigNameRelation class which defines the
ConfigNameRelation.Relation enum and static methods to work with name relations
for the ValidatorConfig.
"""

from pyndn.security.validator_config_error import ValidatorConfigError

class ConfigNameRelation(object):
    class Relation(object):
        EQUAL = 0
        IS_PREFIX_OF = 1
        IS_STRICT_PREFIX_OF = 2

    @staticmethod
    def toString(relation):
        """
        Get a string representation of the Relation enum.

        :param int relation: The value for the ConfigNameRelation.Relation enum.
        :return: The string representation.
        :rtype: str
        """
        if relation == ConfigNameRelation.Relation.EQUAL:
            return "equal"
        elif relation == ConfigNameRelation.Relation.IS_PREFIX_OF:
            return "is-prefix-of"
        elif relation == ConfigNameRelation.Relation.IS_STRICT_PREFIX_OF:
            return "is-strict-prefix-of"
        else:
            # We don't expect this to happen.
            return ""

    @staticmethod
    def checkNameRelation(relation, name1, name2):
        """
        Check whether name1 and name2 satisfy the relation.

        :param int relation: The value for the ConfigNameRelation.Relation enum.
        :param Name name1: The first name to check.
        :param Name name2: The second name to check.
        :return: True if the names satisfy the relation.
        :rtype: bool
        """
        if relation == ConfigNameRelation.Relation.EQUAL:
            return name1.equals(name2)
        elif relation == ConfigNameRelation.Relation.IS_PREFIX_OF:
            return name1.isPrefixOf(name2)
        elif relation == ConfigNameRelation.Relation.IS_STRICT_PREFIX_OF:
            return name1.isPrefixOf(name2) and name1.size() < name2.size()
        else:
            # We don't expect this to happen.
            return False

    @staticmethod
    def getNameRelationFromString(relationString):
        """
        Convert relationString to a Relation enum.

        :param str relationString: the string to convert.
        :return: The value for the ConfigNameRelation.Relation enum.
        :rtype: int
        :raises: ValidatorConfigError if relationString cannot be converted.
        """
        if relationString.lower() == "equal":
            return ConfigNameRelation.Relation.EQUAL
        elif relationString.lower() == "is-prefix-of":
            return ConfigNameRelation.Relation.IS_PREFIX_OF
        elif relationString.lower() == "is-strict-prefix-of":
            return ConfigNameRelation.Relation.IS_STRICT_PREFIX_OF
        else:
            raise ValidatorConfigError("Unsupported relation: " +
             relationString)


# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2016 Regents of the University of California.
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
This module defines the InterestFilter class which holds a Name prefix and
optional regex match expression for use in Face.setInterestFilter.
"""

from pyndn.name import Name
from pyndn.util.ndn_regex import NdnRegexMatcher

class InterestFilter(object):
    """
    Create an InterestFilter to match any Interest whose name starts with the
    given prefix. If the optional regexFilter is provided then the remaining
    components match the regexFilter regular expression as described in
    doesMatch.

    :param prefix: The prefix. If a Name then this makes a copy of the Name.
      Otherwise it create a Name from the URI string.
    :type prefix: Name or str
    :param str regexFilter: (optional) The regular expression for matching the
      remaining name components.
    """
    def __init__(self, prefix, regexFilter = None):
        if type(prefix) is InterestFilter:
            interestFilter = prefix
            # The copy constructor.
            self._prefix = Name(interestFilter._prefix)
            self._regexFilter = interestFilter._regexFilter
            self._regexFilterPattern = interestFilter._regexFilterPattern
        else:
            self._prefix = Name(prefix)
            self._regexFilter = regexFilter
            if regexFilter != None:
                self._regexFilterPattern = self.makePattern(regexFilter)
            else:
                self._regexFilterPattern = None

    def doesMatch(self, name):
        """
        Check if the given name matches this filter. Match if name starts with
        this filter's prefix. If this filter has the optional regexFilter then
        the remaining components match the regexFilter regular expression.
        For example, the following InterestFilter:

           InterestFilter("/hello", "<world><>+")

        will match all Interests, whose name has the prefix `/hello` which is
        followed by a component `world` and has at least one more component
        after it. Examples:

           /hello/world/!
           /hello/world/x/y/z

        Note that the regular expression will need to match all remaining
        components (e.g., there are implicit heading `^` and trailing `$`
        symbols in the regular expression).

        :param Name name: The name to check against this filter.
        :return: True if name matches this filter, otherwise False.
        :rtype: bool
        """
        if len(name) < len(self._prefix):
            return False

        if self.hasRegexFilter():
            # Perform a prefix match and regular expression match for the
            # remaining components.
            if not self._prefix.match(name):
                return False

            return None != NdnRegexMatcher.match(
              self._regexFilterPattern, name.getSubName(len(self._prefix)))
        else:
            # Just perform a prefix match.
            return self._prefix.match(name)

    def getPrefix(self):
        """
        Get the prefix given to the constructor.

        :return: The prefix Name which you should not modify.
        :rtype: Name
        """
        return self._prefix

    def hasRegexFilter(self):
        """
        Check if a regexFilter was supplied to the constructor.

        :return: True if a regexFilter was supplied to the constructor.
        :rtype: bool
        """
        return self._regexFilter != None

    def getRegexFilter(self):
        """
        Get the regex filter. This is only valid if hasRegexFilter() is True.

        :return: The regular expression for matching the remaining name
          components.
        :rtype: str
        """
        return self._regexFilter

    @staticmethod
    def makePattern(regexFilter):
        """
        If regexFilter doesn't already have them, add ^ to the beginning and $
        to the end since these are required by NdnRegexMatcher.match.

        :param str regexFilter: The regex filter.
        :return: The regex pattern with ^ and $.
        :rtype str:
        """
        if len(regexFilter) == 0:
            # We don't expect this.
            return "^$"

        pattern = regexFilter
        if pattern[0] != '^':
            pattern = "^" + pattern
        if pattern[-1] != '$':
            pattern = pattern + "$"

        return pattern

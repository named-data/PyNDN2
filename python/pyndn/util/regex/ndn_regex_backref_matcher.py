# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Yingdi Yu <http://irl.cs.ucla.edu/~yingdi/>
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

from pyndn.util.regex.ndn_regex_matcher_base import NdnRegexMatcherBase

class NdnRegexBackrefMatcher(NdnRegexMatcherBase):
    """
    Create an NdnRegexBackrefMatcher.

    :param str expr:
    :param NdnRegexBackrefManager backrefManager:
    """
    def __init__(self, expr, backrefManager):
        super(NdnRegexBackrefMatcher, self).__init__(
          expr, NdnRegexMatcherBase.NdnRegexExprType.BACKREF, backrefManager)

    def lateCompile(self):
        self._compile()

    def _compile(self):
        if len(self._expr) < 2:
            raise NdnRegexMatcherBase.Error("Unrecognized format: " + self._expr)

        lastIndex = len(self._expr) - 1
        if '(' == self._expr[0] and ')' == self._expr[lastIndex]:
            matcher = NdnRegexPatternListMatcher(
              self._expr[1:lastIndex], self._backrefManager)
            self._matchers.append(matcher)
        else:
            raise NdnRegexMatcherBase.Error("Unrecognized format: " + self._expr)

# Put this last to avoid an import loop.
from pyndn.util.regex.ndn_regex_pattern_list_matcher import NdnRegexPatternListMatcher

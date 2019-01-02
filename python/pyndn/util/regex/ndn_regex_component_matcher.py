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

import re
from pyndn.util.regex.ndn_regex_matcher_base import NdnRegexMatcherBase

class NdnRegexComponentMatcher(NdnRegexMatcherBase):
    """
    Create a RegexComponent matcher from expr.

    :param str expr: The standard regular expression to match a component.
    :param NdnRegexBackrefManager backrefManager: The back reference manager.
    :param bool isExactMatch: (optional) The flag to provide exact match. If
      omitted, use True.
    """
    def __init__(self, expr, backrefManager, isExactMatch = True):
        super(NdnRegexComponentMatcher, self).__init__(
          expr, NdnRegexMatcherBase.NdnRegexExprType.COMPONENT, backrefManager)
        self._componentRegex = None
        # Array of NdnRegexPseudoMatcher
        self._pseudoMatchers = []

        self._isExactMatch = isExactMatch

        self._compile()

    def match(self, name, offset, length):
        """
        :param Name name:
        :param int offset:
        :param int length:
        :rtype: bool
        """
        self._matchResult = []

        if self._expr == "":
            self._matchResult.append(name.get(offset))
            return True

        if self._isExactMatch:
            targetStr = name.get(offset).toEscapedString()
            subResult = self._componentRegex.search(targetStr)
            if subResult != None:
                for i in range(1, self._componentRegex.groups + 1):
                    self._pseudoMatchers[i].resetMatchResult()
                    self._pseudoMatchers[i].setMatchResult(subResult.group(i))

                self._matchResult.append(name.get(offset))
                return True
        else:
            raise NdnRegexMatcherBase.Error(
              "Non-exact component search is not supported yet")

        return False

    def _compile(self):
        self._componentRegex = re.compile(self._expr)

        self._pseudoMatchers = []
        self._pseudoMatchers.append(NdnRegexPseudoMatcher())

        for i in range(1, self._componentRegex.groups + 1):
            pMatcher = NdnRegexPseudoMatcher()
            self._pseudoMatchers.append(pMatcher)
            self._backrefManager.pushRef(pMatcher)

# Put this last to avoid an import loop.
from pyndn.util.regex.ndn_regex_pseudo_matcher import NdnRegexPseudoMatcher

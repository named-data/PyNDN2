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

class NdnRegexComponentSetMatcher(NdnRegexMatcherBase):
    """
    Create an NdnRegexComponentSetMatcher matcher from expr.

    :param str expr: The standard regular expression to match a component.
    :param NdnRegexBackrefManager backrefManager: A back-reference manager.
    """
    def __init__(self, expr, backrefManager):
        super(NdnRegexComponentSetMatcher, self).__init__(
          expr, NdnRegexMatcherBase.NdnRegexExprType.COMPONENT_SET,
          backrefManager)
        # Array of NdnRegexComponentMatcher
        self._components = []
        self._isInclusion = True

        self._compile()

    def match(self, name, offset, length):
        """
        :param Name name:
        :param int offset:
        :param int length:
        :rtype: bool
        """
        isMatched = False

        # ComponentSet only matches one component.
        if length != 1:
            return False

        for matcher in self._components:
            if matcher.match(name, offset, length):
                isMatched = True
                break

        self._matchResult = []

        if (isMatched if self._isInclusion else not isMatched):
            self._matchResult.append(name.get(offset))
            return True
        else:
            return False

    def _compile(self):
        """
        Compile the regular expression to generate more matchers when necessary.
        """
        if len(self._expr) < 2:
            raise NdnRegexMatcherBase.Error(
              "Regexp compile error (cannot parse " + self._expr + ")")

        if self._expr[0] == '<':
            self._compileSingleComponent()
        elif self._expr[0] == '[':
            lastIndex = len(self._expr) - 1
            if ']' != self._expr[lastIndex]:
                raise NdnRegexMatcherBase.Error(
                  "Regexp compile error (no matching ']' in " + self._expr + ")")

            if '^' == self._expr[1]:
                self._isInclusion = False
                self._compileMultipleComponents(2, lastIndex)
            else:
                self._compileMultipleComponents(1, lastIndex)
        else:
            raise NdnRegexMatcherBase.Error(
              "Regexp compile error (cannot parse " + self._expr + ")")

    def _extractComponent(self, index):
        """
        :param int index:
        :rtype: int
        """
        lcount = 1
        rcount = 0

        while lcount > rcount:
            if index >= len(self._expr):
                raise NdnRegexMatcherBase.Error("Error: angle brackets mismatch")

            if self._expr[index] == '<':
                lcount += 1
            elif self._expr[index] == '>':
                rcount += 1

            index += 1

        return index

    def _compileSingleComponent(self):
        end = self._extractComponent(1)

        if len(self._expr) != end:
            raise NdnRegexMatcherBase.Error("Component expr error " + self._expr)
        else:
            component = NdnRegexComponentMatcher(
              self._expr[1 : end - 1], self._backrefManager)

            self._components.append(component)

    def _compileMultipleComponents(self, start, lastIndex):
        """
        :param int start:
        :param int lastIndex:
        """
        index = start
        tempIndex = start

        while index < lastIndex:
            if '<' != self._expr[index]:
                raise NdnRegexMatcherBase.Error(
                  "Component expr error " + self._expr)

            tempIndex = index + 1
            index = self._extractComponent(tempIndex)

            component = NdnRegexComponentMatcher(
              self._expr[tempIndex : index - 1], self._backrefManager)

            self._components.append(component)

        if index != lastIndex:
            raise NdnRegexMatcherBase.Error(
              "Not sufficient expr to parse " + self._expr)

# Put this last to avoid an import loop.
from pyndn.util.regex.ndn_regex_component_matcher import NdnRegexComponentMatcher

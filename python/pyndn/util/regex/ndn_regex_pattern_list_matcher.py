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

class NdnRegexPatternListMatcher(NdnRegexMatcherBase):
    """
    Create an NdnRegexPatternListMatcher.

    :param str expr:
    :param NdnRegexBackrefManager backrefManager:
    """
    def __init__(self, expr, backrefManager):
        super(NdnRegexPatternListMatcher, self).__init__(
          expr, NdnRegexMatcherBase.NdnRegexExprType.PATTERN_LIST, backrefManager)

        self._compile()

    def _compile(self):
        length = len(self._expr)
        index = [0]
        subHead = index[0]

        while index[0] < length:
            subHead = index[0]

            if not self._extractPattern(subHead, index):
                 raise NdnRegexMatcherBase.Error("Compile error")

    def _extractPattern(self, index, next):
        """
        :param int index:
        :param Array<int> next: Update next[0]
        :rtype: bool
        """
        start = index
        end = index
        indicator = index

        if self._expr[index] == '(':
            index += 1
            index = self._extractSubPattern('(', ')', index)
            indicator = index
            end = self._extractRepetition(index)
            if indicator == end:
                matcher = NdnRegexBackrefMatcher(
                  self._expr[start : end], self._backrefManager)
                self._backrefManager.pushRef(matcher)
                matcher.lateCompile()

                self._matchers.append(matcher)
            else:
                self._matchers.append(NdnRegexRepeatMatcher
                  (self._expr[start : end], self._backrefManager,
                   indicator - start))
        elif self._expr[index] == '<':
            index += 1
            index = self._extractSubPattern('<', '>', index)
            indicator = index
            end = self._extractRepetition(index)
            self._matchers.append(NdnRegexRepeatMatcher
              (self._expr[start : end], self._backrefManager, indicator - start))
        elif self._expr[index] == '[':
            index += 1
            index = self._extractSubPattern('[', ']', index)
            indicator = index
            end = self._extractRepetition(index)
            self._matchers.append(NdnRegexRepeatMatcher
              (self._expr[start : end], self._backrefManager, indicator - start))
        else:
            raise NdnRegexMatcherBase.Error("Unexpected syntax")

        next[0] = end

        return True

    def _extractSubPattern(self, left, right, index):
        """
        :param str left:
        :param str right:
        :param int index:
        :rtype: int
        """
        lcount = 1
        rcount = 0

        while lcount > rcount:
            if index >= len(self._expr):
                raise NdnRegexMatcherBase.Error("Parenthesis mismatch")

            if left == self._expr[index]:
                lcount += 1

            if right == self._expr[index]:
                rcount += 1

            index += 1

        return index

    def _extractRepetition(self, index):
        """
        :param int index:
        :rtype: int
        """
        exprSize = len(self._expr)

        if index == exprSize:
            return index

        if ('+' == self._expr[index] or '?' == self._expr[index] or
            '*' == self._expr[index]):
            index += 1
            return index

        if '{' == self._expr[index]:
            while '}' != self._expr[index]:
                index += 1
                if index == exprSize:
                    break

            if index == exprSize:
                raise NdnRegexMatcherBase.Error("Missing right brace bracket")
            else:
                index += 1
                return index
        else:
            return index

# Put these last to avoid an import loop.
from pyndn.util.regex.ndn_regex_backref_matcher import NdnRegexBackrefMatcher
from pyndn.util.regex.ndn_regex_repeat_matcher import NdnRegexRepeatMatcher

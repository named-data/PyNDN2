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

class NdnRegexRepeatMatcher(NdnRegexMatcherBase):
    """
    Create an NdnRegexRepeatMatcher.

    :param str expr:
    :param NdnRegexBackrefManager backrefManager:
    :param int indicator:
    """
    def __init__(self, expr, backrefManager, indicator):
        super(NdnRegexRepeatMatcher, self).__init__(
          expr, NdnRegexMatcherBase.NdnRegexExprType.REPEAT_PATTERN, backrefManager)
        self._repeatMin = 0
        self._repeatMax = 0

        self._indicator = indicator

        self._compile()

    def match(self, name, offset, length):
        """
        :param Name name:
        :param int offset:
        :param int length:
        :rtype: bool
        """
        self._matchResult = []

        if 0 == self._repeatMin:
            if 0 == length:
                return True

        if self._recursiveMatch2(0, name, offset, length):
            for i in range(offset, offset + length):
                self._matchResult.append(name.get(i))
            return True
        else:
            return False

    def _compile(self):
        """
        Compile the regular expression to generate more matchers when necessary.
        """
        if '(' == self._expr[0]:
            matcher = NdnRegexBackrefMatcher(
              self._expr[0 : self._indicator], self._backrefManager)
            self._backrefManager.pushRef(matcher)
            matcher.lateCompile()
        else:
            matcher = NdnRegexComponentSetMatcher(
              self._expr[0 : self._indicator], self._backrefManager)

        self._matchers.append(matcher)

        self._parseRepetition()

    def _parseRepetition(self):
        exprSize = len(self._expr)
        MAX_REPETITIONS = 32767

        if exprSize == self._indicator:
            self._repeatMin = 1
            self._repeatMax = 1

            return True
        else:
            if exprSize == self._indicator + 1:
                if '?' == self._expr[self._indicator]:
                    self._repeatMin = 0
                    self._repeatMax = 1
                    return True
                if '+' == self._expr[self._indicator]:
                    self._repeatMin = 1
                    self._repeatMax = MAX_REPETITIONS
                    return True
                if '*' == self._expr[self._indicator]:
                    self._repeatMin = 0
                    self._repeatMax = MAX_REPETITIONS
                    return True
            else:
                repeatStruct = self._expr[self._indicator : exprSize]
                rsSize = len(repeatStruct)
                min = 0
                max = 0

                if re.match("\\{[0-9]+,[0-9]+\\}", repeatStruct) != None:
                    separator = repeatStruct.index(',')
                    min = int(repeatStruct[1 : separator])
                    max = int(repeatStruct[separator + 1 : rsSize - 1])
                elif re.match("\\{,[0-9]+\\}", repeatStruct) != None:
                    separator = repeatStruct.index(',')
                    min = 0
                    max = int(repeatStruct[separator + 1 : rsSize - 1])
                elif re.match("\\{[0-9]+,\\}", repeatStruct) != None:
                    separator = repeatStruct.index(',')
                    min = int(repeatStruct[1 : separator])
                    max = MAX_REPETITIONS
                elif re.match("\\{[0-9]+\\}", repeatStruct) != None:
                    min = int(repeatStruct[1 : rsSize - 1])
                    max = min
                else:
                    raise NdnRegexMatcherBase.Error(
                      "Error: RegexRepeatMatcher.ParseRepetition(): Unrecognized format " +
                      self._expr)

                if min > MAX_REPETITIONS or max > MAX_REPETITIONS or min > max:
                    raise NdnRegexMatcherBase.Error(
                      "Error: RegexRepeatMatcher.ParseRepetition(): Wrong number " +
                      self._expr)

                self._repeatMin = min
                self._repeatMax = max

                return True

        return False

    def _recursiveMatch2(self, repeat, name, offset, length):
        """
        :param int repeat:
        :param Name name:
        :param int offset:
        :param int length:
        :rtype bool:
        """
        tried = length
        matcher = self._matchers[0]

        if 0 < length and repeat >= self._repeatMax:
            return False

        if 0 == length and repeat < self._repeatMin:
            return False

        if 0 == length and repeat >= self._repeatMin:
            return True

        while tried >= 0:
            if (matcher.match(name, offset, tried) and
                self._recursiveMatch2(repeat + 1, name, offset + tried,
                                      length - tried)):
                return True
            tried -= 1

        return False

# Put these last to avoid an import loop.
from pyndn.util.regex.ndn_regex_backref_matcher import NdnRegexBackrefMatcher
from pyndn.util.regex.ndn_regex_component_set_matcher import NdnRegexComponentSetMatcher

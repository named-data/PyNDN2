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

from pyndn.name import Name
from pyndn.util.regex.ndn_regex_matcher_base import NdnRegexMatcherBase
from pyndn.util.regex.ndn_regex_backref_manager import NdnRegexBackrefManager
from pyndn.util.regex.ndn_regex_pattern_list_matcher import NdnRegexPatternListMatcher

class NdnRegexTopMatcher(NdnRegexMatcherBase):
    """
    Create an NdnRegexTopMatcher.

    :param str expr: The expression.
    :param str expand:
    """
    def __init__(self, expr, expand = ""):
        super(NdnRegexTopMatcher, self).__init__(
          expr, NdnRegexMatcherBase.NdnRegexExprType.TOP)
        self._primaryMatcher = None
        self._secondaryMatcher = None
        self._primaryBackrefManager = NdnRegexBackrefManager()
        self._secondaryBackrefManager = NdnRegexBackrefManager()
        self._isSecondaryUsed = False

        self._expand = expand

        self._compile()

    def match(self, name, offset = None, length = None):
        """
        :param Name name:
        :param int offset: Ignored.
        :param int length: Ignored.
        :rtype: bool
        """
        self._isSecondaryUsed = False

        self._matchResult = []

        if self._primaryMatcher.match(name, 0, name.size()):
            self._matchResult = []
            for component in self._primaryMatcher.getMatchResult():
                self._matchResult.append(component)
            return True
        else:
            if (self._secondaryMatcher != None and
                self._secondaryMatcher.match(name, 0, name.size())):
                self._matchResult = []
                for component in self._secondaryMatcher.getMatchResult():
                    self._matchResult.append(component)
                self._isSecondaryUsed = True
                return True

            return False

    def expand(self, expandStr = ""):
        """
        :param str expandStr:
        :rtype: Name
        """
        result = Name()

        backrefManager = (self._secondaryBackrefManager if self._isSecondaryUsed
                          else self._primaryBackrefManager)

        backrefNo = backrefManager.size()

        if expandStr != "":
            usingExpand = expandStr
        else:
            usingExpand = self._expand

        offset = [0]
        while offset[0] < len(usingExpand):
            item = NdnRegexTopMatcher._getItemFromExpand(usingExpand, offset)
            if item[0] == '<':
                result.append(item[1 : len(item) - 1])

            if item[0] == '\\':
                index = int(item[1 : len(item)])

                if 0 == index:
                    for component in self._matchResult:
                        result.append(component)
                elif index <= backrefNo:
                    for component in backrefManager.getBackref(
                                       index - 1).getMatchResult():
                        result.append(component)
                else:
                    raise NdnRegexMatcherBase.Error(
                      "Exceeded the range of back reference")

        return result

    @staticmethod
    def fromName(name, hasAnchor = False):
        """
        :param Name name:
        :param bool hasAnchor:
        :rtype: NdnRegexTopMatcher
        """
        regexStr = "^"

        for i in range(name.size()):
            regexStr += "<"
            regexStr += NdnRegexTopMatcher._convertSpecialChar(
              name.get(i).toEscapedString())
            regexStr += ">"

        if hasAnchor:
            regexStr += "$"

        return NdnRegexTopMatcher(regexStr)

    def _compile(self):
        errMsg = "Error: RegexTopMatcher.Compile(): "

        expr = self._expr

        if '$' != expr[-1]:
            expr = expr + "<.*>*"
        else:
            expr = expr[0 : -1]

        if '^' != expr[0]:
            self._secondaryMatcher = NdnRegexPatternListMatcher(
              "<.*>*" + expr, self._secondaryBackrefManager)
        else:
            expr = expr[1:]

        self._primaryMatcher = NdnRegexPatternListMatcher(
           expr, self._primaryBackrefManager)

    @staticmethod
    def _getItemFromExpand(expand, offset):
        """
        :param str expand:
        :param Array<int> offset: This updates offset[0].
        :rtype: str
        """
        begin = offset[0]

        if expand[offset[0]] == '\\':
            offset[0] += 1
            if offset[0] >= len(expand):
                raise NdnRegexMatcherBase.Error("Wrong format of expand string!")

            while (offset[0] < len(expand) and
                   expand[offset[0]] <= '9' and expand[offset[0]] >= '0'):
                offset[0] += 1
                if offset[0] > len(expand):
                    raise NdnRegexMatcherBase.Error(
                      "Wrong format of expand string!")

            if offset[0] > begin + 1:
                return expand[begin : offset[0]]
            else:
                raise NdnRegexMatcherBase.Error("Wrong format of expand string!")
        elif expand[offset[0]] == '<':
            offset[0] += 1
            if offset[0] >= len(expand):
                raise NdnRegexMatcherBase.Error("Wrong format of expand string!")

            left = 1
            right = 0
            while right < left:
                if expand[offset[0]] == '<':
                    left += 1
                if expand[offset[0]] == '>':
                    right += 1

                offset[0] += 1
                if offset[0] >= len(expand):
                    raise NdnRegexMatcherBase.Error(
                      "Wrong format of expand string!")

            return expand[begin : offset[0]]
        else:
            raise NdnRegexMatcherBase.Error("Wrong format of expand string!")

    @staticmethod
    def _convertSpecialChar(string):
        """
        :param str string:
        :rtype: str
        """
        newStr = ""
        for c in string:
          if (c == '.' or
              c == '[' or
              c == '{' or
              c == '}' or
              c == '(' or
              c == ')' or
              c == '\\' or
              c == '*' or
              c == '+' or
              c == '?' or
              c == '|' or
              c == '^' or
              c == '$'):
              newStr += '\\'
              newStr += c
          else:
              newStr += c

        return newStr

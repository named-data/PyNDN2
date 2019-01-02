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

from pyndn.util.regex.ndn_regex_backref_manager import NdnRegexBackrefManager

class NdnRegexMatcherBase(object):
    """
    Create an instance of the abstract class NdnRegexMatcherBase.

    :param str expr: The expression.
    :param type:
    :type type: An int from the NdnRegexMatcherBase.NdnRegexExprType enum
    :param NdnRegexBackrefManager backrefManager: (optional) The
      NdnRegexBackrefManager to use. If omitted or None, use a new
      NdnRegexBackrefManager().
    """
    def __init__(self, expr, type, backrefManager = None):
        # Array of NdnRegexMatcherBase
        self._matchers = []
        # Array of Name.Component
        self._matchResult = []

        self._expr = expr
        self._type = type
        if backrefManager == None:
            backrefManager = NdnRegexBackrefManager()
        self._backrefManager = backrefManager

    class Error(Exception):
        """
        Create an NdnRegexMatcherBase.Error for errors using
        NdnRegexMatcherBase methods.

        :param str message: The error message.
        """
        def __init__(self, message):
            super(NdnRegexMatcherBase.Error, self).__init__(message)

    class NdnRegexExprType(object):
        TOP = 0
        PATTERN_LIST = 1
        REPEAT_PATTERN = 2
        BACKREF = 3
        COMPONENT_SET = 4
        COMPONENT = 5
        PSEUDO = 6

    def match(self, name, offset, length):
        """
        :param Name name:
        :param int offset:
        :param int length:
        :rtype: bool
        """
        result = False

        self._matchResult = []

        if self._recursiveMatch(0, name, offset, length):
            i = offset
            while i < offset + length:
                self._matchResult.append(name.get(i))
                i += 1
            result = True
        else:
            result = False

        return result

    def getMatchResult(self):
        """
        Get the list of matched name components.

        :return: The matched name components. You must not modify this list.
        :rtype: Array<Name.Component>
        """
        return self._matchResult

    def getExpr(self):
        """
        :rtype: str
        """
        return self._expr

    def _compile(self):
        """
        Compile the regular expression to generate more matchers when necessary.
        """
        raise RuntimeError("NdnRegexMatcherBase.compile is not implemented")

    def _recursiveMatch(self, matcherNo, name, offset, length):
        """
        :param int matcherNo:
        :param Name name:
        :param int offset:
        :param int length:
        :rtype: bool
        """
        tried = length

        if matcherNo >= len(self._matchers):
            return (length == 0)

        matcher = self._matchers[matcherNo]

        while tried >= 0:
            if (matcher.match(name, offset, tried) and
                self._recursiveMatch(
                  matcherNo + 1, name, offset + tried, length - tried)):
                return True
            tried -= 1

        return False

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

class NdnRegexPseudoMatcher(NdnRegexMatcherBase):
    """
    Create an NdnRegexPseudoMatcher.
    """
    def __init__(self):
        super(NdnRegexPseudoMatcher, self).__init__(
          "", NdnRegexMatcherBase.NdnRegexExprType.PSEUDO)

    def _compile(self):
        pass

    def setMatchResult(self, value):
        """
        :param str value:
        """
        self._matchResult.append(Name.Component(value))

    def resetMatchResult(self):
        self._matchResult = []

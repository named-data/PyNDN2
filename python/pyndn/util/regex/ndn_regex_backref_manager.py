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

class NdnRegexBackrefManager(object):
    def __init__(self):
        # Array of NdnRegexMatcherBase
        self._backrefs = []

    def pushRef(self, matcher):
        """
        :param NdnRegexMatcherBase matcher:
        :rtype: int
        """
        last = len(self._backrefs)
        self._backrefs.append(matcher)

        return last

    def popRef(self):
        self._backrefs.pop()

    def size(self):
        """
        :rtype: int
        """
        return len(self._backrefs)

    def getBackref(self, i):
        """
        :param int i:
        :rtype: NdnRegexMatcherBase
        """
        return self._backrefs[i]

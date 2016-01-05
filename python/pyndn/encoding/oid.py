# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From code in ndn-cxx by Yingdi Yu <yingdi@cs.ucla.edu>
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

class OID(object):
    def __init__(self, oid = None):
        if oid is None:
            self._oid = []
        elif type(oid) is str:
            self._oid = [int(p) for p in oid.split('.')]
        else:
            # Assume oid is an array of int.  Make a copy.
            self._oid = oid[:]

    def getIntegerList(self):
        return self._oid

    def setIntegerList(self, oid):
        # Make a copy.
         self._oid = oid[:]

    def __str__(self):
        result = ""
        for i in range(len(self._oid)):
            if i != 0:
                result += "."
            result += repr(self._oid[i])

        return result

    def __eq__(self, other):
        if not (type(other) is OID):
            return False
        if len(self._oid) != len(other._oid):
            return False

        for i in range(len(self._oid)):
            if self._oid[i] != other._oid[i]:
                return False

        return True

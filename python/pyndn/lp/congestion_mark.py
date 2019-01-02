# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
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

"""
This module defines the CongestionMark class which represents the congestion
mark header field in an NDNLPv2 packet.
http://redmine.named-data.net/projects/nfd/wiki/NDNLPv2
"""

class CongestionMark(object):
    def __init__(self):
        self._congestionMark = 0

    def getCongestionMark(self):
        """
        Get the congestion mark value.

        :return: The congestion mark value.
        :rtype: int
        """
        return self._congestionMark

    def setCongestionMark(self, congestionMark):
        """
        Set the congestion mark value.

        :param int congestionMark: The congestion mark ID value.
        """
        self._congestionMark = congestionMark

    @staticmethod
    def getFirstHeader(lpPacket):
        """
        Get the first header field in lpPacket which is an CongestionMark. This
        is an internal method which the application normally would not use.

        :param LpPacket lpPacket: The LpPacket with the header fields to search.
        :return: The first CongestionMark header field, or None if not found.
        :rtype: CongestionMark
        """
        for i in range(lpPacket.countHeaderFields()):
            field = lpPacket.getHeaderField(i)
            if isinstance(field, CongestionMark):
                return field

        return None

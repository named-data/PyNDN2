# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx fields.hpp https://github.com/named-data/ndn-cxx/blob/master/src/lp/fields.hpp
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
This module defines the IncomingFaceId class which represents the incoming face
ID header field in an NDNLPv2 packet.
http://redmine.named-data.net/projects/nfd/wiki/NDNLPv2
"""

class IncomingFaceId(object):
    def __init__(self):
        self._faceId = None

    def getFaceId(self):
        """
        Get the incoming face ID value.

        :return: The face ID value.
        :rtype: int
        """
        return self._faceId

    def setFaceId(self, faceId):
        """
        Set the face ID value.

        :param int faceId: The incoming face ID value.
        """
        self._faceId = faceId

    @staticmethod
    def getFirstHeader(lpPacket):
        """
        Get the first header field in lpPacket which is an IncomingFaceId. This
        is an internal method which the application normally would not use.

        :param LpPacket lpPacket: The LpPacket with the header fields to search.
        :return: The first IncomingFaceId header field, or None if not found.
        :rtype: IncomingFaceId
        """
        for i in range(lpPacket.countHeaderFields()):
            field = lpPacket.getHeaderField(i)
            if isinstance(field, IncomingFaceId):
                return field

        return None

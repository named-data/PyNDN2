# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx nack.hpp https://github.com/named-data/ndn-cxx/blob/master/src/lp/nack.hpp
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
This module defines the NetworkNack class which represents a network Nack packet
and includes a Nack reason.
"""

class NetworkNack(object):
    def __init__(self):
        self._reason = NetworkNack.Reason.NONE
        self._otherReasonCode = -1

    class Reason(object):
        """
        A NetworkNack.Reason specifies the reason in a NetworkNack packet. If
        the reason code in the packet is not a recognized enum value, then we
        use Reason.OTHER_CODE and you can call getOtherReasonCode(). We do this
        to keep the recognized reason values independent of packet encoding
        formats.
        """
        NONE =         0
        OTHER_CODE =   1
        CONGESTION =  50
        DUPLICATE =  100
        NO_ROUTE =   150

    def getReason(self):
        """
        Get the network Nack reason.

        :return: The reason enum value. If this is Reason.OTHER_CODE, then call
          getOtherReasonCode() to get the unrecognized reason code.
        :rtype: an int from NetworkNack.Reason
        """
        return self._reason

    def getOtherReasonCode(self):
        """
        Get the reason code from the packet which is other than a recognized
        Reason enum value. This is only meaningful if getReason() is
        Reason.OTHER_CODE.

        :return: The reason code.
        :rtype: int
        """
        return self._otherReasonCode

    def setReason(self, reason):
        """
        Set the network Nack reason.

        :param reason: The network Nack reason enum value. If the packet's
          reason code is not a recognized Reason enum value, use
          Reason.OTHER_CODE and call setOtherReasonCode().
        :type reason: an int from NetworkNack.Reason
        """
        self._reason = reason

    def setOtherReasonCode(self, otherReasonCode):
        """
        Set the packet's reason code to use when the reason enum is
        Reason.OTHER_CODE. If the packet's reason code is a recognized enum
        value, just call setReason().

        :param int otherReasonCode: The packet's unrecognized reason code.
        """
        self._otherReasonCode = otherReasonCode

    @staticmethod
    def getFirstHeader(lpPacket):
        """
        Get the first header field in lpPacket which is a NetworkNack. This is
        an internal method which the application normally would not use.

        :param LpPacket lpPacket: The LpPacket with the header fields to search.
        :return: The first NetworkNack header field, or None if not found.
        :rtype: NetworkNack
        """
        for i in range(lpPacket.countHeaderFields()):
            field = lpPacket.getHeaderField(i)
            if isinstance(field, NetworkNack):
                return field

        return None

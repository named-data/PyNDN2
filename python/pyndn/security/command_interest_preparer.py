# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/command-interest-signer.cpp
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
This module defines the CommandInterestPreparer class which keeps track of a
timestamp and prepares a command interest by adding a timestamp and nonce to the
name of an Interest. This class is primarily designed to be used by the
CommandInterestSigner, but can also be using in an application that defines
custom signing methods not supported by the KeyChain (such as HMAC-SHA1). See
the Command Interest documentation:
https://redmine.named-data.net/projects/ndn-cxx/wiki/CommandInterest
"""

from random import SystemRandom
from pyndn.util.blob import Blob
from pyndn.util.common import Common
from pyndn.encoding.tlv.tlv_encoder import TlvEncoder
from pyndn.encoding.wire_format import WireFormat

# The Python documentation says "Use SystemRandom if you require a
#   cryptographically secure pseudo-random number generator."
# http://docs.python.org/2/library/random.html
_systemRandom = SystemRandom()

class CommandInterestPreparer(object):
    """
    Create a CommandInterestPreparer and initialize the timestamp to now.
    """
    def __init__(self):
        self._lastUsedTimestamp = round(Common.getNowMilliseconds())
        self._nowOffsetMilliseconds = 0

    def prepareCommandInterestName(self, interest, wireFormat = None):
        """
        Append a timestamp component and a random nonce component to interest's
        name. This ensures that the timestamp is greater than the timestamp used
        in the previous call.

        :param Interest interest: The interest whose name is append with
          components.
        :param WireFormat wireFormat: (optional) A WireFormat object used to
          encode the SignatureInfo. If omitted, use WireFormat
          getDefaultWireFormat().
        """
        if wireFormat == None:
            wireFormat = WireFormat.getDefaultWireFormat()

        # _nowOffsetMilliseconds is only used for testing.
        now = Common.getNowMilliseconds() + self._nowOffsetMilliseconds
        timestamp =  round(now)
        while timestamp <= self._lastUsedTimestamp:
          timestamp += 1.0

        # Update the timestamp now. In the small chance that signing fails, it
        # just means that we have bumped the timestamp.
        self._lastUsedTimestamp = timestamp

        # The timestamp is encoded as a TLV nonNegativeInteger.
        encoder = TlvEncoder(8)
        encoder.writeNonNegativeInteger(int(timestamp))
        interest.getName().append(Blob(encoder.getOutput(), False))

        # The random value is a TLV nonNegativeInteger too, but we know it is 8
        # bytes, so we don't need to call the nonNegativeInteger encoder.
        randomBuffer = bytearray(8)
        for i in range(len(randomBuffer)):
            randomBuffer[i] = _systemRandom.randint(0, 0xff)
        interest.getName().append(Blob(randomBuffer, False))

    def _setNowOffsetMilliseconds(self, nowOffsetMilliseconds):
        """
        Set the offset when prepareCommandInterestName() gets the current time,
        which should only be used for testing.

        :param float nowOffsetMilliseconds: The offset in milliseconds.
        """
        self._nowOffsetMilliseconds = nowOffsetMilliseconds

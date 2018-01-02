# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2018 Regents of the University of California.
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
 * This sends a faces channels request to the local NFD and prints the response.
 * This is equivalent to the NFD command line command "nfd-status -c".
 * See http://redmine.named-data.net/projects/nfd/wiki/Management .
"""

import time
from pyndn import Face
from pyndn import Name
from pyndn import Interest
from pyndn.encoding import ProtobufTlv
from pyndn.util.segment_fetcher import SegmentFetcher
# This module is produced by: protoc --python_out=. channel-status.proto
import channel_status_pb2

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str else str(element)) + " "
    print(result)

def main():
    # The default Face connects to the local NFD.
    face = Face()

    interest = Interest(Name("/localhost/nfd/faces/channels"))
    interest.setInterestLifetimeMilliseconds(4000)
    dump("Express interest", interest.getName().toUri())

    enabled = [True]

    def onComplete(content):
        enabled[0] = False
        printChannelStatuses(content)

    def onError(errorCode, message):
        enabled[0] = False
        dump(message)

    SegmentFetcher.fetch(face, interest, None, onComplete, onError)

    # Loop calling processEvents until a callback sets enabled[0] = False.
    while enabled[0]:
        face.processEvents()

        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.01)

def printChannelStatuses(encodedMessage):
    """
    This is called when all the segments are received to decode the
    encodedMessage repeated TLV ChannelStatus messages and display the values.

    :param Blob encodedMessage: The repeated TLV-encoded ChannelStatus.
    """
    channelStatusMessage = channel_status_pb2.ChannelStatusMessage()
    ProtobufTlv.decode(channelStatusMessage, encodedMessage)

    dump("Channels:");
    for channelStatus in channelStatusMessage.channel_status:
        # Format to look the same as "nfd-status -c".
        dump("  " + channelStatus.local_uri)

main()

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
This sends a rib list request to the local NFD and prints the response.
This is equivalent to the NFD command line command "nfd-status -r".
See http://redmine.named-data.net/projects/nfd/wiki/Management .
"""

import time
from pyndn import Face
from pyndn import Name
from pyndn import Interest
from pyndn.util import Blob
from pyndn.encoding import ProtobufTlv
from pyndn.util.segment_fetcher import SegmentFetcher
# This moudle is produced by: protoc --python_out=. rib-entry.proto
import rib_entry_pb2

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str else str(element)) + " "
    print(result)

def main():
    # The default Face connects to the local NFD.
    face = Face()

    interest = Interest(Name("/localhost/nfd/rib/list"))
    interest.setInterestLifetimeMilliseconds(4000)
    dump("Express interest", interest.getName().toUri())

    enabled = [True]

    def onComplete(content):
        enabled[0] = False
        printRibEntries(content)

    def onError(errorCode, message):
        enabled[0] = False
        dump(message)

    SegmentFetcher.fetch(face, interest, None, onComplete, onError)

    # Loop calling processEvents until a callback sets enabled[0] = False.
    while enabled[0]:
        face.processEvents()

        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.01)

def printRibEntries(encodedMessage):
    """
    This is called when all the segments are received to decode the
    encodedMessage as repeated TLV RibEntry messages and display the values.

    :param Blob encodedMessage: The repeated TLV-encoded RibEntry.
    """
    ribEntryMessage = rib_entry_pb2.RibEntryMessage()
    ProtobufTlv.decode(ribEntryMessage, encodedMessage)

    dump("RIB:");
    for ribEntry in ribEntryMessage.rib_entry:
        line = ""
        line += ProtobufTlv.toName(ribEntry.name.component).toUri()

        # Show the routes.
        for route in ribEntry.routes:
            line += (" route={faceId=" + str(route.face_id) + " (origin=" +
              str(route.origin) + " cost=" + str(route.cost))
            if (route.flags & 1) != 0:
                line += " ChildInherit"
            if (route.flags & 2) != 0:
                line += " Capture"
            if route.HasField("expiration_period"):
                line += " expirationPeriod=" + str(route.expiration_period)
            line += ")}"

        dump(line)

main()

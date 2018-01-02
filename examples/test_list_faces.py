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
This sends a faces list request to the local NFD and prints the response.
This is equivalent to the NFD command line command "nfd-status -f".
See http://redmine.named-data.net/projects/nfd/wiki/Management .
"""

import time
from pyndn import Face
from pyndn import Name
from pyndn import Interest
from pyndn.encoding import ProtobufTlv
from pyndn.util.segment_fetcher import SegmentFetcher
# This module is produced by: protoc --python_out=. face-status.proto
import face_status_pb2

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str else str(element)) + " "
    print(result)

def main():
    # The default Face connects to the local NFD.
    face = Face()

    interest = Interest(Name("/localhost/nfd/faces/list"))
    interest.setInterestLifetimeMilliseconds(4000)
    dump("Express interest", interest.getName().toUri())

    enabled = [True]

    def onComplete(content):
        enabled[0] = False
        printFaceStatuses(content)

    def onError(errorCode, message):
        enabled[0] = False
        dump(message)

    SegmentFetcher.fetch(face, interest, None, onComplete, onError)

    # Loop calling processEvents until a callback sets enabled[0] = False.
    while enabled[0]:
        face.processEvents()

        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.01)

def printFaceStatuses(encodedMessage):
    """
    This is called when all the segments are received to decode the
    encodedMessage repeated TLV FaceStatus messages and display the values.

    :param Blob encodedMessage: The repeated TLV-encoded FaceStatus.
    """
    faceStatusMessage = face_status_pb2.FaceStatusMessage()
    ProtobufTlv.decode(faceStatusMessage, encodedMessage)

    dump("Faces:");
    for faceStatus in faceStatusMessage.face_status:
        line = ""
        # Format to look the same as "nfd-status -f".
        line += ("  faceid=" + str(faceStatus.face_id) +
            " remote=" + faceStatus.uri +
            " local=" + faceStatus.local_uri)
        if faceStatus.HasField("expiration_period"):
            # Convert milliseconds to seconds.
            line += (" expires=" +
              str(round(faceStatus.expiration_period / 1000.0)) + "s")
        line += (" counters={" + "in={" + str(faceStatus.n_in_interests) +
          "i " + str(faceStatus.n_in_datas) + "d " + str(faceStatus.n_in_bytes) + "B}" +
          " out={" + str(faceStatus.n_out_interests) + "i "+ str(faceStatus.n_out_datas) +
          "d " + str(faceStatus.n_out_bytes) + "B}" + "}" +
          " " + ("local" if faceStatus.face_scope == 1 else "non-local") +
          " " + ("permanent" if faceStatus.face_persistency == 2 else
                 ("on-demand" if faceStatus.face_persistency == 1 else "persistent")) +
          " " + ("multi-access" if faceStatus.link_type == 1 else "point-to-point"))

        dump(line)

main()

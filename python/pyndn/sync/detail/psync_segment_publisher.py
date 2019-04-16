# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From the PSync library https://github.com/named-data/PSync/blob/master/PSync/segment-publisher.cpp
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
This module defines the PSyncSegmentPublisher class which has methods to publish
segmented data used by PSync.
"""

from pyndn.name import Name
from pyndn.data import Data
from pyndn.security.signing_info import SigningInfo
from pyndn.in_memory_storage.in_memory_storage_retaining import InMemoryStorageRetaining
from pyndn.util.blob import Blob
from pyndn.util.common import Common

class PSyncSegmentPublisher(object):
    MAX_SEGMENTS_STORED = 100

    """
    Create a PSyncSegmentPublisher.
    :param Face face: The application's Face.
    :param KeyChain keyChain: The KeyChain for signing Data packets.
    :param int inMemoryStorageLimit: (optional) The limit for the in-memory
      storage. If omitted, use MAX_SEGMENTS_STORED.
    """
    def __init__(self, face, keyChain,
      inMemoryStorageLimit = MAX_SEGMENTS_STORED):
        self._face = face
        self._keyChain = keyChain
        # Until InMemoryStorageFifo implements an eviction policy, use InMemoryStorageRetaining.
        # storage_(inMemoryStorageLimit)
        self._storage = InMemoryStorageRetaining()

    def publish(self, interestName, dataName, content, freshnessPeriod, 
      signingInfo = SigningInfo()):
        """
        Put all the segments in the memory store.

        :param Name interestName: If the Interest name ends in a segment,
          immediately send the Data packet for the segment to the Face.
        :param Name dataName: The Data name, which has components after the
          Interest name.
        :param Blob content: The content of the data to be segmented.
        :param float freshnessPeriod The freshness period of the segments,
          in milliseconds.
        :param SigningInfo signingInfo (optional) The SigningInfo for signing
          segment Data packets. If omitted, use the default SigningInfo().
        """
        interestSegment = 0
        if interestName[-1].isSegment():
            interestSegment = interestName[-1].toSegment()

        rawBuffer = content.buf()
        iSegmentBegin = 0
        iEnd = len(content)

        maxPacketSize = int(Common.MAX_NDN_PACKET_SIZE / 2)

        totalSegments = int(len(content) / maxPacketSize)
        finalBlockId = Name.Component.fromSegment(totalSegments)

        segmentPrefix = Name(dataName)
        segmentPrefix.appendVersion(int(Common.getNowMilliseconds()))

        segmentNo = 0
        while(True):
            iSegmentEnd = iSegmentBegin + maxPacketSize
            if iSegmentEnd > iEnd:
                iSegmentEnd = iEnd

            segmentName = Name(segmentPrefix)
            segmentName.appendSegment(segmentNo)

            data = Data(segmentName)
            data.setContent(Blob(rawBuffer[iSegmentBegin : iSegmentEnd]))
            data.getMetaInfo().setFreshnessPeriod(freshnessPeriod)
            data.getMetaInfo().setFinalBlockId(finalBlockId)

            iSegmentBegin = iSegmentEnd

            self._keyChain.sign(data, signingInfo)

            # Only send the segment to the Face if it has a pending interest.
            # Otherwise, the segment is unsolicited.
            if interestSegment == segmentNo:
                self._face.putData(data)

            # Until InMemoryStorageFifo implements an eviction policy, use InMemoryStorageRetaining.
            # storage_.insert(*data, freshnessPeriod)
            self._storage.insert(data)

            # Make and return a callback since segmentName is different each time.
            def makeCallback(localSegmentName):
                def callback():
                    self._storage.remove(localSegmentName)
                return callback

            self._face.callLater(freshnessPeriod, makeCallback(segmentName))

            segmentNo += 1
            
            if not (iSegmentBegin < iEnd):
                break

    def replyFromStore(self, interestName):
        """
        Try to reply to the Interest name from the memory store.

        :param Name interestName: The Interest name for looking up in the memory
          store.
        :return: True if sent the segment Data packet to the Face, or false if
          we cannot find the segment, in which case the caller is expected to
          publish the segment.
        :rtype: bool
        """
        data = self._storage.find(interestName)

        if data != None:
            self._face.putData(data)
            return True

        return False

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx util/segment-fetcher https://github.com/named-data/ndn-cxx
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
This module defines the SegmentFetcher class which is a utility class to fetch
the latest version of segmented data.

SegmentFetcher assumes that the data is named /<prefix>/<version>/<segment>,
where:

- <prefix> is the specified name prefix,
- <version> is an unknown version that needs to be discovered, and
- <segment> is a segment number. (The number of segments is unknown and is
  controlled by the `FinalBlockId` field in at least the last Data packet.

The following logic is implemented in SegmentFetcher:

1. Express the first Interest to discover the version:

   >> Interest: /<prefix>?ChildSelector=1&MustBeFresh=true

2. Infer the latest version of the Data: <version> = Data.getName().get(-2)

3. If the segment number in the retrieved packet == 0, go to step 5.

4. Send an Interest for segment 0:

   >> Interest: /<prefix>/<version>/<segment=0>

5. Keep sending Interests for the next segment while the retrieved Data does
   not have a FinalBlockId or the FinalBlockId != Data.getName().get(-1).

   >> Interest: /<prefix>/<version>/<segment=(N+1))>

6. Call the onComplete callback with a Blob that concatenates the content
   from all the segmented objects.

If an error occurs during the fetching process, the onError callback is called
with a proper error code.  The following errors are possible:

- `INTEREST_TIMEOUT`: if any of the Interests times out
- `DATA_HAS_NO_SEGMENT`: if any of the retrieved Data packets don't have a segment
  as the last component of the name (not counting the implicit digest)
- `SEGMENT_VERIFICATION_FAILED`: if any retrieved segment fails
  the user-provided VerifySegment callback

In order to validate individual segments, a verifySegment callback needs to
be specified. If the callback returns False, the fetching process is aborted
with SEGMENT_VERIFICATION_FAILED. If data validation is not required, the
provided DontVerifySegment object can be used.

Example:
    def onComplete(content):
        ...

    def onError(errorCode, message):
        ...

    interest = Interest(Name("/data/prefix"))
    interest.setInterestLifetimeMilliseconds(1000)

    SegmentFetcher.fetch(
      face, interest, SegmentFetcher.DontVerifySegment, onComplete, onError)
"""

import logging
from pyndn.interest import Interest
from pyndn.util.blob import Blob

class SegmentFetcher(object):
    """
    A private constructor to create a new SegmentFetcher to use the Face. An
    application should use SegmentFetcher.fetch.

    :param Face face: This calls face.expressInterest to fetch more segments.
    :param verifySegment: When a Data packet is received this calls
      verifySegment(data) where data is a Data object. If it returns False then
      abort fetching and call onError with
      SegmentFetcher.ErrorCode.SEGMENT_VERIFICATION_FAILED.
    :type verifySegment: function object
    :param onComplete: When all segments are received, call
      onComplete(content) where content is a Blob which has the concatenation of
      the content of all the segments.
      NOTE: The library will log any exceptions raised by this callback, but
      for better error handling the callback should catch and properly
      handle any exceptions.
    :type onComplete: function object
    :param onError: Call onError.onError(errorCode, message) for timeout or an
      error processing segments. errorCode is a value from
      SegmentFetcher.ErrorCode and message is a related string.
      NOTE: The library will log any exceptions raised by this callback, but
      for better error handling the callback should catch and properly
      handle any exceptions.
    :type onError: function object
    """
    def __init__(self, face, verifySegment, onComplete, onError):
        self._face = face
        self._verifySegment = verifySegment
        self._onComplete = onComplete
        self._onError = onError

        self._contentParts = [] # of Blob

    class ErrorCode(object):
        """
        An ErrorCode value is passed in the onError callback.
        """
        INTEREST_TIMEOUT = 1
        DATA_HAS_NO_SEGMENT = 2
        SEGMENT_VERIFICATION_FAILED =  3

    @staticmethod
    def DontVerifySegment(data):
        """
        DontVerifySegment may be used in fetch to skip validation of Data
        packets.
        """
        return True

    @staticmethod
    def fetch(face, baseInterest, verifySegment, onComplete, onError):
        """
        Initiate segment fetching. For more details, see the documentation for
        the module.

        :param Face face: This calls face.expressInterest to fetch more segments.
        :param Interest baseInterest: An Interest for the initial segment of the
          requested data, where baseInterest.getName() has the name prefix.
          This interest may include a custom InterestLifetime and selectors that
          will propagate to all subsequent Interests. The only exception is that
          the initial Interest will be forced to include selectors
          "ChildSelector=1" and "MustBeFresh=true" which will be turned off in
          subsequent Interests.
        :param verifySegment: When a Data packet is received this calls
          verifySegment(data) where data is a Data object. If it returns False then
          abort fetching and call onError with
          SegmentFetcher.ErrorCode.SEGMENT_VERIFICATION_FAILED. If data
          validation is not required, use SegmentFetcher.DontVerifySegment.
        :type verifySegment: function object
        :param onComplete: When all segments are received, call
          onComplete(content) where content is a Blob which has the concatenation of
          the content of all the segments.
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onComplete: function object
        :param onError: Call onError.onError(errorCode, message) for timeout or an
          error processing segments. errorCode is a value from
          SegmentFetcher.ErrorCode and message is a related string.
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onError: function object
        """
        SegmentFetcher(face, verifySegment, onComplete, onError)._fetchFirstSegment(
          baseInterest)

    def _fetchFirstSegment(self, baseInterest):
        interest = Interest(baseInterest)
        interest.setChildSelector(1)
        interest.setMustBeFresh(True)
        self._face.expressInterest(interest, self._onData, self._onTimeout)

    def _fetchNextSegment(self, originalInterest, dataName, segment):
        # Start with the original Interest to preserve any special selectors.
        interest = Interest(originalInterest)
        # Changing a field clears the nonce so that the library will
        #   generate a new one.
        interest.setMustBeFresh(False)
        interest.setName(dataName.getPrefix(-1).appendSegment(segment))
        self._face.expressInterest(interest, self._onData, self._onTimeout)

    def _onData(self, originalInterest, data):
        if not self._verifySegment(data):
            try:
                self._onError(
                  self.ErrorCode.SEGMENT_VERIFICATION_FAILED,
                  "Segment verification failed")
            except:
                logging.exception("Error in onError")
            return

        if not self._endsWithSegmentNumber(data.getName()):
            # We don't expect a name without a segment number.  Treat it as
            # a bad packet.
            try:
                self._onError(
                  self.ErrorCode.DATA_HAS_NO_SEGMENT,
                   "Got an unexpected packet without a segment number: " +
                   data.getName().toUri())
            except:
                logging.exception("Error in onError")
        else:
            currentSegment = 0
            try:
                currentSegment = data.getName().get(-1).toSegment()
            except RuntimeError as ex:
                try:
                    self._onError(
                      self.ErrorCode.DATA_HAS_NO_SEGMENT,
                       "Error decoding the name segment number " +
                       data.getName().get(-1).toEscapedString() + ": " + str(ex))
                except:
                    logging.exception("Error in onError")
                return

            expectedSegmentNumber = len(self._contentParts)
            if currentSegment != expectedSegmentNumber:
              # Try again to get the expected segment.  This also includes
              # the case where the first segment is not segment 0.
                self._fetchNextSegment(
                  originalInterest, data.getName(), expectedSegmentNumber)
            else:
                # Save the content and check if we are finished.
                self._contentParts.append(data.getContent())

                if data.getMetaInfo().getFinalBlockId().getValue().size() > 0:
                    finalSegmentNumber = 0
                    try:
                      finalSegmentNumber = (data.getMetaInfo()
                        .getFinalBlockId().toSegment())
                    except RuntimeError as ex:
                        try:
                            self._onError(
                              self.ErrorCode.DATA_HAS_NO_SEGMENT,
                               "Error decoding the FinalBlockId segment number " +
                               data.getMetaInfo().getFinalBlockId().toEscapedString() +
                               ": " + str(ex))
                        except:
                            logging.exception("Error in onError")
                        return

                    if currentSegment == finalSegmentNumber:
                        # We are finished.

                        # Get the total size and concatenate to get content.
                        totalSize = 0
                        for i in range(len(self._contentParts)):
                            totalSize += self._contentParts[i].size()
                        content = bytearray(totalSize)
                        offset = 0
                        for i in range(len(self._contentParts)):
                            part = self._contentParts[i]
                            content[offset:offset + part.size()] = part.buf()
                            offset += part.size()

                        try:
                            self._onComplete(Blob(content, False))
                        except:
                            logging.exception("Error in onComplete")
                        return

                # Fetch the next segment.
                self._fetchNextSegment(
                  originalInterest, data.getName(), expectedSegmentNumber + 1)

    def _onTimeout(self, interest):
        try:
            self._onError(
              self.ErrorCode.INTEREST_TIMEOUT,
               "Time out for interest " + interest.getName().toUri())
        except:
            logging.exception("Error in onError")

    @staticmethod
    def _endsWithSegmentNumber(name):
        """
        Check if the last component in the name is a segment number.

        :param Name name: The name to check.
        :return: True if the name ends with a segment number, otherwise False.
        :rtype: bool
        """
        return (name.size() >= 1 and
                name.get(-1).getValue().size() >= 1 and
                name.get(-1).getValue().buf()[0] == 0)

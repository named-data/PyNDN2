# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2016 Regents of the University of California.
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
This module defines the Schedule class which is used to manage the times when a
member can access data using two sets of RepetitiveInterval as follows.
whiteIntervalList is an ordered set for the times a member is allowed to access
to data, and blackIntervalList is for the times a member is not allowed.
Note: This class is an experimental feature. The API may change.
"""

from datetime import datetime
from pyndn.encoding.tlv.tlv import Tlv
from pyndn.encoding.tlv.tlv_encoder import TlvEncoder
from pyndn.encoding.tlv.tlv_decoder import TlvDecoder
from pyndn.util.blob import Blob
from pyndn.encrypt.interval import Interval
from pyndn.encrypt.repetitive_interval import RepetitiveInterval

class Schedule(object):
    """
    Create a Schedule with one of these forms:
    Schedule() A Schedule with empty whiteIntervalList and blackIntervalList.
    Schedule(schedule). A copy of the given schedule.
    """
    def __init__(self, value = None):
        if type(value) is Schedule:
            # Make a copy.
            schedule = value

            # RepetitiveInterval is immutable, so we don't need to make a deep copy.
            self._whiteIntervalList = schedule._whiteIntervalList[:]
            self._blackIntervalList = schedule._blackIntervalList[:]
        else:
            # The default constructor.
            self._whiteIntervalList = []
            self._blackIntervalList = []

    def addWhiteInterval(self, repetitiveInterval):
        """
        Add the repetitiveInterval to the whiteIntervalList.

        :param RepetitiveInterval repetitiveInterval: The RepetitiveInterval to
          add. If the list already contains the same RepetitiveInterval, this
          does nothing.
        :return: This Schedule so you can chain calls to add.
        :rtype: Schedule
        """
        # RepetitiveInterval is immutable, so we don't need to make a copy.
        Schedule._sortedSetAdd(self._whiteIntervalList, repetitiveInterval)
        return self

    def addBlackInterval(self, repetitiveInterval):
        """
        Add the repetitiveInterval to the blackIntervalList.

        :param RepetitiveInterval repetitiveInterval: The RepetitiveInterval to
          add. If the list already contains the same RepetitiveInterval, this
          does nothing.
        :return: This Schedule so you can chain calls to add.
        :rtype: Schedule
        """
        # RepetitiveInterval is immutable, so we don't need to make a copy.
        Schedule._sortedSetAdd(self._blackIntervalList, repetitiveInterval)
        return self

    class Result(object):
        def __init__(self, isPositive, interval):
            self.isPositive = isPositive
            self.interval = interval

    def getCoveringInterval(self, timeStamp):
        """
        Get the interval that covers the time stamp. This iterates over the two
        repetitive interval sets and find the shortest interval that allows a
        group member to access the data. If there is no interval covering the
        time stamp, this returns False for isPositive and a negative interval.

        :param float timeStamp: The time stamp as milliseconds since Jan 1,
          1970 UTC.
        :return: An object with fields "isPositive" and "interval" where
          isPositive is True if the returned interval is positive or False if
          negative, and interval is the Interval covering the time stamp, or a
          negative interval if not found.
        :rtype: Schedule.Result
        """
        blackPositiveResult = Interval(True)
        whitePositiveResult = Interval(True)

        blackNegativeResult = Interval()
        whiteNegativeResult = Interval()

        # Get the black result.
        Schedule._calculateIntervalResult(
          self._blackIntervalList, timeStamp, blackPositiveResult,
          blackNegativeResult)

        # If the black positive result is not empty, then isPositive must be False.
        if not blackPositiveResult.isEmpty():
            return Schedule.Result(False, blackPositiveResult)

        # Get the whiteResult.
        Schedule._calculateIntervalResult(
          self._whiteIntervalList, timeStamp, whitePositiveResult,
          whiteNegativeResult)

        if whitePositiveResult.isEmpty() and not whiteNegativeResult.isValid():
            # There is no white interval covering the time stamp.
            # Return False and a 24-hour interval.
            timeStampDateOnly = RepetitiveInterval._toDateOnlyMilliseconds(
              timeStamp)
            return Schedule.Result(False, Interval(
              timeStampDateOnly,
              timeStampDateOnly + RepetitiveInterval.MILLISECONDS_IN_DAY))

        if not whitePositiveResult.isEmpty():
            # There is white interval covering the time stamp.
            # Return True and calculate the intersection.
            if blackNegativeResult.isValid():
                return Schedule.Result(
                  True, whitePositiveResult.intersectWith(blackNegativeResult))
            else:
                return Schedule.Result(True, whitePositiveResult)
        else:
            # There is no white interval covering the time stamp.
            # Return False.
            return Schedule.Result(False, whiteNegativeResult)

    def wireEncode(self):
        """
        Encode this Schedule.

        :return: The encoded buffer.
        :rtype: Blob
        """
        # For now, don't use WireFormat and hardcode to use TLV since the
        # encoding doesn't go out over the wire, only into the local SQL database.
        encoder = TlvEncoder(256)
        saveLength = len(encoder)

        # Encode backwards.
        # Encode the blackIntervalList.
        saveLengthForList = len(encoder)
        for i in range(len(self._blackIntervalList) - 1, -1, -1):
            Schedule._encodeRepetitiveInterval(self._blackIntervalList[i], encoder)
        encoder.writeTypeAndLength(
          Tlv.Encrypt_BlackIntervalList, len(encoder) - saveLengthForList)

        # Encode the whiteIntervalList.
        saveLengthForList = len(encoder)
        for i in range(len(self._whiteIntervalList) - 1, -1, -1):
            Schedule._encodeRepetitiveInterval(self._whiteIntervalList[i], encoder)
        encoder.writeTypeAndLength(
          Tlv.Encrypt_WhiteIntervalList, len(encoder) - saveLengthForList)

        encoder.writeTypeAndLength(
          Tlv.Encrypt_Schedule, len(encoder) - saveLength)

        return Blob(encoder.getOutput(), False)

    def wireDecode(self, input):
        """
        Decode the input and update this Schedule object.

        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :raises ValueError: For invalid encoding.
        """
        # If input is a blob, get its buf().
        decodeBuffer = input.buf() if isinstance(input, Blob) else input

        # For now, don't use WireFormat and hardcode to use TLV since the
        # encoding doesn't go out over the wire, only into the local SQL database.
        decoder = TlvDecoder(decodeBuffer)

        endOffset = decoder.readNestedTlvsStart(Tlv.Encrypt_Schedule)

        # Decode the whiteIntervalList.
        self._whiteIntervalList = []
        listEndOffset = decoder.readNestedTlvsStart(Tlv.Encrypt_WhiteIntervalList)
        while decoder.getOffset() < listEndOffset:
            Schedule._sortedSetAdd(
              self._whiteIntervalList, Schedule._decodeRepetitiveInterval(decoder))
        decoder.finishNestedTlvs(listEndOffset)

        # Decode the blackIntervalList.
        self._blackIntervalList = []
        listEndOffset = decoder.readNestedTlvsStart(Tlv.Encrypt_BlackIntervalList)
        while decoder.getOffset() < listEndOffset:
            Schedule._sortedSetAdd(
              self._blackIntervalList, Schedule._decodeRepetitiveInterval(decoder))
        decoder.finishNestedTlvs(listEndOffset)

        decoder.finishNestedTlvs(endOffset)

    @staticmethod
    def _sortedSetAdd(list, element):
        """
        Insert element into the list, sorted using element.compare(). If it is a
        duplicate of an existing list element, don't add it.
        """
        # Find the index of the first element where it is not less than element.
        i = 0
        while i < len(list):
            comparison = list[i].compare(element)
            if comparison == 0:
              # Don't add a duplicate.
              return
            if not (comparison < 0):
              break

            i += 1

        list.insert(i, element)

    @staticmethod
    def _encodeRepetitiveInterval(repetitiveInterval, encoder):
        """
        Encode the RepetitiveInterval as NDN-TLV to the encoder.

        :param RepetitiveInterval repetitiveInterval: The RepetitiveInterval to
          encode.
        :param TlvEncoder encoder: The TlvEncoder to receive the encoding.
        """
        saveLength = len(encoder)

        # Encode backwards.
        # The RepeatUnit enum has the same values as the encoding.
        encoder.writeNonNegativeIntegerTlv(
          Tlv.Encrypt_RepeatUnit, repetitiveInterval.getRepeatUnit())
        encoder.writeNonNegativeIntegerTlv(
          Tlv.Encrypt_NRepeats, repetitiveInterval.getNRepeats())
        encoder.writeNonNegativeIntegerTlv(
          Tlv.Encrypt_IntervalEndHour, repetitiveInterval.getIntervalEndHour())
        encoder.writeNonNegativeIntegerTlv(
          Tlv.Encrypt_IntervalStartHour, repetitiveInterval.getIntervalStartHour())
        # Use Blob to convert the string to UTF8 encoding.
        encoder.writeBlobTlv(Tlv.Encrypt_EndDate,
          Blob(Schedule.toIsoString(repetitiveInterval.getEndDate())).buf())
        encoder.writeBlobTlv(Tlv.Encrypt_StartDate,
          Blob(Schedule.toIsoString(repetitiveInterval.getStartDate())).buf())

        encoder.writeTypeAndLength(
          Tlv.Encrypt_RepetitiveInterval, len(encoder) - saveLength)

    @staticmethod
    def _decodeRepetitiveInterval(decoder):
        """
        Decode the input as an NDN-TLV RepetitiveInterval.

        :param TlvDecoder decoder: The decoder with the input to decode.
        :return: A new RepetitiveInterval with the decoded result.
        :rtype: RepetitiveInterval
        """
        endOffset = decoder.readNestedTlvsStart(Tlv.Encrypt_RepetitiveInterval)

        # Use Blob to convert UTF8 to a string.
        startDate = Schedule.fromIsoString(
          str(Blob(decoder.readBlobTlv(Tlv.Encrypt_StartDate), True)))
        endDate = Schedule.fromIsoString(
          str(Blob(decoder.readBlobTlv(Tlv.Encrypt_EndDate), True)))
        startHour = decoder.readNonNegativeIntegerTlv(Tlv.Encrypt_IntervalStartHour)
        endHour = decoder.readNonNegativeIntegerTlv(Tlv.Encrypt_IntervalEndHour)
        nRepeats = decoder.readNonNegativeIntegerTlv(Tlv.Encrypt_NRepeats)

        # The RepeatUnit enum has the same values as the encoding.
        repeatUnit = decoder.readNonNegativeIntegerTlv(Tlv.Encrypt_RepeatUnit)

        decoder.finishNestedTlvs(endOffset)
        return RepetitiveInterval(
          startDate, endDate, startHour, endHour, nRepeats, repeatUnit)

    @staticmethod
    def _calculateIntervalResult(list, timeStamp, positiveResult, negativeResult):
        """
        A helper function to calculate black interval results or white interval
        results.

        :param list list: The set of RepetitiveInterval, which can be the white
          list or the black list.
        :param float timeStamp: The time stamp as milliseconds since Jan 1,
          1970 UTC.
        :param Interval positiveResult: The positive result which is updated.
        :param Interval negativeResult: The negative result which is updated.
        """
        for i in range(len(list)):
            element = list[i]

            result = element.getInterval(timeStamp)
            tempInterval = result.interval
            if result.isPositive == True:
                positiveResult.unionWith(tempInterval)
            else:
                if not negativeResult.isValid():
                    negativeResult.set(tempInterval)
                else:
                    negativeResult.intersectWith(tempInterval)

    @staticmethod
    def toIsoString(msSince1970):
        """
        Convert a UNIX timestamp to ISO time representation with the "T" in the
        middle.

        :param float msSince1970: Timestamp as milliseconds since Jan 1, 1970 UTC.
        :return: The string representation.
        :rtype: str
        """
        dateFormat = "%Y%m%dT%H%M%S"
        return datetime.utcfromtimestamp(
          round(msSince1970 / 1000.0)).strftime(dateFormat)

    @staticmethod
    def fromIsoString(timeString):
        """
        Convert an ISO time representation with the "T" in the middle to a UNIX
        timestamp.

        :param str timeString: The ISO time representation.
        :return: The timestamp as milliseconds since Jan 1, 1970 UTC.
        :rtype: float
        """
        if len(timeString) != 15 or timeString[8:9] != 'T':
            raise RuntimeError("fromIsoString: Format is not the expected yyyymmddThhmmss")

        utc = datetime(
          int(timeString[0:4]),
          int(timeString[4:6]),
          int(timeString[6:8]),
          int(timeString[9:11]),
          int(timeString[11:13]),
          int(timeString[13:15]))
        return (utc - Schedule._posixEpoch).total_seconds() * 1000.0

    _posixEpoch = datetime.utcfromtimestamp(0)

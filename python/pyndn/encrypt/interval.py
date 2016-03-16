# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt src/interval https://github.com/named-data/ndn-group-encrypt
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
This module defines the Interval class which defines a time duration which
contains a start timestamp and an end timestamp.
Note: This class is an experimental feature. The API may change.
"""

import sys

class Interval(object):
    """
    Create an Interval with one of these forms:
    Interval(isValid).
    Interval(startTime, endTime).
    Interval(interval).

    :param bool isValid: True to create a valid empty interval, false to create
      an invalid interval.
    :param float startTime: The start time as milliseconds since Jan 1, 1970 UTC.
      The start time must be less than the end time. To create an empty interval
      (start time equals end time), use the constructor Interval(true).
    :param float endTime: The end time as milliseconds since Jan 1, 1970 UTC.
    :param Interval interval: The other interval with values to copy.
    """
    def __init__(self, value = None, endTime = None):
        if type(value) is Interval:
            # Make a copy.
            self._startTime = value._startTime
            self._endTime = value._endTime
            self._isValid = value._isValid
        elif type(value) is float or type(value) is int:
            startTime = float(value)
            endTime = float(endTime)

            if not (startTime < endTime):
                raise RuntimeError("Interval start time must be less than the end time")

            self._startTime = startTime
            self._endTime = endTime
            self._isValid = True
        else:
            isValid = True if value else False

            self._startTime = -sys.float_info.max
            self._endTime = -sys.float_info.max
            self._isValid = isValid

    def set(self, other):
        """
        Set this interval to have the same values as the other interval.

        :param Interval other: The other Interval with values to copy.
        """
        self._startTime = other._startTime
        self._endTime = other._endTime
        self._isValid = other._isValid

    def covers(self, timePoint):
        """
        Check if the time point is in this interval.

        :param float timePoint: The time point to check as milliseconds since
          Jan 1, 1970 UTC.
        :return: True if timePoint is in this interval.
        :rtype: bool
        :raises RuntimeError: if this Interval is invalid.
        """
        if not self._isValid:
            raise RuntimeError("Interval.covers: This Interval is invalid")

        if self.isEmpty():
            return False
        else:
            return self._startTime <= timePoint and timePoint < self._endTime

    def intersectWith(self, interval):
        """
        Set this Interval to the intersection of this and the other interval.
        This and the other interval should be valid but either can be empty.

        :param Interval interval: The other Interval to intersect with.
        :return: This Interval.
        :rtype: Interval
        :raises RuntimeError: if this Interval or the other interval is invalid.
        """
        if not self._isValid:
            raise RuntimeError("Interval.intersectWith: This Interval is invalid")
        if not interval._isValid:
            raise RuntimeError("Interval.intersectWith: The other Interval is invalid")

        if self.isEmpty() or interval.isEmpty():
            # If either is empty, the result is empty.
            self._startTime = self._endTime
            return self

        if (self._startTime >= interval._endTime or
            self._endTime <= interval._startTime):
            # The two intervals don't have an intersection, so the result is empty.
            self._startTime = self._endTime
            return self

        # Get the start time.
        if self._startTime <= interval._startTime:
            self._startTime = interval._startTime

        # Get the end time.
        if self._endTime > interval._endTime:
            self._endTime = interval._endTime

        return self

    def unionWith(self, interval):
        """
        Set this Interval to the union of this and the other interval. This and
        the other interval should be valid but either can be empty. This and the
        other interval should have an intersection. (Contiguous intervals are
        not allowed.)

        :param Interval interval: The other Interval to union with.
        :return: This Interval.
        :rtype: Interval
        :raises RuntimeError: if this Interval or the other interval is invalid,
          or if the two intervals do not have an intersection.
        """
        if not self._isValid:
            raise RuntimeError("Interval.intersectWith: This Interval is invalid")
        if not interval._isValid:
            raise RuntimeError("Interval.intersectWith: The other Interval is invalid")

        if self.isEmpty():
            # This interval is empty, so use the other.
            self._startTime = interval._startTime
            self._endTime = interval._endTime
            return self

        if interval.isEmpty():
            # The other interval is empty, so keep using this one.
            return self

        if (self._startTime >= interval._endTime or
            self._endTime <= interval._startTime):
            raise RuntimeError(
              "Interval.unionWith: The two intervals do not have an intersection")

        # Get the start time.
        if self._startTime > interval._startTime:
            self._startTime = interval._startTime

        # Get the end time.
        if self._endTime < interval._endTime:
            self._endTime = interval._endTime

        return self

    def getStartTime(self):
        """
        Get the start time.

        :return: The start time as milliseconds since Jan 1, 1970 UTC.
        :rtype: float
        :raises RuntimeError: if this Interval is invalid.
        """
        if not self._isValid:
            raise RuntimeError("Interval.getStartTime: This Interval is invalid")
        return self._startTime

    def getEndTime(self):
        """
        Get the end time.

        :return: The end time as milliseconds since Jan 1, 1970 UTC.
        :rtype: float
        :raises RuntimeError: if this Interval is invalid.
        """
        if not self._isValid:
            raise RuntimeError("Interval.getEndTime: This Interval is invalid")
        return self._endTime

    def isValid(self):
        """
        Check if this Interval is valid.

        :return: True if this interval is valid, False if invalid.
        :rtype: bool
        """
        return self._isValid

    def isEmpty(self):
        """
        Check if this Interval is empty.

        :return: True if this Interval is empty (start time equals end time),
          False if not.
        :rtype: bool
        :raises RuntimeError: if this Interval is invalid.
        """
        if not self._isValid:
            raise RuntimeError("Interval.isEmpty: This Interval is invalid")
        return self._startTime == self._endTime

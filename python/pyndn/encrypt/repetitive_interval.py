# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt src/repetitive-interval https://github.com/named-data/ndn-group-encrypt
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
This module defines the RepetitiveInterval class which is an advanced interval
which can repeat and can be used to find a simple Interval that a time point
falls in.
Note: This class is an experimental feature. The API may change.
"""

import sys
from datetime import datetime
from pyndn.encrypt.interval import Interval

class RepetitiveInterval(object):
    """
    Create a RepetitiveInterval with one of these forms:
    RepetitiveInterval() A RepetitiveInterval with one day duration, non-repeating..
    RepetitiveInterval(startDate, endDate, intervalStartHour, intervalEndHour, nRepeats, repeatUnit).
    RepetitiveInterval(repetitiveInterval).

    :param float startDate: The start date as milliseconds since Jan 1, 1970 UTC.
      startDate must be earlier than or same as endDate. Or if repeatUnit is
      RepetitiveInterval.RepeatUnit.NONE, then it must equal endDate.
    :param float endDate: The end date as milliseconds since Jan 1, 1970 UTC.
    :param int intervalStartHour: The start hour in the day, from 0 to 23.
      intervalStartHour must be less than intervalEndHour.
    :param int intervalEndHour: The end hour in the day from 1 to 24.
    :param int nRepeats: (optional) Repeat the interval nRepeats repetitions,
      every unit, until endDate. If ommitted, use 0.
    :param int repeatUnit: (optional) The unit of the repetition, from
      RepetitiveInterval.RepeatUnit. If ommitted, use NONE. If this is NONE or
      ommitted, then startDate must equal endDate.
    """
    def __init__(self, startDate = None, endDate = None, intervalStartHour = None,
                 intervalEndHour = None, nRepeats = None, repeatUnit = None):
        if type(startDate) is RepetitiveInterval:
            # Make a copy.
            repetitiveInterval = startDate

            self._startDate = repetitiveInterval._startDate
            self._endDate = repetitiveInterval._endDate
            self._intervalStartHour = repetitiveInterval._intervalStartHour
            self._intervalEndHour = repetitiveInterval._intervalEndHour
            self._nRepeats = repetitiveInterval._nRepeats
            self._repeatUnit = repetitiveInterval._repeatUnit
        elif type(startDate) is float or type(startDate) is int:
            if nRepeats == None:
                nRepeats = 0
            if repeatUnit == None:
                repeatUnit = RepetitiveInterval.RepeatUnit.NONE

            self._startDate = RepetitiveInterval._toDateOnlyMilliseconds(startDate)
            self._endDate = RepetitiveInterval._toDateOnlyMilliseconds(endDate)
            self._intervalStartHour = intervalStartHour
            self._intervalEndHour = intervalEndHour
            self._nRepeats = nRepeats
            self._repeatUnit = repeatUnit

            # Validate.
            if not (self._intervalStartHour < self._intervalEndHour):
                raise RuntimeError(
                  "ReptitiveInterval: startHour must be less than endHour")
            if not (self._startDate <= self._endDate):
                raise RuntimeError(
                  "ReptitiveInterval: startDate must be earlier than or same as endDate")
            if not (self._intervalStartHour >= 0):
                raise RuntimeError(
                  "ReptitiveInterval: intervalStartHour must be non-negative")
            if not (self._intervalEndHour >= 1 and self._intervalEndHour <= 24):
                raise RuntimeError(
                  "ReptitiveInterval: intervalEndHour must be from 1 to 24")
            if self._repeatUnit == RepetitiveInterval.RepeatUnit.NONE:
                if not (self._startDate == self._endDate):
                    raise RuntimeError(
                      "ReptitiveInterval: With RepeatUnit.NONE, startDate must equal endDate")
        else:
            # The default constructor.
            self._startDate = -sys.float_info.max
            self._endDate = -sys.float_info.max
            self._intervalStartHour = 0
            self._intervalEndHour = 24
            self._nRepeats = 0
            self._repeatUnit = RepetitiveInterval.RepeatUnit.NONE

    class RepeatUnit(object):
        NONE  = 0
        DAY   = 1
        MONTH = 2
        YEAR  = 3

    class Result(object):
        def __init__(self, isPositive, interval):
            self.isPositive = isPositive
            self.interval = interval

    def getInterval(self, timePoint):
        """
        Get an interval that covers the time point. If there is no interval
        covering the time point, this returns False for isPositive and returns a
        negative interval.

        :param float timePoint: The time point as milliseconds since Jan 1,
          1970 UTC.
        :return: An object with fields "isPositive" and "interval" where
          isPositive is True if the returned interval is positive or False if
          negative, and interval is the Interval covering the time point or a
          negative interval if not found.
        :rtype: RepetitiveInterval.Result
        """
        if not self._hasIntervalOnDate(timePoint):
            # There is no interval on the date of timePoint.
            startTime = RepetitiveInterval._toDateOnlyMilliseconds(timePoint)
            endTime = (RepetitiveInterval._toDateOnlyMilliseconds(timePoint) +
              24 * RepetitiveInterval.MILLISECONDS_IN_HOUR)
            isPositive = False
        else:
            # There is an interval on the date of timePoint.
            startTime = (RepetitiveInterval._toDateOnlyMilliseconds(timePoint) +
              self._intervalStartHour * RepetitiveInterval.MILLISECONDS_IN_HOUR)
            endTime = (RepetitiveInterval._toDateOnlyMilliseconds(timePoint) +
              self._intervalEndHour * RepetitiveInterval.MILLISECONDS_IN_HOUR)

            # Check if in the time duration.
            if timePoint < startTime:
                endTime = startTime
                startTime = RepetitiveInterval._toDateOnlyMilliseconds(timePoint)
                isPositive = False
            elif timePoint > endTime:
                startTime = endTime
                endTime = (RepetitiveInterval._toDateOnlyMilliseconds(timePoint) +
                  RepetitiveInterval.MILLISECONDS_IN_DAY)
                isPositive = False
            else:
                isPositive = True

        return RepetitiveInterval.Result(isPositive, Interval(startTime, endTime))

    def compare(self, other):
        """
        Compare this to the other RepetitiveInterval.

        :param RepetitiveInterval other: The other RepetitiveInterval to
          compare to.
        :return: -1 if this is less than the other, 1 if greater and 0 if equal.
        :rtype: int
        """
        if self._startDate < other._startDate:
            return -1
        if self._startDate > other._startDate:
            return 1

        if self._endDate < other._endDate:
            return -1
        if self._endDate > other._endDate:
            return 1

        if self._intervalStartHour < other._intervalStartHour:
            return -1
        if self._intervalStartHour > other._intervalStartHour:
            return 1

        if self._intervalEndHour < other._intervalEndHour:
            return -1
        if self._intervalEndHour > other._intervalEndHour:
            return 1

        if self._nRepeats < other._nRepeats:
            return -1
        if self._nRepeats > other._nRepeats:
            return 1

        if self._repeatUnit < other._repeatUnit:
            return -1
        if self._repeatUnit > other._repeatUnit:
            return 1

        return 0

    def getStartDate(self):
        """
        Get the start date.

        :return: The start date as milliseconds since Jan 1, 1970 UTC.
        :rtype: float
        """
        return self._startDate

    def getEndDate(self):
        """
        Get the end date.

        :return: The end date as milliseconds since Jan 1, 1970 UTC.
        :rtype: float
        """
        return self._endDate

    def getIntervalStartHour(self):
        """
        Get the interval start hour.

        :return: The interval start hour.
        :rtype: int
        """
        return self._intervalStartHour

    def getIntervalEndHour(self):
        """
        Get the interval end hour.

        :return: The interval end hour.
        :rtype: int
        """
        return self._intervalEndHour

    def getNRepeats(self):
        """
        Get the number of repeats.

        :return: The number of repeats.
        :rtype: int
        """
        return self._nRepeats

    def getRepeatUnit(self):
        """
        Get the repeat unit.

        :return: The repeat unit, from RepetitiveInterval.RepeatUnit.
        :rtype: int
        """
        return self._repeatUnit

    def _hasIntervalOnDate(self, timePoint):
        """
        Check if the date of the time point is in any interval.

        :param float timePoint: The time point as milliseconds since Jan 1,
          1970 UTC.
        :return: True if the date of the time point is in any interval.
        :rtype: bool
        """
        timePointDate = datetime.utcfromtimestamp(
          round(RepetitiveInterval._toDateOnlyMilliseconds(timePoint) / 1000.0))
        startDate = datetime.utcfromtimestamp(self._startDate / 1000.0)
        endDate = datetime.utcfromtimestamp(self._endDate / 1000.0)

        if timePointDate < startDate or timePointDate > endDate:
            return False

        if self._repeatUnit == RepetitiveInterval.RepeatUnit.NONE:
            return True

        if self._repeatUnit == RepetitiveInterval.RepeatUnit.DAY:
            durationDays = int(round(
              (timePointDate - startDate).total_seconds() /
              RepetitiveInterval.SECONDS_IN_DAY))
            if durationDays % self._nRepeats == 0:
                return True
        elif (self._repeatUnit == RepetitiveInterval.RepeatUnit.MONTH and
              timePointDate.day == startDate.day):
            yearDifference = timePointDate.year - startDate.year
            monthDifference = (12 * yearDifference +
              timePointDate.month - startDate.month)
            if monthDifference % self._nRepeats == 0:
              return True
        elif (self._repeatUnit == RepetitiveInterval.RepeatUnit.YEAR and
              timePointDate.day == startDate.day and
              timePointDate.month == startDate.month):
            difference = timePointDate.year - startDate.year
            if difference % self._nRepeats == 0:
              return True

        return False

    @staticmethod
    def _toDateOnlyMilliseconds(timePoint):
        """
        Return a time point on the beginning of the date (without hours,
        minutes, etc.)

        :param float timePoint: The time point as milliseconds since Jan 1,
          1970 UTC.
        :return: A time point as milliseconds since Jan 1, 1970 UTC.
        :rtype: float
        """
        result = round(float(timePoint))
        result -= result % RepetitiveInterval.MILLISECONDS_IN_DAY
        return result

    MILLISECONDS_IN_HOUR = 3600 * 1000
    MILLISECONDS_IN_DAY = 24 * 3600 * 1000
    SECONDS_IN_DAY = 24 * 3600

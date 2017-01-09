# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2016-2017 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# @author: From ndn-cxx src/security https://github.com/named-data/ndn-cxx
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
This module defines the ValidityPeriod class which is used in a Data packet's
SignatureInfo and represents the begin and end times of a certificate's validity
period.
"""

import math

class ValidityPeriod(object):
    """
    Create a new ValidityPeriod object, possibly copying values from another object.

    :param ValidityPeriod value: (optional) If value is a ValidityPeriod, copy
      its values. If value is omitted, reate a default ValidityPeriodLite where
      the period is not specified.
    """
    def __init__(self, value = None):
        if value == None:
            self._notBefore = 1e37
            self._notAfter = -1e37
        elif type(value) is ValidityPeriod:
            # Copy its values.
            self._notBefore = value._notBefore
            self._notAfter = value._notAfter
        else:
            raise RuntimeError(
              "Unrecognized type for ValidityPeriod constructor: " +
              str(type(value)))

        self._changeCount = 0

    def hasPeriod(self):
        """
        Check if the period has been set.

        :return: True if the period has been set, False if the period is not
          specified (after calling the default constructor or clear).
        :rtype: bool
        """
        return not (self._notBefore == 1e37 and
                    self._notAfter == -1e37)

    def getNotBefore(self):
        """
        Get the beginning of the validity period range.

        :return: The time as milliseconds since Jan 1, 1970 UTC.
        :rtype: float
        """
        return self._notBefore

    def getNotAfter(self):
        """
        Get the end of the validity period range.

        :return: The time as milliseconds since Jan 1, 1970 UTC.
        :rtype: float
        """
        return self._notAfter

    def clear(self):
        """
        Reset to a default ValidityPeriod where the period is not specified.
        """
        self._notBefore = 1e37
        self._notAfter = -1e37
        self._changeCount += 1

    def setPeriod(self, notBefore, notAfter):
        """
        Set the validity period.

        :param float notBefore: The beginning of the validity period range as
          milliseconds since Jan 1, 1970 UTC. Note that this is rounded up to
          the nearest whole second.
        :param float notAfter: The end of the validity period range as
          milliseconds since Jan 1, 1970 UTC. Note that this is rounded down to
          the nearest whole second.
        :return: This ValidityPeriod so that you can chain calls to update
          values.
        :rtype: ValidityPeriod
        """
        # Round up to the nearest second.
        self._notBefore = round(math.ceil(round(notBefore) / 1000.0) * 1000.0)
        # Round down to the nearest second.
        self._notAfter = round(math.floor(round(notAfter) / 1000.0) * 1000.0)
        self._changeCount += 1

        return self

    def isValid(self, time):
        """
        Check if the time falls within the validity period.

        :param float time: The time to check as milliseconds since Jan 1, 1970
          UTC.
        :return: True if the beginning of the validity period is less than or
          equal to time and time is less than or equal to the end of the
          validity period.
        :rtype: bool
        """
        return self._notBefore <= time and time <= self._notAfter

    def getChangeCount(self):
        """
        Get the change count, which is incremented each time this object is
        changed.

        :return: The change count.
        :rtype: int
        """
        return self._changeCount

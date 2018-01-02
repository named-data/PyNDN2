# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt unit tests
# https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/schedule.t.cpp
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

import unittest as ut
from test_utils import toIsoString, fromIsoString
from pyndn.util import Blob
from pyndn.encrypt import RepetitiveInterval, Schedule

SCHEDULE = bytearray([
  0x8f, 0xc4,# Schedule
  0x8d, 0x90,# WhiteIntervalList
  #####
  0x8c, 0x2e, # RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x04,
    0x89, 0x01,
      0x07,
    0x8a, 0x01,
      0x00,
    0x8b, 0x01,
      0x00,
  #####
  0x8c, 0x2e, # RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x38, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x05,
    0x89, 0x01,
      0x0a,
    0x8a, 0x01,
      0x02,
    0x8b, 0x01,
      0x01,
  #####
  0x8c, 0x2e, # RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x38, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x06,
    0x89, 0x01,
      0x08,
    0x8a, 0x01,
      0x01,
    0x8b, 0x01,
      0x01,
  #####
  0x8e, 0x30, # BlackIntervalList
  #####
  0x8c, 0x2e, # RepetitiveInterval
     0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x37, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x37, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x07,
    0x89, 0x01,
      0x08,
    0x8a, 0x01,
      0x00,
    0x8b, 0x01,
      0x00
])

class TestSchedule(ut.TestCase):
    def test_calculate_interval_with_black_and_white(self):
        schedule = Schedule()

        interval1 = RepetitiveInterval(
          fromIsoString("20150825T000000"),
          fromIsoString("20150827T000000"), 5, 10, 2,
          RepetitiveInterval.RepeatUnit.DAY)
        interval2 = RepetitiveInterval(
          fromIsoString("20150825T000000"),
          fromIsoString("20150827T000000"), 6, 8, 1,
          RepetitiveInterval.RepeatUnit.DAY)
        interval3 = RepetitiveInterval(
          fromIsoString("20150827T000000"),
          fromIsoString("20150827T000000"), 7, 8)
        interval4 = RepetitiveInterval(
          fromIsoString("20150825T000000"),
          fromIsoString("20150825T000000"), 4, 7)

        schedule.addWhiteInterval(interval1)
        schedule.addWhiteInterval(interval2)
        schedule.addWhiteInterval(interval4)
        schedule.addBlackInterval(interval3)

        # timePoint1 --> positive 8.25 4-10
        timePoint1 = fromIsoString("20150825T063000")
        result = schedule.getCoveringInterval(timePoint1)
        self.assertEqual(result.isPositive, True)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20150825T040000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20150825T100000")

        # timePoint2 --> positive 8.26 6-8
        timePoint2 = fromIsoString("20150826T073000")
        result = schedule.getCoveringInterval(timePoint2)
        self.assertEqual(result.isPositive, True)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20150826T060000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20150826T080000")

        # timePoint3 --> positive 8.27 5-7
        timePoint3 = fromIsoString("20150827T053000")
        result = schedule.getCoveringInterval(timePoint3)
        self.assertEqual(result.isPositive, True)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20150827T050000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20150827T070000")

        # timePoint4 --> positive 8.27 5-7
        timePoint4 = fromIsoString("20150827T063000")
        result = schedule.getCoveringInterval(timePoint4)
        self.assertEqual(result.isPositive, True)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20150827T050000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20150827T070000")

        # timePoint5 --> negative 8.27 7-8
        timePoint5 = fromIsoString("20150827T073000")
        result = schedule.getCoveringInterval(timePoint5)
        self.assertEqual(result.isPositive, False)
        self.assertEqual(result.interval.isEmpty(), False)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20150827T070000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20150827T080000")

        # timePoint6 --> negative 8.25 10-24
        timePoint6 = fromIsoString("20150825T113000")
        result = schedule.getCoveringInterval(timePoint6)
        self.assertEqual(result.isPositive, False)
        self.assertEqual(result.interval.isEmpty(), False)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20150825T100000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20150826T000000")

    def test_calculate_interval_without_black(self):
        schedule = Schedule()

        interval1 = RepetitiveInterval(
          fromIsoString("20150825T000000"),
          fromIsoString("20150827T000000"), 5, 10, 2,
          RepetitiveInterval.RepeatUnit.DAY)
        interval2 = RepetitiveInterval(
          fromIsoString("20150825T000000"),
          fromIsoString("20150827T000000"), 6, 8, 1,
          RepetitiveInterval.RepeatUnit.DAY)
        interval3 = RepetitiveInterval(
          fromIsoString("20150825T000000"),
          fromIsoString("20150825T000000"), 4, 7)

        schedule.addWhiteInterval(interval1)
        schedule.addWhiteInterval(interval2)
        schedule.addWhiteInterval(interval3)

        # timePoint1 --> positive 8.25 4-10
        timePoint1 = fromIsoString("20150825T063000")
        result = schedule.getCoveringInterval(timePoint1)
        self.assertEqual(result.isPositive, True)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20150825T040000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20150825T100000")

        # timePoint2 --> positive 8.26 6-8
        timePoint2 = fromIsoString("20150826T073000")
        result = schedule.getCoveringInterval(timePoint2)
        self.assertEqual(result.isPositive, True)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20150826T060000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20150826T080000")

        # timePoint3 --> positive 8.27 5-10
        timePoint3 = fromIsoString("20150827T053000")
        result = schedule.getCoveringInterval(timePoint3)
        self.assertEqual(result.isPositive, True)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20150827T050000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20150827T100000")

        # timePoint4 --> negative 8.25 10-24
        timePoint4 = fromIsoString("20150825T113000")
        result = schedule.getCoveringInterval(timePoint4)
        self.assertEqual(result.isPositive, False)
        self.assertEqual(result.interval.isEmpty(), False)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20150825T100000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20150826T000000")

        # timePoint5 --> negative 8.25 0-4
        timePoint5 = fromIsoString("20150825T013000")
        result = schedule.getCoveringInterval(timePoint5)
        self.assertEqual(result.isPositive, False)
        self.assertEqual(result.interval.isEmpty(), False)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20150825T000000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20150825T040000")

    def test_calculate_interval_without_white(self):
        schedule = Schedule()

        interval1 = RepetitiveInterval(
          fromIsoString("20150825T000000"),
          fromIsoString("20150827T000000"), 5, 10, 2,
          RepetitiveInterval.RepeatUnit.DAY)
        interval2 = RepetitiveInterval(
          fromIsoString("20150825T000000"),
          fromIsoString("20150827T000000"), 6, 8, 1,
          RepetitiveInterval.RepeatUnit.DAY)

        schedule.addBlackInterval(interval1)
        schedule.addBlackInterval(interval2)

        # timePoint1 --> negative 8.25 4-10
        timePoint1 = fromIsoString("20150825T063000")
        result = schedule.getCoveringInterval(timePoint1)
        self.assertEqual(result.isPositive, False)
        self.assertEqual(result.interval.isEmpty(), False)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20150825T050000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20150825T100000")

        # timePoint2 --> negative 8.25 0-4
        timePoint2 = fromIsoString("20150825T013000")
        result = schedule.getCoveringInterval(timePoint2)
        self.assertEqual(result.isPositive, False)
        self.assertEqual(result.interval.isEmpty(), False)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20150825T000000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20150826T000000")

    def test_encode_and_decode(self):
        schedule = Schedule()

        interval1 = RepetitiveInterval(
          fromIsoString("20150825T000000"),
          fromIsoString("20150828T000000"), 5, 10, 2,
          RepetitiveInterval.RepeatUnit.DAY)
        interval2 = RepetitiveInterval(
          fromIsoString("20150825T000000"),
          fromIsoString("20150828T000000"), 6, 8, 1,
          RepetitiveInterval.RepeatUnit.DAY)
        interval3 = RepetitiveInterval(
          fromIsoString("20150827T000000"),
          fromIsoString("20150827T000000"), 7, 8)
        interval4 = RepetitiveInterval(
          fromIsoString("20150825T000000"),
          fromIsoString("20150825T000000"), 4, 7)

        schedule.addWhiteInterval(interval1)
        schedule.addWhiteInterval(interval2)
        schedule.addWhiteInterval(interval4)
        schedule.addBlackInterval(interval3)

        encoding = schedule.wireEncode()
        encoding2 = Blob(SCHEDULE, False)
        self.assertTrue(encoding.equals(encoding2))

        schedule2 = Schedule()
        schedule2.wireDecode(encoding)

        # timePoint1 --> positive 8.25 4-10
        timePoint1 = fromIsoString("20150825T063000")
        result = schedule.getCoveringInterval(timePoint1)
        self.assertEqual(result.isPositive, True)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20150825T040000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20150825T100000")

        # timePoint2 --> positive 8.26 6-8
        timePoint2 = fromIsoString("20150826T073000")
        result = schedule.getCoveringInterval(timePoint2)
        self.assertEqual(result.isPositive, True)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20150826T060000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20150826T080000")

if __name__ == '__main__':
    ut.main(verbosity=2)

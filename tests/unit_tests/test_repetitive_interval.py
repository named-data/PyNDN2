# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt unit tests
# https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/repetitive-interval.t.cpp
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
from pyndn.encrypt import RepetitiveInterval

class TestRepetitiveInterval(ut.TestCase):
    def test_construction(self):
        repetitiveInterval1 = RepetitiveInterval(
          fromIsoString("20150825T000000"),
          fromIsoString("20150825T000000"), 5, 10)
        self.assertEqual(toIsoString(repetitiveInterval1.getStartDate()), "20150825T000000")
        self.assertEqual(toIsoString(repetitiveInterval1.getEndDate()), "20150825T000000")
        self.assertEqual(repetitiveInterval1.getIntervalStartHour(), 5)
        self.assertEqual(repetitiveInterval1.getIntervalEndHour(), 10)

        repetitiveInterval2 = RepetitiveInterval(
          fromIsoString("20150825T000000"),
          fromIsoString("20150827T000000"), 5, 10, 1,
          RepetitiveInterval.RepeatUnit.DAY)

        self.assertEqual(repetitiveInterval2.getNRepeats(), 1)
        self.assertEqual(
          repetitiveInterval2.getRepeatUnit(), RepetitiveInterval.RepeatUnit.DAY)

        repetitiveInterval3 = RepetitiveInterval(
          fromIsoString("20150825T000000"),
          fromIsoString("20151227T000000"), 5, 10, 2,
          RepetitiveInterval.RepeatUnit.MONTH)

        self.assertEqual(repetitiveInterval3.getNRepeats(), 2)
        self.assertEqual(
          repetitiveInterval3.getRepeatUnit(), RepetitiveInterval.RepeatUnit.MONTH)

        repetitiveInterval4 = RepetitiveInterval(
          fromIsoString("20150825T000000"),
          fromIsoString("20301227T000000"), 5, 10, 5,
          RepetitiveInterval.RepeatUnit.YEAR)

        self.assertEqual(repetitiveInterval4.getNRepeats(), 5)
        self.assertEqual(
          repetitiveInterval4.getRepeatUnit(), RepetitiveInterval.RepeatUnit.YEAR)

        repetitiveInterval5 = RepetitiveInterval()

        self.assertEqual(repetitiveInterval5.getNRepeats(), 0)
        self.assertEqual(
          repetitiveInterval5.getRepeatUnit(), RepetitiveInterval.RepeatUnit.NONE)

    def test_cover_time_point(self):
        ################################ With the repeat unit DAY.

        repetitiveInterval1 = RepetitiveInterval(
          fromIsoString("20150825T000000"),
          fromIsoString("20150925T000000"), 5, 10, 2,
          RepetitiveInterval.RepeatUnit.DAY)

        timePoint1 = fromIsoString("20150825T050000")

        result = repetitiveInterval1.getInterval(timePoint1)
        self.assertEqual(result.isPositive, True)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20150825T050000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20150825T100000")

        timePoint2 = fromIsoString("20150902T060000")

        result = repetitiveInterval1.getInterval(timePoint2)
        self.assertEqual(result.isPositive, True)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20150902T050000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20150902T100000")

        timePoint3 = fromIsoString("20150929T040000")

        result = repetitiveInterval1.getInterval(timePoint3)
        self.assertEqual(result.isPositive, False)

        ################################ With the repeat unit MONTH.

        repetitiveInterval2 = RepetitiveInterval(
          fromIsoString("20150825T000000"),
          fromIsoString("20160825T000000"), 5, 10, 2,
          RepetitiveInterval.RepeatUnit.MONTH)

        timePoint4 = fromIsoString("20150825T050000")

        result = repetitiveInterval2.getInterval(timePoint4)
        self.assertEqual(result.isPositive, True)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20150825T050000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20150825T100000")

        timePoint5 = fromIsoString("20151025T060000")

        result = repetitiveInterval2.getInterval(timePoint5)
        self.assertEqual(result.isPositive, True)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20151025T050000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20151025T100000")

        timePoint6 = fromIsoString("20151226T050000")

        result = repetitiveInterval2.getInterval(timePoint6)
        self.assertEqual(result.isPositive, False)

        timePoint7 = fromIsoString("20151225T040000")

        result = repetitiveInterval2.getInterval(timePoint7)
        self.assertEqual(result.isPositive, False)

        ################################ With the repeat unit YEAR.

        repetitiveInterval3 = RepetitiveInterval(
          fromIsoString("20150825T000000"),
          fromIsoString("20300825T000000"), 5, 10, 3,
          RepetitiveInterval.RepeatUnit.YEAR)

        timePoint8 = fromIsoString("20150825T050000")

        result = repetitiveInterval3.getInterval(timePoint8)
        self.assertEqual(result.isPositive, True)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20150825T050000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20150825T100000")

        timePoint9 = fromIsoString("20180825T060000")

        result = repetitiveInterval3.getInterval(timePoint9)
        self.assertEqual(result.isPositive, True)
        self.assertEqual(toIsoString(result.interval.getStartTime()), "20180825T050000")
        self.assertEqual(toIsoString(result.interval.getEndTime()), "20180825T100000")

        timePoint10 = fromIsoString("20180826T050000")
        result = repetitiveInterval3.getInterval(timePoint10)
        self.assertEqual(result.isPositive, False)

        timePoint11 = fromIsoString("20210825T040000")
        result = repetitiveInterval3.getInterval(timePoint11)
        self.assertEqual(result.isPositive, False)

        timePoint12 = fromIsoString("20300825T040000")
        result = repetitiveInterval3.getInterval(timePoint12)
        self.assertEqual(result.isPositive, False)

    def test_comparison(self):
        def check(small, big):
            return small.compare(big) < 0 and not (big.compare(small) < 0)

        self.assertTrue(check(RepetitiveInterval(fromIsoString("20150825T000000"),
                                                 fromIsoString("20150828T000000"),
                                             5, 10, 2, RepetitiveInterval.RepeatUnit.DAY),
                              RepetitiveInterval(fromIsoString("20150826T000000"),
                                                 fromIsoString("20150828T000000"),
                                             5, 10, 2, RepetitiveInterval.RepeatUnit.DAY)))

        self.assertTrue(check(RepetitiveInterval(fromIsoString("20150825T000000"),
                                                 fromIsoString("20150828T000000"),
                                             5, 10, 2, RepetitiveInterval.RepeatUnit.DAY),
                              RepetitiveInterval(fromIsoString("20150825T000000"),
                                                 fromIsoString("20150828T000000"),
                                             6, 10, 2, RepetitiveInterval.RepeatUnit.DAY)))

        self.assertTrue(check(RepetitiveInterval(fromIsoString("20150825T000000"),
                                                 fromIsoString("20150828T000000"),
                                             5, 10, 2, RepetitiveInterval.RepeatUnit.DAY),
                              RepetitiveInterval(fromIsoString("20150825T000000"),
                                                 fromIsoString("20150828T000000"),
                                             5, 11, 2, RepetitiveInterval.RepeatUnit.DAY)))

        self.assertTrue(check(RepetitiveInterval(fromIsoString("20150825T000000"),
                                                 fromIsoString("20150828T000000"),
                                             5, 10, 2, RepetitiveInterval.RepeatUnit.DAY),
                              RepetitiveInterval(fromIsoString("20150825T000000"),
                                                 fromIsoString("20150828T000000"),
                                             5, 10, 3, RepetitiveInterval.RepeatUnit.DAY)))

        self.assertTrue(check(RepetitiveInterval(fromIsoString("20150825T000000"),
                                                 fromIsoString("20150828T000000"),
                                             5, 10, 2, RepetitiveInterval.RepeatUnit.DAY),
                              RepetitiveInterval(fromIsoString("20150825T000000"),
                                                 fromIsoString("20150828T000000"),
                                             5, 10, 2, RepetitiveInterval.RepeatUnit.MONTH)))

if __name__ == '__main__':
    ut.main(verbosity=2)

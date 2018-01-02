# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt unit tests
# https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/interval.t.cpp
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
from pyndn.encrypt import Interval

class TestInterval(ut.TestCase):
    def test_construction(self):
        # Construct with the right parameters.
        interval1 = Interval(fromIsoString("20150825T120000"),
                             fromIsoString("20150825T160000"))
        self.assertEqual(toIsoString(interval1.getStartTime()), "20150825T120000")
        self.assertEqual(toIsoString(interval1.getEndTime()), "20150825T160000")
        self.assertTrue(interval1.isValid())

        # Construct with the invalid interval.
        interval2 = Interval()
        self.assertTrue(not interval2.isValid())

        # Construct with the empty interval.
        interval3 = Interval(True)
        self.assertTrue(interval3.isValid())
        self.assertTrue(interval3.isEmpty())

    def test_cover_time_point(self):
        interval = Interval(fromIsoString("20150825T120000"),
                            fromIsoString("20150825T160000"))

        timePoint1 = fromIsoString("20150825T120000")
        timePoint2 = fromIsoString("20150825T130000")
        timePoint3 = fromIsoString("20150825T170000")
        timePoint4 = fromIsoString("20150825T110000")

        self.assertTrue(interval.covers(timePoint1))
        self.assertTrue(interval.covers(timePoint2))
        self.assertTrue(not interval.covers(timePoint3))
        self.assertTrue(not interval.covers(timePoint4))

    def test_intersection_and_union(self):
        interval1 = Interval(fromIsoString("20150825T030000"),
                             fromIsoString("20150825T050000"))
        # No intersection.
        interval2 = Interval(fromIsoString("20150825T050000"),
                             fromIsoString("20150825T070000"))
        # No intersection.
        interval3 = Interval(fromIsoString("20150825T060000"),
                             fromIsoString("20150825T070000"))
        # There's an intersection.
        interval4 = Interval(fromIsoString("20150825T010000"),
                             fromIsoString("20150825T040000"))
        # Right in interval1, there's an intersection.
        interval5 = Interval(fromIsoString("20150825T030000"),
                             fromIsoString("20150825T040000"))
        # Wrap interval1, there's an intersection.
        interval6 = Interval(fromIsoString("20150825T010000"),
                             fromIsoString("20150825T050000"))
        # Empty interval.
        interval7 = Interval(True)

        tempInterval = Interval(interval1)
        tempInterval.intersectWith(interval2)
        self.assertTrue(tempInterval.isEmpty())

        tempInterval = Interval(interval1)
        gotError = True
        try:
            tempInterval.unionWith(interval2)
            gotError = False
        except:
            pass
        if not gotError:
          self.fail("Expected error in unionWith(interval2)")

        tempInterval = Interval(interval1)
        tempInterval.intersectWith(interval3)
        self.assertTrue(tempInterval.isEmpty())

        tempInterval = Interval(interval1)
        gotError = True
        try:
          tempInterval.unionWith(interval3)
          gotError = False
        except:
            pass
        if not gotError:
          self.fail("Expected error in unionWith(interval3)")

        tempInterval = Interval(interval1)
        tempInterval.intersectWith(interval4)
        self.assertTrue(not tempInterval.isEmpty())
        self.assertEqual(toIsoString(tempInterval.getStartTime()), "20150825T030000")
        self.assertEqual(toIsoString(tempInterval.getEndTime()), "20150825T040000")

        tempInterval = Interval(interval1)
        tempInterval.unionWith(interval4)
        self.assertTrue(not tempInterval.isEmpty())
        self.assertEqual(toIsoString(tempInterval.getStartTime()), "20150825T010000")
        self.assertEqual(toIsoString(tempInterval.getEndTime()), "20150825T050000")

        tempInterval = Interval(interval1)
        tempInterval.intersectWith(interval5)
        self.assertTrue(not tempInterval.isEmpty())
        self.assertEqual(toIsoString(tempInterval.getStartTime()), "20150825T030000")
        self.assertEqual(toIsoString(tempInterval.getEndTime()), "20150825T040000")

        tempInterval = Interval(interval1)
        tempInterval.unionWith(interval5)
        self.assertTrue(not tempInterval.isEmpty())
        self.assertEqual(toIsoString(tempInterval.getStartTime()), "20150825T030000")
        self.assertEqual(toIsoString(tempInterval.getEndTime()), "20150825T050000")

        tempInterval = Interval(interval1)
        tempInterval.intersectWith(interval6)
        self.assertTrue(not tempInterval.isEmpty())
        self.assertEqual(toIsoString(tempInterval.getStartTime()), "20150825T030000")
        self.assertEqual(toIsoString(tempInterval.getEndTime()), "20150825T050000")

        tempInterval = Interval(interval1)
        tempInterval.unionWith(interval6)
        self.assertTrue(not tempInterval.isEmpty())
        self.assertEqual(toIsoString(tempInterval.getStartTime()), "20150825T010000")
        self.assertEqual(toIsoString(tempInterval.getEndTime()), "20150825T050000")

        tempInterval = Interval(interval1)
        tempInterval.intersectWith(interval7)
        self.assertTrue(tempInterval.isEmpty())

        tempInterval = Interval(interval1)
        tempInterval.unionWith(interval7)
        self.assertTrue(not tempInterval.isEmpty())
        self.assertEqual(toIsoString(tempInterval.getStartTime()), "20150825T030000")
        self.assertEqual(toIsoString(tempInterval.getEndTime()), "20150825T050000")

if __name__ == '__main__':
    ut.main(verbosity=2)

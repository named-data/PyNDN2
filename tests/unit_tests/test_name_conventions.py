# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx NamingConventions unit tests:
# https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/test-name.cpp.
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
from pyndn import Name

class TestNameConventions(ut.TestCase):
    def testNumberWithMarker(self):
        expected = Name("/%AA%03%E8")
        number = 1000
        marker = 0xAA
        self.assertEqual(Name().append(Name.Component.fromNumberWithMarker(number, marker)), expected, "fromNumberWithMarker did not create the expected component")
        self.assertEqual(expected[0].toNumberWithMarker(marker), number, "toNumberWithMarker did not return the expected value")

    def testSegment(self):
        expected = Name("/%00%27%10")
        self.assertTrue(expected.get(0).isSegment())
        number = 10000
        self.assertEqual(Name().appendSegment(number), expected,  "appendSegment did not create the expected component")
        self.assertEqual(expected[0].toSegment(), number,  "toSegment did not return the expected value")

    def testSegmentOffset(self):
        expected = Name("/%FB%00%01%86%A0")
        self.assertTrue(expected.get(0).isSegmentOffset())
        number = 100000
        self.assertEqual(Name().appendSegmentOffset(number), expected,  "appendSegmentOffset did not create the expected component")
        self.assertEqual(expected[0].toSegmentOffset(), number,  "toSegmentOffset did not return the expected value")

    def testVersion(self):
        expected = Name("/%FD%00%0FB%40")
        self.assertTrue(expected.get(0).isVersion())
        number = 1000000
        self.assertEqual(Name().appendVersion(number), expected,  "appendVersion did not create the expected component")
        self.assertEqual(expected[0].toVersion(), number,  "toVersion did not return the expected value")

    def testSequenceNumber(self):
        expected = Name("/%FE%00%98%96%80")
        self.assertTrue(expected.get(0).isSequenceNumber())
        number = 10000000
        self.assertEqual(Name().appendSequenceNumber(number), expected,  "appendSequenceNumber did not create the expected component")
        self.assertEqual(expected[0].toSequenceNumber(), number,  "toSequenceNumber did not return the expected value")

    def testTimestamp(self):
        expected = Name("/%FC%00%04%7BE%E3%1B%00%00")
        self.assertTrue(expected.get(0).isTimestamp())
        # 40 years (not counting leap years) in microseconds.
        number = 40 * 365 * 24 * 3600 * 1000000
        self.assertEqual(Name().appendTimestamp(number), expected,  "appendTimestamp did not create the expected component")
        self.assertEqual(expected[0].toTimestamp(), number,  "toTimestamp did not return the expected value")

if __name__ == '__main__':
    ut.main(verbosity=2)

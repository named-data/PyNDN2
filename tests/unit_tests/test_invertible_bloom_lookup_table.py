# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From PSync unit tests:
# https://github.com/named-data/PSync/blob/master/tests/test-iblt.cpp
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
from pyndn.util import Blob
from pyndn.util.common import Common
from pyndn.sync.detail.invertible_bloom_lookup_table import InvertibleBloomLookupTable

class TestInvertibleBloomLookupTable(ut.TestCase):
    def testEqual(self):
        size = 10

        iblt1 = InvertibleBloomLookupTable(size)
        iblt2 = InvertibleBloomLookupTable(size)

        self.assertTrue(iblt1.equals(iblt2))

        prefix = Name("/test/memphis").appendNumber(1).toUri()
        newHash = Common.murmurHash3Blob(11, prefix)
        iblt1.insert(newHash)
        iblt2.insert(newHash)
        self.assertTrue(iblt1.equals(iblt2))

        ibfName1 = Name("/sync")
        ibfName2 = Name("/sync")

        ibfName1.append(iblt1.encode());
        ibfName2.append(iblt2.encode());
        self.assertTrue(ibfName1.equals(ibfName2))

    def testNameAppendAndExtract(self):
        size = 10

        iblt = InvertibleBloomLookupTable(size)
        prefix = Name("/test/memphis").appendNumber(1).toUri()
        newHash = Common.murmurHash3Blob(11, prefix)
        iblt.insert(newHash)

        expectedEncoding = [
          0x78, 0xda, 0x63, 0x64, 0x60, 0x60, 0xd8, 0x55, 0xb5, 0xfc,
          0x5b, 0xb2, 0xef, 0xe2, 0x6c, 0x06, 0x0a, 0x00, 0x23, 0x1d,
          0xcd, 0x01, 0x00, 0x65, 0x29, 0x0d, 0xb1
        ]

        ibltName = Name("sync")
        encodedIblt = iblt.encode()
        self.assertTrue(encodedIblt.equals(Blob(expectedEncoding)))
        ibltName.append(encodedIblt)

        received = InvertibleBloomLookupTable(size)
        received.initialize(ibltName.get(-1).getValue())

        self.assertTrue(iblt.equals(received))

        receivedDifferentSize = InvertibleBloomLookupTable(20)
        try:
            receivedDifferentSize.initialize(ibltName.get(-1).getValue())
            self.fail("Did not throw the expected exception")
        except RuntimeError:
            pass
        else:
            self.fail("Did not throw the expected exception")

    def testCopyInsertErase(self):
        size = 10

        iblt1 = InvertibleBloomLookupTable(size)

        prefix = Name("/test/memphis").appendNumber(1).toUri()
        hash1 = Common.murmurHash3Blob(11, prefix)
        iblt1.insert(hash1)

        iblt2 = InvertibleBloomLookupTable(iblt1)
        iblt2.erase(hash1)
        prefix = Name("/test/memphis").appendNumber(2).toUri()
        hash3 = Common.murmurHash3Blob(11, prefix)
        iblt2.insert(hash3)

        iblt1.erase(hash1)
        prefix = Name("/test/memphis").appendNumber(5).toUri()
        hash5 = Common.murmurHash3Blob(11, prefix)
        iblt1.insert(hash5)

        iblt2.erase(hash3)
        iblt2.insert(hash5)

        self.assertTrue(iblt1.equals(iblt2))

    def testHigherSequence(self):
        # This is the case where we can't recognize if the received IBF has a
        # higher sequence number. This is relevant to the full sync case.
        size = 10

        ownIblt = InvertibleBloomLookupTable(size)
        receivedIblt = InvertibleBloomLookupTable(size)

        prefix = Name("/test/memphis").appendNumber(3).toUri()
        hash1 = Common.murmurHash3Blob(11, prefix)
        ownIblt.insert(hash1)

        prefix2 = Name("/test/memphis").appendNumber(4).toUri()
        hash2 = Common.murmurHash3Blob(11, prefix2)
        receivedIblt.insert(hash2)

        diff = ownIblt.difference(receivedIblt)
        positive = set()
        negative = set()

        self.assertTrue(diff.listEntries(positive, negative))
        self.assertEqual(1, len(positive))
        self.assertTrue(min(positive) == hash1)

        self.assertEqual(1, len(negative))
        self.assertTrue(min(negative) == hash2)

    def testDifference(self):
        size = 10

        ownIblt = InvertibleBloomLookupTable(size)

        receivedIblt = InvertibleBloomLookupTable(ownIblt)

        diff = ownIblt.difference(receivedIblt)

        # Non-empty positive means we have some elements that the other doesn't.
        positive = set()
        negative = set()

        self.assertTrue(diff.listEntries(positive, negative))
        self.assertEqual(0, len(positive))
        self.assertEqual(0, len(negative))

        prefix = Name("/test/memphis").appendNumber(1).toUri()
        newHash = Common.murmurHash3Blob(11, prefix)
        ownIblt.insert(newHash)

        diff = ownIblt.difference(receivedIblt)
        self.assertTrue(diff.listEntries(positive, negative))
        self.assertEqual(1, len(positive))
        self.assertEqual(0, len(negative))

        prefix = Name("/test/csu").appendNumber(1).toUri()
        newHash = Common.murmurHash3Blob(11, prefix)
        receivedIblt.insert(newHash)

        diff = ownIblt.difference(receivedIblt)
        self.assertTrue(diff.listEntries(positive, negative))
        self.assertEqual(1, len(positive))
        self.assertEqual(1, len(negative))

    def testDifferenceBwOversizedIblts(self):
        # Insert 50 elements into an IBLT of size 10. Then check that we can
        # still list the difference even though we can't list the IBLT itself.

        size = 10

        ownIblt = InvertibleBloomLookupTable(size)

        for i in range(50):
            prefix = Name("/test/memphis" + str(i)).appendNumber(1).toUri()
            newHash = Common.murmurHash3Blob(11, prefix)
            ownIblt.insert(newHash)

        receivedIblt = InvertibleBloomLookupTable(ownIblt)

        prefix = Name("/test/ucla").appendNumber(1).toUri()
        newHash = Common.murmurHash3Blob(11, prefix)
        ownIblt.insert(newHash)

        diff = ownIblt.difference(receivedIblt)

        positive = set()
        negative = set()
        self.assertTrue(diff.listEntries(positive, negative))
        self.assertEqual(1, len(positive))
        self.assertEqual(newHash, min(positive))
        self.assertEqual(0, len(negative))

        self.assertTrue(not ownIblt.listEntries(positive, negative))
        self.assertTrue(not receivedIblt.listEntries(positive, negative))

if __name__ == '__main__':
    ut.main(verbosity=2)

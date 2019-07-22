# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From the PSync library https://github.com/named-data/PSync/blob/master/PSync/detail/iblt.cpp
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
This module defines the InvertibleBloomLookupTable class which implements an
Invertible Bloom Lookup Table (IBLT) (Invertible Bloom Filter). This is used by
FullPSync2017.
"""

import zlib
from pyndn.util.blob import Blob
from pyndn.util.common import Common

class InvertibleBloomLookupTable(object):
    """
    There are two forms of the constructor:
    InvertibleBloomLookupTable(expectedNEntries) - Create an
    InvertibleBloomLookupTable with the expected number of entries.
    InvertibleBloomLookupTable(iblt) - Create an
    InvertibleBloomLookupTable as a copy of the given iblt.

    :param int expectedNEntries: the expected number of entries in the IBLT.
    :param InvertibleBloomLookupTable iblt: The other
      InvertibleBloomLookupTable to copy.
    """
    def __init__(self, value):
        if isinstance(value, InvertibleBloomLookupTable):
            # Make a deep copy the _hashTable array.
            self._hashTable = [None] * len(value._hashTable)
            for i in range(len(value._hashTable)):
                self._hashTable[i] = InvertibleBloomLookupTable._HashTableEntry(
                  value._hashTable[i])
        else:
            expectedNEntries = value
            # 1.5 times the expected number of entries gives a very low probability
            # of a decoding failure.
            nEntries = int(int(expectedNEntries) + int(expectedNEntries) / 2)
            # Make nEntries exactly divisible by N_HASH.
            remainder = nEntries % InvertibleBloomLookupTable.N_HASH
            if remainder != 0:
                nEntries += (InvertibleBloomLookupTable.N_HASH - remainder);

            # initialize() will set the elements.
            self._hashTable = [None] * nEntries  # of _HashTableEntry
            for i in range(len(self._hashTable)):
                self._hashTable[i] = InvertibleBloomLookupTable._HashTableEntry()

    def initialize(self, encoding):
        """
        Populate the hash table using the encoded array representation of the
        IBLT.

        :param Blob encoding: The encoded representation of the IBLT.
        :raises RuntimeError: if the size of the decoded values is not
          compatible with this IBLT.
        """
        values = InvertibleBloomLookupTable._decode(encoding)

        if 3 * len(self._hashTable) != len(values):
            raise RuntimeError(
              "The received Invertible Bloom Filter cannot be decoded")

        for i in range(len(self._hashTable)):
            entry = self._hashTable[i]
            if values[i * 3] != 0:
                entry._count = values[i * 3]
                entry._keySum = values[(i * 3) + 1]
                entry._keyCheck = values[(i * 3) + 2]

    def insert(self, key):
        """
        Insert an entry for the key.
        
        :param int key:
        """
        self._update(InvertibleBloomLookupTable.INSERT, key)

    def erase(self, key):
        """
        Erase an entry for the key.

        :param int key:
        """
        self._update(InvertibleBloomLookupTable.ERASE, key)

    def listEntries(self, positive, negative):
        """
        List all the entries in the IBLT.
        This is called on a difference of two IBLTs: ownIBLT - receivedIBLT.
        Entries listed in positive are in ownIBLT but not in receivedIBLT.
        Entries listed in negative are in receivedIBLT but not in ownIBLT.

        :param set positive: Add positive entries to this set. This first clears
          the set.
        :param set negative: Add negative entries to this set. This first clears
          the set.
        :return: True if decoding is completed successfully.
        :rtype: bool
        """
        positive.clear()
        negative.clear()

        # Make a deep copy.
        peeled = InvertibleBloomLookupTable(self)

        nErased = 0
        while True:
            nErased = 0;
            for entry in peeled._hashTable:
                if entry.isPure():
                    if entry._count == 1:
                        positive.add(entry._keySum)
                    else:
                        negative.add(entry._keySum)

                    peeled._update(-entry._count, entry._keySum)
                    nErased += 1
            
            if not nErased > 0:
                break

        # If any buckets for one of the hash functions is not empty, then we
        # didn't peel them all.
        for entry in peeled._hashTable:
            if not entry.isEmpty():
                return False

        return True

    def difference(self, other):
        """
        Get a new IBLT which is the difference of the other IBLT from this IBLT.

        :param InvertibleBloomLookupTable other: The other IBLT.
        :return: A new IBLT of this - other.
        :rtype: InvertibleBloomLookupTable
        """
        if len(self._hashTable) != len(other._hashTable):
            raise RuntimeError("IBLT difference: Both tables must be the same size")

        result = InvertibleBloomLookupTable(self)
        for i in range(len(self._hashTable)):
            e1 = result._hashTable[i]
            e2 = other._hashTable[i]
            e1._count -= e2._count
            e1._keySum ^= e2._keySum
            e1._keyCheck ^= e2._keyCheck

        return result

    def encode(self):
        """
         Encode this IBLT to a Blob. This encodes this hash table from a
         uint32_t array to a uint8_t array. We create a uin8_t array 12 times
         the size of the uint32_t array. We put the first count in the first 4
         cells, keySum in the next 4, and keyCheck in the next 4. We repeat for
         all the other cells of the hash table. Then we append this uint8_t
         array to the name.

         :return: The encoded Blob.
         :rtype: Blob
        """
        nEntries = len(self._hashTable)
        # hard coding
        unitSize = int((32 * 3) / 8)
        tableSize = unitSize * nEntries

        table = [0] * tableSize

        for i in range(nEntries):
            entry = self._hashTable[i]

            # table[i*12],   table[i*12+1], table[i*12+2], table[i*12+3] --> hashTable[i]._count

            table[(i * unitSize)]     = 0xFF & entry._count
            table[(i * unitSize) + 1] = 0xFF & (entry._count >> 8)
            table[(i * unitSize) + 2] = 0xFF & (entry._count >> 16)
            table[(i * unitSize) + 3] = 0xFF & (entry._count >> 24)

            # table[i*12+4], table[i*12+5], table[i*12+6], table[i*12+7] --> hashTable[i]._keySum

            table[(i * unitSize) + 4] = 0xFF & entry._keySum
            table[(i * unitSize) + 5] = 0xFF & (entry._keySum >> 8)
            table[(i * unitSize) + 6] = 0xFF & (entry._keySum >> 16)
            table[(i * unitSize) + 7] = 0xFF & (entry._keySum >> 24)

            # table[i*12+8], table[i*12+9], table[i*12+10], table[i*12+11] --> hashTable[i]._keyCheck

            table[(i * unitSize) + 8] = 0xFF & entry._keyCheck
            table[(i * unitSize) + 9] = 0xFF & (entry._keyCheck >> 8)
            table[(i * unitSize) + 10] = 0xFF & (entry._keyCheck >> 16)
            table[(i * unitSize) + 11] = 0xFF & (entry._keyCheck >> 24)

        Z_BEST_COMPRESSION = 9
        # Use Blob to convert an array to bytes on both Python 2 and 3.
        compressedBytes = zlib.compress(Blob(table, False).toBytes(), Z_BEST_COMPRESSION)
        return Blob(compressedBytes, False)

    def equals(self, other):
        """
        Check if this IBLT has the same number of entries as the other IBLT and
        that they are equal.

        :param InvertibleBloomLookupTable other: The other OBLT to check.
        """
        iblt1HashTable = self._hashTable
        iblt2HashTable = other._hashTable
        if len(iblt1HashTable) != len(iblt2HashTable):
            return False

        for i in range(len(iblt1HashTable)):
            if  (iblt1HashTable[i]._count != iblt2HashTable[i]._count or
                 iblt1HashTable[i]._keySum != iblt2HashTable[i]._keySum or
                 iblt1HashTable[i]._keyCheck != iblt2HashTable[i]._keyCheck):
                return False

        return True

    def __eq__(self, other):
        return isinstance(other, InvertibleBloomLookupTable) and self.equals(other)

    def __ne__(self, other):
        return not self == other

    class _HashTableEntry(object):
        def __init__(self, other = None):
            if isinstance(other, InvertibleBloomLookupTable._HashTableEntry):
                self._count = other._count
                self._keySum = other._keySum
                self._keyCheck = other._keyCheck
            else:
                self._count = 0
                self._keySum = 0
                self._keyCheck = 0

        def isPure(self):
            """
            :rtype: bool
            """
            if self._count == 1 or self._count == -1:
                # Debug: Convert to
                check = Common.murmurHash3Uint32(
                  InvertibleBloomLookupTable.N_HASHCHECK, self._keySum)
                return self._keyCheck == check

            return False

        def isEmpty(self):
            """
            :rtype: bool
            """
            return self._count == 0 and self._keySum == 0 and self._keyCheck == 0

    def _update(self, plusOrMinus, key):
        """
        Update the entries in _hashTable.

        :param int plusOrMinus: The amount to update the count.
        :param int key: The key for computing the entry.
        """
        bucketsPerHash = int(len(self._hashTable) / InvertibleBloomLookupTable.N_HASH)

        for i in range(InvertibleBloomLookupTable.N_HASH):
            startEntry = i * bucketsPerHash
            h = Common.murmurHash3Uint32(i, key)
            entry = self._hashTable[startEntry + (h % bucketsPerHash)]
            entry._count += plusOrMinus
            entry._keySum ^= key
            entry._keyCheck ^= Common.murmurHash3Uint32(
              InvertibleBloomLookupTable.N_HASHCHECK, key)

    @staticmethod
    def _decode(encoding):
        """
        Decode the IBLT from the Blob. This converts the Blob into a uint8_t
        array which is then decoded to a uint32_t array.

        :param Blob encoding: The encoded IBLT.
        :return: A uint32_t array representing the hash table of the IBLT.
        :rtype: Array<int>
        """
        # Use Blob to convert bytes to an integer array.
        ibltValues = Blob(zlib.decompress(encoding.toBytes()), False)

        nEntries = int(len(ibltValues) / 4)
        values = [0] * nEntries

        ibltValuesBuf = ibltValues.buf()
        for i in range(0, 4 * nEntries, 4):
          t = ((ibltValuesBuf[i + 3] << 24) +
               (ibltValuesBuf[i + 2] << 16) +
               (ibltValuesBuf[i + 1] << 8)  +
               ibltValuesBuf[i])
          values[int(i / 4)] = t

        return values

    N_HASH = 3
    N_HASHCHECK = 11

    INSERT = 1
    ERASE = -1

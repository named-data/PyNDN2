# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
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

from pyndn.util.dynamic_byte_array import DynamicByteArray

"""
This module defines the TlvEncoder class for encoding in the NDN-TLV wire
format.  It encodes into the bytebuffer in a DynamicByteArray, writing
"backwards" from the back of the buffer.
"""

class TlvEncoder(object):
    """
    Create a new TlvEncoder with an initialCapacity for the encoding buffer.

    :param int initialCapacity: (optional) The initial capacity of the encoding
      buffer. If omitted, use a default value.
    """
    def __init__(self, initialCapacity = 16):
        self._output = DynamicByteArray(initialCapacity)
        # _length is the number of bytes that have been written to the back of
        #   self._output._array.
        self._length = 0

    def __len__(self):
        """
        Get the number of bytes that have been written to the output.  You can
        save this number, write sub TLVs, then subtract the new len from this
        to get the total length of the sub TLVs.

        :return: The number of bytes that have been written to the output.
        :rtype: int
        """
        return self._length

    def writeVarNumber(self, varNumber):
        """
        Encode varNumber as a VAR-NUMBER in NDN-TLV and write it to
        self._output just before self._length from the back.
        Advance self._length.

        :param int varNumber: The non-negative number to encode.
        """
        if varNumber < 253:
            self._length += 1
            self._output.ensureLengthFromBack(self._length)
            self._output._array[-self._length] = varNumber & 0xff
        elif varNumber <= 0xffff:
            self._length += 3
            self._output.ensureLengthFromBack(self._length)
            self._output._array[-self._length] = 253
            self._output._array[-self._length + 1] = (varNumber >> 8) & 0xff
            self._output._array[-self._length + 2] = varNumber & 0xff
        elif varNumber <= 0xffffffff:
            self._length += 5
            self._output.ensureLengthFromBack(self._length)
            self._output._array[-self._length] = 254
            self._output._array[-self._length + 1] = (varNumber >> 24) & 0xff
            self._output._array[-self._length + 2] = (varNumber >> 16) & 0xff
            self._output._array[-self._length + 3] = (varNumber >> 8) & 0xff
            self._output._array[-self._length + 4] = varNumber & 0xff
        else:
            self._length += 9
            self._output.ensureLengthFromBack(self._length)
            self._output._array[-self._length] = 255
            self._output._array[-self._length + 1] = (varNumber >> 56) & 0xff
            self._output._array[-self._length + 2] = (varNumber >> 48) & 0xff
            self._output._array[-self._length + 3] = (varNumber >> 40) & 0xff
            self._output._array[-self._length + 4] = (varNumber >> 32) & 0xff
            self._output._array[-self._length + 5] = (varNumber >> 24) & 0xff
            self._output._array[-self._length + 6] = (varNumber >> 16) & 0xff
            self._output._array[-self._length + 7] = (varNumber >> 8) & 0xff
            self._output._array[-self._length + 8] = varNumber & 0xff

    def writeTypeAndLength(self, type, length):
        """
        Encode the type and length as VAR-NUMBER and write to
        self._output just before self._length from the back.
        Advance self._length.

        :param int type: The type of the TLV.
        :param int length: The non-negative length of the TLV.
        """
        # Write backwards.
        self.writeVarNumber(length)
        self.writeVarNumber(type)

    def writeNonNegativeInteger(self, value):
        """
        Encode value as a non-negative integer and write it to self._output
        just before self._length from the back. Advance self._length.

        :param int value: The non-negative integer to encode.
        """
        if value < 0:
            raise ValueError("TLV integer value may not be negative")

        if value <= 0xff:
            self._length += 1
            self._output.ensureLengthFromBack(self._length)
            self._output._array[-self._length] = value & 0xff
        elif value <= 0xffff:
            self._length += 2
            self._output.ensureLengthFromBack(self._length)
            self._output._array[-self._length]     = (value >> 8) & 0xff
            self._output._array[-self._length + 1] = value & 0xff
        elif value <= 0xffffffff:
            self._length += 4
            self._output.ensureLengthFromBack(self._length)
            self._output._array[-self._length]     = (value >> 24) & 0xff
            self._output._array[-self._length + 1] = (value >> 16) & 0xff
            self._output._array[-self._length + 2] = (value >> 8) & 0xff
            self._output._array[-self._length + 3] = value & 0xff
        else:
            self._length += 8
            self._output.ensureLengthFromBack(self._length)
            self._output._array[-self._length]     = (value >> 56) & 0xff
            self._output._array[-self._length + 1] = (value >> 48) & 0xff
            self._output._array[-self._length + 2] = (value >> 40) & 0xff
            self._output._array[-self._length + 3] = (value >> 32) & 0xff
            self._output._array[-self._length + 4] = (value >> 24) & 0xff
            self._output._array[-self._length + 5] = (value >> 16) & 0xff
            self._output._array[-self._length + 6] = (value >> 8) & 0xff
            self._output._array[-self._length + 7] = value & 0xff

    def writeNonNegativeIntegerTlv(self, type, value):
        """
        Write the type, then the length of the encoded value then encode value
        as a non-negative integer and write it to self._output just before
        self._length from the back. Advance self._length.

        :param int type: The type of the TLV.
        :param int value: The non-negative integer to encode.
        """
        # Write backwards.
        saveNBytes = self._length
        self.writeNonNegativeInteger(value)
        self.writeTypeAndLength(type, self._length - saveNBytes)

    def writeOptionalNonNegativeIntegerTlv(self, type, value):
        """
        If value is negative or None then do nothing, otherwise call
        writeNonNegativeIntegerTlv.

        :param int type: The type of the TLV.
        :param int value: If negative or None do nothing, otherwise the integer
          to encode.
        """
        if value != None and value >= 0:
            self.writeNonNegativeIntegerTlv(type, value)

    def writeOptionalNonNegativeIntegerTlvFromFloat(self, type, value):
        """
        If value is negative or None then do nothing, otherwise call
        writeNonNegativeIntegerTlv.

        :param int type: The type of the TLV.
        :param float value: If negative or None do nothing, otherwise use
          int(round(value)).
        """
        if value != None and value >= 0:
            # Note: int() will return int, or long if value is large and this
            #   is a 32-bit system.
            self.writeNonNegativeIntegerTlv(type, int(round(value)))

    def writeBuffer(self, buffer):
        """
        Write the buffer value to self._output just before self._length from the
        back. Advance self._length.

        :param buffer: The byte array with the bytes to write. If value is None,
          then do nothing.
        :type value: bytearray or memoryview
        """
        if buffer == None:
            return

        self._length += len(buffer)
        self._output.copyFromBack(buffer, self._length)

    def writeBlobTlv(self, type, value):
        """
        Write the type, then the length of the blob then the blob value
        to self._output just before self._length from the back.
        Advance self._length.

        :param int type: The type of the TLV.
        :param value: The byte array with the bytes of the blob.  If value is
          None, then just write the type and length 0.
        :type value: bytearray or memoryview
        """
        if value == None:
            self.writeTypeAndLength(type, 0)
            return

        # Write backwards, starting with the blob array.
        self.writeBuffer(value)
        self.writeTypeAndLength(type, len(value))

    def writeOptionalBlobTlv(self, type, value):
        """
        If the byte array is None or zero length then do nothing, otherwise
        call writeBlobTlv.

        :param int type: The type of the TLV.
        :param value: If None or zero length do nothing, otherwise the byte
          array with the bytes of the blob.
        :type value: bytearray or memoryview
        """
        if value != None and len(value) > 0:
            self.writeBlobTlv(type, value)

    def getOutput(self):
        """
        Get a memoryview slice of the encoded bytes.

        :return: a memoryview backed by the bytearray encoding buffer.
        :rtype: memoryview
        """
        # Create a memoryview from getArray() to make sure we don't copy.
        return memoryview(
         self._output.getArray())[len(self._output.getArray()) - self._length:]

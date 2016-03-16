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

from pyndn.util.blob import Blob

"""
This module defines the TlvDecoder class for decoding in the NDN-TLV wire
format.
"""

class TlvDecoder(object):
    """
    Create a new TlvDecoder to decode the input using NDN-TLV.

    :param input: The array with the bytes to decode.
    :type input: An array type with int elements
    """
    def __init__(self, input):
        self._input = input
        # Create a Blob and take its buf() since this creates a memoryview
        #   which is more efficient for slicing.
        self._inputView = Blob(input, False).buf()
        self._offset = 0

    def readVarNumber(self):
        """
        Decode VAR-NUMBER in NDN-TLV and return it. Update offset.

        :return: The decoded VAR-NUMBER.
        :rtype: int
        """
        try:
            # Assume array values are in the range 0 to 255.
            firstOctet = self._input[self._offset]
            self._offset += 1
            if firstOctet < 253:
                return firstOctet
            else:
                return self.readExtendedVarNumber(firstOctet)
        except IndexError:
            raise ValueError("Read past the end of the input")

    def readExtendedVarNumber(self, firstOctet):
        """
        A private function to do the work of readVarNumber, given the firstOctet
        which is >= 253.

        :param int firstOctet: The first octet which is >= 253, used to decode
          the remaining bytes.
        :return: The decoded VAR-NUMBER.
        :rtype: int
        """
        # This is a private function so we know firstOctet >= 253.
        if firstOctet == 253:
            result = ((self._input[self._offset] << 8) +
                       self._input[self._offset + 1])
            self._offset += 2
        elif firstOctet == 254:
            result = ((self._input[self._offset]     << 24) +
                      (self._input[self._offset + 1] << 16) +
                      (self._input[self._offset + 2] << 8) +
                       self._input[self._offset + 3])
            self._offset += 4
        else:
            result = ((self._input[self._offset]     << 56) +
                      (self._input[self._offset + 1] << 48) +
                      (self._input[self._offset + 2] << 40) +
                      (self._input[self._offset + 3] << 32) +
                      (self._input[self._offset + 4] << 24) +
                      (self._input[self._offset + 5] << 16) +
                      (self._input[self._offset + 6] << 8) +
                       self._input[self._offset + 7])
            self._offset += 8

        return result

    def readTypeAndLength(self, expectedType):
        """
        Decode the type and length from self's input starting at offset,
        expecting the type to be expectedType and return the length.
        Update offset.  Also make sure the decoded length does not exceed the
        number of bytes remaining in the input.

        :param int expectedType: The expected type.
        :return: The length of the TLV.
        :rtype: int
        :raises ValueError: if did not get the expected TLV type or
          the TLV length exceeds the buffer length.
        """
        type = self.readVarNumber()
        if type != expectedType:
            raise ValueError("Did not get the expected TLV type")

        length = self.readVarNumber()
        if self._offset + length > len(self._input):
            raise ValueError("TLV length exceeds the buffer length")

        return length

    def readNestedTlvsStart(self, expectedType):
        """
        Decode the type and length from self's input starting at offset,
        expecting the type to be expectedType.  Update offset.  Also make sure
        the decoded length does not exceed the number of bytes remaining in the
        input. Return the offset of the end of this parent TLV, which is used in
        decoding optional nested TLVs. After reading all nested TLVs, call
        finishNestedTlvs.

        :param int expectedType: The expected type.
        :return: The offset of the end of the parent TLV.
        :rtype: int
        :raises ValueError: if did not get the expected TLV type or
          the TLV length exceeds the buffer length.
        """
        return self.readTypeAndLength(expectedType) + self._offset

    def finishNestedTlvs(self, endOffset):
        """
        Call this after reading all nested TLVs to skip any remaining
        unrecognized TLVs and to check if the offset after the final nested TLV
        matches the endOffset returned by readNestedTlvsStart.

        :param int endOffset: The offset of the end of the parent TLV, returned
          by readNestedTlvsStart.
        :raises ValueError: if the TLV length does not equal the total length of
          the nested TLVs.
        """
        # We expect _offset to be endOffset, so check this first.
        if self._offset == endOffset:
            return

        # Skip remaining TLVs.
        while self._offset < endOffset:
            # Skip the type VAR-NUMBER.
            self.readVarNumber()
            # Read the length and update offset.
            length = self.readVarNumber()
            self._offset += length

            if self._offset > len(self._input):
                raise ValueError("TLV length exceeds the buffer length")

        if self._offset != endOffset:
            raise ValueError(
               "TLV length does not equal the total length of the nested TLVs")

    def peekType(self, expectedType, endOffset):
        """
        Decode the type from self's input starting at offset, and if it is the
        expectedType, then return True, else False.  However, if self's offset
        is greater than or equal to endOffset, then return False and don't try
        to read the type. Do not update offset.

        :param int expectedType: The expected type.
        :param int endOffset: The offset of the end of the parent TLV, returned
          by readNestedTlvsStart.
        :return: True if the type of the next TLV is the expectedType,
          otherwise False.
        :rtype: bool
        """
        if self._offset >= endOffset:
            # No more sub TLVs to look at.
            return False
        else:
            saveOffset = self._offset
            type = self.readVarNumber()
            # Restore offset.
            self._offset = saveOffset

            return type == expectedType

    def readNonNegativeInteger(self, length):
        """
        Decode a non-negative integer in NDN-TLV and return it. Update offset
        by length.

        :param int length: The number of bytes in the encoded integer.
        :return: The integer.
        :rtype: int (or long if a large integer on a 32-bit system)
        :raises ValueError: if length is an invalid length for a TLV
          non-negative integer.
        """
        try:
            if length == 1:
                result = self._input[self._offset]
            elif length == 2:
                result = ((self._input[self._offset] << 8) +
                           self._input[self._offset + 1])
            elif length == 4:
                result = ((self._input[self._offset]     << 24) +
                          (self._input[self._offset + 1] << 16) +
                          (self._input[self._offset + 2] << 8) +
                           self._input[self._offset + 3])
            elif length == 8:
                result = ((self._input[self._offset]     << 56) +
                          (self._input[self._offset + 1] << 48) +
                          (self._input[self._offset + 2] << 40) +
                          (self._input[self._offset + 3] << 32) +
                          (self._input[self._offset + 4] << 24) +
                          (self._input[self._offset + 5] << 16) +
                          (self._input[self._offset + 6] << 8) +
                           self._input[self._offset + 7])
            else:
                raise ValueError("Invalid length for a TLV nonNegativeInteger")

            self._offset += length
            return result
        except IndexError:
            raise ValueError("Read past the end of the input")

    def readNonNegativeIntegerTlv(self, expectedType):
        """
        Decode the type and length from self's input starting at offset,
        expecting the type to be expectedType. Then decode a non-negative
        integer in NDN-TLV and return it.  Update offset.

        :param int expectedType: The expected type.
        :return: The integer.
        :rtype: int
        :raises ValueError: if did not get the expected TLV type or
          can't decode the value.
        """
        length = self.readTypeAndLength(expectedType)
        return self.readNonNegativeInteger(length)

    def readOptionalNonNegativeIntegerTlv(self, expectedType, endOffset):
        """
        Peek at the next TLV, and if it has the expectedType then call
        readNonNegativeIntegerTlv and return the integer.  Otherwise, return
        None.  However, if self's offset is greater than or equal to endOffset,
        then return None and don't try to read the type.

        :param int expectedType: The expected type.
        :param int endOffset: The offset of the end of the parent TLV, returned
          by readNestedTlvsStart.
        :return: The integer or None if the next TLV doesn't have the expected
          type.
        :rtype: int
        """
        if self.peekType(expectedType, endOffset):
            return self.readNonNegativeIntegerTlv(expectedType)
        else:
            return None

    def readOptionalNonNegativeIntegerTlvAsFloat(self, expectedType, endOffset):
        """
        Peek at the next TLV, and if it has the expectedType then call
        readNonNegativeIntegerTlv and return the integer converted to a float.
        Otherwise, return None.
        However, if self's offset is greater than or equal to endOffset,
        then return None and don't try to read the type.

        :param int expectedType: The expected type.
        :param int endOffset: The offset of the end of the parent TLV, returned
          by readNestedTlvsStart.
        :return: The integer or None if the next TLV doesn't have the expected
          type.
        :rtype: float
        """
        if self.peekType(expectedType, endOffset):
            # Note: readNonNegativeIntegerTlv will return int, or long if
            #   it is large and this is a 32-bit system.
            return float(self.readNonNegativeIntegerTlv(expectedType))
        else:
            return None

    def readBlobTlv(self, expectedType):
        """
        Decode the type and length from self's input starting at offset,
        expecting the type to be expectedType. Then return an array of the bytes
        in the value.  Update offset.

        :param int expectedType: The expected type.
        :return: The bytes in the value as a slice on the byte array.  This is
          not necessarily a copy of the bytes in the input buffer.  If you need
          a copy, then you must make a copy of the return value.
        :rtype: memoryview or equivalent
        :raises ValueError: if did not get the expected TLV type.
        """
        length = self.readTypeAndLength(expectedType)
        # Use _inputView to get the slice.
        result = self._inputView[self._offset:self._offset + length]

        # readTypeAndLength already checked if length exceeds the input buffer.
        self._offset += length
        return result

    def readOptionalBlobTlv(self, expectedType, endOffset):
        """
        Peek at the next TLV, and if it has the expectedType then call
        readBlobTlv and return the value.  Otherwise, return None.
        However, if self's offset is greater than or equal to endOffset,
        then return None and don't try to read the type.

        :param int expectedType: The expected type.
        :param int endOffset: The offset of the end of the parent TLV, returned
          by readNestedTlvsStart.
        :return: The bytes in the value as a slice on the byte array or None if
          the next TLV doesn't have the expected type.  This is not necessarily
          a copy of the bytes in the input buffer.  If you need a copy, then you
          must make a copy of the return value.
        :rtype: memoryview or equivalent
        """
        if self.peekType(expectedType, endOffset):
            return self.readBlobTlv(expectedType)
        else:
            return None

    def readBooleanTlv(self, expectedType, endOffset):
        """
        Peek at the next TLV, and if it has the expectedType then read a type
        and value, ignoring the value, and return True. Otherwise, return False.
        However, if self's offset is greater than or equal to endOffset,
        then return False and don't try to read the type.

        :param int expectedType: The expected type.
        :param int endOffset: The offset of the end of the parent TLV, returned
          by readNestedTlvsStart.
        :return: Return True, or else False if the next TLV doesn't have the
          expected type.
        :rtype: bool
        """
        if self.peekType(expectedType, endOffset):
            length = self.readTypeAndLength(expectedType)
            # We expect the length to be 0, but update offset anyway.
            self._offset += length
            return True
        else:
            return False

    def getOffset(self):
        """
        Get the offset into the input buffer, used for the next read.

        :return: The offset.
        :rtype: int
        """
        return self._offset

    def seek(self, offset):
        """
        Set the offset into the input, used for the next read.

        :param int offset: The new offset.
        """
        self._offset = offset

    def getSlice(self, beginOffset, endOffset):
        """
        Return an array of a slice of the input for the given offset range.

        :param int beginOffset: The offset in the input of the beginning of the
          slice.
        :param int endOffset: The offset in the input of the end of the slice.
        :return: The bytes in the value as a slice on the byte array.  This is
          not necessarily a copy of the bytes in the input buffer.  If you need
          a copy, then you must make a copy of the return value.
        :rtype: memoryview or equivalent
        """
        # Use _inputView to get the slice.
        return self._inputView[beginOffset:endOffset]

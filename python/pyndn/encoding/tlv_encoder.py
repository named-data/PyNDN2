# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

from pyndn.util.dynamic_byte_array import DynamicByteArray

"""
This module defines the TlvEncoder class for encoding in the NDN-TLV wire 
format.  It encodes into the bytebuffer in a DynamicByteArray, writing 
"backwards" from the back of the buffer.
"""

class TlvEncoder(object):
    """
    Create a new TlvEncoder with an initialCapacity for the encoding buffer.
    
    :param initialCapacity: (optional) The initial capacity of the encoding 
      buffer. If omitted, use a default value.
    :type initialCapacity: int
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
        
        :param varNumber: The non-negative number to encode.
        :type varNumber: int
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
        
        :param type: The type of the TLV.
        :type type: int
        :param length: The non-negative length of the TLV.
        :type length: int
        """
        # Write backwards.
        self.writeVarNumber(length)
        self.writeVarNumber(type)
        
    def writeNonNegativeIntegerTlv(self, type, value):
        """
        Write the type, then the length of the encoded value then encode value 
        as a non-negative integer and write it to self._output just before 
        self._length from the back. Advance self._length.
 
        :param type: The type of the TLV.
        :type type: int
        :param value: The non-negative integer to encode.
        :type value: int
        """
        if value < 0:
            raise ValueError("TLV integer value may not be negative")
        
        # Write backwards.
        saveNBytes = self._length
        if value < 253:
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

        self.writeTypeAndLength(type, self._length - saveNBytes)

    def writeOptionalNonNegativeIntegerTlv(self, type, value):
        """
        If value is negative or None then do nothing, otherwise call 
        writeNonNegativeIntegerTlv.
 
        :param type: The type of the TLV.
        :type type: int
        :param value: Negative for none, otherwise the integer to encode.
        :type value: int
        """
        if value != None and value >= 0:
            self.writeNonNegativeIntegerTlv(type, value)

    def writeOptionalNonNegativeIntegerTlvFromFloat(self, type, value):
        """
        If value is negative or None then do nothing, otherwise call 
        writeNonNegativeIntegerTlv.
 
        :param type: The type of the TLV.
        :type type: int
        :param value: Negative for none, otherwise otherwise use 
          int(round(value)).
        :type value: float
        """
        if value != None and value >= 0:
            # Note: int() will return int, or long if value is large and this 
            #   is a 32-bit system.
            self.writeNonNegativeIntegerTlv(type, int(round(value)))

    def writeBlobTlv(self, type, value):
        """
        Write the type, then the length of the blob then the blob value 
        to self._output just before self._length from the back. 
        Advance self._length.
        
        :param type: The type of the TLV.
        :type type: int
        :param value: The byte array with the bytes of the blob.
        :type value: bytearray or memoryview
        """
        # Write backwards, starting with the blob array.        
        self._length += len(value)
        self._output.copyFromBack(value, self._length)
        
        self.writeTypeAndLength(type, len(value))

    def getOutput(self):
        """
        Get a memoryview slice of the encoded bytes.
        
        :return: a memoryview backed by the bytearray encoding buffer.
        :rtype: memoryview
        """
        return memoryview(self._output._array)[-self._length:]
    
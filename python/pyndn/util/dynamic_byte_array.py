# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the DynamicByteArray class which holds a 
bytearray which can be expanded as needed.
"""

class DynamicByteArray(object):
    """
    Create a new DynamicByteArray with an initial bytearray.

    :param length: (optional) The initial length of the bytearray.  If omitted, 
      use a default value.
    :type length: int
    """
    def __init__(self, length = 16):
        self._array = bytearray(length)

    def ensureLengthFromBack(self, length):
        """
        Ensure length.
        
        :param length: The minimum length for the bytebuffer.
        :type length: int
        """
        if len(self._array) >= length:
            return
    
        # See if double is enough.
        newLength = len(self._array) * 2
        if length > newLength:
            # The needed length is much greater, so use it.
            newLength = length
    
        newArray = bytearray(newLength)
        # Copy to the back of newArray.
        newArray[-len(self._array):] = self._array
        self._array = newArray

    def copyFromBack(self, value, offsetFromBack):
        """
        First call ensureLengthFromBack to make sure the bytebuffer has
        offsetFromBack bytes, then copy value into the bytebuffer starting
        offsetFromBack bytes fromt the back of the buffer.

        :param value: The byte array with the bytes to copy.
        :type value: bytearray or memoryview
        :param offsetFromBack: The offset from the back of the array to start
          copying.
        :type offsetFromBack: int
        """
        self.ensureLengthFromBack(offsetFromBack)
        startIndex = len(self._array) - offsetFromBack
        self._array[startIndex:startIndex + len(value)] = value
        
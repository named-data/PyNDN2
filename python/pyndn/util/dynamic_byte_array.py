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

"""
This module defines the DynamicByteArray class which holds a
bytearray which can be expanded as needed.
"""

from pyndn.util.blob import _memoryviewWrapper

class DynamicByteArray(object):
    """
    Create a new DynamicByteArray with an initial bytearray.

    :param int length: (optional) The initial length of the bytearray.  If
      omitted, use a default value.
    """
    def __init__(self, length = 16):
        self._array = bytearray(length)

    def ensureLength(self, length):
        """
        Ensure length.  If necessary, reallocate the bytearray and copy
        existing data to the front of the new array.

        :param int length: The minimum length for the bytearray.
        """
        if len(self._array) >= length:
            return

        # See if double is enough.
        newLength = len(self._array) * 2
        if length > newLength:
            # The needed length is much greater, so use it.
            newLength = length

        newArray = bytearray(newLength)
        # Copy into newArray at offset.
        newArray[:len(self._array)] = self._array
        self._array = newArray

    def copy(self, value, offset):
        """
        First call ensureLength to make sure the bytearray has
        offset + len(value) bytes, then copy value into the bytearray starting
        at offset.

        :param value: The byte array with the bytes to copy.
        :type value: bytearray or memoryview
        :param int offset: The offset in the array to start copying into.
        """
        self.ensureLength(offset + len(value))
        if type(value) is _memoryviewWrapper:
            # Use the underlying memoryview directly.  (When we only support
            #   Python 3.3 or later, this check is not necessary.)
            self._array[offset:offset + len(value._view)] = value._view
        else:
            self._array[offset:offset + len(value)] = value

    def ensureLengthFromBack(self, length):
        """
        Ensure length.  If necessary, reallocate the bytearray and shift
        existing data to the back of the new array.

        :param int length: The minimum length for the bytearray.
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
        First call ensureLengthFromBack to make sure the bytearray has
        offsetFromBack bytes, then copy value into the bytearray starting
        offsetFromBack bytes from the back of the array.

        :param value: The byte array with the bytes to copy.
        :type value: bytearray or memoryview
        :param int offsetFromBack: The offset from the back of the array to
          start copying.
        """
        self.ensureLengthFromBack(offsetFromBack)
        startIndex = len(self._array) - offsetFromBack
        if type(value) is _memoryviewWrapper:
            # Use the underlying memoryview directly.  (When we only support
            #   Python 3.3 or later, this check is not necessary.)
            self._array[startIndex:startIndex + len(value._view)] = value._view
        else:
            self._array[startIndex:startIndex + len(value)] = value

    def getArray(self):
        """
        Get the bytearray.  After more method calls, the result of getArray()
        may change.

        :return: The bytearray.
        :rtype: bytearray.
        """
        return self._array

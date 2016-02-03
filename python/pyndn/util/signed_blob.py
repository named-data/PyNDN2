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
This module defines the SignedBlob class which extends Blob to keep the offsets
of a signed portion (e.g., the bytes of Data packet).
"""

import sys
from pyndn.util.blob import Blob
from pyndn.util.blob import _memoryviewWrapper

class SignedBlob(Blob):
    """
    Create a new SignedBlob using the given Blob and offsets.

    :param blob: (optional) The Blob with a signed portion.  If omitted,
      then isNull() is True.
    :type blob: Blob or SignedBlob
    :param int signedPortionBeginOffset: (optional) The offset in the buffer of
      the beginning of the signed portion.
    :param int signedPortionEndOffset: (optional) The offset in the buffer of
      the end of the signed portion.
    """
    def __init__(
          self, blob = None, signedPortionBeginOffset = None,
          signedPortionEndOffset = None):
        super(SignedBlob, self).__init__(blob)
        if self.isNull():
            self._signedPortionBeginOffset = 0
            self._signedPortionEndOffset = 0
        elif type(blob) is SignedBlob:
            # Copy the SignedBlob, allowing override for offsets.
            self._signedPortionBeginOffset = (
              blob._signedPortionBeginOffset if signedPortionBeginOffset == None
              else signedPortionBeginOffset)
            self._signedPortionEndOffset = (
              blob._signedPortionEndOffset if signedPortionEndOffset == None
              else signedPortionEndOffset)
        else:
            self._signedPortionBeginOffset = signedPortionBeginOffset
            self._signedPortionEndOffset = signedPortionEndOffset

        if self.isNull():
            self._signedArray = None
        else:
            self._signedArray = self._array[
              signedPortionBeginOffset:signedPortionEndOffset]

    def signedSize(self):
        """
        Get the length of the signed portion of the immutable byte buffer.

        :return: The length of the signed portion, or 0 if isNull().
        :rtype: int
        """
        if self._signedArray == None:
            return 0
        else:
            return len(self._signedArray)

    def signedBuf(self):
        """
        Return the signed portion of the byte array which you must treat as
        immutable and not modify the contents.

        :return: An array which you should not modify, or None if isNull().
        :rtype: An array type with int elements, such as bytearray.
        """
        return self._signedArray

    def toSignedBuffer(self):
        """
        Return an array of the signed portion which implements the buffer
        protocol (but for Python versions before 3.3 it doesn't have int elements).
        This method is only needed by Python versions before 3.3 to check if
        signedBuf() would return a _memoryviewWrapper and to return its internal
        memoryview instead.  However, if this is a Python version
        (3.3 or greater) whose memoryview already uses int, then
        toSignedBuffer() is the same as signedBuf().
        """
        if _memoryviewUsesInt:
            # We can use the normal signedBuf().
            return self.signedBuf()
        else:
            if self._signedArray == None:
                return None
            elif type(self._signedArray) is _memoryviewWrapper:
                # Return the underlying memoryview (which doesn't have int
                #   elements) but implements the buffer protocol.
                return self._signedArray._view
            else:
                return self._signedArray

    def toSignedBytes(self):
        """
        Return an object which is the same as the bytes() operator of the signed
        portion. In Python 2, this makes a raw string because bytes is the same
        as str. In Python 3, this converts the byte array to a bytes type. This
        method is necessary because the bytes type is different in Python 2 and
        3. This does not do any character encoding such as UTF-8.

        :return: The array as a bytes type, or None if isNull().
        :rtype: bytes (str in Python 2)
        """
        if self._array == None:
            return None
        else:
            if sys.version_info[0] > 2:
                return bytes(self._signedArray)
            else:
                # For Python 2, make a raw string.
                return "".join(map(chr, self._signedArray))

# Set this up once at the module level for the constructor to use.
# Expect that this is True for Python version 3.3 or later.
_memoryviewUsesInt = type(memoryview(bytearray(1))[0]) is int

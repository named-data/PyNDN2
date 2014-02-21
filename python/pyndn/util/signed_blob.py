# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the SignedBlob class which extends Blob to keep the offsets
of a signed portion (e.g., the bytes of Data packet). 
"""

from pyndn.util.blob import Blob
from pyndn.util.blob import _memoryviewWrapper

class SignedBlob(Blob):
    """
    Create a new SignedBlob using the given Blob and offsets.
    
    :param blob: (optional) The Blob with a signed portion.  If omitted,
      then isNull() is True.
    :type blob: Blob or SignedBlob
    :param signedPortionBeginOffset: (optional) The offset in the buffer of the
      beginning of the signed portion.
    :type signedPortionBeginOffset: int
    :param signedPortionEndOffset: (optional) The offset in the buffer of the
      end of the signed portion.
    :type signedPortionEndOffset: int
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

    def _toSignedBufferFromMemoryViewWrapper(self):
        """
        This is an internal function (which is only needed by Python versions
        before 3.3) to check if signedBuf() would return a _memoryviewWrapper and
        to return its internal memoryview instead, so that it implements
        the buffer protocol (but doesn't have int elements).  However, if
        this is a Python version (3.3 or greater) whose memoryview already
        uses int, then toSignedBuffer() is the same as signedBuf().
        """
        if self._signedArray == None:
            return None
        elif type(self._signedArray) == _memoryviewWrapper:
            # Return the underlying memoryview.
            return self._signedArray._view
        else:
            return self._signedArray
    
    if type(memoryview(bytearray(1))[0]) == int:
        # We can use the normal signedBuf().
        toSignedBuffer = signedBuf
    else:
        toSignedBuffer = _toSignedBufferFromMemoryViewWrapper

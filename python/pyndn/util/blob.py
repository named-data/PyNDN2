# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the Blob class which holds an immutable byte array.
We use an immutable buffer so that it is OK to pass the object into methods
because the new or old owner can't change the bytes.
Note that the pointer to the buffer can be None.
"""

from io import BytesIO
from pyndn.util.common import Common

class Blob(object):
    """
    Create a new Blob which holds an immutable array of bytes.
    
    :param array: (optional) The array of bytes, or None.  If array is str,
      then encode using UTF-8.  If you just want a Blob from a raw str
      without encoding, use Blob.fromRawStr.
    :type array: Blob, bytearray, memoryview or other array of int
    :param copy: (optional) If true, copy the contents of array into a new
      bytearray.  If false, just use the existing array without copying.
      If omitted, then copy the contents (unless value is already a Blob).
      IMPORTANT: If copy is false, if you keep a pointer to the array then you 
      must treat the array as immutable and promise not to change it.
    :type copy: bool
    """
    def __init__(self, array = None, copy = True):
        if array == None:
            self._array = None
        elif isinstance(array, Blob):
            # Use the existing _array.  Don't need to check for copy.
            self._array = array._array
        else:
            if type(array) is str:
                # Convert from a string to utf-8 byte encoding.
                if _encodeResultIsStr:
                    # encode produces a str. Force it to be an array of int.
                    array = map(ord, array.encode('utf-8'))
                else:
                    array = array.encode('utf-8')
                
            if copy:
                # We are copying, so just make another bytearray.
                # We always use a memoryview so that slicing is efficient.
                if type(array) is _memoryviewWrapper:
                    # Use the underlying memoryview directly. (When we only 
                    # support Python 3.3 or later, this check is not necessary.)
                    self._array = memoryview(bytearray(array._view))
                else:
                    self._array = memoryview(bytearray(array))                    
            else:
                if type(array) is bytearray:
                    # We always use a memoryview so that slicing is efficient.
                    self._array = memoryview(array)
                else:
                    # Can't take a memoryview, so use as-is.
                    self._array = array
                    
            if not _memoryviewUsesInt and type(self._array) is memoryview:
                # memoryview elements are not int (Python versions before 3.3)
                #   so we need a wrapper which will return int elements.
                self._array = _memoryviewWrapper(self._array)
                
    def size(self):
        """
        Return the length of the immutable byte array.
        
        :return: The length of the array.
        :rtype: int
        """
        if self._array == None:
            return 0
        else:
            return len(self._array)

    def __len__(self):
        return self.size()

    def buf(self):
        """
        Return the byte array which you must treat as immutable and not 
        modify the contents.
        Note: For compatibility with Python versions before 3.3, if you
        need an object which implements the buffer protocol (e.g. for writing
        to a socket) then call toBuffer() instead.
        
        :return: An array which you should not modify, or None if isNull().
        :rtype: An array type with int elements, such as bytearray.
        """
        if self._array == None:
            return None
        else:
            return self._array
        
    def toBuffer(self):
        """
        Return an array which implements the buffer protocol (but for Python
        versions before 3.3 it doesn't have int elements).
        This method is only needed by Python versions before 3.3 to check if 
        buf() would return a _memoryviewWrapper and to return its internal 
        memoryview instead.  However, if this is a Python version 
        (3.3 or greater) whose memoryview already uses int, then toBuffer() is 
        the same as buf().
        
        :return: The array which implements the buffer protocol, or None if 
          isNull().
        :rtype: an array which implements the buffer protocol
        """
        if _memoryviewUsesInt:
            # We can use the normal buf().
            return self.buf()
        else:
            if self._array == None:
                return None
            elif type(self._array) is _memoryviewWrapper:
                # Return the underlying memoryview (which doesn't have int 
                #   elements) but implements the buffer protocol.
                return self._array._view
            else:
                return self._array

    def toRawStr(self):
        """
        Return the bytes of the byte array as a raw str of the same length.
        This does not do any character encoding such as UTF-8.
        
        :return: The array as a str, or None if isNull().
        :rtype: str
        """
        if self._array == None:
            return None
        else:
            return "".join(map(chr, self.buf()))

    @staticmethod
    def fromRawStr(rawStr):
        """
        Convert rawStr to a Blob.  This does not do any character decoding 
        such as UTF-8.  If you want decode the string such as UTF-8, then
        just pass the string to the Blob constructor.
        
        :param rawStr: The raw string to convert to a Blob.
        :type rawStr: str
        :return: A new Blob created from rawStr.
        :rtype: Blob
        """
        return Blob(bytearray(map(ord, rawStr)), False)

    def isNull(self):
        """
        Return True if the array is None, otherwise False.
        
        :return: True if the array is None.
        :rtype: bool
        """
        return self._array == None
    
    def equals(self, other):
        """
        Check if this is byte-wise equal to the other Blob.  If this and other
        are both isNull(), then this returns True.

        :param other: The other Blob to compare with.
        :type other: Blob
        :return: True if the blobs are equal, otherwise False.
        :rtype: bool
        """
        if self._array == None and other._array == None:
            return True
        if self._array == None or other._array == None:
            # One of the blobs is null and the other isn't.
            return False
        
        if len(self._array) != len(other._array):
            return False
        
        buffer1 = self.toBuffer()
        buffer1Type = type(buffer1)
        buffer2 = other.toBuffer()
        buffer2Type = type(buffer2)
        if  ((buffer1Type is memoryview or buffer1Type is bytearray) and
             (buffer2Type is memoryview or buffer2Type is bytearray) or
             buffer1Type is str and buffer2Type is str or
             buffer1Type is list and buffer2Type is list):
            # We can compare directly.
            return buffer1 == buffer2
        else:
            # Manually compare int elements.
            for i in range(len(self._array)):
                if self._array[i] != other._array[i]:
                    return False
            return True

    def toHex(self):
        """
        Return the hex representation of the bytes in array.
        
        :return: The hex string.
        :rtype: str
        """
        if self._array == None:
            return ""
        
        array = self.buf()
        result = BytesIO()
        hexBuffer = bytearray(2)
        for i in range(len(array)):
            # Get the hex string and transfer to hexBuffer for writing.
            hex = "%02X" % array[i]
            hexBuffer[0] = ord(hex[0])
            hexBuffer[1] = ord(hex[1])
            result.write(hexBuffer)
        
        return Common.getBytesIOString(result)

# Set this up once at the module level for the constructor to use.
# Expect that this is True for Python version 3.3 or later.
_memoryviewUsesInt = type(memoryview(bytearray(1))[0]) is int

_encodeResultIsStr = type("A".encode('utf-8')) is str

class _memoryviewWrapper(object):
    """
    _memoryviewWrapper is an internal class used by Blob which wraps a 
    memoryview to override  __getitem__ so that it returns int instead of str 
    (Python 2.7) or bytes (Python 3.2).  (When we only support Python 3.3 or 
    later, this class is not necessary.)
    
    :param view: The memoryview to wrap.
    :type view: memoryview
    """
    def __init__(self, view):
        self._view = view

    def __len__(self):
        """
        Get the length of the wrapped memoryview.
        
        :return: The length of the array.
        :rtype: int
        """
        return len(self._view)

    def __getitem__(self, index):
        if type(index) is slice:
            # Return a new _memoryviewWrapper for the slice.
            return _memoryviewWrapper(self._view.__getitem__(index))
        else:
            # Convert str or bytes to int.
            return ord(self._view[index])

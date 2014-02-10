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

from StringIO import StringIO

class Blob(object):
    """
    Create a new Blob which holds an immutable array of bytes.
    
    :param array: (optional) The array of bytes, or None.
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
            if copy:
                # We are copying, so just make another bytearray.
                # We always use a memoryview so that slicing is efficient.
                self._array = memoryview(bytearray(array))
            else:
                if type(array) == bytearray:
                    # We always use a memoryview so that slicing is efficient.
                    self._array = memoryview(array)
                else:
                    # Can't take a memoryview, so use as-is.
                    self._array = array
                    
            if not Blob._memoryviewUsesInt and type(self._array) == memoryview:
                # memoryview elements are not int (Python versions before 3.2)
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
    
    def buf(self):
        """
        Return the byte array which you must treat as immutable and not 
        modify the contents.
        Note: For compatibility with Python versions before 3.2, if you
        need an object which implements the buffer protocol (e.g. for writing
        to a socket) then call toBuffer() instead.
        
        :return: An array which you should not modify, or None if the pointer 
          is None.
        :rtype: An array type with int elements, such as bytearray.
        """
        if self._array == None:
            return None
        else:
            return self._array
    
    def _toBufferFromMemoryViewWrapper(self):
        """
        This is an internal function (which is only needed by Python versions
        before 3.2) to check if buf() would return a _memoryviewWrapper and
        to return its internal memoryview instead, so that it implements
        the buffer protocol (but doesn't have int elements).
        """
        if self._array == None:
            return None
        elif type(self._array) == _memoryviewWrapper:
            # Return the underlying memoryview.
            return self._array._view
        else:
            return self._array
    
    if type(memoryview(bytearray(1))[0]) == int:
        # We can use the normal buf().
        toBuffer = buf
    else:
        toBuffer = _toBufferFromMemoryViewWrapper

    def isNull(self):
        """
        Return True if the array is None, otherwise False.
        
        :return: True if the array is None.
        :rtype: bool
        """
        return self._array == None
    
    def toHex(self):
        """
        Return the hex representation of the bytes in array.
        
        :return: The hex string.
        :rtype: str
        """
        if self._array == None:
            return ""
        
        array = self.buf()
        result = StringIO()
        for i in range(len(array)):
            result.write("%02X" % array[i])
        
        return result.getvalue()

    # Set this up once at the class level for the constructor to use.
    _memoryviewUsesInt = (type(memoryview(bytearray(1))[0]) == int)
        
class _memoryviewWrapper(object):
    """
    _memoryviewWrapper is an internal class used by Blob which wraps a 
    memoryview to override  __getitem__ so that it returns int instead of str 
    (Python 2.7) or bytes (Python 3.1).  (When we only support Python 3.2 or 
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

    def _getFromStr(self, index):
        if type(index) == slice:
            # Return a new _memoryviewWrapper for the slice.
            return _memoryviewWrapper(self._view.__getitem__(index))
        else:
            # Convert str to int.
            return ord(self._view[index])

    def _getFromBytes(self, index):
        if type(index) == slice:
            # Return a new _memoryviewWrapper for the slice.
            return _memoryviewWrapper(self._view.__getitem__(index))
        else:
            # Convert bytes to int.
            return self._view[index][0]

    # Different versions of Python implement memoryarray with elements
    #   of different types, so define __getitem__ accordingly.
    if type(memoryview(bytearray(1))[0]) == str:
        # memoryview elements are str.
        __getitem__ = _getFromStr
    elif type(memoryview(bytearray(1))[0]) == bytes:
        # memoryview elements are bytes.
        __getitem__ = _getFromBytes
    else:
        raise ValueError("Unexpected type of element for _memoryviewWrapper")

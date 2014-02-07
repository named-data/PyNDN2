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
Note that  the pointer to the ByteBuffer can be None.
"""

class Blob(object):
    def __init__(self, value):
        # TODO: Add copy parameter
        if type(value) is memoryview:
            self._array = value
        elif type(value) is Blob:
            self._array = value._array
        else:
            # Assume the type is an array of ints
            self._array = memoryview(value)
        
    def size(self):
        return len(self)
    
    def getImmutableArray(self):
        """
        Return the byte array.  This is called getImmutableArray to remind you 
        not to change the contents of the returned array.
        
        :return: An array which you should not modify, or None if the pointer 
          is None.
        :rtype: memoryview or bytearray
        """
        if self._array == None:
            return None
        else:
            return self._array
    
    def isNull(self):
        return self._array == None
    
    def __len__(self):
        if self._array == None:
            return 0
        else:
            return len(self._array)
        
    def _getFromStr(self, i):
        return ord(self._array[i])

    def _getFromBytes(self, i):
        return self._array[i][0]

    def _getFromInt(self, i):
        return self._array[i]

    # Different versions of Python implement memoryarray with elements
    #   of different types, so define __getitem__ accordingly.
    if type(memoryview(bytearray(1))[0]) is str:
        # memoryview elements are str.
        __getitem__ = _getFromStr
    elif type(memoryview(bytearray(1))[0]) is bytes:
        # memoryview elements are bytes.
        __getitem__ = _getFromBytes
    else:
        # Assume memoryview elements are int.
        __getitem__ = _getFromInt
    
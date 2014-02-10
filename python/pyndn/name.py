# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

from io import BytesIO
from pyndn.util import Blob

"""
This module defines the NDN Name class.
"""

class Name(object):
    class Component(object):
        def __init__(self, value):
            if type(value) == Name.Component:
                # Use the existing Blob in the other Component.
                self._value = value._value
            else:
                # Blob will make a copy.
                self._value = value if isinstance(value, Blob) else Blob(value)
            
        def getValue(self):
            return self._value

    def __init__(self, value = None):
        self._components = []
        self._changeCount = 0
        
    def append(self, value):
        if isinstance(value, Name.Component):
            self._components.append(value)
        else:
            self._components.append(Name.Component(value))
            
        self._changeCount += 1
        return self

    def get(self, i):
        return self._components[i]
    
    def clear(self):
        self._components = []
        self._changeCount += 1
    
    _slash = bytearray([ord('/')])
    def toUri(self):
        """
        Encode this name as a URI according to the NDN URI Scheme.
        
        :return: The encoded URI.
        :rtype: str
        """
        if len(self._components) == 0:
            return "/"
  
        result = BytesIO()
        for component in self._components:
            # write is required to take a byte buffer.
            result.write(Name._slash)
            self.toEscapedString(component._value.buf(), result)
  
        value = result.getvalue()
        if not type(value) is str:
            # Assume value is a Python 3 bytes object.  Convert to string.
            value = str(value, encoding = "Latin-1")
        return value
        
    def getChangeCount(self):
        """
        Get the change count, which is incremented each time this object is 
        changed.
        
        :return: The change count.
        :rtype: int
        """
        
    _dot = bytearray([ord('.')])
    @staticmethod
    def toEscapedString(value, result):
        """
        Write the value to result, escaping characters according to the NDN URI 
        Scheme. This also adds "..." to a value with zero or more ".".
        
        :param value: The buffer with the value to escape.
        :type value: An array type with int elements.
        :param result: The BytesIO stream to write to.
        :type result: BytesIO
        """
        gotNonDot = False
        for i in range(len(value)):
            if value[i] != Name._dot[0]:
                gotNonDot = True
                break

        if not gotNonDot:
            # Special case for component of zero or more periods. Add 3 periods.
            for i in range(len(value) + 3):
                result.write(Name._dot)
        else:
            charBuffer = bytearray(1)
            hexBuffer = bytearray(3)
            hexBuffer[0] = ord('%')
            for i in range(len(value)):
                x = value[i]
                # Check for 0-9, A-Z, a-z, (+), (-), (.), (_)
                if ((x >= 0x30 and x <= 0x39) or (x >= 0x41 and x <= 0x5a) or
                    (x >= 0x61 and x <= 0x7a) or x == 0x2b or x == 0x2d or
                    x == 0x2e or x == 0x5f):
                    charBuffer[0] = x
                    # write is required to take a byte buffer.
                    result.write(charBuffer)
                else:
                    # Write '%' followed by the hex value.
                    hex = "%02X" % x
                    hexBuffer[1]  = ord(hex[0])
                    hexBuffer[2]  = ord(hex[1])
                    # write is required to take a byte buffer.
                    result.write(hexBuffer)
        
    # Python operators.

    def __len__(self):
        return len(self._components)
        
    def __getitem__(self, key):
        if type(key) == int:
            return self._components[key]
        else:
            raise ValueError("Unknown __getitem__ type: %s" % type(key))

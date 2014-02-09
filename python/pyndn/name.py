# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

from StringIO import StringIO
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
    
    def toUri(self):
        """
        Encode this name as a URI according to the NDN URI Scheme.
        
        :return: The encoded URI.
        :rtype: str
        """
        if len(self._components) == 0:
            return "/"
  
        result = StringIO()
        for component in self._components:
            result.write("/")
            self.toEscapedString(component.getValue(), result)
  
        return result.getvalue()
        
    def getChangeCount(self):
        """
        Get the change count, which is incremented each time this object is 
        changed.
        
        :return: The change count.
        :rtype: int
        """
        
    @staticmethod
    def toEscapedString(value, result):
        """
        Write the value to result, escaping characters according to the NDN URI 
        Scheme. This also adds "..." to a value with zero or more ".".
        
        :param value: The buffer with the value to escape.
        :type value: An array type with int elements.
        :param result: The StringIO stream to write to.
        :type result: StringIO
        """
        gotNonDot = False
        for i in range(len(value)):
            if value[i] != 0x2e:
                gotNonDot = True
                break

        if not gotNonDot:
            # Special case for component of zero or more periods. Add 3 periods.
            result.write("...")
            for i in range(len(value)):
                result.write('.')
        else:
            for i in range(len(value)):
                x = value[i]
                # Check for 0-9, A-Z, a-z, (+), (-), (.), (_)
                if ((x >= 0x30 and x <= 0x39) or (x >= 0x41 and x <= 0x5a) or
                    (x >= 0x61 and x <= 0x7a) or x == 0x2b or x == 0x2d or
                    x == 0x2e or x == 0x5f):
                    result.write(chr(x))
                else:
                    result.write("%%%02X" % x)
        
    # Python operators.

    def __len__(self):
        return len(self._components)
        
    def __getitem__(self, key):
        if type(key) == int:
            return self._components[key]
        else:
            raise ValueError("Unknown __getitem__ type: %s" % type(key))

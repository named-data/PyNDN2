# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

from io import BytesIO
from pyndn.name import Name

"""
This module defines the Exclude class which is used by Interest and represents
the fields of an NDN Exclude selector.
"""

class Exclude(object):
    """
    Create a new Interest object, possibly copying values from another object.
    
    :param value: (optional) If value is an Exclude, copy its values.  If
      value is omitted, this creates an object with no entries.
    :type value: Exclude
    """
    def __init__(self, value = None):
        if value == None:
            self._entries = []
        elif type(value) is Exclude:
            # Copy its values.  Each entry is read-only, so do a shallow copy.
            self._entries = value._entries[:]
        else:
            raise RuntimeError(
              "Unrecognized type for Interest constructor: " +
              repr(type(value)))
                    
        self._changeCount = 0

    ANY = 0
    COMPONENT = 1

    class Entry(object):
        """
        Create a new Exclude.Entry.
        
        :param value: (optional) If value is omitted, create an Exclude.Entry of
          type Exclude.ANY.  Otherwise creat an Exclude.Entry of type 
          Exclude.COMPONENT with the value.
        :type value: Name.Component or a value for the Name.Component 
          constructor
        """
        def __init__(self, value = None):
            if value == None:
                self._type = Exclude.ANY
                self._component = None
            else:
                self._type = Exclude.COMPONENT
                self._component = (value if type(value) is Name.Component
                                   else Name.Component(value))

        def getType(self):
            """
            Get the type of this Exclude.Entry.
            
            :return: The type of this entry which is Exclude.ANY or
              Exclude.COMPONENT.
            :rtype: int
            """
            return self._type
        
        def getComponent(self):
            """
            Get the component for this Exclude.Entry (if the type of this 
              is Exclude.COMPONENT).
            
            :return: The component for this entry, or None if the type of
              this entry is not Exclude.COMPONENT.
            :rtype: Name.Component
            """
            return self._component
        
    def size(self):
        """
        Get the number of entries.
        
        :return: The number of entries.
        :rtype: int
        """
        return len(self._entries)
    
    def get(self, i):
        """
        Get the entry at the given index.
        
        :param i: The index of the entry, starting from 0.
        :type i: int
        :return: The entry at the index.
        :rtype: Exclude.Entry
        """
        self._entries[i]
        
    def appendAny(self):
        """
        Append a new entry of type Exclude.ANY.
        
        :return: This Exclude so that you can chain calls to append.
        :rype: Exclude
        """
        self._entries.append(Exclude.Entry())
        self._changeCount += 1
        return self
        
    def appendComponent(self, component):
        """
        Append a new entry of type Exclude.COMPONENT with the give component.
        
        :param component: The new exclude component.
        :type component: Exclude.Entry, Name.Component or a value for the 
          Name.Component constructor
        :return: This Exclude so that you can chain calls to append.
        :rype: Exclude
        """
        self._entries.append(component if type(component) is Exclude.Entry
                             else Exclude.Entry(component))
        self._changeCount += 1
        return self

    def clear(self):
        """
        Clear all the entries.
        """
        self._entries = []
        self._changeCount += 1

    _star = bytearray([ord('*')])
    _comma = bytearray([ord(',')])
    def toUri(self):
        """
        Return a string representation of the exclude values.
        
        :return: The string representation.
        :rtype: string
        """
        if len(self._entries) == 0:
            return ""
  
        result = BytesIO()
        didFirst = False
        for entry in self._entries:
            if didFirst:
                # write is required to take a byte buffer.
                result.write(Exclude._comma)
                
            if entry.getType() == Exclude.ANY:
                # write is required to take a byte buffer.
                result.write(Exclude._star)
            else:
                entry.getComponent().toEscapedString(result)
            didFirst = True
  
        value = result.getvalue()
        if not type(value) is str:
            # Assume value is a Python 3 bytes object.  Convert to string.
            value = str(value, encoding = 'ascii')
        return value

    def matches(self, component):
        """
        Check if the component matches any of the exclude criteria.
        
        :param component: The name component to check.
        :type component: Name.Component
        :return: True if the component matches any of the exclude criteria, 
          otherwise False.
        """
        # TODO: Implement Exclude.matches
        raise RuntimeError("Exclude.matches is not implemented")

    def getChangeCount(self):
        """
        Get the change count, which is incremented each time this object is 
        changed.
        
        :return: The change count.
        :rtype: int
        """
        return self._changeCount

    # Python operators.

    def __len__(self):
        return len(self._entries)
        
    def __getitem__(self, key):
        if type(key) is int:
            return self._entries[key]
        else:
            raise ValueError("Unknown __getitem__ type: %s" % type(key))

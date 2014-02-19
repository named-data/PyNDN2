# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the NDN Name class.
"""

from io import BytesIO
from pyndn.util import Blob

class Name(object):
    """
    Create a new Name which holds an array of Name.Component and represents an 
    NDN name.
    
    :param value: (optional) If value is another Name, then copy it.  If value 
      is a str then call set(value) to create from the URI.  If ommitted,
      create an empty name.
    :type value: Name or str
    """
    def __init__(self, value = None):
        if type(value) is Name:
            # Copy the components array, but don't need to copy each Component.
            self._components = value._components[:]
        elif type(value) is str:
            self._components = []
            # Set _changeCount now because self.set() expects it.
            self._changeCount = 0
            self.set(value)
        else:
            self._components = []
            
        self._changeCount = 0
        
    class Component(object):
        """
        Create a new Name.Component.
        
        :param value: (optional) If value is already a Blob or Name.Component,
          then take another pointer to the value.  Otherwise, create a new
          Blob with a copy of the value.  If omitted, create an empty component.
        :type value: Blob or Name.Component or value for Blob constructor
        """
        def __init__(self, value = None):
            if type(value) == Name.Component:
                # Use the existing Blob in the other Component.
                self._value = value._value
            else:
                # Blob will make a copy.
                self._value = value if isinstance(value, Blob) else Blob(value)
            
        def getValue(self):
            """
            Get the value of the component.

            :return: The component value.
            :rtype: Blob
            """
            return self._value
        
        def toEscapedString(self, result = None):
            """
            Convert this component to a string, escaping characters according
            to the NDN URI Scheme. This also adds "..." to a value with zero or
            more ".".

            :param result: (optional) The BytesIO stream to write to.  If 
              omitted, return a str with the result.
            :type result: BytesIO
            :return: The result as a string (only if result is omitted).
            :rtype: str
            """
            if result == None:
                return Name.toEscapedString(self._value.buf())
            else:
                Name.toEscapedString(self._value.buf(), result)

    def set(self, uri):
        """
        Parse the uri according to the NDN URI Scheme and set the name with 
        the components.
        
        :param uri: The URI string.
        :type uri: str
        """
        self.clear()
  
        uri = uri.strip()
        if len(uri) == 0:
            return

        iColon = uri.find(':')
        if iColon >= 0:
            # Make sure the colon came before a '/'.
            iFirstSlash = uri.find('/')
            if iFirstSlash < 0 or iColon < iFirstSlash:
                # Omit the leading protocol such as ndn:
                uri = uri[iColon + 1:].strip()

        # Trim the leading slash and possibly the authority.
        if uri[0] == '/':
            if len(uri) >= 2 and uri[1] == '/':
                # Strip the authority following "//".
                iAfterAuthority = uri.find('/', 2)
                if iAfterAuthority < 0:
                    # Unusual case: there was only an authority.
                    return
                else:
                    uri = uri[iAfterAuthority + 1:].strip()
            else:
                uri = uri[1:].strip()

        iComponentStart = 0
  
        # Unescape the components.
        while iComponentStart < len(uri):
            iComponentEnd = uri.find('/', iComponentStart)
            if iComponentEnd < 0:
                iComponentEnd = len(uri)
    
            component = Name.fromEscapedString(uri, iComponentStart, 
                                               iComponentEnd)
            # Ignore illegal components.  This also gets rid of a trailing '/'.
            if not component.isNull():
                self.append(component)
    
            iComponentStart = iComponentEnd + 1

    def append(self, value):
        """
        Append a new component.
        
        :param value: If value is another Name.Component, use its value.
          Otherwise pass value to the Name.Component constructor.
        :type value: Name.Component or value for Name.Component constructor
        """
        if isinstance(value, Name.Component):
            self._components.append(value)
        else:
            self._components.append(Name.Component(value))
            
        self._changeCount += 1
        return self
    
    def clear(self):
        """
        Clear all the components.
        """
        self._components = []
        self._changeCount += 1

    def getSubName(self, iStartComponent, nComponents = None):
        """
        Get a new name, constructed as a subset of components.
        
        :param iStartComponent: The index if the first component to get.
        :type iStartComponent: int
        :param nComponents: (optional) nComponents The number of components 
          starting at iStartComponent.  If omitted, return components starting 
          at iStartComponent until the end of the name.
        :type nComponents: int
        :return: A new name.
        :rtype: Name
        """
        if nComponents == None:
            nComponents = len(self._components) - iStartComponent

        result = Name()

        iEnd = min(iStartComponent + nComponents, len(self._components))
        for i in range(iStartComponent, iEnd):
            result._components.append(self._components[i])

        return result

    def size(self):
        """
        Get the number of components.
        
        :return: The number of components.
        :rtype: int
        """
        return len(self._components)

    def get(self, i):
        """
        Get the component at the given index.
        
        :param i: The index of the component, starting from 0.  However, if i is
          negative, return the component at size() - (-i).
        :type i: int
        """
        return self._components[i]
    
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
            component.toEscapedString(result)
  
        value = result.getvalue()
        if not type(value) is str:
            # Assume value is a Python 3 bytes object.  Convert to string.
            value = str(value, encoding = 'ascii')
        return value
        
    def getChangeCount(self):
        """
        Get the change count, which is incremented each time this object is 
        changed.
        
        :return: The change count.
        :rtype: int
        """
        return self._changeCount
        
    @staticmethod
    def fromEscapedString(escapedString, beginOffset = 0, endOffset = None):
        """
        Make a Blob value by decoding the escapedString between beginOffset and
        endOffset according to the NDN URI Scheme.  (If offsets are omitted,
        then decode the whole string.)  If the escaped string is "", "." or ".."
        then return a Blob with a null pointer, which means the component should
        be skipped in a URI name.
        
        :param escapedString: The escaped string.
        :type escapedString: str
        :return: The unescaped Blob value. If the escapedString is not a valid 
          escaped component, then the Blob isNull().
        """
        if endOffset == None:
            endOffset = len(escapedString)
        value = Name._unescape(escapedString[beginOffset:endOffset].strip())
        
        gotNonDot = False
        for i in range(len(value)):
            if value[i] != '.':
                gotNonDot = True
                break

        if not gotNonDot:
            # Special case for component of only periods.
            if len(value) <= 2:
                # Zero, one or two periods is illegal.  Ignore this component.
                return Blob()
            else:
                # Remove 3 periods.
                return Blob(value[3:])
        else:
            return Blob(value)
        
    @staticmethod
    def toEscapedString(value, result = None):
        """
        Convert value to a string, escaping characters according to the NDN URI 
        Scheme. This also adds "..." to a value with zero or more ".".
        
        :param value: The buffer with the value to escape.
        :type value: An array type with int elements
        :param result: (optional) The BytesIO stream to write to.  If omitted,
          return a str with the result.
        :type result: BytesIO
        :return: The result as a string (only if result is omitted).
        :rtype: str
        """
        if result == None:
            result = BytesIO()
            Name.toEscapedString(value, result)
            
            value = result.getvalue()
            if not type(value) is str:
                # Assume value is a Python 3 bytes object.  Convert to string.
                value = str(value, encoding = 'ascii')
            return value            
            
        gotNonDot = False
        for i in range(len(value)):
            if value[i] != ord('.'):
                gotNonDot = True
                break

        charBuffer = bytearray(1)
        if not gotNonDot:
            charBuffer[0] = ord('.')
            # Special case for component of zero or more periods. Add 3 periods.
            for i in range(len(value) + 3):
                result.write(charBuffer)
        else:
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

    @staticmethod
    def _unescape(escaped):
        """
        A private method to return a copy of the escaped string, converting 
        each escaped "%XX" to the char value.
        
        :param escaped: The escaped string.
        :type escaped: str
        :return: The unescaped buffer
        :rtype: bytearray
        """
        result = BytesIO()

        buffer = bytearray(1)
        i = 0
        while i < len(escaped):
            if escaped[i] == '%' and i + 2 < len(escaped):
                try:
                    buffer[0] = int(escaped[i + 1:i + 3], 16)
                    result.write(buffer)
                except ValueError:
                    # Invalid hex characters.  An unusual case, so just keep 
                    #   the escaped string.
                    for j in range(i, i + 3):
                        buffer[0] = ord(escaped[j])
                        result.write(buffer)
                    
                # Skip ahead past the escaped value.
                i += 2
            else:
                # Just copy through.
                buffer[0] = ord(escaped[i])
                # write is required to take a byte buffer.
                result.write(buffer)

            i += 1

        return bytearray(result.getvalue())          

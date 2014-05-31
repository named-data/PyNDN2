# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
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
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU General Public License is in the file COPYING.

"""
This module defines the NDN Name class.
"""

from io import BytesIO
from pyndn.util import Blob
from pyndn.util.common import Common

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
        elif Common.typeIsString(value):
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
            if type(value) is Name.Component:
                # Use the existing Blob in the other Component.
                self._value = value._value
            elif value == None:
                self._value = Blob([])
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

            :param BytesIO result: (optional) The BytesIO stream to write to.  
              If omitted, return a str with the result.
            :return: The result as a string (only if result is omitted).
            :rtype: str
            """
            if result == None:
                return Name.toEscapedString(self._value.buf())
            else:
                Name.toEscapedString(self._value.buf(), result)

        def toNumber(self):
            """
            Interpret this name component as a network-ordered number and return 
            an integer.
            
            :return: The integer number.
            :rtype: int
            """
            result = 0
            for i in range(self._value.size()):
                result *= 256
                result += self._value.buf()[i]
            return result
        
        def toNumberWithMarker(self, marker):
            """
            Interpret this name component as a network-ordered number with a 
            marker and return an integer.
            
            :param int marker: The required first byte of the component.
            :return: The integer number.
            :rtype: int
            :raises RuntimeError: If the first byte of the component does not 
              equal the marker.
            """
            if self._value.size() <= 0 or self._value.buf()[0] != marker:
                raise RuntimeError(
                       "Name component does not begin with the expected marker")

            result = 0
            for i in range(1, self._value.size()):
                result *= 256
                result += self._value.buf()[i]
            return result
        
        def toSegment(self):
            """
            Interpret this name component as a segment number according to NDN 
            name conventions (a network-ordered number where the first byte is 
            the marker 0x00).
            
            :return: The integer segment number.
            :rtype: int
            :raises RuntimeError: If the first byte of the component is not the 
              expected marker.
            """
            return self.toNumberWithMarker(0x00)
        
        def toVersion(self):
            """
            Interpret this name component as a version number according to NDN 
            name conventions (a network-ordered number where the first byte is 
            the marker 0xFD).  Note that this returns the exact number from the 
            component without converting it to a time representation.
            
            :return: The integer version number.
            :rtype: int
            :raises RuntimeError: If the first byte of the component is not the 
              expected marker.
            """
            return self.toNumberWithMarker(0xFD)
        
        def equals(self, other):
            """
            Check if this is the same component as other.
            
            :param Name.Component other: The other Component to compare with.
            :return: True if the components are equal, otherwise False.
            :rtype: bool
            """
            return self._value.equals(other._value)
        
        def compare(self, other):
            """
            Compare this to the other Component using NDN canonical ordering.
            
            :param Name.Component other: The other Component to compare with.
            :return: 0 If they compare equal, -1 if self comes before other in 
              the canonical ordering, or 1 if self comes after other in the 
              canonical ordering.
            :rtype: int
            :see: http://named-data.net/doc/0.2/technical/CanonicalOrder.html
            """
            if self._value.size() < other._value.size():
                return -1
            if self._value.size() > other._value.size():
                return 1

            # The components are equal length. Just do a byte compare.
            return self._value.compare(other._value)
        
        @staticmethod
        def fromNumber(number):
            """
            Create a component whose value is the network-ordered encoding of 
            the number. Note: if the number is zero, the result is empty.
            
            :param int number: The number to be encoded.
            :return: The component value.
            :rtype: Name.Component
            """
            value = []

            # First encode in little endian.
            while number != 0:
                value.append(number & 0xff)
                number >>= 8
                
            # Make it big endian.
            value.reverse()
            return Name.Component(Blob(value, False))
        
        @staticmethod
        def fromNumberWithMarker(number, marker):
            """
            Create a component whose value is the marker appended with the 
            network-ordered encoding of the number. Note: if the number is zero, 
            no bytes are used for the number - the result will have only the 
            marker.

            :param int number: The number to be encoded.
            :param int marker: The marker to use as the first byte of the 
              component.
            :return: The component value.
            :rtype: Name.Component
            """
            value = []

            # First encode in little endian.
            while number != 0:
                value.append(number & 0xff)
                number >>= 8
                
            # Make it big endian.
            value.reverse()
            
            # Prepend the leading marker.
            value.insert(0, marker)
            
            return Name.Component(Blob(value, False))

        # Python operators
        
        def __eq__(self, other):
            return type(other) is Name.Component and self.equals(other)
        
        def __ne__(self, other):
            return not self == other

        def __le__(self, other):
            return self.compare(other) <= 0

        def __lt__(self, other):
            return self.compare(other) < 0

        def __ge__(self, other):
            return self.compare(other) >= 0

        def __gt__(self, other):
            return self.compare(other) > 0

    def set(self, uri):
        """
        Parse the uri according to the NDN URI Scheme and set the name with 
        the components.
        
        :param str uri: The URI string.
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
        
        :param value: If value is another Name, append all its components.
          If value is another Name.Component, use its value.
          Otherwise pass value to the Name.Component constructor.
        :type value: Name, Name.Component or value for Name.Component constructor
        """
        if isinstance(value, Name):
            for component in value._components:
                self._components.append(component)
        elif isinstance(value, Name.Component):
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
        
        :param int iStartComponent: The index if the first component to get.
        :param int nComponents: (optional) nComponents The number of components 
          starting at iStartComponent.  If omitted, return components starting 
          at iStartComponent until the end of the name.
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

    def getPrefix(self, nComponents):
        """
        Return a new Name with the first nComponents components of this Name.
        
        :param int nComponents: The number of prefix components.  If nComponents 
          is -N then return the prefix up to name.size() - N. For example 
          getPrefix(-1) returns the name without the final component.
        """
        if nComponents < 0:
            return self.getSubName(0, len(self._components) + nComponents)
        else:
            return self.getSubName(0, nComponents)
  
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
        
        :param int i: The index of the component, starting from 0.  However, if 
          i is negative, return the component at size() - (-i).
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
  
        return Common.getBytesIOString(result)
        
        
    def appendSegment(self, segment):
        """
        Append a component with the encoded segment number.
        
        :param int segment: The segment number.
        :return: This name so that you can chain calls to append.
        :rtype: Name
        """
        return self.append(Name.Component.fromNumberWithMarker(segment, 0x00))
    
    def appendVersion(self, version):
        """
        Append a component with the encoded version number.
        
        :param int version: The version number.
        :return: This name so that you can chain calls to append.
        :rtype: Name        
        """
        return self.append(Name.Component.fromNumberWithMarker(version, 0xFD))
        
    def equals(self, name):
        """
        Check if this name has the same component count and components as the 
        given name.
        
        :param Name name: 
        :return: True if the names are equal, otherwise False.
        :rtype: bool
        """
        if len(self._components) != len(name._components):
            return False

        for i in range(len(self._components)):
            if not self._components[i].equals(name._components[i]):
                return False

        return True
        
    def compare(self, other):
        """
        Compare this to the other Name using NDN canonical ordering.  If the 
        first components of each name are not equal, this returns -1 if the 
        first comes before the second using the NDN canonical ordering for name 
        components, or 1 if it comes after. If they are equal, this compares the 
        second components of each name, etc.  If both names are the same up to
        the size of the shorter name, this returns -1 if the first name is 
        shorter than the second or 1 if it is longer.  For example, sorted 
        gives: /a/b/d /a/b/cc /c /c/a /bb .  This is intuitive because all names
        with the prefix /a are next to each other.  But it may be also be 
        counter-intuitive because /c comes before /bb according to NDN canonical 
        ordering since it is shorter.
        
        :param Name other: The other Name to compare with.
        :return: 0 If they compare equal, -1 if self comes before other in the 
          canonical ordering, or 1 if self comes after other in the canonical 
          ordering.
        :rtype: int
        :see: http://named-data.net/doc/0.2/technical/CanonicalOrder.html
        """
        for i in range(min(len(self._components), len(other._components))):
            comparison = self._components[i].compare(other._components[i])
            if comparison == 0:
                # The components at this index are equal, so check the next 
                #   components.
                continue

            # Otherwise, the result is based on the components at this index.
            return comparison

        # The components up to min(self.size(), other.size()) are equal, so the 
        #   shorter name is less.
        if len(self._components) < len(other._components):
            return -1
        elif len(self._components) > len(other._components):
            return 1
        else:
            return 0
        
    def match(self, name):
        """
        Check if the N components of this name are the same as the first N 
        components of the given name.
        
        :param Name name: The Name to check.
        :return: True if this matches the given name, otherwise False.  This 
          always returns True if this name is empty.
        :rtype: bool
        """
        # Check if this name is longer than the name we are checking it against.
        if len(self._components) > len(name._components):
            return False

        # Check if at least one of given components doesn't match.
        for i in range(len(self._components)):
            if not self._components[i].getValue().equals( 
                  name._components[i].getValue()):
                return False

        return True
        
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
        
        :param str escapedString: The escaped string.
        :return: The unescaped Blob value. If the escapedString is not a valid 
          escaped component, then the Blob isNull().
        """
        if endOffset == None:
            endOffset = len(escapedString)
        value = Name._unescape(escapedString[beginOffset:endOffset].strip())
        
        gotNonDot = False
        for i in range(len(value)):
            if value[i] != ord('.'):
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
        :param BytesIO result: (optional) The BytesIO stream to write to.  If 
          omitted, return a str with the result.
        :return: The result as a string (only if result is omitted).
        :rtype: str
        """
        if result == None:
            result = BytesIO()
            Name.toEscapedString(value, result)
            return Common.getBytesIOString(result)            
            
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
        if type(key) is int:
            return self._components[key]
        else:
            raise ValueError("Unknown __getitem__ type: %s" % type(key))

    def __eq__(self, other):
        return type(other) is Name and self.equals(other)

    def __ne__(self, other):
        return not self == other

    def __le__(self, other):
        return self.compare(other) <= 0

    def __lt__(self, other):
        return self.compare(other) < 0

    def __ge__(self, other):
        return self.compare(other) >= 0

    def __gt__(self, other):
        return self.compare(other) > 0

    @staticmethod
    def _unescape(escaped):
        """
        A private method to return a copy of the escaped string, converting 
        each escaped "%XX" to the char value.
        
        :param str escaped: The escaped string.
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

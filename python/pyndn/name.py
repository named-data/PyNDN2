# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2019 Regents of the University of California.
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
This module defines the NDN Name class.
"""

from io import BytesIO

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
        if isinstance(value, Name):
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
        self._hash = None
        self._hashCodeChangeCount = 0

    class Component(object):
        """
        Create a new Name.Component with a copy of the given value.
        (To create an ImplicitSha256Digest component, use fromImplicitSha256Digest.)
        (To create a ParametersSha256Digest component, use fromParametersSha256Digest.)

        :param value: (optional) If value is already a Blob or Name.Component,
          then take another pointer to the value.  Otherwise, create a new
          Blob with a copy of the value.  If omitted, create an empty component.
        :type value: Blob or Name.Component or value for Blob constructor
        :param int type: (optional) The component type as an int from the
          ComponentType enum. If name component type is not a recognized
          ComponentType enum value, then set this to ComponentType.OTHER_CODE
          and use the otherTypeCode parameter. If omitted, use
          ComponentType.GENERIC.
        :param int otherTypeCode: (optional) If type is ComponentType.OTHER_CODE,
          then this is the packet's unrecognized content type code, which must
          be non-negative.
        """
        def __init__(self, value = None, type = None, otherTypeCode = None):
            if isinstance(value, Name.Component):
                # Copy constructor. Use the existing Blob in the other Component.
                self._value = value._value
                self._type = value._type
                self._otherTypeCode = value._otherTypeCode
                return

            if value == None:
                self._value = Blob([])
            else:
                # Blob will make a copy.
                self._value = value if isinstance(value, Blob) else Blob(value)

            if type == ComponentType.OTHER_CODE:
                if otherTypeCode == None:
                  raise ValueError(
                    "To use an other code, call Name.Component(value, ComponentType.OTHER_CODE, otherTypeCode)")

                if otherTypeCode < 0:
                    raise ValueError(
                      "Name.Component other type code must be non-negative")
                self._otherTypeCode = otherTypeCode
            else:
                self._otherTypeCode = -1

            self._type = ComponentType.GENERIC if type == None else type

        def getValue(self):
            """
            Get the value of the component.

            :return: The component value.
            :rtype: Blob
            """
            return self._value

        def getType(self):
            """
            Get the name component type.

            :return: The name component type as an int from the ComponentType
              enum. If this is ComponentType.OTHER_CODE, then call
              getOtherTypeCode() to get the unrecognized component type code.
            :rtype: int
            """
            return self._type

        def getOtherTypeCode(self):
            """
            Get the component type code from the packet which is other than a
              recognized ComponentType enum value. This is only meaningful if
              getType() is ComponentType.OTHER_CODE.

            :return: The type code.
            :rtype: int
            """
            return self._otherTypeCode

        def toEscapedString(self, result = None):
            """
            Convert this component to a string, escaping characters according
            to the NDN URI Scheme. This also adds "..." to a value with zero or
            more ".". This adds a type code prefix as needed, such as
            "sha256digest=".

            :param BytesIO result: (optional) The BytesIO stream to write to.
              If omitted, return a str with the result.
            :return: The result as a string (only if result is omitted).
            :rtype: str
            """
            if result == None:
                result = BytesIO()
                self.toEscapedString(result)
                return Common.getBytesIOString(result)

            if self._type == ComponentType.IMPLICIT_SHA256_DIGEST:
                result.write("sha256digest=".encode('utf-8'))
                self._value.toHex(result)
                return

            if self._type == ComponentType.PARAMETERS_SHA256_DIGEST:
                result.write("params-sha256=".encode('utf-8'))
                self._value.toHex(result)
                return

            if self._type != ComponentType.GENERIC:
                text = (str(self._otherTypeCode)
                  if self._type == ComponentType.OTHER_CODE else str(self._type))
                text += "="
                # write requires the encoded buffer.
                result.write(text.encode('utf-8'))

            Name.toEscapedString(self._value.buf(), result)

        def isSegment(self):
            """
            Check if this component is a segment number according to NDN
            naming conventions for "Segment number" (marker 0x00).
            http://named-data.net/doc/tech-memos/naming-conventions.pdf

            :return: True if this is a segment number.
            :rtype: bool
            """
            return (self._value.size() >= 1 and self._value.buf()[0] == 0x00 and
                    self.isGeneric())

        def isSegmentOffset(self):
            """
            Check if this component is a segment byte offset according to NDN
            naming conventions for segment "Byte offset" (marker 0xFB).
            http://named-data.net/doc/tech-memos/naming-conventions.pdf

            :return: True if this is a segment byte offset.
            :rtype: bool
            """
            return (self._value.size() >= 1 and self._value.buf()[0] == 0xFB and
                    self.isGeneric())

        def isVersion(self):
            """
            Check if this component is a version number according to NDN
            naming conventions for "Versioning" (marker 0xFD).
            http://named-data.net/doc/tech-memos/naming-conventions.pdf

            :return: True if this is a version number.
            :rtype: bool
            """
            return (self._value.size() >= 1 and self._value.buf()[0] == 0xFD and
                    self.isGeneric())

        def isTimestamp(self):
            """
            Check if this component is a timestamp according to NDN
            naming conventions for "Timestamp" (marker 0xFC).
            http://named-data.net/doc/tech-memos/naming-conventions.pdf

            :return: True if this is a timestamp.
            :rtype: bool
            """
            return (self._value.size() >= 1 and self._value.buf()[0] == 0xFC and
                    self.isGeneric())

        def isSequenceNumber(self):
            """
            Check if this component is a sequence number according to NDN
            naming conventions for "Sequencing" (marker 0xFE).
            http://named-data.net/doc/tech-memos/naming-conventions.pdf

            :return: True if this is a sequence number.
            :rtype: bool
            """
            return (self._value.size() >= 1 and self._value.buf()[0] == 0xFE and
                    self.isGeneric())

        def isGeneric(self):
            """
            Check if this component is a generic component.

            :return: True if this is an generic component.
            :rtype: bool
            """
            return self._type == ComponentType.GENERIC

        def isImplicitSha256Digest(self):
            """
            Check if this component is an ImplicitSha256Digest component.

            :return: True if this is an ImplicitSha256Digest component.
            :rtype: bool
            """
            return self._type == ComponentType.IMPLICIT_SHA256_DIGEST

        def isParametersSha256Digest(self):
            """
            Check if this component is a ParametersSha256Digest component.

            :return: True if this is a ParametersSha256Digest component.
            :rtype: bool
            """
            return self._type == ComponentType.PARAMETERS_SHA256_DIGEST

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
            naming conventions for "Segment number" (marker 0x00).
            http://named-data.net/doc/tech-memos/naming-conventions.pdf

            :return: The integer segment number.
            :rtype: int
            :raises RuntimeError: If the first byte of the component is not the
              expected marker.
            """
            return self.toNumberWithMarker(0x00)

        def toSegmentOffset(self):
            """
            Interpret this name component as a segment byte offset according to
            NDN naming conventions for segment "Byte offset" (marker 0xFB).
            http://named-data.net/doc/tech-memos/naming-conventions.pdf

            :return: The integer segment byte offset.
            :rtype: int
            :raises RuntimeError: If the first byte of the component is not the
              expected marker.
            """
            return self.toNumberWithMarker(0xFB)

        def toVersion(self):
            """
            Interpret this name component as a version number  according to NDN
            naming conventions for "Versioning" (marker 0xFD). Note that this
            returns the exact number from the component without converting it to
            a time representation.
            http://named-data.net/doc/tech-memos/naming-conventions.pdf

            :return: The integer version number.
            :rtype: int
            :raises RuntimeError: If the first byte of the component is not the
              expected marker.
            """
            return self.toNumberWithMarker(0xFD)

        def toTimestamp(self):
            """
            Interpret this name component as a timestamp  according to NDN naming
            conventions for "Timestamp" (marker 0xFC).
            http://named-data.net/doc/tech-memos/naming-conventions.pdf

            :return: The number of microseconds since the UNIX epoch (Thursday,
              1 January 1970) not counting leap seconds.
            :rtype: int
            :raises RuntimeError: If the first byte of the component is not the
              expected marker.
            """
            return self.toNumberWithMarker(0xFC)

        def toSequenceNumber(self):
            """
            Interpret this name component as a sequence number according to NDN
            naming conventions for "Sequencing" (marker 0xFE).
            http://named-data.net/doc/tech-memos/naming-conventions.pdf

            :return: The integer sequence number.
            :rtype: int
            :raises RuntimeError: If the first byte of the component is not the
              expected marker.
            """
            return self.toNumberWithMarker(0xFE)

        def equals(self, other):
            """
            Check if this is the same component as other.

            :param Name.Component other: The other Component to compare with.
            :return: True if the components are equal, otherwise False.
            :rtype: bool
            """
            if self._type == ComponentType.OTHER_CODE:
                return (self._value.equals(other._value) and
                  other._type == ComponentType.OTHER_CODE and
                  self._otherTypeCode == other._otherTypeCode)
            else:
                return self._value.equals(other._value) and self._type == other._type

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
            myTypeCode = (self._otherTypeCode
              if self._type == ComponentType.OTHER_CODE else self._type)
            otherTypeCode = (other._otherTypeCode
              if other._type == ComponentType.OTHER_CODE else other._type)

            if myTypeCode < otherTypeCode:
                return -1
            if myTypeCode > otherTypeCode:
                return 1

            if self._value.size() < other._value.size():
                return -1
            if self._value.size() > other._value.size():
                return 1

            # The components are equal length. Just do a byte compare.
            return self._value.compare(other._value)

        @staticmethod
        def fromNumber(number, type = None, otherTypeCode = None):
            """
            Create a component whose value is the nonNegativeInteger encoding of
            the number.

            :param int number: The number to be encoded.
            :param int type: (optional) The component type as an int from the
              ComponentType enum. If name component type is not a recognized
              ComponentType enum value, then set this to ComponentType.OTHER_CODE
              and use the otherTypeCode parameter. If omitted, use
              ComponentType.GENERIC.
            :param int otherTypeCode: (optional) If type is
              ComponentType.OTHER_CODE, then this is the packet's unrecognized
              content type code, which must be non-negative.
            :return: The new component value.
            :rtype: Name.Component
            """
            encoder = TlvEncoder(8)
            encoder.writeNonNegativeInteger(number)
            return Name.Component(
              Blob(encoder.getOutput(), False), type, otherTypeCode)

        @staticmethod
        def fromNumberWithMarker(number, marker):
            """
            Create a component whose value is the marker appended with the
            nonNegativeInteger encoding of the number.

            :param int number: The number to be encoded.
            :param int marker: The marker to use as the first byte of the
              component.
            :return: The component value.
            :rtype: Name.Component
            """
            encoder = TlvEncoder(9)
            # Encode backwards.
            encoder.writeNonNegativeInteger(number)
            encoder.writeNonNegativeInteger(marker)
            return Name.Component(Blob(encoder.getOutput(), False))

        @staticmethod
        def fromSegment(segment):
            """
            Create a component with the encoded segment number according to NDN
            naming conventions for "Segment number" (marker 0x00).
            http://named-data.net/doc/tech-memos/naming-conventions.pdf

            :param int segment: The segment number.
            :return: The new Component.
            :rtype: Name.Component
            """
            return Name.Component.fromNumberWithMarker(segment, 0x00)

        @staticmethod
        def fromSegmentOffset(segmentOffset):
            """
            Create a component with the encoded segment byte offset according to NDN
            naming conventions for segment "Byte offset" (marker 0xFB).
            http://named-data.net/doc/tech-memos/naming-conventions.pdf

            :param int segmentOffset: The segment byte offset.
            :return: The new Component.
            :rtype: Name.Component
            """
            return Name.Component.fromNumberWithMarker(segmentOffset, 0xFB)

        @staticmethod
        def fromVersion(version):
            """
            Create a component with the encoded version number according to NDN
            naming conventions for "Versioning" (marker 0xFD).
            http://named-data.net/doc/tech-memos/naming-conventions.pdf
            Note that this encodes the exact value of version without converting
            from a time representation.

            :param int version: The version number.
            :return: The new Component.
            :rtype: Name.Component
            """
            return Name.Component.fromNumberWithMarker(int(version), 0xFD)

        @staticmethod
        def fromTimestamp(timestamp):
            """
            Create a component with the encoded timestamp according to NDN naming
            conventions for "Timestamp" (marker 0xFC).
            http://named-data.net/doc/tech-memos/naming-conventions.pdf

            :param int timestamp: The number of microseconds since the UNIX epoch
              (Thursday, 1 January 1970) not counting leap seconds.
            :return: The new Component.
            :rtype: Name.Component
            """
            return Name.Component.fromNumberWithMarker(int(timestamp), 0xFC)

        @staticmethod
        def fromSequenceNumber(sequenceNumber):
            """
            Create a component with the encoded sequence number according to NDN naming
            conventions for "Sequencing" (marker 0xFE).
            http://named-data.net/doc/tech-memos/naming-conventions.pdf

            :param int sequenceNumber: The sequence number.
            :return: The new Component.
            :rtype: Name.Component
            """
            return Name.Component.fromNumberWithMarker(sequenceNumber, 0xFE)

        @staticmethod
        def fromImplicitSha256Digest(digest):
            """
            Create a component of type ImplicitSha256DigestComponent, so that
            isImplicitSha256Digest() is true.

            :param digest: The SHA-256 digest value.
            :type digest: Blob or value for Blob constructor
            :return: The new Component.
            :rtype: Name.Component
            :raises RuntimeError: If the digest length is not 32 bytes.
            """
            digestBlob = digest if isinstance(digest, Blob) else Blob(digest)
            if digestBlob.size() != 32:
              raise RuntimeError(
                "Name.Component.fromImplicitSha256Digest: The digest length must be 32 bytes")

            result = Name.Component(digestBlob)
            result._type = ComponentType.IMPLICIT_SHA256_DIGEST
            return result

        @staticmethod
        def fromParametersSha256Digest(digest):
            """
            Create a component of type ParametersSha256DigestComponent, so that
            isParametersSha256Digest() is true.

            :param digest: The SHA-256 digest value.
            :type digest: Blob or value for Blob constructor
            :return: The new Component.
            :rtype: Name.Component
            :raises RuntimeError: If the digest length is not 32 bytes.
            """
            digestBlob = digest if isinstance(digest, Blob) else Blob(digest)
            if digestBlob.size() != 32:
              raise RuntimeError(
                "Name.Component.fromParametersSha256Digest: The digest length must be 32 bytes")

            result = Name.Component(digestBlob)
            result._type = ComponentType.PARAMETERS_SHA256_DIGEST
            return result

        def getSuccessor(self):
            """
            Get the successor of this component, as described in
            Name.getSuccessor.

            :return: A new Name.Component which is the successor of this.
            :rtype: Name.Component
            """
            # Allocate an extra byte in case the result is larger.
            result = bytearray(self._value.size() + 1)

            carry = True
            for i in range(self._value.size() - 1, -1, -1):
                if carry:
                    result[i] = (self._value.buf()[i] + 1) & 0xff
                    carry = (result[i] == 0)
                else:
                    result[i] = self._value.buf()[i]

            if carry:
                # Assume all the bytes were set to zero (or the component was
                # empty). In NDN ordering, carry does not mean to prepend a 1,
                # but to make a component one byte longer of all zeros.
                result[len(result) - 1] = 0
            else:
                # We didn't need the extra byte.
                result = result[0:self._value.size()]

            return Name.Component(
             Blob(result, False), self._type, self._otherTypeCode)

        # Python operators

        def __eq__(self, other):
            return isinstance(other, Name.Component) and self.equals(other)

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

        def __len__(self):
            return self._value.size()

        def __str__(self):
            return self.toEscapedString()

        def __hash__(self):
            return (37 *
              (self._otherTypeCode if self._type == ComponentType.OTHER_CODE
                                   else self._type) +
              hash(self._value))

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
        sha256digestPrefix = "sha256digest="
        paramsSha256Prefix = "params-sha256="
        while iComponentStart < len(uri):
            iComponentEnd = uri.find('/', iComponentStart)
            if iComponentEnd < 0:
                iComponentEnd = len(uri)

            if (uri[iComponentStart:iComponentStart + len(sha256digestPrefix)] ==
                sha256digestPrefix):
              hexString = uri[iComponentStart + len(sha256digestPrefix):].strip()
              component = Name.Component.fromImplicitSha256Digest(
                Blob(bytearray.fromhex(hexString), False))
            elif (uri[iComponentStart:iComponentStart + len(paramsSha256Prefix)] ==
                paramsSha256Prefix):
              hexString = uri[iComponentStart + len(paramsSha256Prefix):].strip()
              component = Name.Component.fromParametersSha256Digest(
                Blob(bytearray.fromhex(hexString), False))
            else:
                type = ComponentType.GENERIC
                otherTypeCode = -1

                # Check for a component type.
                iTypeCodeEnd = uri.find("=", iComponentStart)
                if iTypeCodeEnd >= 0 and iTypeCodeEnd < iComponentEnd:
                    typeString = uri[iComponentStart : iTypeCodeEnd]
                    try:
                        otherTypeCode = int(typeString)
                    except ValueError:
                        raise ValueError("Can't parse decimal Name Component type: " +
                           typeString + " in URI " + uri)

                    # Allow for a decimal value of recognized component types.
                    if (otherTypeCode == ComponentType.GENERIC or
                        otherTypeCode == ComponentType.IMPLICIT_SHA256_DIGEST or
                        otherTypeCode == ComponentType.PARAMETERS_SHA256_DIGEST):
                        # The enum values are the same as the TLV type codes.
                        type = otherTypeCode
                    else:
                        type = ComponentType.OTHER_CODE

                    iComponentStart = iTypeCodeEnd + 1

                component = Name.Component(
                  Name.fromEscapedString(uri, iComponentStart, iComponentEnd),
                  type, otherTypeCode)

            # Ignore illegal components.  This also gets rid of a trailing '/'.
            if not component.getValue().isNull():
                self.append(component)

            iComponentStart = iComponentEnd + 1

    def append(self, value, type = None, otherTypeCode = None):
        """
        Append a new component to this Name.
        (To append an ImplicitSha256Digest component, use appendImplicitSha256Digest.)
        (To append a ParametersSha256Digest component, use appendParametersSha256Digest.)

        :param value: If value is another Name, append all its components.
          If value is another Name.Component, use its value.
          Otherwise pass value to the Name.Component constructor.
        :type value: Name, Name.Component or value for Name.Component constructor
        :param int type: (optional) The component type as an int from the
          ComponentType enum. If name component type is not a recognized
          ComponentType enum value, then set this to ComponentType.OTHER_CODE
          and use the otherTypeCode parameter. If omitted, use
          ComponentType.GENERIC. If the component param is a Name or another
          Name.Component, then this is ignored.
        :param int otherTypeCode: (optional) If type is ComponentType.OTHER_CODE,
          then this is the packet's unrecognized content type code, which must
          be non-negative. If the component param is a Name or another
          Name.Component, then this is ignored.
        :return: This name so that you can chain calls to append.
        :rtype: Name
        """
        if isinstance(value, Name):
            if value == self:
                # Special case, when we need to create a copy before appending to self.
                components = self._components[:]
            else:
                components = value._components

            for component in components:
                self._components.append(component)
        elif isinstance(value, Name.Component):
            # The Name.Component is immutable, so use it as is.
            self._components.append(value)
        else:
            # Just use the Name.Component constructor.
            self._components.append(Name.Component(value, type, otherTypeCode))

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

        :param int iStartComponent: The index if the first component to get. If
          iStartComponent is -N then return return components starting from
          name.size() - N.
        :param int nComponents: (optional) The number of components starting at
          iStartComponent. If omitted or greater than the size of this name, get
          until the end of the name.
        :return: A new name.
        :rtype: Name
        """
        if iStartComponent < 0:
            iStartComponent = len(self._components) - (-iStartComponent)

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
        :return: The name prefix.
        :rtype: Name
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
    def toUri(self, includeScheme = False):
        """
        Encode this name as a URI according to the NDN URI Scheme.

        :param bool includeScheme: (optional) If True, include the "ndn:" scheme
          in the URI, e.g. "ndn:/example/name". If False, just return the path,
          e.g. "/example/name". If ommitted, then just return the path which is
          the default case where toUri() is used for display.

        :return: The encoded URI.
        :rtype: str
        """
        if len(self._components) == 0:
            return "ndn:/" if includeScheme else "/"

        result = BytesIO()
        if includeScheme:
            result.write("ndn:".encode('utf-8'))
        for component in self._components:
            # write is required to take a byte buffer.
            result.write(Name._slash)
            component.toEscapedString(result)

        return Common.getBytesIOString(result)

    def appendNumber(self, number, type = None, otherTypeCode = None):
        """
        Append a component whose value is the nonNegativeInteger encoding of the
        number.

        :param int number: The number to be encoded.
        :param int type: (optional) The component type as an int from the
          ComponentType enum. If name component type is not a recognized
          ComponentType enum value, then set this to ComponentType.OTHER_CODE
          and use the otherTypeCode parameter. If omitted, use
          ComponentType.GENERIC.
        :param int otherTypeCode: (optional) If type is
          ComponentType.OTHER_CODE, then this is the packet's unrecognized
          content type code, which must be non-negative.
        :return: This name so that you can chain calls to append.
        :rtype: Name
        """
        return self.append(Name.Component.fromNumber(number, type, otherTypeCode))

    def appendSegment(self, segment):
        """
        Append a component with the encoded segment number according to NDN
        naming conventions for "Segment number" (marker 0x00).
        http://named-data.net/doc/tech-memos/naming-conventions.pdf

        :param int segment: The segment number.
        :return: This name so that you can chain calls to append.
        :rtype: Name
        """
        return self.append(Name.Component.fromSegment(segment))

    def appendSegmentOffset(self, segmentOffset):
        """
        Append a component with the encoded segment byte offset according to NDN
        naming conventions for segment "Byte offset" (marker 0xFB).
        http://named-data.net/doc/tech-memos/naming-conventions.pdf

        :param int segmentOffset: The segment byte offset.
        :return: This name so that you can chain calls to append.
        :rtype: Name
        """
        return self.append(Name.Component.fromSegmentOffset(segmentOffset))

    def appendVersion(self, version):
        """
        Append a component with the encoded version number according to NDN
        naming conventions for "Versioning" (marker 0xFD).
        http://named-data.net/doc/tech-memos/naming-conventions.pdf
        Note that this encodes the exact value of version without converting
        from a time representation.

        :param int version: The version number.
        :return: This name so that you can chain calls to append.
        :rtype: Name
        """
        return self.append(Name.Component.fromVersion(version))

    def appendTimestamp(self, timestamp):
        """
        Append a component with the encoded timestamp according to NDN naming
        conventions for "Timestamp" (marker 0xFC).
        http://named-data.net/doc/tech-memos/naming-conventions.pdf

        :param int timestamp: The number of microseconds since the UNIX epoch
          (Thursday, 1 January 1970) not counting leap seconds.
        :return: This name so that you can chain calls to append.
        :rtype: Name
        """
        return self.append(Name.Component.fromTimestamp(timestamp))

    def appendSequenceNumber(self, sequenceNumber):
        """
        Append a component with the encoded sequence number according to NDN naming
        conventions for "Sequencing" (marker 0xFE).
        http://named-data.net/doc/tech-memos/naming-conventions.pdf

        :param int sequenceNumber: The sequence number.
        :return: This name so that you can chain calls to append.
        :rtype: Name
        """
        return self.append(Name.Component.fromSequenceNumber(sequenceNumber))

    def appendImplicitSha256Digest(self, digest):
        """
        Append a component of type ImplicitSha256DigestComponent, so that
        isImplicitSha256Digest() is true.

        :param digest: The SHA-256 digest value.
        :type digest: Blob or value for Blob constructor
        :return: This name so that you can chain calls to append.
        :rtype: Name
        :raises RuntimeError: If the digest length is not 32 bytes.
        """
        return self.append(Name.Component.fromImplicitSha256Digest(digest))

    def appendParametersSha256Digest(self, digest):
        """
        Append a component of type ParametersSha256DigestComponent, so that
        isParametersSha256Digest() is true.

        :param digest: The SHA-256 digest value.
        :type digest: Blob or value for Blob constructor
        :return: This name so that you can chain calls to append.
        :rtype: Name
        :raises RuntimeError: If the digest length is not 32 bytes.
        """
        return self.append(Name.Component.fromParametersSha256Digest(digest))

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

        # Check from last to first since the last components are more likely to differ.
        for i in range(len(self._components) - 1, -1, -1):
            if not self._components[i].equals(name._components[i]):
                return False

        return True

    def compare(self, iStartComponent, nComponents = None, other = None,
          iOtherStartComponent = None, nOtherComponents = None):
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
        ordering since it is shorter. The first form of compare is simply
        compare(other). The second form is
        compare(iStartComponent, nComponents, other [, iOtherStartComponent] [, nOtherComponents])
        which is equivalent to
        self.getSubName(iStartComponent, nComponents).compare
        (other.getSubName(iOtherStartComponent, nOtherComponents)) .

        :param int iStartComponent: The index if the first component of this
          name to get. If iStartComponent is -N then compare components
          starting from name.size() - N.
        :param int nComponents: The number of components starting at
          iStartComponent. If greater than the size of this name, compare until
          the end of the name.
        :param Name other: The other Name to compare with.
        :param int iOtherStartComponent: (optional) The index if the first
          component of the other name to compare. If iOtherStartComponent is -N
          then compare components starting from other.size() - N. If omitted,
          compare starting from index 0.
        :param int nOtherComponents: (optional) The number of components
          starting at iOtherStartComponent. If omitted or greater than the size
          of this name, compare until the end of the name.
        :return: 0 If they compare equal, -1 if self comes before other in the
          canonical ordering, or 1 if self comes after other in the canonical
          ordering.
        :rtype: int
        :see: http://named-data.net/doc/0.2/technical/CanonicalOrder.html
        """
        if isinstance(iStartComponent, Name):
            # compare(other)
            other = iStartComponent
            iStartComponent = 0
            nComponents = self.size()

        if iOtherStartComponent == None:
            iOtherStartComponent = 0
        if nOtherComponents == None:
            nOtherComponents = other.size()

        if iStartComponent < 0:
            iStartComponent = self.size() - (-iStartComponent)
        if iOtherStartComponent < 0:
            iOtherStartComponent = other.size() - (-iOtherStartComponent)

        nComponents = min(nComponents, self.size() - iStartComponent)
        nOtherComponents = min(nOtherComponents, other.size() - iOtherStartComponent)

        count = min(nComponents, nOtherComponents)
        for i in range(count):
            comparison = self._components[iStartComponent + i].compare(
              other._components[iOtherStartComponent + i])
            if comparison == 0:
                # The components at this index are equal, so check the next
                #   components.
                continue

            # Otherwise, the result is based on the components at this index.
            return comparison

        # The components up to min(self.size(), other.size()) are equal, so the
        #   shorter name is less.
        if nComponents < nOtherComponents:
            return -1
        elif nComponents > nOtherComponents:
            return 1
        else:
            return 0

    def getSuccessor(self):
        """
        Get the successor of this name which is defined as follows.

            N represents the set of NDN Names, and X,Y in N.
            Operator < is defined by the NDN canonical order on N.
            Y is the successor of X, if (a) X < Y, and (b) not exists Z in N
            s.t. X < Z < Y.

        In plain words, the successor of a name is the same name, but with its last
        component advanced to a next possible value.

        Examples:

        - The successor of / is /sha256digest=0000000000000000000000000000000000000000000000000000000000000000
        - The successor of /%00%01/%01%02 is /%00%01/%01%03
        - The successor of /%00%01/%01%FF is /%00%01/%02%00
        - The successor of /%00%01/%FF%FF is /%00%01/%00%00%00

        :return: A new name which is the successor of this.
        :rtype: Name
        """
        if self.size() == 0:
            return Name("/sha256digest=0000000000000000000000000000000000000000000000000000000000000000")
        else:
            return self.getPrefix(-1).append(self.get(-1).getSuccessor())

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

        # Check if at least one of given components doesn't match. Check from
        # last to first since the last components are more likely to differ.
        for i in range(len(self._components) - 1, -1, -1):
            if not self._components[i].getValue().equals(
                  name._components[i].getValue()):
                return False

        return True

    def isPrefixOf(self, name):
        """
        Check if the N components of this name are the same as the first N
        components of the given name.

        :param Name name: The Name to check.
        :return: True if this matches the given name, otherwise False.  This
          always returns True if this name is empty.
        :rtype: bool
        """
        return self.match(name)

    def wireEncode(self, wireFormat = None):
        """
        Encode this Name for a particular wire format.

        :param wireFormat: (optional) A WireFormat object used to encode this
           Name. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        :return: The encoded buffer.
        :rtype: Blob
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        return wireFormat.encodeName(self)

    def wireDecode(self, input, wireFormat = None):
        """
        Decode the input using a particular wire format and update this Name.

        :param input: The array with the bytes to decode.
        :type input: A Blob or an array type with int elements
        :param wireFormat: (optional) A WireFormat object used to decode this
           Name. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        if isinstance(input, Blob):
          # Input is a blob, so get its buf() and set copy False.
          wireFormat.decodeName(self, input.buf(), False)
        else:
          wireFormat.decodeName(self, input, True)

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
        This does not check for a type code prefix such as "sha256digest=".

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
        This does not add a type code prefix such as "sha256digest=".

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
            # Get the component.
            return self._components[key]
        elif type(key) is slice:
            # Call self.getSubName
            if key.step != None and key.step != 1:
                raise ValueError("Name slice only supports a step of 1. Got %d." % key.step)
            if key.start == None:
                start = 0
            else:
                start = (min(key.start, len(self._components)) if key.start >= 0 else
                         max(len(self._components) + key.start, 0))

            if key.stop == None:
                stop = len(self._components)
            else:
                stop =  (min(key.stop, len(self._components)) if key.stop >= 0 else
                         max(len(self._components) + key.stop, 0))

            return self.getSubName(start, stop - start)
        else:
            raise ValueError("Unknown __getitem__ type: %s" % type(key))

    def __eq__(self, other):
        return isinstance(other, Name) and self.equals(other)

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

    def __str__(self):
        return self.toUri()

    def __repr__(self):
        return self.toUri()

    def __hash__(self):
        if self._hashCodeChangeCount != self.getChangeCount():
            # The values have changed, so the previous hash code is invalidated.
            self._hash = None
            self._hashCodeChangeCount = self.getChangeCount()

        if self._hash == None:
            hashCode = 0
            # Use a similar hash code algorithm as String.
            for component in self._components:
                hashCode = 37 * hashCode + hash(component)

            self._hash = hashCode

        return self._hash

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

class ComponentType(object):
    """
    A ComponentType specifies the recognized types of a name component. If the
    component type in the packet is not a recognized enum value, then we use
    ComponentType.OTHER_CODE and you can call Name.Component.getOtherTypeCode().
    We do this to keep the recognized component type values independent of
    packet encoding details.
    """
    IMPLICIT_SHA256_DIGEST = 1
    PARAMETERS_SHA256_DIGEST = 2
    GENERIC                = 8
    OTHER_CODE             = 0x7fff

# Import these at the end of the file to avoid circular references.
from pyndn.encoding.tlv.tlv_encoder import TlvEncoder
from pyndn.encoding.wire_format import WireFormat
from pyndn.util.blob import Blob
from pyndn.util.common import Common

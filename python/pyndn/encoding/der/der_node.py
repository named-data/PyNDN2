# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
# Author: Adeola Bannis <thecodemaiden@gmail.com>
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

import math
from pyndn.encoding.der.der import Der
from pyndn.util.blob import Blob
from pyndn.encoding.der.der_exceptions import NegativeLengthException, DerEncodingException, DerDecodingException

from datetime import datetime

"""
This module defines the implemented DER node types used in encoding/decoding DER formatted data.
"""

class DerNode (object):
    def __init__(self, nodeType):
        """
        Create an untyped DER node. This class should never be instantiated directly: instead, use one of the node classesdefined below.

        :param nodeType: The DER node type
        :type nodeType: An int defined in the Der class
        """
        self._parent = None
        self._nodeType = nodeType
        self._header = bytearray()
        self._payload = bytearray()

    def getSize(self):
        """
        Get the total length of the encoding.
        :return: The total (header + payload) length
        :rtype: int
        """
        return len(self._header) + len(self._payload)

    def _encodeHeader(self, size):
        """
        Encode the given size and update the header.
        :param size: The payload size to encode
        :type size: int
        """
        self._header = bytearray()
        self._header.append(self._nodeType)
        if size < 0:
            raise NegativeLengthException("DER object has negative length")
        elif size <= 127:
            self._header.append(size & 0xff)
        else:
            tempBuf = bytearray()
            n = 0
            val = size
            while val != 0:
                tempBuf.insert(0, (val & 0xff))
                val >>= 8
                n += 1
            tempBuf.insert(0, ((1<<7) |n ) & 0xff)
            self._header.extend(tempBuf)

    def _decodeHeader(self, inputBuf, startIdx=0):
        """
            Extracts the header from an input buffer.
            :param inputBuf: The input buffer to read from.
            :type inputBuf: bytearray or Blob
            :param startIdx: (optional) An offset into the buffer.
            :type startIdx: int
        """

        if isinstance(inputBuf, Blob):
            inputBuf = inputBuf.buf()

        idx = startIdx

        nodeType = inputBuf[idx]
        idx += 1

        self._nodeType = nodeType

        sizeLen = inputBuf[idx]
        idx += 1

        self._header = bytearray([nodeType, sizeLen])

        size = sizeLen
        isLongFormat = sizeLen & (1 << 7)
        if isLongFormat:
            lenCount = sizeLen & ((1<<7) -1)
            size = 0
            while lenCount > 0:
                b = inputBuf[idx]
                idx += 1
                self._header.append(b)
                size = 256*size + int(b)
                lenCount -= 1

        return size

    def encode(self):
        """
        :return: The raw data encoding for this node
        :rtype: Blob
        """
        val = self._header+self._payload
        return Blob(val)

    def decode(self, inputBuf, startIdx=0):
        """
        Decode and store the data from an input buffer.
        :param inputBuf: The input buffer to read from.
        :type inputBuf: bytearray or Blob
        :param startIdx: (optional) An offset into the buffer.
        :type startIdx: int
        """
        if isinstance(inputBuf, Blob):
            inputBuf = inputBuf.buf()

        idx = startIdx
        payloadSize = self._decodeHeader(inputBuf, idx)
        skipBytes = len(self._header)
        if payloadSize > 0:
            idx += skipBytes
            self._payload.extend(inputBuf[idx:idx+payloadSize])

    @staticmethod
    def parse(inputBuf, startIdx=0):
        """
        Parse the data from the input buffer recursively and return the root as a subclass of DerNode.
        :param inputBuf: The input buffer to read from.
        :type inputBuf: bytearray or Blob
        :param startIdx: (optional) An offset into the buffer.
        :type startIdx: int
        """
        if isinstance(inputBuf, Blob):
            inputBuf = inputBuf.buf()

        nodeType = inputBuf[startIdx] # don't increment, we're just peeking

        outputType = None

        if nodeType == Der.Boolean:
            outputType = DerBoolean
        elif nodeType == Der.Integer:
            outputType = DerInteger
        elif nodeType == Der.BitString:
            outputType = DerBitString
        elif nodeType == Der.OctetString:
            outputType = DerOctetString
        elif nodeType == Der.Null:
            outputType = DerNull
        elif nodeType == Der.ObjectIdentifier:
            outputType = DerOid
        elif nodeType == Der.Sequence:
            outputType = DerSequence
        elif nodeType == Der.PrintableString:
            outputType = DerPrintableString
        elif nodeType == Der.GeneralizedTime:
            outputType = DerGeneralizedTime
        else:
            raise DerDecodingException("Unimplemented DER type {}".format(nodeType))

        newNode = outputType()
        newNode.decode(inputBuf, startIdx)
        return newNode

    def toVal(self):
        """
        Convert the encoded data to a standard representation. Overridden by some subclasses (e.g. DerBoolean)
        :return: The encoded data
        :rtype: Blob
        """
        return self.encode()

    def getPayload(self):
        """
        Get a copy of the payload bytes.
        :return: A copy of the payload.
        :rtype: Blob
        """
        return Blob(self._payload, True)

    def getChildren(self):
        """
        If this object is a DerSequence, get the children of this node. Otherwise,
        raise an exception. (DerSequence overrides to implement this method.)
        :return: The children of this node
        :rtype: array of DerNode
        :raises: DerDecodingException if this object is not a DerSequence.
        """
        raise DerDecodingException("getChildren: This DerNode is not DerSequence")

    @staticmethod
    def getSequence(children, index):
        """
        Check that index is in bounds for the children list, and return
        children[index].

        :param children: The list of DerNode, usually returned by another
          call to getChildren.
        :type children: array of DerNode
        :param int index: The index of the children.
        :return: children[index] which is a DerSequence
        :rtype: DerSequence
        :raises: DerDecodingException if index is out of bounds or if
          children[index] is not a DerSequence.
        """
        if index < 0 or index >= len(children):
            raise DerDecodingException("getSequence: Child index is out of bounds")

        if not (type(children[index]) is DerSequence):
            raise DerDecodingException(
              "getSequence: Child DerNode is not a DerSequence")

        return children[index]

class DerStructure(DerNode):
    def __init__(self, nodeType):
       """
       Create a DerNode that can hold other DerNodes. Do not instantiate this directly: instead use a DerSequence.
       :param nodeType: The DER node type
       :type nodeType: An int defined in the Der class
       """
       super(DerStructure, self).__init__(nodeType)
       self._childChanged = False
       self._nodeList = []
       self._size = 0

    def getSize(self):
        """
        Get the total length of the encoding, including children
        :return: The total (header + payload) length
        :rtype: int
        """
        if self._childChanged:
            self.updateSize()
            self._childChanged = False

        self._header = bytearray()
        self._encodeHeader(self._size)
        return self._size + len(self._header)

    def getChildren(self):
        """
        :return: The children of this node
        :rtype: array of DerNode
        """
        return self._nodeList

    def updateSize(self):
        """
            Returns a Blob
        """
        newSize = 0

        for n in self._nodeList:
            newSize += n.getSize()

        self._size = newSize
        self._childChanged = False

    def addChild(self, node, notifyParent=False):
        """
        Add a child to this node.
        :param node: The child node to add.
        :type node: DerNode
        :param notifyParent: (optional) Set to true to cause any containing nodes to update their size
        :type notifyParent: boolean
        """
        node._parent = self
        self._nodeList.append(node)
        if notifyParent:
            if self._parent is not None:
                self._parent.setChildChanged()
        self._childChanged = True

    def setChildChanged(self):
        """
        Mark the child list as dirty, so that we update size when necessary.
        """
        if self._parent is not None:
            self._parent.setChildChanged()
        self._childChanged = True

    def encode(self):
        """
        :return: The raw data encoding for this node and its children
        :rtype: Blob
        """
        temp = bytearray()
        self.updateSize()
        self._header = bytearray()
        self._encodeHeader(self._size)
        temp.extend(self._header)
        for n in self._nodeList:
            encodedChild = n.encode()
            temp.extend(encodedChild.buf())

        return Blob(temp)

    def decode(self, inputBuf, startIdx = 0):
        """
        Decode and store the data from an input buffer. Recursively populates child nodes.
        :param inputBuf: The input buffer to read from.
        :type inputBuf: bytearray or Blob
        :param startIdx: (optional) An offset into the buffer.
        :type startIdx: int
        """

        idx = startIdx
        self._size = self._decodeHeader(inputBuf, idx)
        idx += len(self._header)
        accSize = 0
        while accSize < self._size:
            node = self.parse(inputBuf, idx)
            idx += node.getSize()
            accSize += node.getSize()
            self.addChild(node, False)

########
# Now for all the node types...
########

class DerByteString(DerNode):
    def __init__(self, inputData, nodeType):
        """
        Create a node that handles byte strings. Do not instantiate this type directly: instead use a subclass such as DerOctetString or DerPrintableString.
        :param inputData: An input buffer containing the string to encode.
        :type inputData: Blob or bytearray
        :param nodeType: The specific DER node type.
        :type nodeType: An int defined in the Der class.
        """
        super(DerByteString, self).__init__(nodeType)
        if inputData is not None:
            if isinstance(inputData, Blob):
                inputData = inputData.buf()
            else:
                inputData = bytearray(inputData)
            self._payload.extend(inputData)
            self._encodeHeader(len(self._payload))

    def toVal(self):
        """
        For byte string types, the payload encodes the string directly, so it is used as a representation.
        :return: The encoded string
        :rtype: bytearray
        """
        return self._payload # already a byte string

class DerBoolean(DerNode):
    def __init__(self, val=None):
        """
        Create a DerNode that encodes a boolean value.
        :param val: (optional) The value to encode
        :type val: boolean
        """
        super(DerBoolean, self).__init__(Der.Boolean)
        if val is not None:
            val = 0xff if val else 0x00
            self._payload.append(val)
            self._encodeHeader(len(self._payload))

    def toVal(self):
        val = self._payload[0]
        return val != 0x00

class DerInteger(DerNode):
    def __init__(self, integer=None):
        """
        Create a DerNode that encodes a integer value.
        :param integer: (optional) The value to encode
        :type integer: int
        """
        super(DerInteger, self).__init__(Der.Integer)
        if integer is not None:
            if integer < 0:
              raise DerEncodingException(
                "DerInteger: Negative integers are not currently supported");

            # convert the integer to bytes the easy/slow way
            temp = bytearray()
            while True:
                temp.insert(0, integer & 0xff)
                integer >>= 8

                if integer <= 0:
                  # We check for 0 at the end so we encode one byte if it is 0.
                  break

            if temp[0] >= 0x80:
                # Make it a non-negative integer.
                temp.insert(0, 0)

            self._payload.extend(temp)
            self._encodeHeader(len(self._payload))

    def toVal(self):
        if len(self._payload) > 0 and self._payload[0] >= 0x80:
            raise DerDecodingException(
              "DerInteger: Negative integers are not currently supported")

        result = 0
        for i in range(len(self._payload)):
            result *= 256
            result += self._payload[i]
        return result

class DerBitString(DerNode):
    def __init__(self, inputBuf=None, padding=None):
        """
        Create a DerNode that encodes a bit string value.
        :param inputBuf: (optional) A buffer containing the bits to encode
        :type inputBuf: Blob or bytearray
        :param padding: (optional) The number of bits of padding at the end of the bit string
        :type padding: int < 8
        """
        super(DerBitString, self).__init__(Der.BitString)
        if inputBuf is not None:
            if isinstance(inputBuf, Blob):
                inputBuf = inputBuf.buf()
            self._payload.append(padding)
            self._payload.extend(inputBuf)

            self._encodeHeader(len(self._payload))

class DerOctetString(DerByteString):
    def __init__(self, inputData = None):
        """
        Create a DerNode to encode a string of bytes
        :param inputData: An input buffer containing the string to encode.
        :type inputData: Blob or bytearray
        """
        super(DerOctetString, self).__init__(inputData, Der.OctetString)

class DerNull(DerNode):
    def __init__(self):
        """
        Create a DerNode to encode a null value
        """
        super(DerNull, self).__init__(Der.Null)
        self._encodeHeader(0)

class DerOid(DerNode):
    def __init__(self, oid = None):
        """
        Create a DerNode to encode an object identifier.
        The object identifier string must begin with 0,1, or 2 and must contain at least 2 digits.
        :param oid: The OID to encode
        :type oid: string or OID
        """
        super(DerOid, self).__init__(Der.ObjectIdentifier)
        if oid is not None:
            if type(oid) is str:
                parts = [int(p) for p in oid.split('.')]
                self.prepareEncoding(parts)
            else:
                # Assume oid is of type OID.
                self.prepareEncoding(oid.getIntegerList())

    def prepareEncoding(self, value):
        """
        Encode a sequence of integers into an OID object.
        """
        firstNumber = 0
        if len(value) == 0:
            raise DerEncodingException("No integer in OID")
        else:
            if value[0] >= 0 and value[0] <= 2:
                firstNumber = value[0]*40
            else:
                raise DerEncodingException("First integer in OID is out of range")

        if len(value) >= 2:
            if value[1] >= 0 and value[1] <= 39:
                firstNumber += value[1]
            else:
                raise DerEncodingException("Second integer in OID is out of range")

        encodedStr = self._encode128(firstNumber)

        if len(value) > 2:
            for i in range(2,len(value)):
                encodedStr.extend(self._encode128(value[i]))

        self._encodeHeader(len(encodedStr))
        self._payload.extend(encodedStr)

    def _encode128(self, value):
        """
        Compute the encoding for one part of an OID, where values greater than 128 must be encoded as multiple bytes.
        :param value: A component of an OID
        :type value: int
        """
        mask = (1 << 7) - 1
        outBytes = bytearray()
        if value < 128:
            outBytes.append(value & mask)
        else:
            outBytes.insert(0, value & mask)
            value >>= 7
            while value != 0:
                outBytes.insert(0, (value & mask) | (1 << 7))
                value >>= 7

        return outBytes

    def _decode128(self, offset):
        """
        Convert an encoded component of the OID to the original integer.
        :param offset: The offset into this node's payload
        :type offset: int
        """
        flagMask = 0x80
        result = 0
        oldOffset = offset

        while self._payload[offset] & flagMask:
            result = 128 * result + self._payload[offset]-128
            offset += 1

        result = result * 128 + self._payload[offset]
        return (result, offset-oldOffset+1)

    def toVal(self):
        """
        :return: The string representation of the OID
        :rtype: string
        """
        offset = 0
        components = []
        while offset < len(self._payload):
            nextVal,skip = self._decode128(offset)
            offset += skip
            components.append(nextVal)
        # for some odd reason, the first digits are represented in one byte
        firstByte = components[0]
        firstDigit = int(math.floor(firstByte/40))
        secondDigit = firstByte%40
        components = [firstDigit, secondDigit]+components[1:]
        return '.'.join([str(b) for b in components])



class DerSequence(DerStructure):
    def __init__(self):
        """
        Create a DerNode that contains an ordered sequence of other nodes.
        """
        super(DerSequence, self).__init__(Der.Sequence)


class DerPrintableString(DerByteString):
    def __init__(self, inputData = None):
        """
        Create a DerNode to encode a printable string
        No escaping or other modification is done to the string
        :param inputData: An input buffer containing the string to encode.
        :type inputData: Blob or bytearray
        """
        super(DerPrintableString, self).__init__(inputData, Der.PrintableString)

    def toVal(self):
        """
        :return: The string encoded in the node
        :rtype: string
        """
        return Blob(self._payload, False).toRawStr()

class DerGeneralizedTime(DerNode):
    def __init__(self, msSince1970 = None):
        super(DerGeneralizedTime, self).__init__(Der.GeneralizedTime)
        """
        Create a DerNode representing a date and time, with millisecond accuracy.
        :param msSince1970: (optional) Timestamp as milliseconds since Jan 1, 1970
        :type msSince1970: float
        """
        if msSince1970 is not None:
            derTime = self.toDerTimeString(msSince1970)
            self._payload.extend(bytearray(derTime, 'ascii'))
            self._encodeHeader(len(self._payload))

    @staticmethod
    def toDerTimeString(msSince1970):
        """
        Convert a UNIX timestamp to the internal string representation
        :param msSince1970: Timestamp as milliseconds since Jan 1, 1970
        :type msSince1970: float
        :return: The time string
        :rtype: str
        """
        secondsSince1970 = msSince1970/1000.0
        utcTime = datetime.utcfromtimestamp(secondsSince1970)

        derTime = utcTime.strftime("%Y%m%d%H%M%SZ")
        return derTime

    def toVal(self):
        # return the milliseconds since 1970
        """
        :return: The timestamp encoded in this node as milliseconds since 1970
        :rtype: float
        """
        timeStr = Blob(self._payload, False).toRawStr()
        dt = datetime.strptime(timeStr, "%Y%m%d%H%M%SZ")
        epochStart = datetime(1970, 1,1)
        msSince1970 = (dt-epochStart).total_seconds()*1000

        return msSince1970

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
This module defines the BinaryXmlStructureDecoder class which we include so that
we can recognize and skip Binary XML packets.
"""

from pyndn.util.dynamic_byte_array import DynamicByteArray
from pyndn.encoding.binary_xml_decoder import BinaryXmlDecoder

class BinaryXmlStructureDecoder(object):
    """
    Create and initialize a BinaryXmlStructureDecoder.
    """
    def __init__(self):
        self._gotElementEnd = False
        self._offset = 0
        self._level = 0
        self._state = self.READ_HEADER_OR_CLOSE
        self._headerLength = 0
        self._useHeaderBuffer = False
        # 10 bytes is enough to hold an encoded header with a type and a 64 bit value.
        self._headerBuffer = DynamicByteArray(10)
        self._nBytesToRead = 0

    READ_HEADER_OR_CLOSE = 0
    READ_BYTES = 1
    
    def findElementEnd(self, input):
        """
        Continue scanning input starting from self._offset to find the element 
        end.  If the end of the element which started at offset 0 is found, 
        this returns True and getOffset() is the length of the element.  
        Otherwise, this returns False which means you should read more into 
        input and call again.
        
        :param input: The input buffer. You have to pass in input each time 
          because the buffer could be reallocated.
        :type input: An array type with int elements
        :return: True if found the element end, False if not.
        :rtype: bool
        """
        if self._gotElementEnd:
            # Someone is calling when we already got the end.
            return True

        decoder = BinaryXmlDecoder(input)

        while True:
            if self._offset >= len(input):
                # All the cases assume we have some input.
                return False

            if self._state == BinaryXmlStructureDecoder.READ_HEADER_OR_CLOSE:                             
                # First check for CLOSE.
                if (self._headerLength == 0 and 
                    input[self._offset] == BinaryXmlDecoder.CLOSE):
                    self._offset += 1
                    # Close the level.
                    self._level -= 1
                    if self._level == 0:
                        # Finished.
                        self._gotElementEnd = True
                        return True

                    if self._level < 0:
                        raise RuntimeError(
                  "BinaryXmlStructureDecoder: Unexpected close tag at offset " + 
                          repr(self._offset - 1))

                    # Get ready for the next header.
                    self._startHeader()
                    continue

                startingHeaderLength = self._headerLength
                while True:
                    if self._offset >= len(input):
                        # We can't get all of the header bytes from this input. 
                        # Save in headerBuffer.
                        self._useHeaderBuffer = True
                        nNewBytes = self._headerLength - startingHeaderLength
                        self._headerBuffer.copy(
                          input[self._offset - nNewBytes:self._offset], 
                          startingHeaderLength)

                        return False

                    headerByte = input[self._offset]
                    self._offset += 1
                    self._headerLength += 1
                    if headerByte & BinaryXmlDecoder.TT_FINAL:
                        # Break and read the header.
                        break

                if self._useHeaderBuffer:
                    # Copy the remaining bytes into headerBuffer.
                    nNewBytes = self._headerLength - startingHeaderLength
                    self._headerBuffer.copy(
                      input[self._offset - nNewBytes:self._offset], 
                      startingHeaderLength)

                    (type, value) = BinaryXmlDecoder(
                      self._headerBuffer.getArray()).decodeTypeAndValue()
                else:
                    # We didn't have to use the headerBuffer.
                    decoder.seek(self._offset - self._headerLength)
                    (type, value) = decoder.decodeTypeAndValue()

                # Set the next state based on the type.
                if type == BinaryXmlDecoder.DATTR:
                    # We already consumed the item. READ_HEADER_OR_CLOSE again.
                    # ndnb has rules about what must follow an attribute, but we 
                    # are just scanning.
                    self._startHeader()
                elif (type == BinaryXmlDecoder.DTAG or 
                      type == BinaryXmlDecoder.EXT):
                    # Start a new level and READ_HEADER_OR_CLOSE again.
                    self._level += 1
                    self._startHeader()
                elif (type == BinaryXmlDecoder.TAG or 
                      type == BinaryXmlDecoder.ATTR):
                    if type == BinaryXmlDecoder.TAG:
                        # Start a new level and read the tag.
                        self._level += 1
                    # Minimum tag or attribute length is 1.
                    self._nBytesToRead = value + 1
                    self._state = BinaryXmlStructureDecoder.READ_BYTES
                    # ndnb has rules about what must follow an attribute, but we 
                    # are just scanning.
                elif (type == BinaryXmlDecoder.BLOB or
                      type == BinaryXmlDecoder.UDATA):
                    self._nBytesToRead = value
                    self._state = BinaryXmlStructureDecoder.READ_BYTES
                else:
                    raise RuntimeError(
                      "BinaryXmlStructureDecoder: Unrecognized header type " + 
                      repr(type))
            elif self._state == BinaryXmlStructureDecoder.READ_BYTES:
                nRemainingBytes = len(input) - self._offset
                if nRemainingBytes < self._nBytesToRead:
                    # Need more.
                    self._offset += nRemainingBytes
                    self._nBytesToRead -= nRemainingBytes
                    return False

                # Got the bytes. Read a new header or close.
                self._offset += self._nBytesToRead
                self._startHeader()
            else:
                # We don't expect this to happen.
                raise RuntimeError(
                  "BinaryXmlStructureDecoder: Unrecognized state " + 
                  repr(self._state))
    
    def getOffset(self):
        """
        Get the current offset into the input buffer.
        
        :return: The offset.
        :rtype: int
        """
        return self._offset
    
    def seek(self, offset):
        """
        Set the offset into the input, used for the next read.
        
        :param int offset: The new offset.
        """
        self._offset = offset
        
    def _startHeader(self):
        """
        A private method to set the state to READ_HEADER_OR_CLOSE and set up to 
        start reading the header.
        """
        self._headerLength = 0
        self._useHeaderBuffer = False
        self._state = BinaryXmlStructureDecoder.READ_HEADER_OR_CLOSE
        
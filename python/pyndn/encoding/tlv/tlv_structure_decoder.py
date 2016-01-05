# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
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
This module defines the TlvStructureDecoder class.
"""

from pyndn.encoding.tlv.tlv_decoder import TlvDecoder

class TlvStructureDecoder(object):
    """
    Create and initialize a TlvStructureDecoder.
    """
    def __init__(self):
        self._gotElementEnd = False
        self._offset = 0
        self._state = self.READ_TYPE
        self._headerLength = 0
        self._useHeaderBuffer = False
        # 8 bytes is enough to hold the extended bytes in the length encoding
        # where it is an 8-byte number.
        self._headerBuffer = bytearray(8)
        self._nBytesToRead = 0

    READ_TYPE =         0
    READ_TYPE_BYTES =   1
    READ_LENGTH =       2
    READ_LENGTH_BYTES = 3
    READ_VALUE_BYTES =  4

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

        decoder = TlvDecoder(input)

        while True:
            if self._offset >= len(input):
                # All the cases assume we have some input. Return and wait
                #   for more.
                return False

            if self._state == self.READ_TYPE:
                firstOctet = input[self._offset]
                self._offset += 1
                if firstOctet < 253:
                    # The value is simple, so we can skip straight to reading
                    #   the length.
                    self._state = self.READ_LENGTH
                else:
                    # Set up to skip the type bytes.
                    if firstOctet == 253:
                        self._nBytesToRead = 2
                    elif firstOctet == 254:
                        self._nBytesToRead = 4
                    else:
                        # value == 255.
                        self._nBytesToRead = 8

                    self._state = self.READ_TYPE_BYTES
            elif self._state == self.READ_TYPE_BYTES:
                nRemainingBytes = len(input) - self._offset
                if nRemainingBytes < self._nBytesToRead:
                    # Need more.
                    self._offset += nRemainingBytes
                    self._nBytesToRead -= nRemainingBytes
                    return False

                # Got the type bytes. Move on to read the length.
                self._offset += self._nBytesToRead
                self._state = self.READ_LENGTH
            elif self._state == self.READ_LENGTH:
                firstOctet = input[self._offset]
                self._offset += 1
                if firstOctet < 253:
                    # The value is simple, so we can skip straight to reading
                    #  the value bytes.
                    self._nBytesToRead = firstOctet
                    if self._nBytesToRead == 0:
                        # No value bytes to read. We're finished.
                        self._gotElementEnd = True
                        return True

                    self._state = self.READ_VALUE_BYTES
                else:
                    # We need to read the bytes in the extended encoding of
                    #  the length.
                    if firstOctet == 253:
                        self._nBytesToRead = 2
                    elif firstOctet == 254:
                        self._nBytesToRead = 4
                    else:
                        # value == 255.
                        self._nBytesToRead = 8

                    # We need to use firstOctet in the next state.
                    self._firstOctet = firstOctet
                    self._state = self.READ_LENGTH_BYTES
            elif self._state == self.READ_LENGTH_BYTES:
                nRemainingBytes = len(input) - self._offset
                if (not self._useHeaderBuffer and
                    nRemainingBytes >= self._nBytesToRead):
                    # We don't have to use the headerBuffer. Set nBytesToRead.
                    decoder.seek(self._offset)

                    self._nBytesToRead = decoder.readExtendedVarNumber(
                      self._firstOctet)
                    # Update self._offset to the decoder's offset after reading.
                    self._offset = decoder.getOffset()
                else:
                    self._useHeaderBuffer = True

                    nNeededBytes = self._nBytesToRead - self._headerLength
                    if nNeededBytes > nRemainingBytes:
                        # We can't get all of the header bytes from this input.
                        # Save in headerBuffer.
                        if (self._headerLength + nRemainingBytes >
                              len(self._headerBuffer)):
                            # We don't expect this to happen.
                            raise RuntimeError(
                 "Cannot store more header bytes than the size of headerBuffer")
                        self._headerBuffer[
                          self._headerLength:self._headerLength + nRemainingBytes] = \
                          input[self._offset:self._offset + nRemainingBytes]
                        self._offset += nRemainingBytes
                        self._headerLength += nRemainingBytes

                        return False

                    # Copy the remaining bytes into headerBuffer, read the
                    #   length and set nBytesToRead.
                    if (self._headerLength + nNeededBytes >
                          len(self._headerBuffer)):
                        # We don't expect this to happen.
                        raise RuntimeError(
                 "Cannot store more header bytes than the size of headerBuffer")
                    self._headerBuffer[
                      self._headerLength:self._headerLength + nNeededBytes] = \
                      input[self._offset:self._offset + nNeededBytes]
                    self._offset += nNeededBytes

                    # Use a local decoder just for the headerBuffer.
                    bufferDecoder = TlvDecoder(self._headerBuffer)
                    # Replace nBytesToRead with the length of the value.
                    self._nBytesToRead = bufferDecoder.readExtendedVarNumber(
                      self._firstOctet)

                if self._nBytesToRead == 0:
                    # No value bytes to read. We're finished.
                    self._gotElementEnd = True
                    return True

                # Get ready to read the value bytes.
                self._state = self.READ_VALUE_BYTES
            elif self._state == self.READ_VALUE_BYTES:
                nRemainingBytes = len(input) - self._offset
                if nRemainingBytes < self._nBytesToRead:
                    # Need more.
                    self._offset += nRemainingBytes
                    self._nBytesToRead -= nRemainingBytes
                    return False

                # Got the bytes. We're finished.
                self._offset += self._nBytesToRead
                self._gotElementEnd = True
                return True
            else:
                # We don't expect this to happen.
                raise RuntimeError("findElementEnd: unrecognized state")

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

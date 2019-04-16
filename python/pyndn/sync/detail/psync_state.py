# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From the PSync library https://github.com/named-data/PSync/blob/master/PSync/detail/state.hpp
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
This module defines the PSyncState class which represents a sequence of Names as
the state of PSync. It has methods to encode and decode for the wire.
"""

from pyndn.name import Name
from pyndn.encoding.tlv.tlv_encoder import TlvEncoder
from pyndn.encoding.tlv.tlv_decoder import TlvDecoder
from pyndn.encoding.tlv_0_2_wire_format import Tlv0_2WireFormat
from pyndn.util.blob import Blob

class PSyncState(object):
    """
    Create a PSyncState and optionally decode the input as an NDN-TLV PSyncContent.

    :param input: (optional) If supplied, input is the array with the bytes to
      decode. If omitted, create a PSyncState with empty content.
    :type input: Blob or an array type with int elements
    """
    def __init__(self, input = None):
        self._content = []
        if input != None:
            self.wireDecode(input)

    def addContent(self, name):
        """
        Append the name to the content.

        :param Name name: The Name to add, which is copied.
        """
        self._content.append(Name(name))

    def getContent(self):
        """
        Get the sequence of Names in the content.

        :return: The array of Names, which you should not modify.
        :rtype: Array<Name>
        """
        return self._content

    def clear(self):
        """
        Remove the content.
        """
        self._content = []

    def wireEncode(self):
        """
        Encode this as an NDN-TLV PSyncContent.

        :return: The encoding as a Blob.
        :rtype: Blob
        """
        # Encode directly as TLV. We don't support the WireFormat abstraction
        # because this isn't meant to go directly on the wire.
        encoder = TlvEncoder(256)
        saveLength = len(encoder)

        # Encode backwards.
        for i in range(len(self._content) - 1, -1, -1):
            Tlv0_2WireFormat._encodeName(self._content[i], encoder)

        encoder.writeTypeAndLength(
          PSyncState.Tlv_PSyncContent, len(encoder) - saveLength)

        return Blob(encoder.getOutput(), False)

    def wireDecode(self, input):
        """
        Decode the input as an NDN-TLV PSyncContent and update this object.

        :param input: The array with the bytes to decode.
        :type input: Blob or an array type with int elements
        """
        # If input is a blob, get its buf().
        decodeBuffer = input.buf() if isinstance(input, Blob) else input

        self.clear()

        # Decode directly as TLV. We don't support the WireFormat abstraction
        # because this isn't meant to go directly on the wire.
        decoder = TlvDecoder(decodeBuffer)
        endOffset = decoder.readNestedTlvsStart(PSyncState.Tlv_PSyncContent)

        # Decode a sequence of Name.
        while decoder.getOffset() < len(decodeBuffer):
            name = Name()
            Tlv0_2WireFormat._decodeName(name, decoder, True)
            self._content.append(name)

        decoder.finishNestedTlvs(endOffset)

    def toString(self):
        """
        Get the string representation of this PSyncState.

        :return: The string representation.
        :rtype: str
        """
        result = "["

        for i in range(len(self._content)):
            result += self._content[i].toUri()
            if i < len(self._content) - 1:
                result += ", "

        result += "]"

        return result

    Tlv_PSyncContent = 128

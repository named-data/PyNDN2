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
This module defines the ProtobufTlv class which has static methods to encode and
decode an Protobuf Message object as NDN-TLV. The Protobuf tag value is used as
the TLV type code. A Protobuf message is encoded/decoded as a nested TLV
encoding. Protobuf types uint32, uint64 and enum are encoded/decoded as TLV
nonNegativeInteger. (It is an error if an enum value is negative.) Protobuf
types bytes and string are encoded/decoded as TLV bytes. The Protobuf type bool
is encoded/decoded as a TLV boolean (a zero length value for True, omitted for
False). Other Protobuf types are an error.

Protobuf has no "outer" message type, so you need to put your TLV message
inside an outer "typeless" message.
"""

import sys
from pyndn.encoding.tlv.tlv_encoder import TlvEncoder
from pyndn.encoding.tlv.tlv_decoder import TlvDecoder
from pyndn.util.blob import Blob
from pyndn.util.common import Common

class ProtobufTlv(object):
    @staticmethod
    def encode(message):
        """
        Encode the Protobuf message object as NDN-TLV.

        :param google.protobuf.message message: The Protobuf message object.
          This calls message.IsInitialized() to ensure that all required fields
          are present and raises an exception if not.
        :return: The encoded buffer in a Blob object.
        :rtype: Blob
        """
        if not message.IsInitialized():
            raise RuntimeError("message is not initialized")
        encoder = TlvEncoder(256)

        ProtobufTlv._encodeMessageValue(message, encoder)
        return Blob(encoder.getOutput(), False)

    @staticmethod
    def decode(message, input):
        """
        Decode the input as NDN-TLV and update the fields of the Protobuf
        message object.

        :param google.protobuf.message message: The Protobuf message object.
          This does not first clear the object.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        """
        # If input is a blob, get its buf().
        decodeBuffer = input.buf() if isinstance(input, Blob) else input
        decoder = TlvDecoder(decodeBuffer)
        ProtobufTlv._decodeMessageValue(message, decoder, len(input))

    @staticmethod
    def _encodeMessageValue(message, encoder):
        # Note: We can't use ListFields because it sorts by field number.
        descriptor = message.DESCRIPTOR
        # Reverse so that we encode backwards.
        for field in reversed(descriptor.fields):
            tlvType = field.number

            if field.label == field.LABEL_REPEATED:
                # Reverse so that we encode backwards.
                values = reversed(getattr(message, field.name))
            else:
                if message.HasField(field.name):
                    # Make a singleton list.
                    values = [getattr(message, field.name)]
                else:
                    continue

            for value in values:
                if field.type == field.TYPE_MESSAGE:
                    saveLength = len(encoder)

                    # Encode backwards.
                    ProtobufTlv._encodeMessageValue(value, encoder)
                    encoder.writeTypeAndLength(
                      tlvType, len(encoder) - saveLength)
                elif (field.type == field.TYPE_UINT32 or
                      field.type == field.TYPE_UINT64):
                    encoder.writeNonNegativeIntegerTlv(tlvType, value)
                elif (field.type == field.TYPE_ENUM):
                    if value < 0:
                        raise RuntimeError(
                          "ProtobufTlv::encode: ENUM value may not be negative")
                    encoder.writeNonNegativeIntegerTlv(tlvType, value)
                elif (field.type == field.TYPE_BYTES or
                      field.type == field.TYPE_STRING):
                    encoder.writeBlobTlv(tlvType, Common.stringToUtf8Array(value))
                elif field.type == field.TYPE_BOOL:
                    if value:
                        encoder.writeTypeAndLength(tlvType, 0)
                else:
                    raise RuntimeError("ProtobufTlv::encode: Unknown field type")

    @staticmethod
    def _decodeMessageValue(message, decoder, endOffset):
        descriptor = message.DESCRIPTOR

        for field in descriptor.fields:
            tlvType = field.number

            if (field.label == field.LABEL_OPTIONAL and
                not decoder.peekType(tlvType, endOffset)):
                continue

            if field.label == field.LABEL_REPEATED:
                while decoder.peekType(tlvType, endOffset):
                    if field.type == field.TYPE_MESSAGE:
                        innerEndOffset = decoder.readNestedTlvsStart(tlvType)
                        ProtobufTlv._decodeMessageValue(
                          getattr(message, field.name).add(), decoder, innerEndOffset)
                        decoder.finishNestedTlvs(innerEndOffset)
                    else:
                        getattr(message, field.name).append(
                          ProtobufTlv._decodeFieldValue(
                            field, tlvType, decoder, endOffset))
            else:
                if field.type == field.TYPE_MESSAGE:
                    innerEndOffset = decoder.readNestedTlvsStart(tlvType)
                    ProtobufTlv._decodeMessageValue(
                      getattr(message, field.name), decoder, innerEndOffset)
                    decoder.finishNestedTlvs(innerEndOffset)
                else:
                    setattr(
                      message, field.name,
                      ProtobufTlv._decodeFieldValue(
                        field, tlvType, decoder, endOffset))

    @staticmethod
    def _decodeFieldValue(field, tlvType, decoder, endOffset):
        """
        This is a helper for _decodeMessageValue.
        Decode a single field and return the value. Assume the field.type is
        not field.TYPE_MESSAGE.
        """
        if (field.type == field.TYPE_UINT32 or
              field.type == field.TYPE_UINT64 or
              field.type == field.TYPE_ENUM):
            return decoder.readNonNegativeIntegerTlv(tlvType)
        elif field.type == field.TYPE_BYTES:
            if sys.version_info[0] > 2:
                # Return a real bytes type.
                return bytes(decoder.readBlobTlv(tlvType))
            else:
                # For Python 2, just return the raw string.
                return "".join(map(chr, decoder.readBlobTlv(tlvType)))
        elif field.type == field.TYPE_STRING:
            return "".join(map(chr, decoder.readBlobTlv(tlvType)))
        elif field.type == field.TYPE_BOOL:
            return decoder.readBooleanTlv(tlvType, endOffset)
        else:
            raise RuntimeError("ProtobufTlv.decode: Unknown field type")

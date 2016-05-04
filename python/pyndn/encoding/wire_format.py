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
This module defines the WireFormat class which is an abstract base class for
encoding and decoding Interest, Data, etc. with a specific wire format.
You should use a derived class such as TlvWireFormat.
"""

class WireFormat(object):
    _defaultWireFormat = None

    def encodeName(self, name):
        """
        Encode name and return the encoding.  Your derived class should
        override.

        :param Name name: The Name object to encode.
        :return: A Blob containing the encoding.
        :rtype: Blob
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("encodeName is not implemented")

    def decodeName(self, name, input):
        """
        Decode input as a name and set the fields of the Name object.
        Your derived class should override.

        :param Name name: The Name object whose fields are updated.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("decodeName is not implemented")

    def encodeInterest(self, interest):
        """
        Encode interest and return the encoding.  Your derived class should
        override.

        :param Interest interest: The Interest object to encode.
        :return: A Tuple of (encoding, signedPortionBeginOffset,
          signedPortionEndOffset) where encoding is a Blob containing the
          encoding, signedPortionBeginOffset is the offset in the encoding of
          the beginning of the signed portion, and signedPortionEndOffset is
          the offset in the encoding of the end of the signed portion. The
          signed portion starts from the first name component and ends just
          before the final name component (which is assumed to be a signature
          for a signed interest).
        :rtype: (Blob, int, int)
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("encodeInterest is not implemented")

    def decodeInterest(self, interest, input):
        """
        Decode input as an interest and set the fields of the interest object.
        Your derived class should override.

        :param Interest interest: The Interest object whose fields are updated.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :return: A Tuple of (signedPortionBeginOffset, signedPortionEndOffset)
          where signedPortionBeginOffset is the offset in the encoding of
          the beginning of the signed portion, and signedPortionEndOffset is
          the offset in the encoding of the end of the signed portion. The
          signed portion starts from the first name component and ends just
          before the final name component (which is assumed to be a signature
          for a signed interest).
        :rtype: (int, int)
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("decodeInterest is not implemented")

    def encodeData(self, data):
        """
        Encode data and return the encoding and signed offsets.  Your derived
        class should override.

        :param Data data: The Data object to encode.
        :return: A Tuple of (encoding, signedPortionBeginOffset,
          signedPortionEndOffset) where encoding is a Blob containing the
          encoding, signedPortionBeginOffset is the offset in the encoding of
          the beginning of the signed portion, and signedPortionEndOffset is
          the offset in the encoding of the end of the signed portion.
        :rtype: (Blob, int, int)
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("encodeData is not implemented")

    def decodeData(self, data, input):
        """
        Decode input as a data packet, set the fields in the data object, and
        return the signed offsets.  Your derived class should override.

        :param Data data: The Data object whose fields are updated.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :return: A Tuple of (signedPortionBeginOffset, signedPortionEndOffset)
          where signedPortionBeginOffset is the offset in the encoding of
          the beginning of the signed portion, and signedPortionEndOffset is
          the offset in the encoding of the end of the signed portion.
        :rtype: (int, int)
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("decodeData is not implemented")

    def encodeControlParameters(self, controlParameters):
        """
        Encode controlParameters and return the encoding.  Your derived class
        should override.

        :param ControlParameters controlParameters: The ControlParameters object
          to encode.
        :return: A Blob containing the encoding.
        :rtype: Blob
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("encodeControlParameters is not implemented")

    def decodeControlParameters(self, controlParameters, input):
        """
        Decode input as a controlParameters and set the fields of the
        controlParameters object. Your derived class should override.

        :param ControlParameters controlParameters: The ControlParameters object
          whose fields are updated.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("decodeControlParameters is not implemented")

    def encodeControlResponse(self, controlResponse):
        """
        Encode controlResponse and return the encoding.  Your derived class
        should override.

        :param ControlResponse controlResponse: The ControlResponse object
          to encode.
        :return: A Blob containing the encoding.
        :rtype: Blob
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("encodeControlResponse is not implemented")

    def decodeControlResponse(self, controlResponse, input):
        """
        Decode input as a controlResponse and set the fields of the
        controlResponse object. Your derived class should override.

        :param ControlResponse controlResponse: The ControlResponse object
          whose fields are updated.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("decodeControlResponse is not implemented")

    def encodeSignatureInfo(self, signature):
        """
        Encode signature as a SignatureInfo and return the encoding.
        Your derived class should override.

        :param signature: An object of a subclass of Signature to encode.
        :type signature: An object of a subclass of Signature
        :return: A Blob containing the encoding.
        :rtype: Blob
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("encodeSignatureInfo is not implemented")

    def decodeSignatureInfoAndValue(self, signatureInfo, signatureValue):
        """
        Decode signatureInfo as a signature info and signatureValue as the
        related SignatureValue, and return a new object which is a subclass of
        Signature. Your derived class should override.

        :param signatureInfo: The array with the signature info input buffer to
          decode.
        :type signatureInfo: An array type with int elements
        :param signatureValue: The array with the signature value input buffer
          to decode.
        :type signatureValue: An array type with int elements
        :return: A new object which is a subclass of Signature.
        :rtype: a subclass of Signature
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("decodeSignatureInfoAndValue is not implemented")

    def encodeSignatureValue(self, signature):
        """
        Encode the signatureValue in the Signature object as a SignatureValue
        (the signature bits) and return the encoding.
        Your derived class should override.

        :param signature: An object of a subclass of Signature with the
          signature value to encode.
        :type signature: An object of a subclass of Signature
        :return: A Blob containing the encoding.
        :rtype: Blob
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("encodeSignatureInfo is not implemented")

    def decodeLpPacket(self, lpPacket, input):
        """
        Decode input as an LpPacket and set the fields of the lpPacket object.
        Your derived class should override.

        :param LpPacket lpPacket: The LpPacket object whose fields are updated.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("decodeLpPacket is not implemented")

    def encodeDelegationSet(self, delegationSet):
        """
        Encode the DelegationSet and return the encoding.
        Your derived class should override.

        :param DelegationSet delegationSet: The DelegationSet object to
          encode.
        :return: A Blob containing the encoding.
        :rtype: Blob
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("encodeDelegationSet is not implemented")

    def decodeDelegationSet(self, delegationSet, input):
        """
        Decode input as a DelegationSet and set the fields of the delegationSet
        object.
        Your derived class should override.

        :param DelegationSet delegationSet: The DelegationSet object
          whose fields are updated.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("decodeDelegationSet is not implemented")

    def encodeEncryptedContent(self, encryptedContent):
        """
        Encode the EncryptedContent and return the encoding.
        Your derived class should override.

        :param EncryptedContent encryptedContent: The EncryptedContent object to
          encode.
        :return: A Blob containing the encoding.
        :rtype: Blob
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("encodeEncryptedContent is not implemented")

    def decodeEncryptedContent(self, encryptedContent, input):
        """
        Decode input as an EncryptedContent and set the fields of the
        encryptedContent object.
        Your derived class should override.

        :param EncryptedContent encryptedContent: The EncryptedContent object
          whose fields are updated.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("decodeEncryptedContent is not implemented")

    @classmethod
    def setDefaultWireFormat(self, wireFormat):
        """
        Set the static default WireFormat used by default encoding and decoding
        methods.

        :param wireFormat: An object of a subclass of WireFormat.
        :type wireFormat: A subclass of WireFormat
        """
        self._defaultWireFormat = wireFormat

    @classmethod
    def getDefaultWireFormat(self):
        """
        Return the default WireFormat used by default encoding and decoding
        methods which was set with setDefaultWireFormat.

        :return: The WireFormat object.
        :rtype: A subclass of WireFormat.
        """
        return self._defaultWireFormat




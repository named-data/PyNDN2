# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

from pyndn.util import Blob
from wire_format import WireFormat
from tlv_encoder import TlvEncoder
from tlv_decoder import TlvDecoder
from tlv import Tlv

"""
This module defines the Tlv0_1a2WireFormat class which extends WireFormat to
override its methods to implment encoding and decoding Interest, Data, etc. 
with the NDN-TLV wire format, version 0.1a2.
"""

class Tlv0_1a2WireFormat(WireFormat):
    def encodeInterest(self, interest):
        """
        Encode interest in NDN-TLV and return the encoding.

        :param interest: The Interest object to encode.
        :type interest: Interest
        :return: A Blob containing the encoding.
        :rtype: Blob
        """
        encoder = TlvEncoder(256)
        self.encodeName(interest.getName(), encoder)
        return Blob(encoder.getOutput())

    def decodeInterest(self, interest, input):
        """
        Decode input as an NDN-TLV interest and set the fields of the interest 
        object.  
        
        :param interest: The Interest object whose fields are updated.
        :type interest: Interest
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements.
        """
        decoder = TlvDecoder(input)
        self.decodeName(interest.getName(), decoder)
        
    @staticmethod
    def encodeName(name, encoder):
        saveLength = len(encoder)
        
        # Encode the components backwards.
        for i in range(len(name) - 1, -1, -1):
            encoder.writeBlobTlv(Tlv.NameComponent, name[i]._value)
    
        encoder.writeTypeAndLength(Tlv.Name, len(encoder) - saveLength)

    @staticmethod
    def decodeName(name, decoder):
        endOffset = decoder.readNestedTlvsStart(Tlv.Name)
        
        while decoder._offset < endOffset:
            # TODO: Use Blob constructor with copy True.
            name.append(decoder.readBlobTlv(Tlv.NameComponent))
   
        decoder.finishNestedTlvs(endOffset)

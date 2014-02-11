# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

from random import SystemRandom
from pyndn.meta_info import ContentType
from pyndn.util import Blob
from pyndn.encoding.wire_format import WireFormat
from pyndn.encoding.tlv_encoder import TlvEncoder
from pyndn.encoding.tlv_decoder import TlvDecoder
from pyndn.encoding.tlv import Tlv

# The Python documentation says "Use SystemRandom if you require a 
#   cryptographically secure pseudo-random number generator."
# http://docs.python.org/2/library/random.html
_systemRandom = SystemRandom()

"""
This module defines the Tlv0_1a2WireFormat class which extends WireFormat to
override its methods to implment encoding and decoding Interest, Data, etc. 
with the NDN-TLV wire format, version 0.1a2.
"""

class Tlv0_1a2WireFormat(WireFormat):
    _instance = None
    
    def encodeInterest(self, interest):
        """
        Encode interest in NDN-TLV and return the encoding.

        :param interest: The Interest object to encode.
        :type interest: Interest
        :return: A Blob containing the encoding.
        :rtype: Blob
        """
        encoder = TlvEncoder(256)
        saveLength = len(encoder)
        
        # Encode backwards.
        encoder.writeOptionalNonNegativeIntegerTlvFromFloat(
          Tlv.InterestLifetime, interest.getInterestLifetimeMilliseconds())
        encoder.writeOptionalNonNegativeIntegerTlv(
          Tlv.Scope, interest.getScope())
        
        # Encode the Nonce as 4 bytes.
        if interest.getNonce().size() == 0:
            # This is the most common case. Generate a nonce.
            nonce = bytearray(4)
            for i in range(4):
                nonce[i] = _systemRandom.randint(0, 0xff)                
            encoder.writeBlobTlv(Tlv.Nonce, nonce)
        elif interest.getNonce().size() < 4:
            nonce = bytearray(4)
            if interest.getNonce().size() > 0:
                # Copy existing nonce bytes.
                nonce[:interest.getNonce().size()] = interest.getNonce().buf()
            
            # Generate random bytes for remainig bytes in the nonce.
            for i in range(interest.getNonce().size(), 4):
                nonce[i] = _systemRandom.randint(0, 0xff)
                
            encoder.writeBlobTlv(Tlv.Nonce, nonce)
        elif interest.getNonce().size() == 4:
            # Use the nonce as-is.
            encoder.writeBlobTlv(Tlv.Nonce, interest.getNonce().buf())
        else:
            # Truncate.
            encoder.writeBlobTlv(Tlv.Nonce, interest.getNonce().buf()[:4])
        
        # TODO: implement Selectors
        self._encodeName(interest.getName(), encoder)

        encoder.writeTypeAndLength(Tlv.Interest, len(encoder) - saveLength)
        
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

        endOffset = decoder.readNestedTlvsStart(Tlv.Interest)
        self._decodeName(interest.getName(), decoder)
        # TODO: implement Selectors

        # Require a Nonce, but don't force it to be 4 bytes.
        nonce = Blob(decoder.readBlobTlv(Tlv.Nonce))
        interest.setScope(decoder.readOptionalNonNegativeIntegerTlv(
          Tlv.Scope, endOffset))
        interest.setInterestLifetimeMilliseconds(
           decoder.readOptionalNonNegativeIntegerTlvAsFloat
           (Tlv.InterestLifetime, endOffset))

        # Set the nonce last because setting other interest fields clears it.
        interest.setNonce(nonce)

        decoder.finishNestedTlvs(endOffset)
        
    def encodeData(self, data):
        """
        Encode data in NDN-TLV and return the encoding and signed offsets.

        :param data: The Data object to encode.
        :type data: Data
        :return: A Tuple of (encoding, signedPortionBeginOffset,
          signedPortionEndOffset) where encoding is a Blob containing the
          encoding, signedPortionBeginOffset is the offset in the encoding of 
          the beginning of the signed portion, and signedPortionEndOffset is
          the offset in the encoding of the end of the signed portion.
        :rtype: (Blob, int, int)
        """
        encoder = TlvEncoder(1500)
        saveLength = len(encoder)
        
        # Encode backwards.
        # TODO: Encode signature bytes.
        signedPortionEndOffsetFromBack = len(encoder)
        # TODO: encodeSignatureSha256WithRsa.
        encoder.writeBlobTlv(Tlv.Content, data.getContent().buf())
        self._encodeMetaInfo(data.getMetaInfo(), encoder)
        self._encodeName(data.getName(), encoder)
        signedPortionBeginOffsetFromBack = len(encoder)

        encoder.writeTypeAndLength(Tlv.Data, len(encoder) - saveLength)
        signedPortionBeginOffset = (len(encoder) - 
                                    signedPortionBeginOffsetFromBack)
        signedPortionEndOffset = len(encoder) - signedPortionEndOffsetFromBack
        
        return (Blob(encoder.getOutput()), signedPortionBeginOffset, 
                signedPortionEndOffset)
        
    def decodeData(self, data, input):
        """
        Decode input as an NDN-TLV data packet, set the fields in the data 
        object, and return the signed offsets.  

        :param data: The Data object whose fields are updated.
        :type data: Data
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements.
        :return: A Tuple of (signedPortionBeginOffset, signedPortionEndOffset) 
          where signedPortionBeginOffset is the offset in the encoding of 
          the beginning of the signed portion, and signedPortionEndOffset is
          the offset in the encoding of the end of the signed portion.
        :rtype: (int, int)
        """
        decoder = TlvDecoder(input)

        endOffset = decoder.readNestedTlvsStart(Tlv.Data)
        signedPortionBeginOffset = decoder._offset
        
        self._decodeName(data.getName(), decoder)
        self._decodeMetaInfo(data.getMetaInfo(), decoder)
        data.setContent(Blob(decoder.readBlobTlv(Tlv.Content)))
        # TODO: decodeSignatureInfo.
        signedPortionEndOffset = decoder._offset
        # TODO: Decode signature bits.

        # TODO: Restore
        #decoder.finishNestedTlvs(endOffset)
        return (signedPortionBeginOffset, signedPortionEndOffset)
    
    @classmethod
    def get(self):
        """
        Get a singleton instance of a Tlv1_0a2WireFormat.  To always use the 
        preferred version NDN-TLV, you should use TlvWireFormat.get().
        
        :return: The singleton instance.
        :rtype: Tlv1_0a2WireFormat
        """
        if self._instance == None:
            self._instance = Tlv1_0a2WireFormat()
        return self._instance
        
    @staticmethod
    def _encodeName(name, encoder):
        saveLength = len(encoder)
        
        # Encode the components backwards.
        for i in range(len(name) - 1, -1, -1):
            encoder.writeBlobTlv(Tlv.NameComponent, name[i]._value.buf())
    
        encoder.writeTypeAndLength(Tlv.Name, len(encoder) - saveLength)

    @staticmethod
    def _decodeName(name, decoder):
        endOffset = decoder.readNestedTlvsStart(Tlv.Name)        
        while decoder._offset < endOffset:
            name.append(decoder.readBlobTlv(Tlv.NameComponent))
   
        decoder.finishNestedTlvs(endOffset)

    @staticmethod
    def _encodeMetaInfo(metaInfo, encoder):
        saveLength = len(encoder)
        
        # Encode backwards.
        encoder.writeOptionalNonNegativeIntegerTlvFromFloat(
          Tlv.FreshnessPeriod, metaInfo.getFreshnessPeriod())
        if not metaInfo.getType() == ContentType.BLOB:
            # Not the default, so we need to encode the type.
            if (metaInfo.getType() == ContentType.LINK or
                  metaInfo.getType() == ContentType.KEY):
                # The ContentType enum is set up with the correct integer for 
                # each NDN-TLV ContentType.
                encoder.writeNonNegativeIntegerTlv(
                  Tlv.Content_Type, metaInfo.getType())
            else:
                raise RuntimeError("unrecognized TLV ContentType")
    
        encoder.writeTypeAndLength(Tlv.MetaInfo, len(encoder) - saveLength)

    @staticmethod
    def _decodeMetaInfo(metaInfo, decoder):
        endOffset = decoder.readNestedTlvsStart(Tlv.MetaInfo)        

        # The ContentType enum is set up with the correct integer for each 
        # NDN-TLV ContentType.  If readOptionalNonNegativeIntegerTlv returns
        # None, then setType will convert it to BLOB.
        metaInfo.setType(decoder.readOptionalNonNegativeIntegerTlv(
          Tlv.Content_Type, endOffset))
        metaInfo.setFreshnessPeriod(
          decoder.readOptionalNonNegativeIntegerTlvAsFloat(
            Tlv.FreshnessPeriod, endOffset))
        
        # TODO: Implement MetaInfo.
        #decoder.finishNestedTlvs(endOffset)
        decoder.seek(endOffset) # TODO: Remove after implementing MetaInfo.

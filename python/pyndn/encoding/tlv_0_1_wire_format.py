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

from random import SystemRandom
from pyndn.exclude import Exclude
from pyndn.meta_info import ContentType
from pyndn.forwarding_flags import ForwardingFlags
from pyndn.key_locator import KeyLocatorType
from pyndn.sha256_with_rsa_signature import Sha256WithRsaSignature
from pyndn.util import Blob
from pyndn.encoding.wire_format import WireFormat
from pyndn.encoding.tlv.tlv_encoder import TlvEncoder
from pyndn.encoding.tlv.tlv_decoder import TlvDecoder
from pyndn.encoding.tlv.tlv import Tlv

# The Python documentation says "Use SystemRandom if you require a 
#   cryptographically secure pseudo-random number generator."
# http://docs.python.org/2/library/random.html
_systemRandom = SystemRandom()

"""
This module defines the Tlv0_1WireFormat class which extends WireFormat to
override its methods to implment encoding and decoding Interest, Data, etc. 
with the NDN-TLV wire format, version 0.1a2.
"""

class Tlv0_1WireFormat(WireFormat):
    _instance = None
    
    def encodeInterest(self, interest):
        """
        Encode interest in NDN-TLV and return the encoding.

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
            # Copy existing nonce bytes.
            nonce[:interest.getNonce().size()] = interest.getNonce().buf()
            
            # Generate random bytes for remaining bytes in the nonce.
            for i in range(interest.getNonce().size(), 4):
                nonce[i] = _systemRandom.randint(0, 0xff)
                
            encoder.writeBlobTlv(Tlv.Nonce, nonce)
        elif interest.getNonce().size() == 4:
            # Use the nonce as-is.
            encoder.writeBlobTlv(Tlv.Nonce, interest.getNonce().buf())
        else:
            # Truncate.
            encoder.writeBlobTlv(Tlv.Nonce, interest.getNonce().buf()[:4])
        
        self._encodeSelectors(interest, encoder)
        
        (tempSignedPortionBeginOffset, tempSignedPortionEndOffset) = \
          self._encodeName(interest.getName(), encoder)
        signedPortionBeginOffsetFromBack = (len(encoder) - 
                                            tempSignedPortionBeginOffset)
        signedPortionEndOffsetFromBack = (len(encoder) - 
                                          tempSignedPortionEndOffset)
        
        encoder.writeTypeAndLength(Tlv.Interest, len(encoder) - saveLength)
        signedPortionBeginOffset = (len(encoder) - 
                                    signedPortionBeginOffsetFromBack)
        signedPortionEndOffset = len(encoder) - signedPortionEndOffsetFromBack
        
        return (Blob(encoder.getOutput(), False), signedPortionBeginOffset, 
                signedPortionEndOffset)

    def decodeInterest(self, interest, input):
        """
        Decode input as an NDN-TLV interest and set the fields of the interest 
        object.  
        
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
        """
        decoder = TlvDecoder(input)

        endOffset = decoder.readNestedTlvsStart(Tlv.Interest)
        offsets = self._decodeName(interest.getName(), decoder)
        if decoder.peekType(Tlv.Selectors, endOffset):
            self._decodeSelectors(interest, decoder)
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
        return offsets
        
    def encodeData(self, data):
        """
        Encode data in NDN-TLV and return the encoding and signed offsets.

        :param Data data: The Data object to encode.
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
        # TODO: The library needs to handle other signature types than 
        #   SignatureSha256WithRsa.
        encoder.writeBlobTlv(Tlv.SignatureValue, 
                             data.getSignature().getSignature().buf())
        signedPortionEndOffsetFromBack = len(encoder)
        
        self._encodeSignatureSha256WithRsa(data.getSignature(), encoder)
        encoder.writeBlobTlv(Tlv.Content, data.getContent().buf())
        self._encodeMetaInfo(data.getMetaInfo(), encoder)
        self._encodeName(data.getName(), encoder)
        signedPortionBeginOffsetFromBack = len(encoder)

        encoder.writeTypeAndLength(Tlv.Data, len(encoder) - saveLength)
        signedPortionBeginOffset = (len(encoder) - 
                                    signedPortionBeginOffsetFromBack)
        signedPortionEndOffset = len(encoder) - signedPortionEndOffsetFromBack
        
        return (Blob(encoder.getOutput(), False), signedPortionBeginOffset, 
                signedPortionEndOffset)
        
    def decodeData(self, data, input):
        """
        Decode input as an NDN-TLV data packet, set the fields in the data 
        object, and return the signed offsets.  

        :param Data data: The Data object whose fields are updated.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :return: A Tuple of (signedPortionBeginOffset, signedPortionEndOffset) 
          where signedPortionBeginOffset is the offset in the encoding of 
          the beginning of the signed portion, and signedPortionEndOffset is
          the offset in the encoding of the end of the signed portion.
        :rtype: (int, int)
        """
        decoder = TlvDecoder(input)

        endOffset = decoder.readNestedTlvsStart(Tlv.Data)
        signedPortionBeginOffset = decoder.getOffset()
        
        self._decodeName(data.getName(), decoder)
        self._decodeMetaInfo(data.getMetaInfo(), decoder)
        data.setContent(Blob(decoder.readBlobTlv(Tlv.Content)))
        self._decodeSignatureInfo(data, decoder)
        
        signedPortionEndOffset = decoder.getOffset()
        # TODO: The library needs to handle other signature types than 
        #   SignatureSha256WithRsa.
        data.getSignature().setSignature(Blob(decoder.readBlobTlv(Tlv.SignatureValue)))

        decoder.finishNestedTlvs(endOffset)
        return (signedPortionBeginOffset, signedPortionEndOffset)
    
    def encodeForwardingEntry(self, forwardingEntry):
        """
        Encode forwardingEntry and return the encoding.

        :param forwardingEntry: The ForwardingEntry object to encode.
        :type forwardingEntry: ForwardingEntry
        :return: A Blob containing the encoding.
        :rtype: Blob
        """
        encoder = TlvEncoder(256)
        saveLength = len(encoder)
        
        # Encode backwards.
        encoder.writeOptionalNonNegativeIntegerTlvFromFloat(
          Tlv.FreshnessPeriod, forwardingEntry.getFreshnessPeriod())
        encoder.writeNonNegativeIntegerTlv(
          Tlv.ForwardingFlags, 
          forwardingEntry.getForwardingFlags().getForwardingEntryFlags())
        encoder.writeOptionalNonNegativeIntegerTlv(
          Tlv.FaceID, forwardingEntry.getFaceId())
        self._encodeName(forwardingEntry.getPrefix(), encoder)
        if (forwardingEntry.getAction() != None and
             len(forwardingEntry.getAction()) > 0):
            # Convert str to a bytearray.
            encoder.writeBlobTlv(
              Tlv.Action, bytearray(forwardingEntry.getAction(), 'ascii'))

        encoder.writeTypeAndLength(Tlv.ForwardingEntry, 
                                   len(encoder) - saveLength)
        
        return Blob(encoder.getOutput(), False)
    
    def decodeForwardingEntry(self, forwardingEntry, input):
        """
        Decode input as an forwardingEntry and set the fields of the 
        forwardingEntry object.
        
        :param forwardingEntry: The ForwardingEntry object whose fields are 
          updated.
        :type forwardingEntry: ForwardingEntry
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        """
        decoder = TlvDecoder(input)

        endOffset = decoder.readNestedTlvsStart(Tlv.ForwardingEntry)
        
        actionBytes = decoder.readOptionalBlobTlv(Tlv.Action, endOffset)
        if actionBytes != None:
            # Convert bytes to a str.
            forwardingEntry.setAction("".join(map(chr, actionBytes)))
        else:
            forwardingEntry.setAction(None)
        
        if decoder.peekType(Tlv.Name, endOffset):
            self._decodeName(forwardingEntry.getPrefix(), decoder)
        else:
            forwardingEntry.getPrefix().clear()
            
        forwardingEntry.setFaceId(
          decoder.readOptionalNonNegativeIntegerTlv(Tlv.FaceID, endOffset))

        forwardingEntryFlags = decoder.readOptionalNonNegativeIntegerTlv(
          Tlv.ForwardingFlags, endOffset)
        if forwardingEntryFlags != None:
            forwardingEntry.getForwardingFlags().setForwardingEntryFlags(
              forwardingEntryFlags)
        else:
            # This sets the default flags.
            forwardingEntry.setForwardingFlags(ForwardingFlags())

        forwardingEntry.setFreshnessPeriod(
          decoder.readOptionalNonNegativeIntegerTlvAsFloat(
            Tlv.FreshnessPeriod, endOffset))

        decoder.finishNestedTlvs(endOffset)
    
    def encodeControlParameters(self, controlParameters):
        """
        Encode controlParameters and return the encoding.

        :param controlParameters: The ControlParameters object to encode.
        :type controlParameters: ControlParameters
        :return: A Blob containing the encoding.
        :rtype: Blob
        """
        encoder = TlvEncoder(256)
        saveLength = len(encoder)
        
        # Encode backwards.
        encoder.writeOptionalNonNegativeIntegerTlvFromFloat(
          Tlv.ControlParameters_ExpirationPeriod, 
          controlParameters.getExpirationPeriod())
          
        # TODO: Encode Strategy.
          
        flags = controlParameters.getForwardingFlags().getNfdForwardingFlags()
        if (flags != ForwardingFlags().getNfdForwardingFlags()):
            # The flags are not the default value.
            encoder.writeNonNegativeIntegerTlv(
              Tlv.ControlParameters_Flags, flags)

        encoder.writeOptionalNonNegativeIntegerTlv(
          Tlv.ControlParameters_Cost, controlParameters.getCost())
        encoder.writeOptionalNonNegativeIntegerTlv(
          Tlv.ControlParameters_Origin, controlParameters.getOrigin())
        encoder.writeOptionalNonNegativeIntegerTlv(
          Tlv.ControlParameters_LocalControlFeature, 
          controlParameters.getLocalControlFeature())
          
        # TODO: Encode Uri.
          
        encoder.writeOptionalNonNegativeIntegerTlv(
          Tlv.FaceID, controlParameters.getFaceId())
        self._encodeName(controlParameters.getName(), encoder)

        encoder.writeTypeAndLength(Tlv.ControlParameters_ControlParameters, 
                                   len(encoder) - saveLength)
        
        return Blob(encoder.getOutput(), False)
    
    def encodeSignatureInfo(self, signature):
        """
        Encode signature as an NDN-TLV SignatureInfo and return the encoding.

        :param signature: An object of a subclass of Signature to encode.
        :type signature: An object of a subclass of Signature
        :return: A Blob containing the encoding.
        :rtype: Blob
        """
        encoder = TlvEncoder(256)
        # TODO: This assumes it is a Sha256WithRsaSignature.
        self._encodeSignatureSha256WithRsa(signature, encoder)
    
        return Blob(encoder.getOutput(), False)

    # SignatureHolder is used by decodeSignatureInfoAndValue.
    class SignatureHolder(object):
        def setSignature(self, signature):
            self._signature = signature
        def getSignature(self):
            return self._signature

    def decodeSignatureInfoAndValue(self, signatureInfo, signatureValue):
        """
        Decode signatureInfo as a signature info and signatureValue as the
        related SignatureValue, and return a new object which is a subclass of
        Signature.

        :param signatureInfo: The array with the signature info input buffer to
          decode.
        :type signatureInfo: An array type with int elements
        :param signatureValue: The array with the signature value input buffer
          to decode.
        :type signatureValue: An array type with int elements
        :return: A new object which is a subclass of Signature.
        :rtype: a subclass of Signature
        """
        # Use a SignatureHolder to imitate a Data object for _decodeSignatureInfo.
        signatureHolder = self.SignatureHolder()
        decoder = TlvDecoder(signatureInfo)
        self._decodeSignatureInfo(signatureHolder, decoder)

        decoder = TlvDecoder(signatureValue)
        # TODO: The library needs to handle other signature types than
        #   SignatureSha256WithRsa.
        signatureHolder.getSignature().setSignature(
          Blob(decoder.readBlobTlv(Tlv.SignatureValue)))

        return signatureHolder.getSignature()

    def encodeSignatureValue(self, signature):
        """
        Encode the signatureValue in the Signature object as an NDN-TLV 
        SignatureValue (the signature bits) and return the encoding.

        :param signature: An object of a subclass of Signature with the 
          signature value to encode.
        :type signature: An object of a subclass of Signature
        :return: A Blob containing the encoding.
        :rtype: Blob
        """
        encoder = TlvEncoder(256)
        # TODO: This assumes it is a Sha256WithRsaSignature.
        encoder.writeBlobTlv(Tlv.SignatureValue, signature.getSignature().buf())
    
        return Blob(encoder.getOutput(), False)

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
        """
        Encode the name to the encoder.
        
        :param Name name: The name to encode.
        :param TlvEncoder encoder: The encoder to receive the encoding.
        :return: A Tuple of (signedPortionBeginOffset, signedPortionEndOffset) 
          where signedPortionBeginOffset is the offset in the encoding of 
          the beginning of the signed portion, and signedPortionEndOffset is
          the offset in the encoding of the end of the signed portion. The 
          signed portion starts from the first name component and ends just 
          before the final name component (which is assumed to be a signature 
          for a signed interest).
        :rtype: (int, int)
        """
        saveLength = len(encoder)
        
        # Encode the components backwards.
        for i in range(len(name) - 1, -1, -1):
            encoder.writeBlobTlv(Tlv.NameComponent, name[i].getValue().buf())
            if i == len(name) - 1:
                signedPortionEndOffsetFromBack = len(encoder)
                
        signedPortionBeginOffsetFromBack = len(encoder)
        encoder.writeTypeAndLength(Tlv.Name, len(encoder) - saveLength)

        signedPortionBeginOffset = (len(encoder) - 
                                    signedPortionBeginOffsetFromBack)
        if len(name) == 0:
            # There is no "final component", so set signedPortionEndOffset 
            #   arbitrarily.
            signedPortionEndOffset = signedPortionBeginOffset
        else:
            signedPortionEndOffset = len(encoder) - signedPortionEndOffsetFromBack
        
        return (signedPortionBeginOffset, signedPortionEndOffset)

    @staticmethod
    def _decodeName(name, decoder):
        """
        Clear the name, decode a Name from the decoder and set the fields of
        the name object.
        
        :param Name name: The name object whose fields are updated.
        :param TlvDecode decode: The decoder with the input.
        :return: A Tuple of (signedPortionBeginOffset, signedPortionEndOffset) 
          where signedPortionBeginOffset is the offset in the encoding of 
          the beginning of the signed portion, and signedPortionEndOffset is
          the offset in the encoding of the end of the signed portion. The 
          signed portion starts from the first name component and ends just 
          before the final name component (which is assumed to be a signature 
          for a signed interest).
        :rtype: (int, int)
        """
        name.clear()
        
        endOffset = decoder.readNestedTlvsStart(Tlv.Name)        
        signedPortionBeginOffset = decoder.getOffset()
        # In case there are no components, set signedPortionEndOffset arbitrarily.
        signedPortionEndOffset = signedPortionBeginOffset

        while decoder.getOffset() < endOffset:
            signedPortionEndOffset = decoder.getOffset()
            name.append(decoder.readBlobTlv(Tlv.NameComponent))
   
        decoder.finishNestedTlvs(endOffset)
        return (signedPortionBeginOffset, signedPortionEndOffset)

    @staticmethod
    def _encodeSelectors(interest, encoder):
        """
        Encode the interest selectors.  If no selectors are written, do not
        output a Selectors TLV.
        """
        saveLength = len(encoder)
        
        # Encode backwards.
        if interest.getMustBeFresh():
            encoder.writeTypeAndLength(Tlv.MustBeFresh, 0)
        encoder.writeOptionalNonNegativeIntegerTlv(
          Tlv.ChildSelector, interest.getChildSelector())
        if interest.getExclude().size() > 0:
            Tlv0_1WireFormat._encodeExclude(interest.getExclude(), encoder)
        if interest.getKeyLocator().getType() != None:
            Tlv0_1WireFormat._encodeKeyLocator(
              Tlv.PublisherPublicKeyLocator, interest.getKeyLocator(), encoder)
        encoder.writeOptionalNonNegativeIntegerTlv(
          Tlv.MaxSuffixComponents, interest.getMaxSuffixComponents())
        encoder.writeOptionalNonNegativeIntegerTlv(
          Tlv.MinSuffixComponents, interest.getMinSuffixComponents())

        # Only output the type and length if values were written.
        if len(encoder) != saveLength:
            encoder.writeTypeAndLength(Tlv.Selectors, len(encoder) - saveLength)

    @staticmethod
    def _decodeSelectors(interest, decoder):
        endOffset = decoder.readNestedTlvsStart(Tlv.Selectors)

        interest.setMinSuffixComponents(
          decoder.readOptionalNonNegativeIntegerTlv
            (Tlv.MinSuffixComponents, endOffset))
        interest.setMaxSuffixComponents(
          decoder.readOptionalNonNegativeIntegerTlv
            (Tlv.MaxSuffixComponents, endOffset))
            
        if decoder.peekType(Tlv.PublisherPublicKeyLocator, endOffset):
            Tlv0_1WireFormat._decodeKeyLocator(
              Tlv.PublisherPublicKeyLocator, interest.getKeyLocator(), decoder)
        else:
            interest.getKeyLocator().clear()
            
        if decoder.peekType(Tlv.Exclude, endOffset):
            Tlv0_1WireFormat._decodeExclude(interest.getExclude(), decoder)
        else:
            interest.getExclude().clear()
            
        interest.setChildSelector(
          decoder.readOptionalNonNegativeIntegerTlv
            (Tlv.ChildSelector, endOffset))
        interest.setMustBeFresh(
          decoder.readBooleanTlv(Tlv.MustBeFresh, endOffset))
   
        decoder.finishNestedTlvs(endOffset)

    @staticmethod
    def _encodeExclude(exclude, encoder):
        saveLength = len(encoder)
        
        # TODO: Do we want to order the components (except for ANY)?
        # Encode the entries backwards.
        for i in range(len(exclude) - 1, -1, -1):
            entry = exclude[i]
            
            if entry.getType() == Exclude.COMPONENT:
                encoder.writeBlobTlv(Tlv.NameComponent, 
                                     entry.getComponent().getValue().buf())
            elif entry.getType() == Exclude.ANY:
                encoder.writeTypeAndLength(Tlv.Any, 0)
            else:
                # We don't expect this to happen, but check anyway.
                raise RuntimeError("Unrecognized Exclude type" + 
                                   repr(entry.getType()))

        encoder.writeTypeAndLength(Tlv.Exclude, len(encoder) - saveLength)

    @staticmethod
    def _decodeExclude(exclude, decoder):
        endOffset = decoder.readNestedTlvsStart(Tlv.Exclude)

        exclude.clear()
        while True:
            if decoder.peekType(Tlv.NameComponent, endOffset):
                exclude.appendComponent(decoder.readBlobTlv(Tlv.NameComponent))
            elif decoder.readBooleanTlv(Tlv.Any, endOffset):
                exclude.appendAny()
            else:
                # Else no more entries.
                break

        decoder.finishNestedTlvs(endOffset)

    @staticmethod
    def _encodeMetaInfo(metaInfo, encoder):
        saveLength = len(encoder)
        
        # Encode backwards.
        finalBlockIdBuf = metaInfo.getFinalBlockID().getValue().buf()
        if finalBlockIdBuf != None and len(finalBlockIdBuf) > 0:
            # FinalBlockId has an inner NameComponent.
            finalBlockIdSaveLength = len(encoder)
            encoder.writeBlobTlv(Tlv.NameComponent, finalBlockIdBuf)
            encoder.writeTypeAndLength(
              Tlv.FinalBlockId, len(encoder) - finalBlockIdSaveLength)
              
        encoder.writeOptionalNonNegativeIntegerTlvFromFloat(
          Tlv.FreshnessPeriod, metaInfo.getFreshnessPeriod())
        if metaInfo.getType() != ContentType.BLOB:
            # Not the default, so we need to encode the type.
            if (metaInfo.getType() == ContentType.LINK or
                  metaInfo.getType() == ContentType.KEY):
                # The ContentType enum is set up with the correct integer for 
                # each NDN-TLV ContentType.
                encoder.writeNonNegativeIntegerTlv(
                  Tlv.ContentType, metaInfo.getType())
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
          Tlv.ContentType, endOffset))
        metaInfo.setFreshnessPeriod(
          decoder.readOptionalNonNegativeIntegerTlvAsFloat(
            Tlv.FreshnessPeriod, endOffset))
        if decoder.peekType(Tlv.FinalBlockId, endOffset):
            finalBlockIdEndOffset = decoder.readNestedTlvsStart(Tlv.FinalBlockId)
            metaInfo.setFinalBlockID(decoder.readBlobTlv(Tlv.NameComponent))
            decoder.finishNestedTlvs(finalBlockIdEndOffset)
        else:
            metaInfo.setFinalBlockID(None)
        
        decoder.finishNestedTlvs(endOffset)

    @staticmethod
    def _encodeSignatureSha256WithRsa(signature, encoder):
        saveLength = len(encoder)
        
        # Encode backwards.
        Tlv0_1WireFormat._encodeKeyLocator(
          Tlv.KeyLocator, signature.getKeyLocator(), encoder)
        encoder.writeNonNegativeIntegerTlv(
          Tlv.SignatureType, Tlv.SignatureType_SignatureSha256WithRsa)
    
        encoder.writeTypeAndLength(Tlv.SignatureInfo, len(encoder) - saveLength)

    @staticmethod
    def _decodeSignatureInfo(data, decoder):
        endOffset = decoder.readNestedTlvsStart(Tlv.SignatureInfo)

        signatureType = decoder.readNonNegativeIntegerTlv(Tlv.SignatureType)
        # TODO: The library needs to handle other signature types than 
        #     SignatureSha256WithRsa.
        if signatureType == Tlv.SignatureType_SignatureSha256WithRsa:
            data.setSignature(Sha256WithRsaSignature())
            # Modify data's signature object because if we create an object
            #   and set it, then data will have to copy all the fields.
            signatureInfo = data.getSignature()
            Tlv0_1WireFormat._decodeKeyLocator(
              Tlv.KeyLocator, signatureInfo.getKeyLocator(), 
              decoder)
        else:
            raise RuntimeError(
              "decodeSignatureInfo: unrecognized SignatureInfo type" + 
              repr(signatureType))
                
        decoder.finishNestedTlvs(endOffset)

    @staticmethod
    def _encodeKeyLocator(type, keyLocator, encoder):
        saveLength = len(encoder)
        
        # Encode backwards.
        if keyLocator.getType() != None:
            if keyLocator.getType() == KeyLocatorType.KEYNAME:
                Tlv0_1WireFormat._encodeName(keyLocator.getKeyName(), encoder)
            elif (keyLocator.getType() == KeyLocatorType.KEY_LOCATOR_DIGEST and
                  len(keyLocator.getKeyData()) > 0):
                encoder.writeBlobTlv(Tlv.KeyLocatorDigest, 
                                     keyLocator.getKeyData().buf())
            else:
                raise RuntimeError("Unrecognized KeyLocatorType " + 
                                   repr(keyLocator.getType()))
    
        encoder.writeTypeAndLength(type, len(encoder) - saveLength)

    @staticmethod
    def _decodeKeyLocator(expectedType, keyLocator, decoder):
        endOffset = decoder.readNestedTlvsStart(expectedType)

        keyLocator.clear()

        if decoder.getOffset() == endOffset:
            # The KeyLocator is omitted, so leave the fields as none.
            return
                
        if decoder.peekType(Tlv.Name, endOffset):
            # KeyLocator is a Name.
            keyLocator.setType(KeyLocatorType.KEYNAME)
            Tlv0_1WireFormat._decodeName(keyLocator.getKeyName(), decoder)
        elif decoder.peekType(Tlv.KeyLocatorDigest, endOffset):
            # KeyLocator is a KeyLocatorDigest.
            keyLocator.setType(KeyLocatorType.KEY_LOCATOR_DIGEST)
            keyLocator.setKeyData(
              Blob(decoder.readBlobTlv(Tlv.KeyLocatorDigest)))
        else:
            raise RuntimeError("decodeKeyLocator: Unrecognized key locator type")

        decoder.finishNestedTlvs(endOffset)

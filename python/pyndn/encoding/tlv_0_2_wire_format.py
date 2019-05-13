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

from datetime import datetime
from random import SystemRandom
from pyndn.name import Name
from pyndn.exclude import Exclude
from pyndn.name import ComponentType
from pyndn.meta_info import ContentType
from pyndn.registration_options import RegistrationOptions
from pyndn.key_locator import KeyLocatorType
from pyndn.digest_sha256_signature import DigestSha256Signature
from pyndn.sha256_with_ecdsa_signature import Sha256WithEcdsaSignature
from pyndn.sha256_with_rsa_signature import Sha256WithRsaSignature
from pyndn.generic_signature import GenericSignature
from pyndn.hmac_with_sha256_signature import HmacWithSha256Signature
from pyndn.control_parameters import ControlParameters
from pyndn.util.blob import Blob
from pyndn.util.common import Common
from pyndn.network_nack import NetworkNack
from pyndn.lp.incoming_face_id import IncomingFaceId
from pyndn.lp.congestion_mark import CongestionMark
from pyndn.encoding.wire_format import WireFormat
from pyndn.encoding.tlv.tlv_encoder import TlvEncoder
from pyndn.encoding.tlv.tlv_decoder import TlvDecoder
from pyndn.encoding.tlv.tlv import Tlv
haveModule_pyndn = True
try:
    import _pyndn
except ImportError:
    haveModule_pyndn = False

# The Python documentation says "Use SystemRandom if you require a
#   cryptographically secure pseudo-random number generator."
# http://docs.python.org/2/library/random.html
_systemRandom = SystemRandom()

"""
This module defines the Tlv0_2WireFormat class which extends WireFormat to
override its methods to implment encoding and decoding Interest, Data, etc.
with the NDN-TLV wire format, version 0.2.
"""

class Tlv0_2WireFormat(WireFormat):
    _instance = None

    _didCanBePrefixWarning = False

    def encodeName(self, name):
        """
        Encode name in NDN-TLV and return the encoding.

        :param Name name: The Name object to encode.
        :return: A Blob containing the encoding.
        :rtype: Blob
        """
        if haveModule_pyndn:
            # Use the C bindings.
            result = _pyndn.Tlv0_1_1WireFormat_encodeName(name)
            return Blob(result, False)

        encoder = TlvEncoder(256)
        self._encodeName(name, encoder)
        return Blob(encoder.getOutput(), False)

    def decodeName(self, name, input, copy = True):
        """
        Decode input as an NDN-TLV name and set the fields of the Name
        object.

        :param Name name: The Name object whose fields are updated.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :param bool copy: (optional) If True, copy from the input when making
          new Blob values. If False, then Blob values share memory with the
          input, which must remain unchanged while the Blob values are used.
          If omitted, use True.
        """
        if haveModule_pyndn:
            # Use the C bindings.
            _pyndn.Tlv0_1_1WireFormat_decodeName(name, input)
            return

        decoder = TlvDecoder(input)
        self._decodeName(name, decoder, copy)

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
        if not interest._didSetCanBePrefix and not self._didCanBePrefixWarning:
            print(
              "WARNING: The default CanBePrefix will change. See Interest.setDefaultCanBePrefix() for details.")
            self._didCanBePrefixWarning = True

        if haveModule_pyndn:
            # Use the C bindings.
            result = _pyndn.Tlv0_1_1WireFormat_encodeInterest(interest)
            return (Blob(result[0], False), result[1], result[2])

        if interest.hasApplicationParameters():
            # The application has specified a format v0.3 field. As we
            # transition to format v0.3, encode as format v0.3 even though the
            # application default is Tlv0_2WireFormat.
            return self._encodeInterestV03(interest)

        encoder = TlvEncoder(256)
        saveLength = len(encoder)

        # Encode backwards.
        if interest.getForwardingHint().size() > 0:
            if interest.getSelectedDelegationIndex() != None:
                raise RuntimeError(
                  "An Interest may not have a selected delegation when encoding a forwarding hint")
            if interest.hasLink():
                raise RuntimeError(
                  "An Interest may not have a link object when encoding a forwarding hint")

            forwardingHintSaveLength = len(encoder)
            Tlv0_2WireFormat._encodeDelegationSet(
              interest.getForwardingHint(), encoder)
            encoder.writeTypeAndLength(
              Tlv.ForwardingHint, len(encoder) - forwardingHintSaveLength)

        encoder.writeOptionalNonNegativeIntegerTlv(
          Tlv.SelectedDelegation, interest.getSelectedDelegationIndex())
        linkWireEncoding = interest.getLinkWireEncoding(self)
        if not linkWireEncoding.isNull():
          # Encode the entire link as is.
          encoder.writeBuffer(linkWireEncoding.buf())

        encoder.writeOptionalNonNegativeIntegerTlvFromFloat(
          Tlv.InterestLifetime, interest.getInterestLifetimeMilliseconds())

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

    def decodeInterest(self, interest, input, copy = True):
        """
        Decode input as an NDN-TLV interest and set the fields of the interest
        object.

        :param Interest interest: The Interest object whose fields are updated.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :param bool copy: (optional) If True, copy from the input when making
          new Blob values. If False, then Blob values share memory with the
          input, which must remain unchanged while the Blob values are used.
          If omitted, use True.
        :return: A Tuple of (signedPortionBeginOffset, signedPortionEndOffset)
          where signedPortionBeginOffset is the offset in the encoding of
          the beginning of the signed portion, and signedPortionEndOffset is
          the offset in the encoding of the end of the signed portion. The
          signed portion starts from the first name component and ends just
          before the final name component (which is assumed to be a signature
          for a signed interest).
        :rtype: (int, int)
        """
        if haveModule_pyndn:
            # Use the C bindings.
            return _pyndn.Tlv0_1_1WireFormat_decodeInterest(interest, input)

        try:
            return self._decodeInterestV02(interest, input, copy)
        except Exception as exceptionV02:
            try:
                # Failed to decode as format v0.2. Try to decode as v0.3.
                return Tlv0_2WireFormat._decodeInterestV03(interest, input, copy)
            except:
                # Ignore the exception decoding as format v0.3 and raise the
                # exception from trying to decode as format as format v0.2.
                raise exceptionV02

    def _decodeInterestV02(self, interest, input, copy):
        """
        Do the work of decodeInterest to decode strictly as format v0.2.
        """
        decoder = TlvDecoder(input)

        endOffset = decoder.readNestedTlvsStart(Tlv.Interest)
        offsets = self._decodeName(interest.getName(), decoder, copy)
        if decoder.peekType(Tlv.Selectors, endOffset):
            self._decodeSelectors(interest, decoder, copy)
        else:
            # Set selectors to none.
            interest.setMinSuffixComponents(None)
            interest.setMaxSuffixComponents(None)
            interest.getKeyLocator().clear()
            interest.getExclude().clear()
            interest.setChildSelector(None)
            interest.setMustBeFresh(False)

        # Require a Nonce, but don't force it to be 4 bytes.
        nonce = Blob(decoder.readBlobTlv(Tlv.Nonce), copy)
        interest.setInterestLifetimeMilliseconds(
           decoder.readOptionalNonNegativeIntegerTlvAsFloat
           (Tlv.InterestLifetime, endOffset))

        if decoder.peekType(Tlv.ForwardingHint, endOffset):
            forwardingHintEndOffset = decoder.readNestedTlvsStart(
              Tlv.ForwardingHint)
            Tlv0_2WireFormat._decodeDelegationSet(
              interest.getForwardingHint(), forwardingHintEndOffset, decoder,
              copy)
            decoder.finishNestedTlvs(forwardingHintEndOffset)

        if decoder.peekType(Tlv.Data, endOffset):
            # Get the bytes of the Link TLV.
            linkBeginOffset = decoder.getOffset()
            linkEndOffset = decoder.readNestedTlvsStart(Tlv.Data)
            decoder.seek(linkEndOffset)

            interest.setLinkWireEncoding(
              Blob(decoder.getSlice(linkBeginOffset, linkEndOffset), copy), self)
        else:
            interest.unsetLink()
        interest.setSelectedDelegationIndex(
          decoder.readOptionalNonNegativeIntegerTlv(
            Tlv.SelectedDelegation, endOffset))
        if (interest.getSelectedDelegationIndex() != None and
            interest.getSelectedDelegationIndex() >= 0 and not interest.hasLink()):
            raise RuntimeError(
              "Interest has a selected delegation, but no link object")

        # Format v0.2 doesn't have application parameters.
        interest.setApplicationParameters(Blob())

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
        if haveModule_pyndn:
            # Use the C bindings.
            result = _pyndn.Tlv0_1_1WireFormat_encodeData(data)
            return (Blob(result[0], False), result[1], result[2])

        encoder = TlvEncoder(1500)
        saveLength = len(encoder)

        # Encode backwards.
        encoder.writeBlobTlv(Tlv.SignatureValue,
                             data.getSignature().getSignature().buf())
        signedPortionEndOffsetFromBack = len(encoder)

        self._encodeSignatureInfo(data.getSignature(), encoder)
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

    def decodeData(self, data, input, copy = True):
        """
        Decode input as an NDN-TLV data packet, set the fields in the data
        object, and return the signed offsets.

        :param Data data: The Data object whose fields are updated.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :param bool copy: (optional) If True, copy from the input when making
          new Blob values. If False, then Blob values share memory with the
          input, which must remain unchanged while the Blob values are used.
          If omitted, use True.
        :return: A Tuple of (signedPortionBeginOffset, signedPortionEndOffset)
          where signedPortionBeginOffset is the offset in the encoding of
          the beginning of the signed portion, and signedPortionEndOffset is
          the offset in the encoding of the end of the signed portion.
        :rtype: (int, int)
        """
        if haveModule_pyndn:
            # Use the C bindings.
            return _pyndn.Tlv0_1_1WireFormat_decodeData(data, input)

        decoder = TlvDecoder(input)

        endOffset = decoder.readNestedTlvsStart(Tlv.Data)
        signedPortionBeginOffset = decoder.getOffset()

        self._decodeName(data.getName(), decoder, copy)
        if decoder.peekType(Tlv.MetaInfo, endOffset):
            self._decodeMetaInfo(data.getMetaInfo(), decoder, copy)
        else:
            data.getMetaInfo().clear()
        data.setContent(Blob(decoder.readOptionalBlobTlv(Tlv.Content, endOffset), copy))
        self._decodeSignatureInfo(data, decoder, copy)

        signedPortionEndOffset = decoder.getOffset()
        data.getSignature().setSignature(
          Blob(decoder.readBlobTlv(Tlv.SignatureValue), copy))

        decoder.finishNestedTlvs(endOffset)
        return (signedPortionBeginOffset, signedPortionEndOffset)

    def encodeControlParameters(self, controlParameters):
        """
        Encode controlParameters and return the encoding.

        :param controlParameters: The ControlParameters object to encode.
        :type controlParameters: ControlParameters
        :return: A Blob containing the encoding.
        :rtype: Blob
        """
        encoder = TlvEncoder(256)
        self._encodeControlParameters(controlParameters, encoder)
        return Blob(encoder.getOutput(), False)

    def decodeControlParameters(self, controlParameters, input, copy = True):
        """
        Decode input as an NDN-TLV ControlParameters and set the fields of the
        controlParameters object.

        :param ControlParameters controlParameters: The ControlParameters object
          whose fields are updated.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :param bool copy: (optional) If True, copy from the input when making
          new Blob values. If False, then Blob values share memory with the
          input, which must remain unchanged while the Blob values are used.
          If omitted, use True.
        """
        decoder = TlvDecoder(input)
        self._decodeControlParameters(controlParameters, decoder, copy)

    def encodeSignatureInfo(self, signature):
        """
        Encode signature as an NDN-TLV SignatureInfo and return the encoding.

        :param signature: An object of a subclass of Signature to encode.
        :type signature: An object of a subclass of Signature
        :return: A Blob containing the encoding.
        :rtype: Blob
        """
        if haveModule_pyndn:
            # Use the C bindings.
            result = _pyndn.Tlv0_1_1WireFormat_encodeSignatureInfo(signature)
            return Blob(result, False)

        encoder = TlvEncoder(256)
        self._encodeSignatureInfo(signature, encoder)

        return Blob(encoder.getOutput(), False)

    def encodeControlResponse(self, controlResponse):
        """
        Encode controlResponse and return the encoding.

        :param controlResponse: The ControlResponse object to encode.
        :type controlResponse: ControlResponse
        :return: A Blob containing the encoding.
        :rtype: Blob
        """
        encoder = TlvEncoder(256)
        saveLength = len(encoder)

        # Encode backwards.

        # Encode the body.
        if controlResponse.getBodyAsControlParameters() != None:
            self._encodeControlParameters(
              controlResponse.getBodyAsControlParameters(), encoder)

        encoder.writeBlobTlv(
          Tlv.NfdCommand_StatusText, Blob(controlResponse.getStatusText()).buf())
        encoder.writeNonNegativeIntegerTlv(
          Tlv.NfdCommand_StatusCode, controlResponse.getStatusCode())

        encoder.writeTypeAndLength(Tlv.NfdCommand_ControlResponse,
                                   len(encoder) - saveLength)

        return Blob(encoder.getOutput(), False)

    def decodeControlResponse(self, controlResponse, input, copy = True):
        """
        Decode input as an NDN-TLV ControlResponse and set the fields of the
        controlResponse object.

        :param ControlResponse controlResponse: The ControlResponse object
          whose fields are updated.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :param bool copy: (optional) If True, copy from the input when making
          new Blob values. If False, then Blob values share memory with the
          input, which must remain unchanged while the Blob values are used.
          If omitted, use True.
        """
        controlResponse.clear()

        decoder = TlvDecoder(input)
        endOffset = decoder.readNestedTlvsStart(
          Tlv.NfdCommand_ControlResponse)

        # decode face ID
        controlResponse.setStatusCode(decoder.readNonNegativeIntegerTlv
            (Tlv.NfdCommand_StatusCode))
        # Set copy False since we just immediately get a string.
        statusText = Blob(
          decoder.readBlobTlv(Tlv.NfdCommand_StatusText), False)
        controlResponse.setStatusText(str(statusText))

        # Decode the body.
        if decoder.peekType(Tlv.ControlParameters_ControlParameters, endOffset):
            controlResponse.setBodyAsControlParameters(ControlParameters())
            # Decode into the existing ControlParameters to avoid copying.
            self._decodeControlParameters(
              controlResponse.getBodyAsControlParameters(), decoder, copy)

        decoder.finishNestedTlvs(endOffset)

    # SignatureHolder is used by decodeSignatureInfoAndValue.
    class SignatureHolder(object):
        def setSignature(self, signature):
            self._signature = signature
        def getSignature(self):
            return self._signature

    def decodeSignatureInfoAndValue(self, signatureInfo, signatureValue, copy = True):
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
        :param bool copy: (optional) If True, copy from the input when making
          new Blob values. If False, then Blob values share memory with the
          input, which must remain unchanged while the Blob values are used.
          If omitted, use True.
        :return: A new object which is a subclass of Signature.
        :rtype: a subclass of Signature
        """
        if haveModule_pyndn:
            # Use the C bindings.
            return _pyndn.Tlv0_1_1WireFormat_decodeSignatureInfoAndValue(
              signatureInfo, signatureValue)

        # Use a SignatureHolder to imitate a Data object for _decodeSignatureInfo.
        signatureHolder = self.SignatureHolder()
        decoder = TlvDecoder(signatureInfo)
        self._decodeSignatureInfo(signatureHolder, decoder, copy)

        decoder = TlvDecoder(signatureValue)
        signatureHolder.getSignature().setSignature(
          Blob(decoder.readBlobTlv(Tlv.SignatureValue), copy))

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
        if haveModule_pyndn:
            # Use the C bindings.
            result = _pyndn.Tlv0_1_1WireFormat_encodeSignatureValue(signature)
            return Blob(result, False)

        encoder = TlvEncoder(256)
        encoder.writeBlobTlv(Tlv.SignatureValue, signature.getSignature().buf())

        return Blob(encoder.getOutput(), False)

    def decodeLpPacket(self, lpPacket, input, copy = True):
        """
        Decode input as an NDN-TLV LpPacket and set the fields of the lpPacket
        object.

        :param LpPacket lpPacket: The LpPacket object whose fields are updated.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :param bool copy: (optional) If True, copy from the input when making
          new Blob values. If False, then Blob values share memory with the
          input, which must remain unchanged while the Blob values are used.
          If omitted, use True.
        """
        lpPacket.clear()

        decoder = TlvDecoder(input)
        endOffset = decoder.readNestedTlvsStart(Tlv.LpPacket_LpPacket)

        while decoder.getOffset() < endOffset:
            # Imitate TlvDecoder.readTypeAndLength.
            fieldType = decoder.readVarNumber()
            fieldLength = decoder.readVarNumber()
            fieldEndOffset = decoder.getOffset() + fieldLength
            if fieldEndOffset > len(input):
                raise ValueError("TLV length exceeds the buffer length")

            if fieldType == Tlv.LpPacket_Fragment:
                # Set the fragment to the bytes of the TLV value.
                lpPacket.setFragmentWireEncoding(
                  Blob(decoder.getSlice(decoder.getOffset(), fieldEndOffset), copy))
                decoder.seek(fieldEndOffset)

                # The fragment is supposed to be the last field.
                break
            elif fieldType == Tlv.LpPacket_Nack:
                networkNack = NetworkNack()
                code = decoder.readOptionalNonNegativeIntegerTlv(
                  Tlv.LpPacket_NackReason, fieldEndOffset)
                # The enum numeric values are the same as this wire format, so
                #   use as is.
                if code < 0 or code == NetworkNack.Reason.NONE:
                    # This includes an omitted NackReason.
                    networkNack.setReason(NetworkNack.Reason.NONE)
                elif (code == NetworkNack.Reason.CONGESTION or
                      code == NetworkNack.Reason.DUPLICATE or
                      code == NetworkNack.Reason.NO_ROUTE):
                    networkNack.setReason(code)
                else:
                    # Unrecognized reason.
                    networkNack.setReason(NetworkNack.Reason.OTHER_CODE)
                    networkNack.setOtherReasonCode(code)

                lpPacket.addHeaderField(networkNack)
            elif fieldType == Tlv.LpPacket_IncomingFaceId:
                incomingFaceId = IncomingFaceId()
                incomingFaceId.setFaceId(decoder.readNonNegativeInteger(fieldLength))
                lpPacket.addHeaderField(incomingFaceId)
            elif fieldType == Tlv.LpPacket_CongestionMark:
                congestionMark = CongestionMark()
                congestionMark.setCongestionMark(
                  decoder.readNonNegativeInteger(fieldLength))
                lpPacket.addHeaderField(congestionMark)
            else:
                # Unrecognized field type. The conditions for ignoring are here:
                # http://redmine.named-data.net/projects/nfd/wiki/NDNLPv2
                canIgnore = (fieldType >= Tlv.LpPacket_IGNORE_MIN and
                             fieldType <= Tlv.LpPacket_IGNORE_MAX and
                             (fieldType & 0x03) == 0)
                if not canIgnore:
                    raise ValueError("Did not get the expected TLV type")

                # Ignore.
                decoder.seek(fieldEndOffset)

            decoder.finishNestedTlvs(fieldEndOffset)

        decoder.finishNestedTlvs(endOffset)

    def encodeDelegationSet(self, delegationSet):
        """
        Encode the DelegationSet in NDN-TLV and return the encoding. Note that
        the sequence of Delegation does not have an outer TLV type and length
        because it is intended to use the type and length of a Data packet's
        Content.

        :param DelegationSet delegationSet: The DelegationSet object to
          encode.
        :return: A Blob containing the encoding.
        :rtype: Blob
        """
        encoder = TlvEncoder(256)
        Tlv0_2WireFormat._encodeDelegationSet(delegationSet, encoder)

        return Blob(encoder.getOutput(), False)

    def decodeDelegationSet(self, delegationSet, input, copy = True):
        """
        Decode input as a DelegationSet in NDN-TLV and set the fields of the
        delegationSet object. Note that the sequence of Delegation does not have
        an outer TLV type and length because it is intended to use the type and
        length of a Data packet's Content. This ignores any elements after the
        sequence of Delegation.

        :param DelegationSet delegationSet: The DelegationSet object
          whose fields are updated.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :param bool copy: (optional) If True, copy from the input when making
          new Blob values. If False, then Blob values share memory with the
          input, which must remain unchanged while the Blob values are used.
          If omitted, use True.
        """
        decoder = TlvDecoder(input)
        Tlv0_2WireFormat._decodeDelegationSet(
          delegationSet, len(input), decoder, copy)

    def encodeEncryptedContent(self, encryptedContent):
        """
        Encode the EncryptedContent v1 in NDN-TLV and return the encoding.

        :param EncryptedContent encryptedContent: The EncryptedContent object to
          encode.
        :return: A Blob containing the encoding.
        :rtype: Blob
        """
        encoder = TlvEncoder(256)
        saveLength = len(encoder)

        # Encode backwards.
        encoder.writeBlobTlv(
          Tlv.Encrypt_EncryptedPayload, encryptedContent.getPayload().buf())
        encoder.writeOptionalBlobTlv(
          Tlv.Encrypt_InitialVector, encryptedContent.getInitialVector().buf())
        # Assume the algorithmType value is the same as the TLV type.
        encoder.writeNonNegativeIntegerTlv(
          Tlv.Encrypt_EncryptionAlgorithm, encryptedContent.getAlgorithmType())
        Tlv0_2WireFormat._encodeKeyLocator(
          Tlv.KeyLocator, encryptedContent.getKeyLocator(), encoder)

        encoder.writeTypeAndLength(
          Tlv.Encrypt_EncryptedContent, len(encoder) - saveLength)

        return Blob(encoder.getOutput(), False)

    def decodeEncryptedContent(self, encryptedContent, input, copy = True):
        """
        Decode input as an EncryptedContent v1 in NDN-TLV and set the fields of the
        encryptedContent object.

        :param EncryptedContent encryptedContent: The EncryptedContent object
          whose fields are updated.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :param bool copy: (optional) If True, copy from the input when making
          new Blob values. If False, then Blob values share memory with the
          input, which must remain unchanged while the Blob values are used.
          If omitted, use True.
        """
        decoder = TlvDecoder(input)
        endOffset = decoder.readNestedTlvsStart(Tlv.Encrypt_EncryptedContent)

        encryptedContent.clear()
        Tlv0_2WireFormat._decodeKeyLocator(
          Tlv.KeyLocator, encryptedContent.getKeyLocator(), decoder, copy)
        encryptedContent.setAlgorithmType(
          decoder.readNonNegativeIntegerTlv(Tlv.Encrypt_EncryptionAlgorithm))
        encryptedContent.setInitialVector(
          Blob(decoder.readOptionalBlobTlv
           (Tlv.Encrypt_InitialVector, endOffset), copy))
        encryptedContent.setPayload(
          Blob(decoder.readBlobTlv(Tlv.Encrypt_EncryptedPayload), copy))

        decoder.finishNestedTlvs(endOffset)

    def encodeEncryptedContentV2(self, encryptedContent):
        """
        Encode the EncryptedContent v2 (used in Name-based Access Control v2) in
        NDN-TLV and return the encoding.
        See https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst .

        :param EncryptedContent encryptedContent: The EncryptedContent object to
          encode.
        :return: A Blob containing the encoding.
        :rtype: Blob
        """
        encoder = TlvEncoder(256)
        saveLength = len(encoder)

        # Encode backwards.
        if encryptedContent.getKeyLocator().getType() == KeyLocatorType.KEYNAME:
            Tlv0_2WireFormat._encodeName(
              encryptedContent.getKeyLocator().getKeyName(), encoder)
        encoder.writeOptionalBlobTlv(
          Tlv.Encrypt_EncryptedPayloadKey, encryptedContent.getPayloadKey().buf())
        encoder.writeOptionalBlobTlv(
          Tlv.Encrypt_InitialVector, encryptedContent.getInitialVector().buf())
        encoder.writeBlobTlv(
          Tlv.Encrypt_EncryptedPayload, encryptedContent.getPayload().buf())

        encoder.writeTypeAndLength(
          Tlv.Encrypt_EncryptedContent, len(encoder) - saveLength)

        return Blob(encoder.getOutput(), False)

    def decodeEncryptedContentV2(self, encryptedContent, input, copy = True):
        """
        Decode input as an EncryptedContent v2 (used in Name-based Access
        Control v2) in NDN-TLV and set the fields of the encryptedContent object.
        See https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst .

        :param EncryptedContent encryptedContent: The EncryptedContent object
          whose fields are updated.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :param bool copy: (optional) If True, copy from the input when making
          new Blob values. If False, then Blob values share memory with the
          input, which must remain unchanged while the Blob values are used.
          If omitted, use True.
        """
        decoder = TlvDecoder(input)
        endOffset = decoder.readNestedTlvsStart(Tlv.Encrypt_EncryptedContent)

        encryptedContent.clear()
        encryptedContent.setPayload(
          Blob(decoder.readBlobTlv(Tlv.Encrypt_EncryptedPayload), copy))
        encryptedContent.setInitialVector(
          Blob(decoder.readOptionalBlobTlv
           (Tlv.Encrypt_InitialVector, endOffset), copy))
        encryptedContent.setPayloadKey(
          Blob(decoder.readOptionalBlobTlv
           (Tlv.Encrypt_EncryptedPayloadKey, endOffset), copy))

        if decoder.peekType(Tlv.Name, endOffset):
            Tlv0_2WireFormat._decodeName(
              encryptedContent.getKeyLocator().getKeyName(), decoder, copy)
            encryptedContent.getKeyLocator().setType(KeyLocatorType.KEYNAME)

        decoder.finishNestedTlvs(endOffset)

    @classmethod
    def get(self):
        """
        Get a singleton instance of a Tlv0_2WireFormat.  To always use the
        preferred version NDN-TLV, you should use TlvWireFormat.get().

        :return: The singleton instance.
        :rtype: Tlv0_2WireFormat
        """
        if self._instance == None:
            self._instance = Tlv0_2WireFormat()
        return self._instance

    @staticmethod
    def _encodeNameComponent(component, encoder):
        """
        Encode the name component to the encoder as NDN-TLV. This handles
        different component types such as ImplicitSha256DigestComponent.

        :param Name.Component component: The name component to encode.
        :param TlvEncoder encoder: The encoder to receive the encoding.
        """
        if component.getType() == ComponentType.OTHER_CODE:
            type = component.getOtherTypeCode()
        else:
            # The enum values are the same as the TLV type codes.
            type = component.getType()

        encoder.writeBlobTlv(type, component.getValue().buf())

    @staticmethod
    def _decodeNameComponent(decoder, copy):
        """
        Decode the name component as NDN-TLV and return the component. This
        handles different component types such as ImplicitSha256DigestComponent.

        :param TlvDecoder decode: The decoder with the input.
        :param bool copy: If True, copy from the input when making new Blob
          values. If False, then Blob values share memory with the input, which
          must remain unchanged while the Blob values are used.
        :return: A new Name.Component.
        :rtype: Name.Component
        """
        savePosition = decoder.getOffset()
        type = decoder.readVarNumber()
        # Restore the position.
        decoder.seek(savePosition)

        value = Blob(decoder.readBlobTlv(type), copy)
        if type == Tlv.ImplicitSha256DigestComponent:
            return Name.Component.fromImplicitSha256Digest(value)
        elif type == Tlv.ParametersSha256DigestComponent:
            return Name.Component.fromParametersSha256Digest(value)
        elif type == Tlv.NameComponent:
            return Name.Component(value)
        else:
            # Unrecognized type code.
            return Name.Component(value, ComponentType.OTHER_CODE, type)

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
            Tlv0_2WireFormat._encodeNameComponent(name[i], encoder)
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
    def _decodeName(name, decoder, copy):
        """
        Clear the name, decode a Name from the decoder and set the fields of
        the name object.

        :param Name name: The name object whose fields are updated.
        :param TlvDecoder decode: The decoder with the input.
        :param bool copy: If True, copy from the input when making new Blob
          values. If False, then Blob values share memory with the input, which
          must remain unchanged while the Blob values are used.
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
            name.append(Tlv0_2WireFormat._decodeNameComponent(decoder, copy))

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
            Tlv0_2WireFormat._encodeExclude(interest.getExclude(), encoder)
        if interest.getKeyLocator().getType() != None:
            Tlv0_2WireFormat._encodeKeyLocator(
              Tlv.PublisherPublicKeyLocator, interest.getKeyLocator(), encoder)
        encoder.writeOptionalNonNegativeIntegerTlv(
          Tlv.MaxSuffixComponents, interest.getMaxSuffixComponents())
        encoder.writeOptionalNonNegativeIntegerTlv(
          Tlv.MinSuffixComponents, interest.getMinSuffixComponents())

        # Only output the type and length if values were written.
        if len(encoder) != saveLength:
            encoder.writeTypeAndLength(Tlv.Selectors, len(encoder) - saveLength)

    @staticmethod
    def _decodeSelectors(interest, decoder, copy):
        endOffset = decoder.readNestedTlvsStart(Tlv.Selectors)

        interest.setMinSuffixComponents(
          decoder.readOptionalNonNegativeIntegerTlv
            (Tlv.MinSuffixComponents, endOffset))
        interest.setMaxSuffixComponents(
          decoder.readOptionalNonNegativeIntegerTlv
            (Tlv.MaxSuffixComponents, endOffset))

        if decoder.peekType(Tlv.PublisherPublicKeyLocator, endOffset):
            Tlv0_2WireFormat._decodeKeyLocator(
              Tlv.PublisherPublicKeyLocator, interest.getKeyLocator(), decoder,
              copy)
        else:
            interest.getKeyLocator().clear()

        if decoder.peekType(Tlv.Exclude, endOffset):
            Tlv0_2WireFormat._decodeExclude(interest.getExclude(), decoder, copy)
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
                Tlv0_2WireFormat._encodeNameComponent(entry.getComponent(), encoder)
            elif entry.getType() == Exclude.ANY:
                encoder.writeTypeAndLength(Tlv.Any, 0)
            else:
                # We don't expect this to happen, but check anyway.
                raise RuntimeError("Unrecognized Exclude type" +
                                   str(entry.getType()))

        encoder.writeTypeAndLength(Tlv.Exclude, len(encoder) - saveLength)

    @staticmethod
    def _decodeExclude(exclude, decoder, copy):
        endOffset = decoder.readNestedTlvsStart(Tlv.Exclude)

        exclude.clear()
        while decoder.getOffset() < endOffset:
            if decoder.peekType(Tlv.Any, endOffset):
                # Read past the Any TLV.
                decoder.readBooleanTlv(Tlv.Any, endOffset);
                exclude.appendAny()
            else:
                exclude.appendComponent(
                  Tlv0_2WireFormat._decodeNameComponent(decoder, copy))

        decoder.finishNestedTlvs(endOffset)

    @staticmethod
    def _encodeMetaInfo(metaInfo, encoder):
        saveLength = len(encoder)

        # Encode backwards.
        finalBlockIdBuf = metaInfo.getFinalBlockId().getValue().buf()
        if finalBlockIdBuf != None and len(finalBlockIdBuf) > 0:
            # FinalBlockId has an inner NameComponent.
            finalBlockIdSaveLength = len(encoder)
            Tlv0_2WireFormat._encodeNameComponent(
              metaInfo.getFinalBlockId(), encoder)
            encoder.writeTypeAndLength(
              Tlv.FinalBlockId, len(encoder) - finalBlockIdSaveLength)

        encoder.writeOptionalNonNegativeIntegerTlvFromFloat(
          Tlv.FreshnessPeriod, metaInfo.getFreshnessPeriod())
        if metaInfo.getType() != ContentType.BLOB:
            # Not the default, so we need to encode the type.
            if (metaInfo.getType() == ContentType.LINK or
                metaInfo.getType() == ContentType.KEY or
                metaInfo.getType() == ContentType.NACK):
                # The ContentType enum is set up with the correct integer for
                # each NDN-TLV ContentType.
                encoder.writeNonNegativeIntegerTlv(
                  Tlv.ContentType, metaInfo.getType())
            elif metaInfo.getType() == ContentType.OTHER_CODE:
                encoder.writeNonNegativeIntegerTlv(
                  Tlv.ContentType, metaInfo.getOtherTypeCode())
            else:
              # We don't expect this to happen.
                raise RuntimeError("unrecognized TLV ContentType")

        encoder.writeTypeAndLength(Tlv.MetaInfo, len(encoder) - saveLength)

    @staticmethod
    def _decodeMetaInfo(metaInfo, decoder, copy):
        endOffset = decoder.readNestedTlvsStart(Tlv.MetaInfo)

        typeCode = decoder.readOptionalNonNegativeIntegerTlv(
          Tlv.ContentType, endOffset)
        if typeCode == None or typeCode < 0 or typeCode == ContentType.BLOB:
            # Default to BLOB if the value is omitted.
            metaInfo.setType(ContentType.BLOB)
        elif (typeCode == ContentType.LINK or
              typeCode == ContentType.KEY or
              typeCode == ContentType.NACK):
            # The ContentType enum is set up with the correct integer for each
            # NDN-TLV ContentType.
            metaInfo.setType(typeCode)
        else:
            # Unrecognized content type.
            metaInfo.setType(ContentType.OTHER_CODE)
            metaInfo.setOtherTypeCode(typeCode)

        metaInfo.setFreshnessPeriod(
          decoder.readOptionalNonNegativeIntegerTlvAsFloat(
            Tlv.FreshnessPeriod, endOffset))
        if decoder.peekType(Tlv.FinalBlockId, endOffset):
            finalBlockIdEndOffset = decoder.readNestedTlvsStart(Tlv.FinalBlockId)
            metaInfo.setFinalBlockId(
              Tlv0_2WireFormat._decodeNameComponent(decoder, copy))
            decoder.finishNestedTlvs(finalBlockIdEndOffset)
        else:
            metaInfo.setFinalBlockId(None)

        decoder.finishNestedTlvs(endOffset)

    @staticmethod
    def _encodeSignatureInfo(signature, encoder):
        """
        An internal method to encode signature as the appropriate form of
        SignatureInfo in NDN-TLV.

        :param Signature signature: An object of a subclass of Signature to encode.
        :param TlvEncoder encoder: The TlvEncoder to receive the encoding.
        """
        if isinstance(signature, GenericSignature):
            # Handle GenericSignature separately since it has the entire encoding.
            encoding = signature.getSignatureInfoEncoding()

            # Do a test decoding to sanity check that it is valid TLV.
            try:
                decoder = TlvDecoder(encoding.buf())
                endOffset = decoder.readNestedTlvsStart(Tlv.SignatureInfo)
                decoder.readNonNegativeIntegerTlv(Tlv.SignatureType)
                # Skip unrecognized TLVs, even if they have a critical type code.
                decoder.finishNestedTlvs(endOffset, True)
            except ValueError as ex:
                raise ValueError(
                  "The GenericSignature encoding is not a valid NDN-TLV SignatureInfo: " +
                   str(ex))

            encoder.writeBuffer(encoding.buf())
            return

        saveLength = len(encoder)

        if isinstance(signature, Sha256WithRsaSignature):
            # Encode backwards.
            if signature.getValidityPeriod().hasPeriod():
                Tlv0_2WireFormat._encodeValidityPeriod(
                  signature.getValidityPeriod(), encoder)
            Tlv0_2WireFormat._encodeKeyLocator(
              Tlv.KeyLocator, signature.getKeyLocator(), encoder)
            encoder.writeNonNegativeIntegerTlv(
              Tlv.SignatureType, Tlv.SignatureType_SignatureSha256WithRsa)
        elif isinstance(signature, Sha256WithEcdsaSignature):
            # Encode backwards.
            if signature.getValidityPeriod().hasPeriod():
                Tlv0_2WireFormat._encodeValidityPeriod(
                  signature.getValidityPeriod(), encoder)
            Tlv0_2WireFormat._encodeKeyLocator(
              Tlv.KeyLocator, signature.getKeyLocator(), encoder)
            encoder.writeNonNegativeIntegerTlv(
              Tlv.SignatureType, Tlv.SignatureType_SignatureSha256WithEcdsa)
        elif isinstance(signature, HmacWithSha256Signature):
            Tlv0_2WireFormat._encodeKeyLocator(
              Tlv.KeyLocator, signature.getKeyLocator(), encoder)
            encoder.writeNonNegativeIntegerTlv(
              Tlv.SignatureType, Tlv.SignatureType_SignatureHmacWithSha256)
        elif isinstance(signature, DigestSha256Signature):
            encoder.writeNonNegativeIntegerTlv(
              Tlv.SignatureType, Tlv.SignatureType_DigestSha256)
        else:
            raise RuntimeError(
              "encodeSignatureInfo: Unrecognized Signature object type")

        encoder.writeTypeAndLength(Tlv.SignatureInfo, len(encoder) - saveLength)

    @staticmethod
    def _decodeSignatureInfo(signatureHolder, decoder, copy):
        beginOffset = decoder.getOffset()
        endOffset = decoder.readNestedTlvsStart(Tlv.SignatureInfo)

        signatureType = decoder.readNonNegativeIntegerTlv(Tlv.SignatureType)
        if signatureType == Tlv.SignatureType_SignatureSha256WithRsa:
            signatureHolder.setSignature(Sha256WithRsaSignature())
            # Modify signatureHolder's signature object because if we create an object
            #   and set it, then signatureHolder will have to copy all the fields.
            signatureInfo = signatureHolder.getSignature()
            Tlv0_2WireFormat._decodeKeyLocator(
              Tlv.KeyLocator, signatureInfo.getKeyLocator(),
              decoder, copy)
            if decoder.peekType(Tlv.ValidityPeriod_ValidityPeriod, endOffset):
                Tlv0_2WireFormat._decodeValidityPeriod(
                  signatureInfo.getValidityPeriod(), decoder)
        elif signatureType == Tlv.SignatureType_SignatureSha256WithEcdsa:
            signatureHolder.setSignature(Sha256WithEcdsaSignature())
            signatureInfo = signatureHolder.getSignature()
            Tlv0_2WireFormat._decodeKeyLocator(
              Tlv.KeyLocator, signatureInfo.getKeyLocator(),
              decoder, copy)
            if decoder.peekType(Tlv.ValidityPeriod_ValidityPeriod, endOffset):
                Tlv0_2WireFormat._decodeValidityPeriod(
                  signatureInfo.getValidityPeriod(), decoder)
        elif signatureType == Tlv.SignatureType_SignatureHmacWithSha256:
            signatureHolder.setSignature(HmacWithSha256Signature())
            Tlv0_2WireFormat._decodeKeyLocator(
              Tlv.KeyLocator, signatureHolder.getSignature().getKeyLocator(),
              decoder, copy)
        elif signatureType == Tlv.SignatureType_DigestSha256:
            signatureHolder.setSignature(DigestSha256Signature())
        else:
            signatureHolder.setSignature(GenericSignature())
            signatureInfo = signatureHolder.getSignature()

            # Get the bytes of the SignatureInfo TLV.
            signatureInfo.setSignatureInfoEncoding(
              Blob(decoder.getSlice(beginOffset, endOffset), copy), signatureType)
            # Skip the remaining TLVs now, allowing unrecognized critical type codes.
            decoder.finishNestedTlvs(endOffset, True)

        decoder.finishNestedTlvs(endOffset)

    @staticmethod
    def _encodeKeyLocator(type, keyLocator, encoder):
        saveLength = len(encoder)

        # Encode backwards.
        if keyLocator.getType() != None:
            if keyLocator.getType() == KeyLocatorType.KEYNAME:
                Tlv0_2WireFormat._encodeName(keyLocator.getKeyName(), encoder)
            elif (keyLocator.getType() == KeyLocatorType.KEY_LOCATOR_DIGEST and
                  len(keyLocator.getKeyData()) > 0):
                encoder.writeBlobTlv(Tlv.KeyLocatorDigest,
                                     keyLocator.getKeyData().buf())
            else:
                raise RuntimeError("Unrecognized KeyLocatorType " +
                                   str(keyLocator.getType()))

        encoder.writeTypeAndLength(type, len(encoder) - saveLength)

    @staticmethod
    def _decodeKeyLocator(expectedType, keyLocator, decoder, copy):
        endOffset = decoder.readNestedTlvsStart(expectedType)

        keyLocator.clear()

        if decoder.getOffset() == endOffset:
            # The KeyLocator is omitted, so leave the fields as none.
            return

        if decoder.peekType(Tlv.Name, endOffset):
            # KeyLocator is a Name.
            keyLocator.setType(KeyLocatorType.KEYNAME)
            Tlv0_2WireFormat._decodeName(keyLocator.getKeyName(), decoder, copy)
        elif decoder.peekType(Tlv.KeyLocatorDigest, endOffset):
            # KeyLocator is a KeyLocatorDigest.
            keyLocator.setType(KeyLocatorType.KEY_LOCATOR_DIGEST)
            keyLocator.setKeyData(
              Blob(decoder.readBlobTlv(Tlv.KeyLocatorDigest), copy))
        else:
            raise RuntimeError("decodeKeyLocator: Unrecognized key locator type")

        decoder.finishNestedTlvs(endOffset)

    @staticmethod
    def _encodeValidityPeriod(validityPeriod, encoder):
        saveLength = len(encoder)

        # Encode backwards.
        encoder.writeBlobTlv(Tlv.ValidityPeriod_NotAfter,
          Blob(Tlv0_2WireFormat.toIsoString(validityPeriod.getNotAfter())).buf())
        encoder.writeBlobTlv(Tlv.ValidityPeriod_NotBefore,
          Blob(Tlv0_2WireFormat.toIsoString(validityPeriod.getNotBefore())).buf())

        encoder.writeTypeAndLength(
          Tlv.ValidityPeriod_ValidityPeriod, len(encoder) - saveLength)

    @staticmethod
    def _decodeValidityPeriod(validityPeriod, decoder):
        endOffset = decoder.readNestedTlvsStart(
          Tlv.ValidityPeriod_ValidityPeriod)

        validityPeriod.clear()

        # Set copy false since we just immediately get the string.
        isoString = Blob(
          decoder.readBlobTlv(Tlv.ValidityPeriod_NotBefore), False)
        notBefore = Tlv0_2WireFormat.fromIsoString(str(isoString))
        isoString = Blob(
          decoder.readBlobTlv(Tlv.ValidityPeriod_NotAfter), False)
        notAfter = Tlv0_2WireFormat.fromIsoString(str(isoString))

        validityPeriod.setPeriod(notBefore, notAfter)

        decoder.finishNestedTlvs(endOffset)

    @staticmethod
    def _encodeControlParameters(controlParameters, encoder):
        saveLength = len(encoder)

        # Encode backwards.
        encoder.writeOptionalNonNegativeIntegerTlvFromFloat(
          Tlv.ControlParameters_ExpirationPeriod,
          controlParameters.getExpirationPeriod())

        if controlParameters.getStrategy().size() > 0:
            strategySaveLength = len(encoder)
            Tlv0_2WireFormat._encodeName(controlParameters.getStrategy(), encoder)
            encoder.writeTypeAndLength(
              Tlv.ControlParameters_Strategy,
              len(encoder) - strategySaveLength)

        flags = controlParameters.getForwardingFlags().getNfdForwardingFlags()
        if (flags != RegistrationOptions().getNfdForwardingFlags()):
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

        if len(controlParameters.getUri()) != 0:
            encoder.writeBlobTlv(
              Tlv.ControlParameters_Uri, Blob(controlParameters.getUri()).buf())

        encoder.writeOptionalNonNegativeIntegerTlv(
          Tlv.ControlParameters_FaceId, controlParameters.getFaceId())
        if controlParameters.getName() != None:
          Tlv0_2WireFormat._encodeName(controlParameters.getName(), encoder)

        encoder.writeTypeAndLength(Tlv.ControlParameters_ControlParameters,
                                   len(encoder) - saveLength)

    @staticmethod
    def _decodeControlParameters(controlParameters, decoder, copy):
        controlParameters.clear()

        endOffset = decoder.readNestedTlvsStart(
          Tlv.ControlParameters_ControlParameters)

        # decode name
        if decoder.peekType(Tlv.Name, endOffset):
            name = Name()
            Tlv0_2WireFormat._decodeName(name, decoder, copy)
            controlParameters.setName(name)

        # decode face ID
        controlParameters.setFaceId(decoder.readOptionalNonNegativeIntegerTlv
            (Tlv.ControlParameters_FaceId, endOffset))

        # decode URI
        if decoder.peekType(Tlv.ControlParameters_Uri, endOffset):
            # Set copy False since we just immediately get a string.
            uri = Blob(
              decoder.readOptionalBlobTlv(Tlv.ControlParameters_Uri, endOffset),
              False)
            controlParameters.setUri(str(uri))

        decoder.skipOptionalTlv(Tlv.ControlParameters_LocalUri, endOffset)

        # decode integers
        controlParameters.setLocalControlFeature(
          decoder.readOptionalNonNegativeIntegerTlv
            (Tlv.ControlParameters_LocalControlFeature, endOffset))
        controlParameters.setOrigin(
          decoder.readOptionalNonNegativeIntegerTlv
            (Tlv.ControlParameters_Origin, endOffset))
        controlParameters.setCost(
          decoder.readOptionalNonNegativeIntegerTlv
            (Tlv.ControlParameters_Cost, endOffset))

        decoder.skipOptionalTlv(Tlv.ControlParameters_Capacity, endOffset)
        decoder.skipOptionalTlv(Tlv.ControlParameters_Count, endOffset)
        decoder.skipOptionalTlv(
          Tlv.ControlParameters_BaseCongestionMarkingInterval, endOffset)
        decoder.skipOptionalTlv(
          Tlv.ControlParameters_DefaultCongestionThreshold, endOffset)
        decoder.skipOptionalTlv(Tlv.ControlParameters_Mtu, endOffset)

        # set forwarding flags
        if decoder.peekType(Tlv.ControlParameters_Flags, endOffset):
            flags = RegistrationOptions()
            flags.setNfdForwardingFlags(
              decoder.readNonNegativeIntegerTlv(Tlv.ControlParameters_Flags))
            controlParameters.setForwardingFlags(flags)

        decoder.skipOptionalTlv(Tlv.ControlParameters_Mask, endOffset)

        # decode strategy
        if decoder.peekType(Tlv.ControlParameters_Strategy, endOffset):
            strategyEndOffset = decoder.readNestedTlvsStart(
              Tlv.ControlParameters_Strategy)
            Tlv0_2WireFormat._decodeName(
              controlParameters.getStrategy(), decoder, copy)
            decoder.finishNestedTlvs(strategyEndOffset)

        # decode expiration period
        controlParameters.setExpirationPeriod(
          decoder.readOptionalNonNegativeIntegerTlv(
            Tlv.ControlParameters_ExpirationPeriod, endOffset))

        decoder.finishNestedTlvs(endOffset)

    @staticmethod
    def _encodeDelegationSet(delegationSet, encoder):
        """
        Encode delegationSet to the encoder as a sequence of NDN-TLV Delegation.
        Note that the sequence of Delegation does not have an outer TLV type and
        length because (when used in a Link object) it is intended to use the
        type and length of a Data packet's Content.

        :param DelegationSet delegationSet: The DelegationSet object to encode.
        :param TlvEncoder encoder The TlvEncoder to receive the encoding.
        """
        # Encode backwards.
        for i in range(delegationSet.size() - 1, -1, -1):
            saveLength = len(encoder)

            Tlv0_2WireFormat._encodeName(delegationSet.get(i).getName(), encoder)
            encoder.writeNonNegativeIntegerTlv(
              Tlv.Link_Preference, delegationSet.get(i).getPreference())

            encoder.writeTypeAndLength(
              Tlv.Link_Delegation, len(encoder) - saveLength)

    @staticmethod
    def _decodeDelegationSet(delegationSet, endOffset, decoder, copy):
        """
        Decode input as a sequence of NDN-TLV Delegation and set the fields of
        the delegationSet object. Note that the sequence of Delegation does not
        have an outer TLV type and length because (when used in a Link object)
        it is intended to use the type and length of a Data packet's Content.

        :param DelegationSet delegationSet: The DelegationSet object whose
          fields are updated.
        :param int endOffset: Decode elements up to endOffset in the input. This
          does not call finishNestedTlvs.
        :param TlvDecoder decoder: The decoder with the input to decode.
        :param bool copy: If True, copy from the input when making new Blob
          values. If False, then Blob values share memory with the input, which
          must remain unchanged while the Blob values are used.
        """
        delegationSet.clear()
        while decoder.getOffset() < endOffset:
            decoder.readTypeAndLength(Tlv.Link_Delegation)
            preference = decoder.readNonNegativeIntegerTlv(Tlv.Link_Preference)
            name = Name()
            Tlv0_2WireFormat._decodeName(name, decoder, copy)

            # Add unsorted to preserve the order so that Interest selected
            # delegation index will work.
            delegationSet.addUnsorted(preference, name)

    @staticmethod
    def _encodeInterestV03(interest):
        """
        Encode interest in NDN-TLV format v0.3 and return the encoding.

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
        # TODO: Throw error if the interest speficies V02 fields.

        encoder = TlvEncoder(256)
        saveLength = len(encoder)

        # Encode backwards.
        encoder.writeOptionalBlobTlv(
          Tlv.ApplicationParameters, interest.getApplicationParameters().buf())
        # TODO: HopLimit.
        encoder.writeOptionalNonNegativeIntegerTlvFromFloat(
          Tlv.InterestLifetime, interest.getInterestLifetimeMilliseconds())

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

        if interest.getForwardingHint().size() > 0:
            if interest.getSelectedDelegationIndex() != None:
                raise RuntimeError(
                  "An Interest may not have a selected delegation when encoding a forwarding hint")
            if interest.hasLink():
                raise RuntimeError(
                  "An Interest may not have a link object when encoding a forwarding hint")

            forwardingHintSaveLength = len(encoder)
            Tlv0_2WireFormat._encodeDelegationSet(
              interest.getForwardingHint(), encoder)
            encoder.writeTypeAndLength(
              Tlv.ForwardingHint, len(encoder) - forwardingHintSaveLength)

        if interest.getMustBeFresh():
            encoder.writeTypeAndLength(Tlv.MustBeFresh, 0)
        if interest.getCanBePrefix():
            encoder.writeTypeAndLength(Tlv.CanBePrefix, 0)

        (tempSignedPortionBeginOffset, tempSignedPortionEndOffset) = \
          Tlv0_2WireFormat._encodeName(interest.getName(), encoder)
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

    @staticmethod
    def _decodeInterestV03(interest, input, copy):
        """
        Decode input as an Interest in NDN-TLV format v0.3 and set the fields of
        the Interest object. This private method is called if the main
        decodeInterest fails to decode as v0.2. This ignores HopLimit and
        Parameters, and interprets CanBePrefix using MaxSuffixComponents.

        :param Interest interest: The Interest object whose fields are updated.
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :param bool copy: (optional) If True, copy from the input when making
          new Blob values. If False, then Blob values share memory with the
          input, which must remain unchanged while the Blob values are used.
          If omitted, use True.
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
        offsets = Tlv0_2WireFormat._decodeName(interest.getName(), decoder, copy)

        # In v0.2 semantics, this calls setMaxSuffixComponents.
        interest.setCanBePrefix(
          decoder.readBooleanTlv(Tlv.CanBePrefix, endOffset))

        interest.setMustBeFresh(
          decoder.readBooleanTlv(Tlv.MustBeFresh, endOffset))

        if decoder.peekType(Tlv.ForwardingHint, endOffset):
            forwardingHintEndOffset = decoder.readNestedTlvsStart(
              Tlv.ForwardingHint)
            Tlv0_2WireFormat._decodeDelegationSet(
              interest.getForwardingHint(), forwardingHintEndOffset, decoder,
              copy)
            decoder.finishNestedTlvs(forwardingHintEndOffset)
        else:
            interest.getForwardingHint().clear()

        nonce = decoder.readOptionalBlobTlv(Tlv.Nonce, endOffset)
        interest.setInterestLifetimeMilliseconds(
           decoder.readOptionalNonNegativeIntegerTlvAsFloat
           (Tlv.InterestLifetime, endOffset))

        # Clear the unused fields.
        interest.setMinSuffixComponents(None)
        interest.getKeyLocator().clear()
        interest.getExclude().clear()
        interest.setChildSelector(None)
        interest.unsetLink()
        interest.setSelectedDelegationIndex(None)

        # Ignore the HopLimit.
        decoder.readOptionalBlobTlv(Tlv.HopLimit, endOffset)

        interest.setApplicationParameters(
          Blob(decoder.readOptionalBlobTlv(Tlv.ApplicationParameters, endOffset), copy))

        # Set the nonce last because setting other interest fields clears it.
        interest.setNonce(Blob() if nonce == None else Blob(nonce, copy))

        decoder.finishNestedTlvs(endOffset)
        return offsets

    @staticmethod
    def toIsoString(msSince1970):
        """
        Convert a UNIX timestamp to ISO time representation with the "T" in the
        middle.

        :param float msSince1970: Timestamp as milliseconds since Jan 1, 1970 UTC.
        :return: The string representation.
        :rtype: str
        """
        dateFormat = "%Y%m%dT%H%M%S"
        return Common.datetimeFromTimestamp(
          round(msSince1970 / 1000.0) * 1000).strftime(dateFormat)

    @staticmethod
    def fromIsoString(timeString):
        """
        Convert an ISO time representation with the "T" in the middle to a UNIX
        timestamp.

        :param str timeString: The ISO time representation.
        :return: The timestamp as milliseconds since Jan 1, 1970 UTC.
        :rtype: float
        """
        if len(timeString) != 15 or timeString[8:9] != 'T':
            raise RuntimeError("fromIsoString: Format is not the expected yyyymmddThhmmss")

        utc = datetime(
          int(timeString[0:4]),
          int(timeString[4:6]),
          int(timeString[6:8]),
          int(timeString[9:11]),
          int(timeString[11:13]),
          int(timeString[13:15]))
        return (utc - Tlv0_2WireFormat._posixEpoch).total_seconds() * 1000.0

    _posixEpoch = datetime.utcfromtimestamp(0)

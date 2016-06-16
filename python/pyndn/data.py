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
This module defines the NDN Data class.
"""

from pyndn.encoding.wire_format import WireFormat
from pyndn.util.blob import Blob
from pyndn.util.signed_blob import SignedBlob
from pyndn.util.change_counter import ChangeCounter
from pyndn.name import Name
from pyndn.meta_info import MetaInfo
from pyndn.sha256_with_rsa_signature import Sha256WithRsaSignature
from pyndn.lp.incoming_face_id import IncomingFaceId

class Data(object):
    def __init__(self, value = None):
        if isinstance(value, Data):
            # Copy the values.
            self._name = ChangeCounter(Name(value.getName()))
            self._metaInfo = ChangeCounter(MetaInfo(value.getMetaInfo()))
            self._signature = ChangeCounter(value.getSignature().clone())
            self._content = value._content
            self._defaultWireEncoding = value.getDefaultWireEncoding()
            self._defaultWireEncodingFormat = value._defaultWireEncodingFormat
        else:
            self._name = ChangeCounter(Name(value) if type(value) is Name
                                                   else Name())
            self._metaInfo = ChangeCounter(MetaInfo())
            self._signature = ChangeCounter(Sha256WithRsaSignature())
            self._content = Blob()
            self._defaultWireEncoding = SignedBlob()
            self._defaultWireEncodingFormat = None

        self._getDefaultWireEncodingChangeCount = 0
        self._changeCount = 0
        self._lpPacket = None

    def wireEncode(self, wireFormat = None):
        """
        Encode this Data for a particular wire format. If wireFormat is the
        default wire format, also set the defaultWireEncoding field to the
        encoded result.

        :param wireFormat: (optional) A WireFormat object used to encode this
           Data object. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        :return: The encoded buffer in a SignedBlob object.
        :rtype: SignedBlob
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        if (not self.getDefaultWireEncoding().isNull() and
            self.getDefaultWireEncodingFormat() == wireFormat):
            # We already have an encoding in the desired format.
            return self.getDefaultWireEncoding()

        (encoding, signedPortionBeginOffset, signedPortionEndOffset) = \
          wireFormat.encodeData(self)
        wireEncoding = SignedBlob(
          encoding, signedPortionBeginOffset, signedPortionEndOffset)

        if wireFormat == WireFormat.getDefaultWireFormat():
            # This is the default wire encoding.
            self._setDefaultWireEncoding(
              wireEncoding, WireFormat.getDefaultWireFormat())
        return wireEncoding

    def wireDecode(self, input, wireFormat = None):
        """
        Decode the input using a particular wire format and update this Data.
        If wireFormat is the default wire format, also set the
        defaultWireEncoding to another pointer to the input.

        :param input: The array with the bytes to decode. If input is not a
          Blob, then copy the bytes to save the defaultWireEncoding (otherwise
          take another pointer to the same Blob).
        :type input: A Blob or an array type with int elements
        :param wireFormat: (optional) A WireFormat object used to decode this
           Data object. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        # If input is a blob, get its buf().
        decodeBuffer = input.buf() if isinstance(input, Blob) else input
        (signedPortionBeginOffset, signedPortionEndOffset) = \
          wireFormat.decodeData(self, decodeBuffer)

        if wireFormat == WireFormat.getDefaultWireFormat():
            # This is the default wire encoding.  In the Blob constructor, set
            #   copy true, but if input is already a Blob, it won't copy.
            self._setDefaultWireEncoding(SignedBlob(
                Blob(input, True),
                signedPortionBeginOffset, signedPortionEndOffset),
            WireFormat.getDefaultWireFormat())
        else:
            self._setDefaultWireEncoding(SignedBlob(), None)

    def getName(self):
        """
        Get the data packet's name.

        :return: The name.
        :rtype: Name
        """
        return self._name.get()

    def getMetaInfo(self):
        """
        Get the data packet's meta info.

        :return: The meta info.
        :rtype: MetaInfo
        """
        return self._metaInfo.get()

    def getSignature(self):
        """
        Get the data packet's signature object.

        :return: The signature object.
        :rtype: a subclass of Signature such as Sha256WithRsaSignature
        """
        return self._signature.get()

    def getContent(self):
        """
        Get the data packet's content.

        :return: The content as a Blob, which isNull() if unspecified.
        :rtype: Blob
        """
        return self._content

    def getDefaultWireEncoding(self):
        """
        Return the default wire encoding, which was encoded with
        getDefaultWireEncodingFormat().

        :return: The default wire encoding, whose isNull() may be true if there
          is no default wire encoding.
        :rtype: SignedBlob
        """
        if self._getDefaultWireEncodingChangeCount != self.getChangeCount():
            # The values have changed, so the default wire encoding is
            # invalidated.
            self._defaultWireEncoding = SignedBlob()
            self._defaultWireEncodingFormat = None
            self._getDefaultWireEncodingChangeCount = self.getChangeCount()

        return self._defaultWireEncoding

    def getDefaultWireEncodingFormat(self):
        """
        Get the WireFormat which is used by getDefaultWireEncoding().

        :return: The WireFormat, which is only meaningful if the
          getDefaultWireEncoding() is not isNull().
        :rtype: WireFormat
        """
        return self._defaultWireEncodingFormat

    def getIncomingFaceId(self):
        """
        Get the incoming face ID according to the incoming packet header.

        :return: The incoming face ID. If not specified, return None.
        :rtype: int
        """
        field = (None if self._lpPacket == None
                 else IncomingFaceId.getFirstHeader(self._lpPacket))
        return None if field == None else field.getFaceId()

    def setName(self, name):
        """
        Set name to a copy of the given Name.

        :param Name name: The Name which is copied.
        :return: This Data so that you can chain calls to update values.
        :rtype: Data
        """
        self._name.set(name if type(name) is Name else Name(name))
        self._changeCount += 1
        return self

    def setMetaInfo(self, metaInfo):
        """
        Set metaInfo to a copy of the given MetaInfo.

        :param MetaInfo metaInfo: The MetaInfo which is copied.
        :return: This Data so that you can chain calls to update values.
        :rtype: Data
        """
        self._metaInfo.set(MetaInfo() if metaInfo == None
                                      else MetaInfo(metaInfo))
        self._changeCount += 1
        return self

    def setSignature(self, signature):
        """
        Set the signature to a copy of the given signature.

        :param signature: The signature object which is cloned.
        :type signature: a subclass of Signature such as Sha256WithRsaSignature
        :return: This Data so that you can chain calls to update values.
        :rtype: Data
        """
        self._signature.set(Sha256WithRsaSignature() if signature == None
                                                     else signature.clone())
        self._changeCount += 1
        return self

    def setContent(self, content):
        """
        Set the content to the given value.

        :param content: The array with the content bytes. If content is not a
          Blob, then create a new Blob to copy the bytes (otherwise
          take another pointer to the same Blob).
        :type content: A Blob or an array type with int elements
        """
        self._content = content if isinstance(content, Blob) else Blob(content)
        self._changeCount += 1

    def setLpPacket(self, lpPacket):
        """
        An internal library method to set the LpPacket for an incoming packet.
        The application should not call this.

        :param LpPacket lpPacket: The LpPacket. This does not make a copy.
        :return: This Data so that you can chain calls to update values.
        :rtype: Data
        :note: This is an experimental feature. This API may change in the future.
        """
        self._lpPacket = lpPacket
        # Don't update _changeCount since this doesn't affect the wire encoding.
        return self

    def getChangeCount(self):
        """
        Get the change count, which is incremented each time this object
        (or a child object) is changed.

        :return: The change count.
        :rtype: int
        """
        # Make sure each of the checkChanged is called.
        changed = self._name.checkChanged()
        changed = self._metaInfo.checkChanged() or changed
        changed = self._signature.checkChanged() or changed
        if changed:
            # A child object has changed, so update the change count.
            self._changeCount += 1

        return self._changeCount

    def _setDefaultWireEncoding(
          self, defaultWireEncoding, defaultWireEncodingFormat):
        self._defaultWireEncoding = defaultWireEncoding
        self._defaultWireEncodingFormat = defaultWireEncodingFormat
        # Set _getDefaultWireEncodingChangeCount so that the next call to
        # getDefaultWireEncoding() won't clear _defaultWireEncoding.
        self._getDefaultWireEncodingChangeCount = self.getChangeCount()

    # Create managed properties for read/write properties of the class for more pythonic syntax.
    name = property(getName, setName)
    metaInfo = property(getMetaInfo, setMetaInfo)
    signature = property(getSignature, setSignature)
    content = property(getContent, setContent)




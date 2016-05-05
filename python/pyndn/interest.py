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
This module defines the NDN Interest class.
"""

from random import SystemRandom
from pyndn.encoding.wire_format import WireFormat
from pyndn.util.blob import Blob
from pyndn.util.signed_blob import SignedBlob
from pyndn.util.change_counter import ChangeCounter
from pyndn.name import Name
from pyndn.key_locator import KeyLocator
from pyndn.exclude import Exclude
from pyndn.link import Link
from pyndn.lp.incoming_face_id import IncomingFaceId

class Interest(object):
    def __init__(self, value = None):
        if type(value) is Interest:
            # Copy the values.
            self._name = ChangeCounter(Name(value.getName()))
            self._minSuffixComponents = value._minSuffixComponents
            self._maxSuffixComponents = value._maxSuffixComponents
            self._keyLocator = ChangeCounter(KeyLocator(value.getKeyLocator()))
            self._exclude = ChangeCounter(Exclude(value.getExclude()))
            self._childSelector = value._childSelector
            self._mustBeFresh = value._mustBeFresh

            self._nonce = value.getNonce()
            self._interestLifetimeMilliseconds = value._interestLifetimeMilliseconds
            self._linkWireEncoding = value._linkWireEncoding
            self._linkWireEncodingFormat = value._linkWireEncodingFormat
            self._link = ChangeCounter(None)
            if value._link.get() != None:
              self._link.set(Link(value._link.get()))
            self._selectedDelegationIndex = value._selectedDelegationIndex
            self._defaultWireEncoding = value.getDefaultWireEncoding()
            self._defaultWireEncodingFormat = value._defaultWireEncodingFormat
        else:
            self._name = ChangeCounter(Name(value) if type(value) is Name
                                                   else Name())
            self._minSuffixComponents = None
            self._maxSuffixComponents = None
            self._keyLocator = ChangeCounter(KeyLocator())
            self._exclude = ChangeCounter(Exclude())
            self._childSelector = None
            self._mustBeFresh = True

            self._nonce = Blob()
            self._interestLifetimeMilliseconds = None
            self._linkWireEncoding = Blob()
            self._linkWireEncodingFormat = None
            self._link = ChangeCounter(None)
            self._selectedDelegationIndex = None
            self._defaultWireEncoding = SignedBlob()
            self._defaultWireEncodingFormat = None

        self._getNonceChangeCount = 0
        self._getDefaultWireEncodingChangeCount = 0
        self._changeCount = 0
        self._lpPacket = None

    def getName(self):
        """
        Get the interest Name.

        :return: The name.  The name size() may be 0 if not specified.
        :rtype: Name
        """
        return self._name.get()

    def getMinSuffixComponents(self):
        """
        Get the min suffix components.

        :return: The min suffix components, or None if not specified.
        :rtype: int
        """
        return self._minSuffixComponents

    def getMaxSuffixComponents(self):
        """
        Get the max suffix components.

        :return: The max suffix components, or None if not specified.
        :rtype: int
        """
        return self._maxSuffixComponents

    def getKeyLocator(self):
        """
        Get the interest key locator.

        :return: The key locator. If getType() is None, then the key locator
          is not specified.
        :rtype: KeyLocator
        """
        return self._keyLocator.get()

    def getExclude(self):
        """
        Get the exclude object.

        :return: The exclude object. If the exclude size() is zero, then
          the exclude is not specified.
        :rtype: Exclude
        """
        return self._exclude.get()

    def getChildSelector(self):
        """
        Get the child selector.

        :return: The child selector, or None if not specified.
        :rtype: int
        """
        return self._childSelector

    def getMustBeFresh(self):
        """
        Get the must be fresh flag.

        :return: The must be fresh flag.  If not specified, the default is
          True.
        :rtype: bool
        """
        return self._mustBeFresh

    def getNonce(self):
        """
        Return the nonce value from the incoming interest.  If you change any of
        the fields in this Interest object, then the nonce value is cleared.

        :return: The nonce.  If isNull() then the nonce is omitted.
        :rtype: Blob
        """
        if self._getNonceChangeCount != self.getChangeCount():
            # The values have changed, so the existing nonce is invalidated.
            self._nonce = Blob()
            self._getNonceChangeCount = self.getChangeCount()

        return self._nonce

    def hasLink(self):
        """
        Check if this interest has a link object (or a link wire encoding which
        can be decoded to make the link object).

        :return:  True if this interest has a link object, False if not.
        :rtype: bool
        """
        return self._link.get() != None or not self._linkWireEncoding.isNull()

    def getLink(self):
        """
        Get the link object. If necessary, decode it from the link wire encoding.

        :return: The link object, or null if not specified.
        :rtype: Link
        :raises ValueError: For error decoding the link wire encoding (if
          necessary).
        """
        if self._link.get() != None:
            return self._link.get()
        elif not self._linkWireEncoding.isNull():
            # Decode the link object from linkWireEncoding_.
            link = Link()
            link.wireDecode(self._linkWireEncoding, self._linkWireEncodingFormat)
            self._link.set(link)

            # Clear _linkWireEncoding since it is now managed by the link object.
            self._linkWireEncoding = Blob()
            self._linkWireEncodingFormat = None

            return link
        else:
            return None

    def getLinkWireEncoding(self, wireFormat = None):
        """
        Get the wire encoding of the link object. If there is already a wire
        encoding then return it. Otherwise encode from the link object (if
        available).

        :param WireFormat wireFormat: (optional) A WireFormat object used to
          encode the Link. If omitted, use WireFormat.getDefaultWireFormat().
        :return: The wire encoding, or an isNull Blob if the link is not
          specified.
        :rtype: Blob
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        if (not self._linkWireEncoding.isNull() and
            self._linkWireEncodingFormat == wireFormat):
          return self._linkWireEncoding

        link = self.getLink()
        if link != None:
          return link.wireEncode(wireFormat)
        else:
          return Blob()

    def getSelectedDelegationIndex(self):
        """
        Get the selected delegation index.

        :return: The selected delegation index. If not specified, return None.
        :rtype: int
        """
        return self._selectedDelegationIndex

    def getInterestLifetimeMilliseconds(self):
        """
        Get the interest lifetime.

        :return: The interest lifetime in milliseconds, or None if not specified.
        :rtype: float
        """
        return self._interestLifetimeMilliseconds

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
        Set the interest name.

        :note: You can also call getName and change the name values directly.
        :param Name name: The interest name. This makes a copy of the name.
        :return: This Interest so that you can chain calls to update values.
        :rtype: Interest
        """
        self._name.set(name if type(name) is Name else Name(name))
        self._changeCount += 1
        return self

    def setMinSuffixComponents(self, minSuffixComponents):
        """
        Set the min suffix components count.

        :param int minSuffixComponents: The min suffix components count. If not
          specified, set to None.
        :return: This Interest so that you can chain calls to update values.
        :rtype: Interest
        """
        self._minSuffixComponents = minSuffixComponents
        self._changeCount += 1
        return self

    def setMaxSuffixComponents(self, maxSuffixComponents):
        """
        Set the max suffix components count.

        :param int maxSuffixComponents: The max suffix components count. If not
          specified, set to None.
        :return: This Interest so that you can chain calls to update values.
        :rtype: Interest
        """
        self._maxSuffixComponents = maxSuffixComponents
        self._changeCount += 1
        return self

    def setKeyLocator(self, keyLocator):
        """
        Set this interest to use a copy of the given KeyLocator object.

        :note: You can also call getKeyLocator and change the key locator directly.
        :param KeyLocator keyLocator: The KeyLocator object. This makes a copy
          of the object. If no key locator is specified, set to a new default
          KeyLocator(), or to a KeyLocator with an unspecified type.
        :return: This Interest so that you can chain calls to update values.
        :rtype: Interest
        """
        self._keyLocator.set(
          KeyLocator(keyLocator) if type(keyLocator) is KeyLocator
                     else KeyLocator())
        self._changeCount += 1
        return self

    def setExclude(self, exclude):
        """
        Set this interest to use a copy of the given Exclude object.

        :note: You can also call getExclude and change the exclude entries directly.
        :param Exclude exclude: The Exclude object. This makes a copy of the
          object. If no exclude is specified, set to a new default Exclude(), or
          to an Exclude with size() 0.
        :return: This Interest so that you can chain calls to update values.
        :rtype: Interest
        """
        self._exclude.set(
          Exclude(exclude) if type(exclude) is Exclude else Exclude())
        self._changeCount += 1
        return self

    def setLinkWireEncoding(self, encoding, wireFormat = None):
        """
        Set the link wire encoding bytes, without decoding them. If there is a
        link object, set it to null. If you later call getLink(), it will decode
        the wireEncoding to create the link object.

        :param Blob encoding: The Blob with the bytes of the link wire encoding.
          If no link is specified, set to an empty Blob() or call unsetLink().
        :param WireFormat wireFormat: The wire format of the encoding, to be
          used later if necessary to decode. If omitted, use
          WireFormat.getDefaultWireFormat().
        :return: This Interest so that you can chain calls to update values.
        :rtype: Interest
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        self._linkWireEncoding = encoding
        self._linkWireEncodingFormat = wireFormat

        # Clear the link object, assuming that it has a different encoding.
        self._link.set(None)

        self._changeCount += 1
        return self

    def unsetLink(self):
        """
        Clear the link wire encoding and link object so that getLink() returns
        None.

        :return: This Interest so that you can chain calls to update values.
        :rtype: Interest
        """
        return self.setLinkWireEncoding(Blob(), None)

    def setSelectedDelegationIndex(self, selectedDelegationIndex):
        """
        Set the selected delegation index.

        :param int selectedDelegationIndex: The selected delegation index. If
          not specified, set to None.
        :return: This Interest so that you can chain calls to update values.
        :rtype: Interest
        """
        self._selectedDelegationIndex = selectedDelegationIndex
        self._changeCount += 1
        return self

    def setChildSelector(self, childSelector):
        """
        Set the child selector.

        :param int childSelector: The child selector. If not specified, set to None.
        :return: This Interest so that you can chain calls to update values.
        :rtype: Interest
        """
        self._childSelector = childSelector
        self._changeCount += 1
        return self

    def setMustBeFresh(self, mustBeFresh):
        """
        Set the MustBeFresh flag.

        :param bool mustBeFresh: True if the content must be fresh, otherwise
          False. If you do not set this flag, the default value is true.
        :return: This Interest so that you can chain calls to update values.
        :rtype: Interest
        """
        self._mustBeFresh = True if mustBeFresh else False
        self._changeCount += 1
        return self

    def setNonce(self, nonce):
        """
        :deprecated: You should let the wire encoder generate a random nonce
          internally before sending the interest.
        """
        self._nonce = nonce if isinstance(nonce, Blob) else Blob(nonce)
        # Set _getNonceChangeCount so that the next call to getNonce() won't
        #   clear _nonce.
        self._changeCount += 1
        self._getNonceChangeCount = self.getChangeCount()
        return self

    def setInterestLifetimeMilliseconds(self, interestLifetimeMilliseconds):
        """
        Set the interest lifetime.

        :param float interestLifetimeMilliseconds: The interest lifetime in
          milliseconds. If not specified, set to -1.
        :return: This Interest so that you can chain calls to update values.
        :rtype: Interest
        """
        self._interestLifetimeMilliseconds = (None
           if interestLifetimeMilliseconds == None
           else float(interestLifetimeMilliseconds))
        self._changeCount += 1
        return self

    def wireEncode(self, wireFormat = None):
        """
        Encode this Interest for a particular wire format. If wireFormat is the
        default wire format, also set the defaultWireEncoding field to the
        encoded result.

        :param wireFormat: (optional) A WireFormat object used to encode this
           Interest. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        :return: The encoded buffer.
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
          wireFormat.encodeInterest(self)
        wireEncoding = SignedBlob(
          encoding, signedPortionBeginOffset, signedPortionEndOffset)

        if wireFormat == WireFormat.getDefaultWireFormat():
            # This is the default wire encoding.
            self._setDefaultWireEncoding(
              wireEncoding, WireFormat.getDefaultWireFormat())
        return wireEncoding

    def wireDecode(self, input, wireFormat = None):
        """
        Decode the input using a particular wire format and update this Interest.
        If wireFormat is the default wire format, also set the
        defaultWireEncoding to another pointer to the input.

        :param input: The array with the bytes to decode. If input is not a
          Blob, then copy the bytes to save the defaultWireEncoding (otherwise
          take another pointer to the same Blob).
        :type input: A Blob or an array type with int elements
        :param wireFormat: (optional) A WireFormat object used to decode this
           Interest. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        # If input is a Blob, get its buf().
        decodeBuffer = input.buf() if isinstance(input, Blob) else input
        (signedPortionBeginOffset, signedPortionEndOffset) = \
          wireFormat.decodeInterest(self, decodeBuffer)

        if wireFormat == WireFormat.getDefaultWireFormat():
            # This is the default wire encoding.  In the Blob constructor, set
            #   copy true, but if input is already a Blob, it won't copy.
            self._setDefaultWireEncoding(SignedBlob(
                Blob(input, True),
                signedPortionBeginOffset, signedPortionEndOffset),
            WireFormat.getDefaultWireFormat())
        else:
            self._setDefaultWireEncoding(SignedBlob(), None)

    def toUri(self):
        """
        Encode the name according to the "NDN URI Scheme".  If there are
        interest selectors, append "?" and add the selectors as a query string.
        For example "/test/name?ndn.ChildSelector=1".
        :note: This is an experimental feature. See the API docs for more detail at
        http://named-data.net/doc/ndn-ccl-api/interest.html#interest-touri-method .

        :return: The URI string.
        :rtype: string
        """
        selectors = ""
        if self._minSuffixComponents != None:
            selectors += "&ndn.MinSuffixComponents=" + repr(
              self._minSuffixComponents)
        if self._maxSuffixComponents != None:
            selectors += "&ndn.MaxSuffixComponents=" + repr(
              self._maxSuffixComponents)
        if self._childSelector != None:
            selectors += "&ndn.ChildSelector=" + repr(self._childSelector)
        if self._mustBeFresh:
            selectors += "&ndn.MustBeFresh=true"
        if self._interestLifetimeMilliseconds != None:
            selectors += "&ndn.InterestLifetime=" + repr(
              int(round(self._interestLifetimeMilliseconds)))
        if self.getNonce().size() > 0:
            selectors += ("&ndn.Nonce=" +
              Name.toEscapedString(self.getNonce().buf()))
        if self.getExclude().size() > 0:
            selectors += "&ndn.Exclude=" + self.getExclude().toUri()

        result = self.getName().toUri()
        if selectors != "":
            # Replace the first & with ?.
            result += "?" + selectors[1:]

        return result

    def refreshNonce(self):
        """
        Update the bytes of the nonce with new random values. This ensures that
        the new nonce value is different than the current one. If the current
        nonce is not specified, this does nothing.
        """
        currentNonce = self.getNonce()
        if currentNonce.size() == 0:
            return

        while True:
            value = bytearray(currentNonce.size())
            for i in range(len(value)):
                value[i] = self._systemRandom.randint(0, 0xff)
            newNonce = Blob(value, False)
            if newNonce != currentNonce:
                break

        self._nonce = newNonce
        # Set _getNonceChangeCount so that the next call to getNonce() won't
        #   clear _nonce.
        self._changeCount += 1
        self._getNonceChangeCount = self.getChangeCount()

    def matchesName(self, name):
        """
        Check if this interest's name matches the given name (using Name.match)
        and the given name also conforms to the interest selectors.

        :param Name name: The name to check.
        :return: True if the name and interest selectors match, False otherwise.
        :rtype: bool
        """
        if not self.getName().match(name):
            return False

        if (self._minSuffixComponents != None and
              # Add 1 for the implicit digest.
              not (name.size() + 1 - self.getName().size() >=
                   self._minSuffixComponents)):
            return False
        if (self._maxSuffixComponents != None and
              # Add 1 for the implicit digest.
              not (name.size() + 1 - self.getName().size() <=
                   self._maxSuffixComponents)):
            return False
        if (self.getExclude().size() > 0 and
              name.size() > self.getName().size() and
              self.getExclude().matches(name[self.getName().size()])):
            return False

        return True

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

    def setLpPacket(self, lpPacket):
        """
        An internal library method to set the LpPacket for an incoming packet.
        The application should not call this.

        :param LpPacket lpPacket: The LpPacket. This does not make a copy.
        :return: This Interest so that you can chain calls to update values.
        :rtype: Interest
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
        changed = self._keyLocator.checkChanged() or changed
        changed = self._exclude.checkChanged() or changed
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

    _systemRandom = SystemRandom()

    # Create managed properties for read/write properties of the class for more pythonic syntax.
    name = property(getName, setName)
    minSuffixComponents = property(getMinSuffixComponents, setMinSuffixComponents)
    maxSuffixComponents = property(getMaxSuffixComponents, setMaxSuffixComponents)
    keyLocator = property(getKeyLocator, setKeyLocator)
    exclude = property(getExclude, setExclude)
    childSelector = property(getChildSelector, setChildSelector)
    mustBeFresh = property(getMustBeFresh, setMustBeFresh)
    nonce = property(getNonce, setNonce)
    interestLifetimeMilliseconds = property(getInterestLifetimeMilliseconds, setInterestLifetimeMilliseconds)



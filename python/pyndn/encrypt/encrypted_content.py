# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt src/encrypted-content https://github.com/named-data/ndn-group-encrypt
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
This module defines the EncryptedContent class which holds an encryption type, a
payload and other fields representing encrypted content.
Note: This class is an experimental feature. The API may change.
"""

from pyndn.util.blob import Blob
from pyndn.key_locator import KeyLocator, KeyLocatorType
from pyndn.encoding.wire_format import WireFormat

class EncryptedContent(object):
    """
    Create an EncryptedContent.

    :param value: (optional) If value is another EncryptedContent then copy it.
      If value is omitted then create an EncryptedContent with unspecified values.
    :type value: EncryptedContent
    """
    def __init__(self, value = None):
        if isinstance(value, EncryptedContent):
            # Make a deep copy.
            self._algorithmType = value._algorithmType
            self._keyLocator = KeyLocator(value._keyLocator)
            self._initialVector = value._initialVector
            self._payload = value._payload
            self._payloadKey = value._payloadKey
        else:
            self.clear()

    def getAlgorithmType(self):
        """
        Get the algorithm type from EncryptAlgorithmType.

        :return: The algorithm type from EncryptAlgorithmType, or None if not
          specified.
        :rtype: int
        """
        return self._algorithmType

    def getKeyLocator(self):
        """
        Get the key locator.

        :return: The key locator. If not specified, getType() is None.
        :rtype: KeyLocator
        """
        return self._keyLocator

    def getKeyLocatorName(self):
        """
        Check that the key locator type is KEYNAME and return the key Name.

        :return: The key Name.
        :rtype: Name
        :raises: RuntimeError if the key locator type is not KEYNAME.
        """
        if self._keyLocator.getType() != KeyLocatorType.KEYNAME:
            raise RuntimeError("getKeyLocatorName: The KeyLocator type must be KEYNAME")

        return self._keyLocator.getKeyName()

    def hasInitialVector(self):
        """
        Check if the initial vector is specified.

        :return: True if the initial vector is specified.
        :rtype: bool
        """
        return not self._initialVector.isNull()

    def getInitialVector(self):
        """
        Get the initial vector.

        :return: The initial vector. If not specified, isNull() is True.
        :rtype: Blob
        """
        return self._initialVector

    def getPayload(self):
        """
        Get the payload.

        :return: The payload. If not specified, isNull() is True.
        :rtype: Blob
        """
        return self._payload

    def getPayloadKey(self):
        """
        Get the encrypted payload key.

        :return: The encrypted payload key. If not specified, isNull() is true.
        :rtype: Blob
        """
        return self._payloadKey

    def setAlgorithmType(self, algorithmType):
        """
        Set the algorithm type.

        :param int algorithmType: The algorithm type from EncryptAlgorithmType.
          If not specified, set to None.
        :return: This EncryptedContent so that you can chain calls to update
          values.
        :rtype: EncryptedContent
        """
        self._algorithmType = algorithmType
        return self

    def setKeyLocator(self, keyLocator):
        """
        Set the key locator.

        :param KeyLocator keyLocator: The key locator. This makes a copy of the
          object. If not specified, set to the default KeyLocator().
        :return: This EncryptedContent so that you can chain calls to update
          values.
        :rtype: EncryptedContent
        """
        self._keyLocator = (KeyLocator(keyLocator) if
          isinstance(keyLocator, KeyLocator) else KeyLocator())
        return self

    def setKeyLocatorName(self, keyName):
        """
         Set the key locator type to KeyLocatorType.KEYNAME and set the key Name.

        :param Name keyName: The key locator Name, which is copied.
        :return: This EncryptedContent so that you can chain calls to update
          values.
        :rtype: EncryptedContent
        """
        self._keyLocator.setType(KeyLocatorType.KEYNAME)
        self._keyLocator.setKeyName(keyName)
        return self

    def setInitialVector(self, initialVector):
        """
        Set the initial vector.

        :param Blob initialVector: The initial vector. If not specified, set to
          the default Blob() where isNull() is True.
        :return: This EncryptedContent so that you can chain calls to update
          values.
        :rtype: EncryptedContent
        """
        self._initialVector = (initialVector if
          isinstance(initialVector, Blob) else Blob(initialVector))
        return self

    def setPayload(self, payload):
        """
        Set the encrypted payload.

        :param Blob payload: The payload. If not specified, set to the default
          Blob() where isNull() is True.
        :return: This EncryptedContent so that you can chain calls to update
          values.
        :rtype: EncryptedContent
        """
        self._payload = payload if isinstance(payload, Blob) else Blob(payload)
        return self

    def setPayloadKey(self, payloadKey):
        """
        Set the encrypted payload key.

        :param Blob payloadKey: The encrypted payload key. If not specified, set
          to the default Blob() where isNull() is True.
        :return: This EncryptedContent so that you can chain calls to update
          values.
        :rtype: EncryptedContent
        """
        self._payloadKey = (payloadKey if isinstance(payloadKey, Blob)
                            else Blob(payloadKey))
        return self

    def clear(self):
        """
        Set all the fields to indicate unspecified values.
        """
        self._algorithmType = None
        self._keyLocator = KeyLocator()
        self._initialVector = Blob()
        self._payload = Blob()
        self._payloadKey = Blob()

    def wireEncode(self, wireFormat = None):
        """
        Encode this to an EncryptedContent v1 for a particular wire format.

        :param wireFormat: (optional) A WireFormat object used to encode this
           EncryptedContent. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        :return: The encoded buffer.
        :rtype: Blob
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        return wireFormat.encodeEncryptedContent(self)

    def wireEncodeV2(self, wireFormat = None):
        """
        Encode this to an EncryptedContent v2 for a particular wire format.

        :param wireFormat: (optional) A WireFormat object used to encode this
           EncryptedContent. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        :return: The encoded buffer.
        :rtype: Blob
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        return wireFormat.encodeEncryptedContentV2(self)

    def wireDecode(self, input, wireFormat = None):
        """
        Decode the input as an EncryptedContent v1 using a particular wire
        format and update this EncryptedContent.

        :param input: The array with the bytes to decode.
        :type input: A Blob or an array type with int elements
        :param wireFormat: (optional) A WireFormat object used to decode this
           EncryptedContent. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        if isinstance(input, Blob):
          # Input is a blob, so get its buf() and set copy False.
          wireFormat.decodeEncryptedContent(self, input.buf(), False)
        else:
          wireFormat.decodeEncryptedContent(self, input, True)

    def wireDecodeV2(self, input, wireFormat = None):
        """
        Decode the input as an EncryptedContent v2 using a particular wire
        format and update this EncryptedContent.

        :param input: The array with the bytes to decode.
        :type input: A Blob or an array type with int elements
        :param wireFormat: (optional) A WireFormat object used to decode this
           EncryptedContent. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        if isinstance(input, Blob):
          # Input is a blob, so get its buf() and set copy False.
          wireFormat.decodeEncryptedContentV2(self, input.buf(), False)
        else:
          wireFormat.decodeEncryptedContentV2(self, input, True)

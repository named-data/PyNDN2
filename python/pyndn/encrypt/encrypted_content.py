# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2016 Regents of the University of California.
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
from pyndn.key_locator import KeyLocator
from pyndn.encoding.wire_format import WireFormat

class EncryptedContent(object):
    """
    Create an EncryptedContent.

    :param value: (optional) If value is another EncryptedContent then copy it.
      If value is omitted then create an EncryptedContent with unspecified values.
    :type value: EncryptedContent
    """
    def __init__(self, value = None):
        if type(value) is EncryptedContent:
            # Make a deep copy.
            self._algorithmType = value._algorithmType
            self._keyLocator = KeyLocator(value._keyLocator)
            self._initialVector = value._initialVector
            self._payload = value._payload
        else:
            self._algorithmType = None
            self._keyLocator = KeyLocator()
            self._initialVector = Blob()
            self._payload = Blob()

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
          type(keyLocator) is KeyLocator else KeyLocator())
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

    def wireEncode(self, wireFormat = None):
        """
        Encode this EncryptedContent for a particular wire format.

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

    def wireDecode(self, input, wireFormat = None):
        """
        Decode the input using a particular wire format and update this
        EncryptedContent.

        :param input: The array with the bytes to decode.
        :type input: A Blob or an array type with int elements
        :param wireFormat: (optional) A WireFormat object used to decode this
           EncryptedContent. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        # If input is a Blob, get its buf().
        decodeBuffer = input.buf() if isinstance(input, Blob) else input
        wireFormat.decodeEncryptedContent(self, decodeBuffer)

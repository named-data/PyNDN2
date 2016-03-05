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
This module defines the ControlParameters class which holds a Name and other
fields for a ControlParameters which is used, for example, in the command
interest to register a prefix with a forwarder.
"""

class ControlParameters(object):
    def __init__(self, value = None):
        if type(value) is ControlParameters:
            # Make a deep copy.
            self._name = None if value._name == None else Name(value._name)
            self._faceId = value._faceId
            self._uri = value._uri
            self._localControlFeature = value._localControlFeature
            self._origin = value._origin
            self._cost = value._cost
            self._forwardingFlags = ForwardingFlags(value._forwardingFlags)
            self._strategy = Name(value._strategy)
            self._expirationPeriod = value._expirationPeriod
        else:
            self._name = None
            self._faceId = None
            self._uri = ""
            self._localControlFeature = None
            self._origin = None
            self._cost = None
            self._forwardingFlags = ForwardingFlags()
            self._strategy = Name()
            self._expirationPeriod = None

    def clear(self):
        self._name = None
        self._faceId = None
        self._uri = ""
        self._localControlFeature = None
        self._origin = None
        self._cost = None
        self._forwardingFlags = ForwardingFlags()
        self._strategy = Name()
        self._expirationPeriod = None

    def wireEncode(self, wireFormat = None):
        """
        Encode this ControlParameters for a particular wire format.

        :param wireFormat: (optional) A WireFormat object used to encode this
           ControlParameters. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        :return: The encoded buffer.
        :rtype: Blob
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        return wireFormat.encodeControlParameters(self)

    def wireDecode(self, input, wireFormat = None):
        """
        Decode the input using a particular wire format and update this
        ControlParameters.

        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :param wireFormat: (optional) A WireFormat object used to decode this
           ControlParameters. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        # If input is a blob, get its buf().
        decodeBuffer = input.buf() if isinstance(input, Blob) else input
        wireFormat.decodeControlParameters(self, decodeBuffer)

    def getName(self):
        """
        Get the name.

        :return: The name. If not specified, return None.
        :rtype: Name
        """
        return self._name

    def getFaceId(self):
        """
        Get the face ID.

        :return: The face ID, or None if not specified.
        :rtype: int
        """
        return self._faceId

    def getUri(self):
        """
        Get the URI.

        :return: The face URI, or an empty string if not specified.
        :rtype: str
        """
        return self._uri

    def getLocalControlFeature(self):
        """
        Get the local control feature value.

        :return: The local control feature value, or None if not specified.
        :rtype: int
        """
        return self._localControlFeature

    def getOrigin(self):
        """
        Get the origin value.

        :return: The origin value, or None if not specified.
        :rtype: int
        """
        return self._origin

    def getCost(self):
        """
        Get the cost value.

        :return: The cost value, or None if not specified.
        :rtype: int
        """
        return self._cost

    def getForwardingFlags(self):
        """
        Get the ForwardingFlags object.

        :return: the ForwardingFlags object.
        :rtype: ForwardingFlags
        """
        return self._forwardingFlags

    def getStrategy(self):
        """
        Get the strategy.

        :return: The strategy or an empty Name.
        :rtype: Name
        """
        return self._strategy

    def getExpirationPeriod(self):
        """
        Get the expiration period.

        :return: The expiration period in milliseconds, or None if not specified.
        :rtype: float
        """
        return self._expirationPeriod

    def setName(self, name):
        """
        Set the name.

        :param Name name: The name. If not specified, set to None. If specified,
          this makes a copy of the name.
        """
        self._name = Name(name) if type(name) is Name else None

    def setFaceId(self, faceId):
        """
        Set the Face ID.

        :param int faceId: The new face ID, or None for not specified.
        """
        self._faceId = faceId

    def setUri(self, uri):
        """
        Set the URI.

        :param str uri: The new uri, or an empty string for not specified.
        """
        self._uri = uri if type(uri) is str else ""

    def setLocalControlFeature(self, localControlFeature):
        """
        Set the local control feature value.

        :param int localControlFeature: The new local control feature value, or
          None for not specified.
        """
        self._localControlFeature = localControlFeature

    def setOrigin(self, origin):
        """
        Set the origin value.

        :param int origin: The new origin value, or None for not specified.
        """
        self._origin = origin

    def setCost(self, cost):
        """
        Set the cost value.

        :param int cost: The new cost value, or None for not specified.
        """
        self._cost = cost

    def setForwardingFlags(self, forwardingFlags):
        """
        Set the ForwardingFlags object to a copy of forwardingFlags.
        You can use getForwardingFlags() and change the existing
        ForwardingFlags object.

        :param ForwardingFlags forwardingFlags: The new ForwardingFlace object.
        """
        self._forwardingFlags = (ForwardingFlags(forwardingFlags)
                                 if type(forwardingFlags) is ForwardingFlags
                                 else ForwardingFlags())

    def setStrategy(self, strategy):
        """
        Set the strategy to a copy of the given Name.

        :param Name strategy: The Name to copy, or an empty Name if not specified.
        """
        self._strategy = Name(strategy) if type(strategy) is Name else Name()

    def setExpirationPeriod(self, expirationPeriod):
        """
        Set the expiration period.

        :param float expirationPeriod: The expiration period in milliseconds, or
          None for not specified.
        """
        self._expirationPeriod = (None if expirationPeriod == None else
                                  float(expirationPeriod))

    # Support property-based equivalence check
    # TODO: Desired syntax?
    def equals(self, other):
        if  (self._name == other._name
        and self._faceId == other._faceId
        and self._uri == other._uri
        and self._localControlFeature == other._localControlFeature
        and self._origin == other._origin
        and self._cost == other._cost
        and self._forwardingFlags == other._forwardingFlags
        and self._strategy == other._strategy
        and self._expirationPeriod == other._expirationPerion):
            return True
        else:
            return False

    # Create managed properties for read/write properties of the class for more pythonic syntax.
    name = property(getName, setName)
    faceId = property(getFaceId, setFaceId)
    uri = property(getUri, setUri)
    localControlFeature = property(getLocalControlFeature, setLocalControlFeature)
    origin = property(getOrigin, setOrigin)
    cost = property(getCost, setCost)
    forwardingFlags = property(getForwardingFlags, setForwardingFlags)
    strategy = property(getStrategy, setStrategy)
    expirationPeriod = property(getExpirationPeriod, setExpirationPeriod)

# Import these at the end of the file to avoid circular references.
from pyndn.forwarding_flags import ForwardingFlags
from pyndn.name import Name
from pyndn.util.blob import Blob
from pyndn.encoding.wire_format import WireFormat

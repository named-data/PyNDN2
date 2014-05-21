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

"""
This module defines the ControlParameters class which holds a Name and other 
fields for a ControlParameters which is used, for example, in the command 
interest to register a prefix with a forwarder.
"""

from pyndn.forwarding_flags import ForwardingFlags
from pyndn.name import Name
from pyndn.encoding import WireFormat
from pyndn.util import Blob

class ControlParameters(object):
    def __init__(self):
        self._name = Name()
        self._faceId = None
        # TODO: Add "Uri" string.
        self._localControlFeature = None
        self._origin = None
        self._cost = None
        self._forwardingFlags = ForwardingFlags()
        # TODO: Add "Strategy" name.
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
           ForwardingEntry. If omitted, use WireFormat.getDefaultWireFormat().
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
        
        :return: The name.
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
    
    def getExpirationPeriod(self):
        """
        Get the expiration period.
        
        :return: The expiration period in milliseconds, or None if not specified.
        :rtype: float
        """
        return self._expirationPeriod

    def setName(self, name):
        """
        Set the name to a copy of the give Name.
        
        :param Name name: The new Name to copy.
        """
        self._name = Name(name) if type(name) is Name else Name()
        
    def setFaceId(self, faceId):
        """
        Set the Face ID.
        
        :param int faceId: The new face ID, or None for not specified.
        """
        self._faceId = faceId
        
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
                                 
    def setExpirationPeriod(self, expirationPeriod):
        """
        Set the expiration period.
        
        :param float expirationPeriod: The expiration period in milliseconds, or 
          None for not specified.
        """
        self._expirationPeriod = expirationPeriod

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
This module defines the ForwardingEntry class which holds an action and Name 
prefix and other fields for a forwarding entry.
"""

from pyndn.forwarding_flags import ForwardingFlags
from pyndn.name import Name
from pyndn.encoding import WireFormat
from pyndn.util import Blob

class ForwardingEntry(object):
    def __init__(self):
        self._action = None
        self._prefix = Name()
        self._faceId = None
        self._forwardingFlags = ForwardingFlags()
        self._freshnessPeriod = None
        
    def getAction(self):
        """
        Get the action string.
        
        :return: The action string, or None if not specified.
        :rtype: str
        """
        return self._action

    def getPrefix(self):
        """
        Get the name prefix.
        
        :return: The name prefix.
        :rtype: Name
        """
        return self._prefix
    
    def getFaceId(self):
        """
        Get the face ID, which is only meaningful if getAction() is 
        "prefixreg" or "unreg".
        
        :return: The face ID, or None if not specified.
        :rtype: int
        """
        return self._faceId
    
    def getForwardingFlags(self):
        """
        Get the ForwardingFlags object.
        
        :return: the ForwardingFlags object.
        :rtype: ForwardingFlags
        """
        return self._forwardingFlags
    
    def getFreshnessPeriod(self):
        """
        Get the freshness period.
        
        :return: The freshness period in milliseconds, or None if not specified.
        :rtype: float
        """
        return self._freshnessPeriod

    def setAction(self, action):
        """
        Set the action string.
        
        :param str action: The new action string, or None for not specified.
        """
        self._action = action
        
    def setPrefix(self, prefix):
        """
        Set the prefix to a copy of the give Name.
        
        :param Name prefix: The new prefix Name to copy, or None for not 
          specified.
        """
        self._prefix = Name(prefix) if type(prefix) is Name else Name()
        
    def setFaceId(self, faceId):
        """
        Set the Face ID.
        
        :param int faceId: The new face ID, or None for not specified.
        """
        self._faceId = faceId
        
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
                                 
    def setFreshnessPeriod(self, freshnessPeriod):
        """
        Set the freshness period.
        
        :param float freshnessPeriod: The freshness period in milliseconds, or 
          None for not specified.
        """
        self._freshnessPeriod = freshnessPeriod
    
    def wireEncode(self, wireFormat = None):
        """
        Encode this ForwardingEntry for a particular wire format.
        
        :param wireFormat: (optional) A WireFormat object used to encode this 
           ForwardingEntry. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        :return: The encoded buffer.
        :rtype: Blob
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        return wireFormat.encodeForwardingEntry(self)
    
    def wireDecode(self, input, wireFormat = None):
        """
        Decode the input using a particular wire format and update this 
        ForwardingEntry.
        
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
        wireFormat.decodeForwardingEntry(self, decodeBuffer)

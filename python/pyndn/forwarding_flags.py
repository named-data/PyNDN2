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
This module defines the ForwardingFlags class which holds the flags which 
specify how the forwarding daemon should forward an interest for a registered 
prefix.  We use a separate ForwardingFlags object to retain future compatibility
if the daemon forwarding bits are changed, amended or deprecated.
"""

class ForwardingFlags(object):
    """
    Create a new ForwardingFlags object, possibly copying values from another 
    object.
    
    :param ForwardingFlags value: (optional) If value is a ForwardingFlags, copy 
      its values.  If value is omitted, the type is the default with "active" 
      and "childInherit" True and other flags False.
    """
    def __init__(self, value = None):
        if value == None:
            self._active = True
            self._childInherit = True
            self._advertise = False
            self._last = False
            self._capture = False
            self._local = False
            self._tap = False
            self._captureOk = False
        elif type(value) is ForwardingFlags:
            # Copy its values.
            self._active = value._active
            self._childInherit = value._childInherit
            self._advertise = value._advertise
            self._last = value._last
            self._capture = value._capture
            self._local = value._local
            self._tap = value._tap
            self._captureOk = value._captureOk
        else:
            raise RuntimeError(
              "Unrecognized type for ForwardingFlags constructor: " +
              repr(type(value)))

    ForwardingEntryFlags_ACTIVE         = 1
    ForwardingEntryFlags_CHILD_INHERIT  = 2
    ForwardingEntryFlags_ADVERTISE      = 4
    ForwardingEntryFlags_LAST           = 8
    ForwardingEntryFlags_CAPTURE       = 16
    ForwardingEntryFlags_LOCAL         = 32
    ForwardingEntryFlags_TAP           = 64
    ForwardingEntryFlags_CAPTURE_OK   = 128

    NfdForwardingFlags_CHILD_INHERIT = 1
    NfdForwardingFlags_CAPTURE       = 2

    def getForwardingEntryFlags(self):
        """
        Get an integer with the bits set according to the flags as used by the 
        ForwardingEntry message.
        
        :return: An integer with the bits set.
        :rtype: int
        """
        result = 0

        if self._active :
            result |= ForwardingFlags.ForwardingEntryFlags_ACTIVE
        if self._childInherit:
            result |= ForwardingFlags.ForwardingEntryFlags_CHILD_INHERIT
        if self._advertise:
            result |= ForwardingFlags.ForwardingEntryFlags_ADVERTISE
        if self._last:
            result |= ForwardingFlags.ForwardingEntryFlags_LAST
        if self._capture:
            result |= ForwardingFlags.ForwardingEntryFlags_CAPTURE
        if self._local:
            result |= ForwardingFlags.ForwardingEntryFlags_LOCAL
        if self._tap:
            result |= ForwardingFlags.ForwardingEntryFlags_TAP
        if self._captureOk:
            result |= ForwardingFlags.ForwardingEntryFlags_CAPTURE_OK

        return result
    
    def setForwardingEntryFlags(self, forwardingEntryFlags):
        """
        Set the flags according to the bits in forwardingEntryFlags as used by 
        the ForwardingEntry message.
        
        :param int forwardingEntryFlags: An integer with the bits set.
        """
        self._active = True if (forwardingEntryFlags & 
                                ForwardingFlags.ForwardingEntryFlags_ACTIVE) else False
        self._childInherit = True if (forwardingEntryFlags & 
                                      ForwardingFlags.ForwardingEntryFlags_CHILD_INHERIT) else False
        self._advertise = True if (forwardingEntryFlags & 
                                   ForwardingFlags.ForwardingEntryFlags_ADVERTISE) else False
        self._last = True if (forwardingEntryFlags & 
                              ForwardingFlags.ForwardingEntryFlags_LAST) else False
        self._capture = True if (forwardingEntryFlags & 
                                 ForwardingFlags.ForwardingEntryFlags_CAPTURE) else False
        self._local = True if (forwardingEntryFlags & 
                               ForwardingFlags.ForwardingEntryFlags_LOCAL) else False
        self._tap = True if (forwardingEntryFlags & 
                             ForwardingFlags.ForwardingEntryFlags_TAP) else False
        self._captureOk = True if (forwardingEntryFlags & 
                                   ForwardingFlags.ForwardingEntryFlags_CAPTURE_OK) else False

    def getNfdForwardingFlags(self):
        """
        Get an integer with the bits set according to the NFD forwarding flags 
        as used in the ControlParameters of the command interest.
        
        :return: An integer with the bits set.
        :rtype: int
        """
        result = 0

        if self._childInherit:
            result |= ForwardingFlags.NfdForwardingFlags_CHILD_INHERIT
        if self._capture:
            result |= ForwardingFlags.NfdForwardingFlags_CAPTURE

        return result
    
    def setNfdForwardingFlags(self, nfdForwardingFlags):
        """
        Set the flags according to the NFD forwarding flags as used in the 
        ControlParameters of the command interest.
        
        :param int nfdForwardingFlags: An integer with the bits set.
        """
        self._childInherit = True if (nfdForwardingFlags & 
                                      ForwardingFlags.NfdForwardingFlags_CHILD_INHERIT) else False
        self._capture = True if (nfdForwardingFlags & 
                                 ForwardingFlags.NfdForwardingFlags_CAPTURE) else False

    def getActive(self):
        return self._active

    def getChildInherit(self):
        return self._childInherit

    def getAdvertise(self):
        return self._advertise

    def getLast(self):
        return self._last

    def getCapture(self):
        return self._capture

    def getLocal(self):
        return self._local

    def getTap(self):
        return self._tap

    def getCaptureOk(self):
        return self._captureOk

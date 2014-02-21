# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

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
    
    :param value: (optional) If value is a ForwardingFlags, copy its values.  If
      value is omitted, the type is the default with "active" and "childInherit"
      True and other flags False.
    :type value: MetaInfo
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

    ACTIVE         = 1
    CHILD_INHERIT  = 2
    ADVERTISE      = 4
    LAST           = 8
    CAPTURE       = 16
    LOCAL         = 32
    TAP           = 64
    CAPTURE_OK   = 128

    def getForwardingEntryFlags(self):
        """
        Get an integer with the bits set according to the flags as used by the 
        ForwardingEntry message.
        
        :return: An integer with the bits set.
        :rtype: int
        """
        result = 0

        if self._active :
            result |= ForwardingFlags.ACTIVE
        if self._childInherit:
            result |= ForwardingFlags.CHILD_INHERIT
        if self._advertise:
            result |= ForwardingFlags.ADVERTISE
        if self._last:
            result |= ForwardingFlags.LAST
        if self._capture:
            result |= ForwardingFlags.CAPTURE
        if self._local:
            result |= ForwardingFlags.LOCAL
        if self._tap:
            result |= ForwardingFlags.TAP
        if self._captureOk:
            result |= ForwardingFlags.CAPTURE_OK

        return result
    
    def setForwardingEntryFlags(self, forwardingEntryFlags):
        """
        Set the flags according to the bits in forwardingEntryFlags as used by 
        the ForwardingEntry message.
        
        :param forwardingEntryFlags: An integer with the bits set.
        :type forwardingEntryFlags: int
        """
        self._active = True if (forwardingEntryFlags & 
                                ForwardingFlags.ACTIVE) else False
        self._childInherit = True if (forwardingEntryFlags & 
                                      ForwardingFlags.CHILD_INHERIT) else False
        self._advertise = True if (forwardingEntryFlags & 
                                   ForwardingFlags.ADVERTISE) else False
        self._last = True if (forwardingEntryFlags & 
                              ForwardingFlags.LAST) else False
        self._capture = True if (forwardingEntryFlags & 
                                 ForwardingFlags.CAPTURE) else False
        self._local = True if (forwardingEntryFlags & 
                               ForwardingFlags.LOCAL) else False
        self._tap = True if (forwardingEntryFlags & 
                             ForwardingFlags.TAP) else False
        self._captureOk = True if (forwardingEntryFlags & 
                                   ForwardingFlags.CAPTURE_OK) else False

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

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2015 Regents of the University of California.
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
              str(type(value)))

    NfdForwardingFlags_CHILD_INHERIT = 1
    NfdForwardingFlags_CAPTURE       = 2

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


    def setActive(self, value):
        self._active = value

    def setChildInherit(self, value):
        self._childInherit = value

    def setAdvertise(self, value):
        self._advertise = value

    def setLast(self, value):
        self._last = value

    def setCapture(self, value):
        self._capture = value

    def setLocal(self, value):
        self._local = value

    def setTap(self, value):
        self._tap = value

    def setCaptureOk(self, value):
        self._captureOk = value

    # Support property-based equivalence check
    # TODO: Desired syntax?
    def equals(self, other):
        if  (self._active == other._active
        and self._childInherit == other._childInherit
        and self._advertise == other._advertise
        and self._last == other._last
        and self._capture == other._capture
        and self._local == other._local
        and self._tap == other._tap
        and self._captureOk == other._captureOk):
            return True
        else:
            return False


    # Create managed properties for read/write properties of the class for more pythonic syntax.
    active = property(getActive, setActive)
    childInherit = property(getChildInherit, setChildInherit)
    advertise = property(getAdvertise, setAdvertise)
    last = property(getLast, setLast)
    capture = property(getCapture, setCapture)
    local = property(getLocal, setLocal)
    tap = property(getTap, setTap)
    captureOk = property(getCaptureOk, setCaptureOk)

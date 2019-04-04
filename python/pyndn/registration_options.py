# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2019 Regents of the University of California.
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
This module defines the RegistrationOptions class which holds the options used
when registering with the forwarder to specify how to forward an interest and
other options. We use a separate RegistrationOptions object to retain future
compatibility if the format of the registration command is changed.
(This class was renamed from ForwardingFlags, which is deprecated.)
"""

class RegistrationOptions(object):
    """
    Create a new RegistrationOptions object, possibly copying values from another
    object.

    :param RegistrationOptions value: (optional) If value is a RegistrationOptions, copy
      its values.  If value is omitted, the type is the default with
      "childInherit" True and other flags False.
    """
    def __init__(self, value = None):
        if value == None:
            self._childInherit = True
            self._capture = False
            self._origin = None
        elif isinstance(value, RegistrationOptions):
            # Copy its values.
            self._childInherit = value._childInherit
            self._capture = value._capture
            self._origin = value._origin
        else:
            raise RuntimeError(
              "Unrecognized type for RegistrationOptions constructor: " +
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
            result |= RegistrationOptions.NfdForwardingFlags_CHILD_INHERIT
        if self._capture:
            result |= RegistrationOptions.NfdForwardingFlags_CAPTURE

        return result

    def setNfdForwardingFlags(self, nfdForwardingFlags):
        """
        Set the flags according to the NFD forwarding flags as used in the
        ControlParameters of the command interest.
        This ignores the origin value.

        :param int nfdForwardingFlags: An integer with the bits set.
        :return: This RegistrationOptions so that you can chain calls to update values.
        :rtype: RegistrationOptions
        """
        self._childInherit = True if (nfdForwardingFlags &
                                      RegistrationOptions.NfdForwardingFlags_CHILD_INHERIT) else False
        self._capture = True if (nfdForwardingFlags &
                                 RegistrationOptions.NfdForwardingFlags_CAPTURE) else False
        return self

    def getChildInherit(self):
        return self._childInherit

    def getCapture(self):
        return self._capture

    def getOrigin(self):
        """
        Get the origin value.

        :return: The origin value, or None if not specified.
        :rtype: int
        """
        return self._origin

    def setChildInherit(self, childInherit):
        """
        Set the value of the "childInherit" flag.

        :param bool childInherit: True to set the "childInherit" flag, False to
          clear it.
        :return: This RegistrationOptions so that you can chain calls to update values.
        :rtype: RegistrationOptions
        """
        self._childInherit = childInherit
        return self

    def setCapture(self, capture):
        """
        Set the value of the "capture" flag.

        :param bool capture: True to set the "capture" flag, False to clear it.
        :return: This RegistrationOptions so that you can chain calls to update values.
        :rtype: RegistrationOptions
        """
        self._capture = capture
        return self

    def setOrigin(self, origin):
        """
        Set the origin value. This is used to set the origin value of the
        ControlParameters for the register prefix command.

        :param int origin: The new origin value, or None for not specified.
        :return: This RegistrationOptions so that you can chain calls to update values.
        :rtype: RegistrationOptions
        """
        self._origin = origin
        return self

    # Support property-based equivalence check
    # TODO: Desired syntax?
    def equals(self, other):
        if (self._childInherit == other._childInherit
        and self._capture == other._capture):
            return True
        else:
            return False

    # Create managed properties for read/write properties of the class for more pythonic syntax.
    childInherit = property(getChildInherit, setChildInherit)
    capture = property(getCapture, setCapture)
    origin = property(getOrigin, setOrigin)


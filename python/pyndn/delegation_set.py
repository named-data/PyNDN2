# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2016 Regents of the University of California.
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
This module defines the DelegationSet class which holds a list of
DelegationSet.Delegation entries which is used as the content of a Link instance.
If you add elements with add(), then the list is a set sorted by preference
number then by name. But wireDecode will add the elements from the wire
encoding, preserving the given order and possible duplicates (in which case a
DelegationSet really holds a "list" and not necessarily a "set").
"""

from pyndn.name import Name
from pyndn.encoding.wire_format import WireFormat
from pyndn.util.blob import Blob

class DelegationSet(object):
    """
    Create a new DelegationSet object, possibly copying values from another
    object.

    :param DelegationSet value: (optional) If value is a DelegationSet, copy its
      values.
    """
    def __init__(self, value  = None):
        if type(value) is DelegationSet:
            # Copy the list.
            self._delegations = value._delegations[:]
        else:
            self._delegations = [] # of DelegationSet.Delegation.

    class Delegation(object):
        """
        A DelegationSet.Delegation holds a preference number and delegation name.
        Create a new DelegationSet.Delegation with the given values.

        :param int preference: The preference number.
        :param Name name: The delegation name. This makes a copy of the name.
        """
        def __init__(self, preference, name):
            self._preference = preference
            self._name = Name(name)

        def getPreference(self):
            """
            Get the preference number.

            :return: The preference number.
            :rtype: int
            """
            return self._preference

        def getName(self):
            """
            Get the delegation name.

            :return: The delegation name. NOTE: You must not change the name
              object - if you need to change it then make a copy.
            :rtype: Name
            """
            return self._name

        def compare(self, other):
            """
            Compare this Delegation with other according to the ordering, based
            first on the preference number, then on the delegation name.

            :param DelegationSet.Delegation other: The other Delegation to
              compare with.
            :return: 0 If they compare equal, -1 if this Delegation comes before
              other in the ordering, or 1 if this Delegation comes after.
            :rtype: int
            """
            if self._preference < other._preference:
                return -1
            if self._preference > other._preference:
                return 1

            return self._name.compare(other._name)

    def add(self, preference, name):
        """
        Add a new DelegationSet.Delegation to the list of delegations, sorted by
        preference number then by name. If there is already a delegation with
        the same name, update its preference, and remove any extra delegations
        with the same name.

        :param int preference: The preference number.
        :param Name name: The delegation name. This makes a copy of the name.
        """
        self.remove(name)

        newDelegation = DelegationSet.Delegation(preference, name)
        # Find the index of the first entry where it is not less than newDelegation.
        i = 0
        while i < len(self._delegations):
          if self._delegations[i].compare(newDelegation) >= 0:
            break

          i += 1

        self._delegations.insert(i, newDelegation)

    def addUnsorted(self, preference, name):
        """
        Add a new DelegationSet.Delegation to the end of the list of delegations,
        without sorting or updating any existing entries. This is useful for
        adding preferences from a wire encoding, preserving the supplied
        ordering and possible duplicates.

        :param int preference: The preference number.
        :param Name name: The delegation name. This makes a copy of the name.
        """
        self._delegations.append(DelegationSet.Delegation(preference, name))

    def remove(self, name):
        """
        Remove every DelegationSet.Delegation with the given name.

        :param Name name: The name to match the name of the delegation(s) to be
          removed.
        :return: True if a DelegationSet.Delegation was removed, otherwise
          False.
        :rtype: bool
        """
        wasRemoved = False
        # Go backwards through the list so we can remove entries.
        i = len(self._delegations) - 1
        while i >= 0:
            if self._delegations[i].getName().equals(name):
                wasRemoved = True
                self._delegations.pop(i)
            i -= 1

        return wasRemoved

    def clear(self):
        """
        Clear the list of delegations.
        """
        self._delegations = []

    def size(self):
        """
        Get the number of delegation entries.

        :return: The number of delegation entries.
        :rtype: int
        """
        return len(self._delegations)

    def get(self, i):
        """
        Get the delegation at the given index, according to the ordering
        described in add().

        :param int i: The index of the component, starting from 0.
        :return:  The delegation at the index.
        :rtype: DelegationSet.Delegation
        """
        return self._delegations[i]

    def find(self, name):
        """
        Find the first delegation with the given name and return its index.

        :param Name name: Then name of the delegation to find.
        :return: The index of the delegation, or -1 if not found.
        :rtype: int
        """
        for i in range(len(self._delegations)):
            if self._delegations[i].getName().equals(name):
                return i

        return -1

    def wireEncode(self, wireFormat = None):
        """
        Encode this DelegationSet for a particular wire format.

        :param wireFormat: (optional) A WireFormat object used to encode this
           DelegationSet. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        :return: The encoded buffer.
        :rtype: Blob
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        return wireFormat.encodeDelegationSet(self)

    def wireDecode(self, input, wireFormat = None):
        """
        Decode the input using a particular wire format and update this
        DelegationSet.

        :param input: The array with the bytes to decode.
        :type input: A Blob or an array type with int elements
        :param wireFormat: (optional) A WireFormat object used to decode this
           DelegationSet. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        # If input is a Blob, get its buf().
        decodeBuffer = input.buf() if isinstance(input, Blob) else input
        wireFormat.decodeDelegationSet(self, decodeBuffer)

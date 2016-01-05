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

from io import BytesIO
from pyndn.name import Name

"""
This module defines the Exclude class which is used by Interest and represents
the fields of an NDN Exclude selector.
"""

class Exclude(object):
    """
    Create a new Interest object, possibly copying values from another object.

    :param Exclude value: (optional) If value is an Exclude, copy its values.  If
      value is omitted, this creates an object with no entries.
    """
    def __init__(self, value = None):
        if value == None:
            self._entries = []
        elif type(value) is Exclude:
            # Copy its values.  Each entry is read-only, so do a shallow copy.
            self._entries = value._entries[:]
        else:
            raise RuntimeError(
              "Unrecognized type for Interest constructor: " +
              str(type(value)))

        self._changeCount = 0

    ANY = 0
    COMPONENT = 1

    class Entry(object):
        """
        Create a new Exclude.Entry.

        :param value: (optional) If value is omitted, create an Exclude.Entry of
          type Exclude.ANY.  Otherwise creat an Exclude.Entry of type
          Exclude.COMPONENT with the value.
        :type value: Name.Component or a value for the Name.Component
          constructor
        """
        def __init__(self, value = None):
            if value == None:
                self._type = Exclude.ANY
                self._component = None
            else:
                self._type = Exclude.COMPONENT
                self._component = (value if type(value) is Name.Component
                                   else Name.Component(value))

        def getType(self):
            """
            Get the type of this Exclude.Entry.

            :return: The type of this entry which is Exclude.ANY or
              Exclude.COMPONENT.
            :rtype: int
            """
            return self._type

        def getComponent(self):
            """
            Get the component for this Exclude.Entry (if the type of this
              is Exclude.COMPONENT).

            :return: The component for this entry, or None if the type of
              this entry is not Exclude.COMPONENT.
            :rtype: Name.Component
            """
            return self._component

    def size(self):
        """
        Get the number of entries.

        :return: The number of entries.
        :rtype: int
        """
        return len(self._entries)

    def get(self, i):
        """
        Get the entry at the given index.

        :param int i: The index of the entry, starting from 0.
        :return: The entry at the index.
        :rtype: Exclude.Entry
        """
        return self._entries[i]

    def appendAny(self):
        """
        Append a new entry of type Exclude.ANY.

        :return: This Exclude so that you can chain calls to append.
        :rtype: Exclude
        """
        self._entries.append(Exclude.Entry())
        self._changeCount += 1
        return self

    def appendComponent(self, component):
        """
        Append a new entry of type Exclude.COMPONENT with the give component.

        :param component: The new exclude component.
        :type component: Exclude.Entry, Name.Component or a value for the
          Name.Component constructor
        :return: This Exclude so that you can chain calls to append.
        :rtype: Exclude
        """
        self._entries.append(component if type(component) is Exclude.Entry
                             else Exclude.Entry(component))
        self._changeCount += 1
        return self

    def clear(self):
        """
        Clear all the entries.
        """
        self._entries = []
        self._changeCount += 1

    _star = bytearray([ord('*')])
    _comma = bytearray([ord(',')])
    def toUri(self):
        """
        Return a string representation of the exclude values.

        :return: The string representation.
        :rtype: string
        """
        if len(self._entries) == 0:
            return ""

        result = BytesIO()
        didFirst = False
        for entry in self._entries:
            if didFirst:
                # write is required to take a byte buffer.
                result.write(Exclude._comma)

            if entry.getType() == Exclude.ANY:
                # write is required to take a byte buffer.
                result.write(Exclude._star)
            else:
                entry.getComponent().toEscapedString(result)
            didFirst = True

        return Common.getBytesIOString(result)

    @staticmethod
    def compareComponents(component1, component2):
        """
        Compare the components using NDN component ordering. A component is less
        if it is shorter, otherwise if equal length do a byte comparison.

        :param Name.Component component1: The first name component.
        :param Name.Component component2: The first name component.
        :return: -1 if component1 is less than component2, 1 if greater or 0
          if equal.
        :rtype: int
        """
        buf1 = component1.getValue().buf()
        buf2 = component2.getValue().buf()
        if len(buf1) < len(buf2):
            return -1
        if len(buf1) > len(buf2):
            return 1

        # The components are equal length.  Just do a byte compare.
        # The Blob buf() is a memoryview which we can't compare.  We could copy
        #   into a bytearray for comparison but that is inefficient.  So, just
        #   directly use normal loop.
        for i in range(len(buf1)):
            if buf1[i] < buf2[i]:
                return -1
            if buf1[i] > buf2[i]:
                return 1

        return 0

    def matches(self, component):
        """
        Check if the component matches any of the exclude criteria.

        :param Name.Component component: The name component to check.
        :return: True if the component matches any of the exclude criteria,
          otherwise False.
        """
        i = 0
        while i < len(self._entries):
            if self._entries[i].getType() == Exclude.ANY:
                lowerBound = None
                if i > 0:
                    lowerBound = self._entries[i - 1]

                # Find the upper bound, possibly skipping over multiple ANY in
                #  a row.
                upperBound = None
                iUpperBound = i + 1
                while iUpperBound < len(self._entries):
                    if self._entries[iUpperBound].getType() == Exclude.COMPONENT:
                        upperBound = self._entries[iUpperBound]
                        break
                    iUpperBound += 1

                # If lowerBound != 0, we already checked component equals
                #   lowerBound on the last pass.
                # If upperBound != 0, we will check component equals upperBound
                #   on the next pass.
                if upperBound != None:
                    if lowerBound != None:
                        if (self.compareComponents(
                                component, lowerBound.getComponent()) > 0 and
                              self.compareComponents(
                                component, upperBound.getComponent()) < 0):
                            return True
                    else:
                        if (self.compareComponents(
                              component, upperBound.getComponent()) < 0):
                            return True

                    # Make i equal iUpperBound on the next pass.
                    i = iUpperBound - 1
                else:
                    if lowerBound != None:
                        if (self.compareComponents(
                              component, lowerBound.getComponent()) > 0):
                            return True
                    else:
                        # this.values has only ANY.
                        return True
            else:
                if (self.compareComponents(
                      component, self._entries[i].getComponent()) == 0):
                    return True

            i +=1

        return False

    def getChangeCount(self):
        """
        Get the change count, which is incremented each time this object is
        changed.

        :return: The change count.
        :rtype: int
        """
        return self._changeCount

    # Python operators.

    def __len__(self):
        return len(self._entries)

    def __getitem__(self, key):
        if type(key) is int:
            return self._entries[key]
        else:
            raise ValueError("Unknown __getitem__ type: %s" % type(key))

# Import these at the end of the file to avoid circular references.
from pyndn.util.common import Common

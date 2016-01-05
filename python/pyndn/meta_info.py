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
This module defines the MetaInfo class which is used by Data and represents
the fields of an NDN MetaInfo.
"""

from pyndn.name import Name

class MetaInfo(object):
    """
    Create a new MetaInfo object, possibly copying values from another object.

    :param MetaInfo value: (optional) If value is a MetaInfo, copy its values.
      If value is omitted, the type is the default ContentType.BLOB and the
      freshness period is not specified.
    """
    def __init__(self, value = None):
        if value == None:
            self._type = ContentType.BLOB
            self._freshnessPeriod = None
            self._finalBlockId = Name.Component()
        elif type(value) is MetaInfo:
            # Copy its values.
            self._type = value._type
            self._freshnessPeriod = value._freshnessPeriod
            self._finalBlockId = value._finalBlockId
        else:
            raise RuntimeError(
              "Unrecognized type for MetaInfo constructor: " +
              str(type(value)))

        self._changeCount = 0

    def getType(self):
        """
        Get the content type.

        :return: The content type.
        :rtype: an int from ContentType
        """
        return self._type

    def getFreshnessPeriod(self):
        """
        Get the freshness period.

        :return: The freshness period in milliseconds, or None if not specified.
        :rtype: float
        """
        return self._freshnessPeriod

    def getFinalBlockId(self):
        """
        Get the final block ID.

        :return: The final block ID as a Name.Component.  If the Name.Component
          getValue().size() is 0, then the final block ID is not specified.
        :rtype: Name.Component
        """
        return self._finalBlockId

    def getFinalBlockID(self):
        """
        :deprecated: Use getFinalBlockId.
        """
        return self.getFinalBlockId()

    def setType(self, type):
        """
        Set the content type.

        :param type: The content type.  If None, this uses ContentType.BLOB.
        :type type: an int from ContentType
        """
        self._type = ContentType.BLOB if type == None or type < 0 else type
        self._changeCount += 1

    def setFreshnessPeriod(self, freshnessPeriod):
        """
        Set the freshness period.

        :param float freshnessPeriod: The freshness period in milliseconds, or
          None for not specified.
        """
        self._freshnessPeriod = freshnessPeriod
        self._changeCount += 1

    def setFinalBlockId(self, finalBlockId):
        """
        Set the final block ID.

        :param finalBlockId: The final block ID.  If it is another
          Name.Component, use its value. Otherwise pass value to the
          Name.Component constructor.  If finalBlockId is None, set to a
          Name.Component of size 0 so that the finalBlockId is not specified
          and not encoded.
        :type finalBlockId: Name.Component or value for the Name.Component
          constructor
        """
        self._finalBlockId = (finalBlockId if type(finalBlockId) is Name.Component
                              else Name.Component(finalBlockId))
        self._changeCount += 1

    def setFinalBlockID(self, finalBlockId):
        """
        :deprecated: Use setFinalBlockId.
        """
        self.setFinalBlockId(finalBlockId)

    def getChangeCount(self):
        """
        Get the change count, which is incremented each time this object is
        changed.

        :return: The change count.
        :rtype: int
        """
        return self._changeCount

    # Support property-based equivalence check
    # TODO: Desired syntax?
    def equals(self, other):
        if  (self._type == other._type
        and self._freshnessPeriod == other._freshnessPeriod
        and self._finalBlockId == other._finalBlockId):
            return True
        else:
            return False

    # Create managed properties for read/write properties of the class for more pythonic syntax.
    type = property(getType, setType)
    freshnessPeriod = property(getFreshnessPeriod, setFreshnessPeriod)
    finalBlockId = property(getFinalBlockId, setFinalBlockId)
    finalBlockID = property(getFinalBlockID, setFinalBlockID)

class ContentType(object):
    """
    A ContentType specifies the content type in a MetaInfo object.
    """
    BLOB = 0
    LINK = 1
    KEY =  2
    NACK = 3

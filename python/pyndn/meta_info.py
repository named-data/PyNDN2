# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2019 Regents of the University of California.
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
from pyndn.util.common import Common

class MetaInfo(object):
    """
    Create a new MetaInfo object, possibly copying values from another object.

    :param MetaInfo value: (optional) If value is a MetaInfo, copy its values.
      If value is omitted, the type is the default ContentType.BLOB and the
      freshness period is not specified.
    """
    def __init__(self, value = None):
        self._changeCount = 0

        if value == None:
            self.clear()
        elif isinstance(value, MetaInfo):
            # Copy its values.
            self._type = value._type
            self._otherTypeCode = value._otherTypeCode
            self._freshnessPeriod = value._freshnessPeriod
            self._finalBlockId = value._finalBlockId
        else:
            raise RuntimeError(
              "Unrecognized type for MetaInfo constructor: " +
              str(type(value)))

    def getType(self):
        """
        Get the content type.

        :return: The content type enum value. If this is ContentType.OTHER_CODE,
          then call getOtherTypeCode() to get the unrecognized content type code.
        :rtype: an int from ContentType
        """
        return self._type

    def getOtherTypeCode(self):
        """
        Get the content type code from the packet which is other than a
        recognized ContentType enum value. This is only meaningful if getType()
        is ContentType.OTHER_CODE.

        :return: The type code.
        :rtype: int
        """
        return self._otherTypeCode

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

        :param type: The content type.  If None, this uses ContentType.BLOB. If
          the packet's content type is not a recognized ContentType enum value,
          use ContentType.OTHER_CODE and call setOtherTypeCode().
        :type type: an int from ContentType
        """
        self._type = ContentType.BLOB if type == None or type < 0 else type
        self._changeCount += 1

    def setOtherTypeCode(self, otherTypeCode):
        """
        Set the packet's content type code to use when the content type enum is
        ContentType.OTHER_CODE. If the packet's content type code is a
        recognized enum value, just call setType().

        :param int otherTypeCode: The packet's unrecognized content type code,
          which must be non-negative.
        """
        if otherTypeCode < 0:
            raise RuntimeError("MetaInfo other type code must be non-negative")

        self._otherTypeCode = otherTypeCode
        self._changeCount += 1

    def setFreshnessPeriod(self, freshnessPeriod):
        """
        Set the freshness period.

        :param float freshnessPeriod: The freshness period in milliseconds, or
          None for not specified.
        """
        self._freshnessPeriod = Common.nonNegativeFloatOrNone(freshnessPeriod)
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
        self._finalBlockId = (finalBlockId if isinstance(finalBlockId, Name.Component)
                              else Name.Component(finalBlockId))
        self._changeCount += 1

    def setFinalBlockID(self, finalBlockId):
        """
        :deprecated: Use setFinalBlockId.
        """
        self.setFinalBlockId(finalBlockId)

    def clear(self):
        """
        Clear fields and reset to default values.
        """
        self._type = ContentType.BLOB
        self._otherTypeCode = -1
        self._freshnessPeriod = None
        self._finalBlockId = Name.Component()

        self._changeCount += 1

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
    A ContentType specifies the content type in a MetaInfo object. If the
    content type in the packet is not a recognized enum value, then we use
    ContentType.OTHER_CODE and you can call MetaInfo.getOtherTypeCode(). We do
    this to keep the recognized content type values independent of packet
    encoding formats.
    """
    BLOB = 0
    LINK = 1
    KEY =  2
    NACK = 3
    OTHER_CODE = 0x7fff

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt src/producer-db https://github.com/named-data/ndn-group-encrypt
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
This module defines the ProducerDb class which is an abstract base class the
storage of keys for the producer. It contains one table that maps time slots (to
the nearest hour) to the content key created for that time slot. A subclass must
implement the methods. For example, see Sqlite3ProducerDb.
Note: This class is an experimental feature. The API may change.
"""

import math

class ProducerDb(object):
    class Error(Exception):
        def __init__(self, message):
            super(ProducerDb.Error, self).__init__(message)

    def hasContentKey(self, timeSlot):
        """
        Check if a content key exists for the hour covering timeSlot.

        :param float timeSlot: The time slot as milliseconds since Jan 1,
          1970 UTC.
        :return: True if there is a content key for timeSlot.
        :rtype: bool
        :raises ProducerDb.Error: For a database error.
        """
        raise RuntimeError("ProducerDb.hasContentKey is not implemented")

    def getContentKey(self, timeSlot):
        """
        Get the content key for the hour covering timeSlot.

        :param float timeSlot: The time slot as milliseconds since Jan 1,
          1970 UTC.
        :return: A Blob with the encoded key.
        :rtype: Blob
        :raises ProducerDb.Error: If there is no key covering timeSlot or other
          database error.
        """
        raise RuntimeError("ProducerDb.getContentKey is not implemented")

    def addContentKey(self, timeSlot, key):
        """
        Add key as the content key for the hour covering timeSlot.

        :param float timeSlot: The time slot as milliseconds since Jan 1,
          1970 UTC.
        :param Blob key: The encoded key.
        :raises ProducerDb.Error: If a key for the same hour already exists in
          the database, or other database error.
        """
        raise RuntimeError("ProducerDb.addContentKey is not implemented")

    def deleteContentKey(self, timeSlot):
        """
         Delete the content key for the hour covering timeSlot. If there is no
         key for the time slot, do nothing.

        :param float timeSlot: The time slot as milliseconds since Jan 1,
          1970 UTC.
        :raises ProducerDb.Error: For a database error.
        """
        raise RuntimeError("ProducerDb.deleteContentKey is not implemented")

    @staticmethod
    def getFixedTimeSlot(timeSlot):
        """
        Get the hour-based time slot.

        :param float timeSlot: The time slot as milliseconds since Jan 1,
          1970 UTC.
        :return: The hour-based time slot as hours since Jan 1, 1970 UTC.
        :rtype: int
        """
        return int(math.floor(round(timeSlot) / 3600000.0))

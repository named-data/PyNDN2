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
This module defines the Sqlite3ProducerDb class which extends ProducerDb to
implement storage of keys for the producer using SQLite3. It contains one table
that maps time slots (to the nearest hour) to the content key created for that
time slot.
Note: This class is an experimental feature. The API may change.
"""

import sqlite3
from pyndn.util.blob import Blob
from pyndn.encrypt.producer_db import ProducerDb

INITIALIZATION1 = """
CREATE TABLE IF NOT EXISTS
  contentkeys(
    rowId            INTEGER PRIMARY KEY,
    timeslot         INTEGER,
    key              BLOB NOT NULL
  );"""
INITIALIZATION2 = """
CREATE UNIQUE INDEX IF NOT EXISTS
   timeslotIndex ON contentkeys(timeslot);"""

class Sqlite3ProducerDb(ProducerDb):
    """
    Create an Sqlite3ProducerDb to use the given SQLite3 file.

    :param str databaseFilePath: The path of the SQLite file.
    """
    def __init__(self, databaseFilePath):
        super(Sqlite3ProducerDb, self).__init__()

        self._database = sqlite3.connect(databaseFilePath)

        cursor = self._database.cursor()
        cursor.execute(INITIALIZATION1)
        cursor.execute(INITIALIZATION2)
        self._database.commit()
        cursor.close()

    def hasContentKey(self, timeSlot):
        """
        Check if a content key exists for the hour covering timeSlot.

        :param float timeSlot: The time slot as milliseconds since Jan 1,
          1970 UTC.
        :return: True if there is a content key for timeSlot.
        :rtype: bool
        :raises ProducerDb.Error: For a database error.
        """
        fixedTimeSlot = ProducerDb.getFixedTimeSlot(timeSlot)
        result = False

        try:
            cursor = self._database.cursor()
            cursor.execute(
              "SELECT key FROM contentkeys where timeslot=?", (fixedTimeSlot, ))
            if cursor.fetchone() != None:
                result = True

            cursor.close()
            return result
        except Exception as ex:
            raise ProducerDb.Error(
              "Sqlite3ProducerDb.hasContentKey: SQLite error: " + str(ex))

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
        fixedTimeSlot = ProducerDb.getFixedTimeSlot(timeSlot)
        contentKey = None

        try:
            cursor = self._database.cursor()
            cursor.execute(
              "SELECT key FROM contentkeys where timeslot=?", (fixedTimeSlot, ))
            result = cursor.fetchone()
            if result != None:
                contentKey = Blob(bytearray(result[0]), False)
            cursor.close()
        except Exception as ex:
            raise ProducerDb.Error(
              "Sqlite3ProducerDb.getContentKey: SQLite error: " + str(ex))

        if contentKey == None:
            raise ProducerDb.Error(
              "Sqlite3ProducerDb.getContentKey: Cannot get the key from the database")

        return contentKey

    def addContentKey(self, timeSlot, key):
        """
        Add key as the content key for the hour covering timeSlot.

        :param float timeSlot: The time slot as milliseconds since Jan 1,
          1970 UTC.
        :param Blob key: The encoded key.
        :raises ProducerDb.Error: If a key for the same hour already exists in
          the database, or other database error.
        """
        fixedTimeSlot = ProducerDb.getFixedTimeSlot(timeSlot)

        try:
            cursor = self._database.cursor()
            cursor.execute(
              "INSERT INTO contentkeys (timeslot, key) values (?, ?)",
              (fixedTimeSlot, sqlite3.Binary(bytearray(key.buf()))))
            self._database.commit()
            cursor.close()
        except Exception as ex:
            raise ProducerDb.Error(
              "Sqlite3ProducerDb.addContentKey: SQLite error: " + str(ex))

    def deleteContentKey(self, timeSlot):
        """
         Delete the content key for the hour covering timeSlot. If there is no
         key for the time slot, do nothing.

        :param float timeSlot: The time slot as milliseconds since Jan 1,
          1970 UTC.
        :raises ProducerDb.Error: For a database error.
        """
        fixedTimeSlot = ProducerDb.getFixedTimeSlot(timeSlot)

        try:
            cursor = self._database.cursor()
            cursor.execute(
              "DELETE FROM contentkeys WHERE timeslot=?", (fixedTimeSlot, ))
            self._database.commit()
            cursor.close()
        except Exception as ex:
            raise ProducerDb.Error(
              "Sqlite3ProducerDb.deleteContentKey: SQLite error: " + str(ex))

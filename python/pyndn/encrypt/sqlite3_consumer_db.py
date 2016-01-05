# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt src/consumer-db https://github.com/named-data/ndn-group-encrypt
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
This module defines the Sqlite3ConsumerDb class which extends ConsumerDb to
implement the storage of decryption keys for the consumer using SQLite3.
Note: This class is an experimental feature. The API may change.
"""

import sqlite3
from pyndn.util.blob import Blob
from pyndn.encoding.tlv_wire_format import TlvWireFormat
from pyndn.encrypt.consumer_db import ConsumerDb

INITIALIZATION1 = """
CREATE TABLE IF NOT EXISTS
  decryptionkeys(
    key_id              INTEGER PRIMARY KEY,
    key_name            BLOB NOT NULL,
    key_buf             BLOB NOT NULL
  );"""
INITIALIZATION2 = """
CREATE UNIQUE INDEX IF NOT EXISTS
   KeyNameIndex ON decryptionkeys(key_name);"""

class Sqlite3ConsumerDb(ConsumerDb):
    """
    Create an Sqlite3ConsumerDb to use the given SQLite3 file.

    :param str databaseFilePath: The path of the SQLite file.
    """
    def __init__(self, databaseFilePath):
        super(Sqlite3ConsumerDb, self).__init__()

        self._database = sqlite3.connect(databaseFilePath)

        cursor = self._database.cursor()
        cursor.execute(INITIALIZATION1)
        cursor.execute(INITIALIZATION2)
        self._database.commit()
        cursor.close()

    def getKey(self, keyName):
        """
        Get the key with keyName from the database.

        :param Name keyName: The key name.
        :return: A Blob with the encoded key, or an isNull Blob if cannot find
          the key with keyName.
        :rtype: Blob
        :raises ConsumerDb.Error: For a database error.
        """
        try:
            cursor = self._database.cursor()
            cursor.execute(
              "SELECT key_buf FROM decryptionkeys WHERE key_name=?",
              (sqlite3.Binary(bytearray(keyName.wireEncode(TlvWireFormat.get()).buf())), ))
            result = cursor.fetchone()
            key = Blob()
            if result != None:
                return Blob(bytearray(result[0]), False)
            cursor.close()

            return key
        except Exception as ex:
            raise ConsumerDb.Error(
              "Sqlite3ConsumerDb.getKey: SQLite error: " + str(ex))

    def addKey(self, keyName, keyBlob):
        """
        Add the key with keyName and keyBlob to the database.

        :param Name keyName: The key name.
        :param Blob keyBlob: The encoded key.
        :raises ConsumerDb.Error: If a key with the same keyName already exists
          in the database, or other database error.
        """
        try:
            cursor = self._database.cursor()
            cursor.execute(
              "INSERT INTO decryptionkeys(key_name, key_buf) values (?, ?)",
              (sqlite3.Binary(bytearray(keyName.wireEncode(TlvWireFormat.get()).buf())),
               sqlite3.Binary(bytearray(keyBlob.buf()))))
            self._database.commit()
            cursor.close()
        except Exception as ex:
            raise ConsumerDb.Error(
              "Sqlite3ConsumerDb.addKey: SQLite error: " + str(ex))

    def deleteKey(self, keyName):
        """
        Delete the key with keyName from the database. If there is no key with
        keyName, do nothing.

        :param Name keyName: The key name.
        :raises ConsumerDb.Error: For a database error.
        """
        try:
            cursor = self._database.cursor()
            cursor.execute(
              "DELETE FROM decryptionkeys WHERE key_name=?",
              (sqlite3.Binary(bytearray(keyName.wireEncode(TlvWireFormat.get()).buf())), ))
            self._database.commit()
            cursor.close()
        except Exception as ex:
            raise ConsumerDb.Error(
              "Sqlite3ConsumerDb.deleteKey: SQLite error: " + str(ex))

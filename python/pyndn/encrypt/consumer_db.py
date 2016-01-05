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
This module defines the ConsumerDb class which is an abstract base class the
storage of decryption keys for the consumer. A subclass must implement the
methods. For example, see Sqlite3ConsumerDb.
Note: This class is an experimental feature. The API may change.
"""

class ConsumerDb(object):
    class Error(Exception):
        def __init__(self, message):
            super(ConsumerDb.Error, self).__init__(message)

    def getKey(self, keyName):
        """
        Get the key with keyName from the database.

        :param Name keyName: The key name.
        :return: A Blob with the encoded key, or an isNull Blob if cannot find
          the key with keyName.
        :rtype: Blob
        :raises ConsumerDb.Error: For a database error.
        """
        raise RuntimeError("ConsumerDb.getKey is not implemented")

    def addKey(self, keyName, keyBlob):
        """
        Add the key with keyName and keyBlob to the database.

        :param Name keyName: The key name.
        :param Blob keyBlob: The encoded key.
        :raises ConsumerDb.Error: If a key with the same keyName already exists
          in the database, or other database error.
        """
        raise RuntimeError("ConsumerDb.addKey is not implemented")

    def deleteKey(self, keyName):
        """
        Delete the key with keyName from the database. If there is no key with
        keyName, do nothing.

        :param Name keyName: The key name.
        :raises ConsumerDb.Error: For a database error.
        """
        raise RuntimeError("ConsumerDb.deleteKey is not implemented")

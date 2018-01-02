# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt unit tests
# https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/producer-db.t.cpp
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

import unittest as ut
import os
from pyndn.encrypt import Schedule, ProducerDb, Sqlite3ProducerDb
from pyndn.encrypt.algo import AesAlgorithm
from pyndn.security import AesKeyParams

class TestProducerDb(ut.TestCase):
    def setUp(self):
        # Reuse the policy_config subdirectory for the temporary SQLite file.
        self.databaseFilePath = "policy_config/test.db"
        try:
            os.remove(self.databaseFilePath)
        except OSError:
            # no such file
            pass

    def tearDown(self):
        try:
            os.remove(self.databaseFilePath)
        except OSError:
            pass

    def test_database_functions(self):
        # Test construction.
        database = Sqlite3ProducerDb(self.databaseFilePath)

        # Create member.
        params = AesKeyParams(128)
        keyBlob1 = AesAlgorithm.generateKey(params).getKeyBits()
        keyBlob2 = AesAlgorithm.generateKey(params).getKeyBits()

        point1 = Schedule.fromIsoString("20150101T100000")
        point2 = Schedule.fromIsoString("20150102T100000")
        point3 = Schedule.fromIsoString("20150103T100000")
        point4 = Schedule.fromIsoString("20150104T100000")

        # Add keys into the database.
        database.addContentKey(point1, keyBlob1)
        database.addContentKey(point2, keyBlob1)
        database.addContentKey(point3, keyBlob2)

        # Throw an exception when adding a key to an existing time slot.
        with self.assertRaises(ProducerDb.Error):
            database.addContentKey(point1, keyBlob1)

        # Check has functions.
        self.assertEqual(True, database.hasContentKey(point1))
        self.assertEqual(True, database.hasContentKey(point2))
        self.assertEqual(True, database.hasContentKey(point3))
        self.assertEqual(False, database.hasContentKey(point4))

        # Get content keys.
        keyResult = database.getContentKey(point1)
        self.assertTrue(keyResult.equals(keyBlob1))

        keyResult = database.getContentKey(point3)
        self.assertTrue(keyResult.equals(keyBlob2))

        # Throw exception when there is no such time slot in the database.
        with self.assertRaises(ProducerDb.Error):
            database.getContentKey(point4)

        # Delete content keys.
        self.assertEqual(True, database.hasContentKey(point1))
        database.deleteContentKey(point1)
        self.assertEqual(False, database.hasContentKey(point1))

        # Delete at a non-existing time slot.
        try:
            database.deleteContentKey(point4)
        except Exception as ex:
            self.fail("Unexpected error deleting a non-existing content key: " + repr(ex))

if __name__ == '__main__':
    ut.main(verbosity=2)

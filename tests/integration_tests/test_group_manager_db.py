# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt unit tests
# https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/group-manager-db.t.cpp
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
from pyndn import Name
from pyndn.util import Blob
from pyndn.encrypt import Schedule, GroupManagerDb, Sqlite3GroupManagerDb
from pyndn.encrypt import RepetitiveInterval
from pyndn.encrypt.algo import RsaAlgorithm
from pyndn.security import RsaKeyParams

SCHEDULE = bytearray([
  0x8f, 0xc4, # Schedule
  0x8d, 0x90, # WhiteIntervalList
  0x8c, 0x2e, # RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x04,
    0x89, 0x01,
      0x07,
    0x8a, 0x01,
      0x00,
    0x8b, 0x01,
      0x00,
  0x8c, 0x2e, # RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x38, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x05,
    0x89, 0x01,
      0x0a,
    0x8a, 0x01,
      0x02,
    0x8b, 0x01,
      0x01,
  0x8c, 0x2e, # RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x38, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x06,
    0x89, 0x01,
      0x08,
    0x8a, 0x01,
      0x01,
    0x8b, 0x01,
      0x01,
  0x8e, 0x30, # BlackIntervalList
  0x8c, 0x2e, # RepetitiveInterval
     0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x37, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x37, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x07,
    0x89, 0x01,
      0x08,
    0x8a, 0x01,
      0x00,
    0x8b, 0x01,
      0x00
])

class TestGroupManagerDb(ut.TestCase):
    def setUp(self):
        # Reuse the policy_config subdirectory for the temporary SQLite file.
        self.databaseFilePath = "policy_config/test.db"
        try:
            os.remove(self.databaseFilePath)
        except OSError:
            # no such file
            pass

        self.database = Sqlite3GroupManagerDb(self.databaseFilePath)

    def tearDown(self):
        try:
            os.remove(self.databaseFilePath)
        except OSError:
            pass

    def test_database_functions(self):
        scheduleBlob = Blob(SCHEDULE, False)

        # Create a schedule.
        schedule = Schedule()
        schedule.wireDecode(scheduleBlob)

        # Create a member.
        params = RsaKeyParams()
        decryptKey = RsaAlgorithm.generateKey(params)
        encryptKey = RsaAlgorithm.deriveEncryptKey(decryptKey.getKeyBits())
        keyBlob = encryptKey.getKeyBits()

        name1 = Name("/ndn/BoyA/ksk-123")
        name2 = Name("/ndn/BoyB/ksk-1233")
        name3 = Name("/ndn/GirlC/ksk-123")
        name4 = Name("/ndn/GirlD/ksk-123")
        name5 = Name("/ndn/Hello/ksk-123")

        # Add schedules into the database.
        self.database.addSchedule("work-time", schedule)
        self.database.addSchedule("rest-time", schedule)
        self.database.addSchedule("play-time", schedule)
        self.database.addSchedule("boelter-time", schedule)

        # Throw an exception when adding a schedule with an existing name.
        with self.assertRaises(GroupManagerDb.Error):
            self.database.addSchedule("boelter-time", schedule)

        # Add members into the database.
        self.database.addMember("work-time", name1, keyBlob)
        self.database.addMember("rest-time", name2, keyBlob)
        self.database.addMember("play-time", name3, keyBlob)
        self.database.addMember("play-time", name4, keyBlob)

        # Throw an exception when adding a member with a non-existing schedule name.
        with self.assertRaises(GroupManagerDb.Error):
            self.database.addMember("false-time", name5, keyBlob)

        self.database.addMember("boelter-time", name5, keyBlob)

        # Throw an exception when adding a member having an existing identity.
        with self.assertRaises(GroupManagerDb.Error):
            self.database.addMember("work-time", name5, keyBlob)

        # Test has functions.
        self.assertEqual(True, self.database.hasSchedule("work-time"))
        self.assertEqual(True, self.database.hasSchedule("rest-time"))
        self.assertEqual(True, self.database.hasSchedule("play-time"))
        self.assertEqual(False, self.database.hasSchedule("sleep-time"))
        self.assertEqual(False, self.database.hasSchedule(""))

        self.assertEqual(True, self.database.hasMember(Name("/ndn/BoyA")))
        self.assertEqual(True, self.database.hasMember(Name("/ndn/BoyB")))
        self.assertEqual(False, self.database.hasMember(Name("/ndn/BoyC")))

        # Get a schedule.
        scheduleResult = self.database.getSchedule("work-time")
        self.assertTrue(scheduleResult.wireEncode().equals(scheduleBlob))

        scheduleResult = self.database.getSchedule("play-time")
        self.assertTrue(scheduleResult.wireEncode().equals(scheduleBlob))

        # Throw an exception when when there is no such schedule in the database.
        with self.assertRaises(GroupManagerDb.Error):
            self.database.getSchedule("work-time-11")

        # List all schedule names.
        names = self.database.listAllScheduleNames()
        self.assertTrue("work-time" in names)
        self.assertTrue("play-time" in names)
        self.assertTrue("rest-time" in names)
        self.assertTrue(not ("sleep-time" in names))

        # List members of a schedule.
        memberMap = self.database.getScheduleMembers("play-time")
        self.assertTrue(len(memberMap) != 0)

        # When there's no such schedule, the return map's size should be 0.
        self.assertEquals(0, len(self.database.getScheduleMembers("sleep-time")))

        # List all members.
        members = self.database.listAllMembers()
        self.assertTrue(Name("/ndn/GirlC") in members)
        self.assertTrue(Name("/ndn/GirlD") in members)
        self.assertTrue(Name("/ndn/BoyA") in members)
        self.assertTrue(Name("/ndn/BoyB") in members)

        # Rename a schedule.
        self.assertEqual(True, self.database.hasSchedule("boelter-time"))
        self.database.renameSchedule("boelter-time", "rieber-time")
        self.assertEqual(False, self.database.hasSchedule("boelter-time"))
        self.assertEqual(True, self.database.hasSchedule("rieber-time"))
        self.assertEqual("rieber-time", self.database.getMemberSchedule(Name("/ndn/Hello")))

        # Update a schedule.
        newSchedule = Schedule()
        newSchedule.wireDecode(scheduleBlob)
        repetitiveInterval = RepetitiveInterval(
          Schedule.fromIsoString("20150825T000000"),
          Schedule.fromIsoString("20150921T000000"), 2, 10,
          5, RepetitiveInterval.RepeatUnit.DAY)
        newSchedule.addWhiteInterval(repetitiveInterval)
        self.database.updateSchedule("rieber-time", newSchedule)
        scheduleResult = self.database.getSchedule("rieber-time")
        self.assertTrue(not scheduleResult.wireEncode().equals(scheduleBlob))
        self.assertTrue(scheduleResult.wireEncode().equals(newSchedule.wireEncode()))

        # Add a new schedule when updating a non-existing schedule.
        self.assertEquals(False, self.database.hasSchedule("ralphs-time"))
        self.database.updateSchedule("ralphs-time", newSchedule)
        self.assertEquals(True, self.database.hasSchedule("ralphs-time"))

        # Update the schedule of a member.
        self.database.updateMemberSchedule(Name("/ndn/Hello"), "play-time")
        self.assertEqual("play-time", self.database.getMemberSchedule(Name("/ndn/Hello")))

        # Delete a member.
        self.assertEqual(True, self.database.hasMember(Name("/ndn/Hello")))
        self.database.deleteMember(Name("/ndn/Hello"))
        self.assertEqual(False, self.database.hasMember(Name("/ndn/Hello")))

        # Delete a non-existing member.
        try:
            self.database.deleteMember(Name("/ndn/notExisting"))
        except Exception as ex:
            self.fail("Unexpected error deleting a non-existing member: " + repr(ex))

        # Delete a schedule. All the members using this schedule should be deleted.
        self.database.deleteSchedule("play-time")
        self.assertEqual(False, self.database.hasSchedule("play-time"))
        self.assertEqual(False, self.database.hasMember(Name("/ndn/GirlC")))
        self.assertEqual(False, self.database.hasMember(Name("/ndn/GirlD")))

        # Delete a non-existing schedule.
        try:
            self.database.deleteSchedule("not-existing-time")
        except Exception as ex:
            self.fail("Unexpected error deleting a non-existing schedule: " + repr(ex))

if __name__ == '__main__':
    ut.main(verbosity=2)

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt src/group-manager-db https://github.com/named-data/ndn-group-encrypt
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
This module defines the GroupManagerDb class which is an abstract base class for
the storage of data used by the GroupManager. It contains two tables to store
Schedules and Members. This is an abstract base class. A subclass must implement
the methods. For example, see Sqlite3GroupManagerDb.
Note: This class is an experimental feature. The API may change.
"""

class GroupManagerDb(object):
    class Error(Exception):
        def __init__(self, message):
            super(GroupManagerDb.Error, self).__init__(message)

    #################################################### Schedule management.

    def hasSchedule(self, name):
        """
        Check if there is a schedule with the given name.

        :param str name: The name of the schedule.
        :return: True if there is a schedule.
        :rtype: bool
        :raises GroupManagerDb.Error: For a database error.
        """
        raise RuntimeError("GroupManagerDb.hasSchedule is not implemented")

    def listAllScheduleNames(self):
        """
        List all the names of the schedules.

        :return: A new List of String with the names of all schedules.
        :rtype: Array<str>
        :raises GroupManagerDb.Error: For a database error.
        """
        raise RuntimeError("GroupManagerDb.listAllScheduleNames is not implemented")

    def getSchedule(self, name):
        """
        Get a schedule with the given name.

        :param str name: The name of the schedule.
        :return: A new Schedule object.
        :rtype: Schedule
        :raises GroupManagerDb.Error: If the schedule does not exist or other
          database error.
        """
        raise RuntimeError("GroupManagerDb.getSchedule is not implemented")

    def getScheduleMembers(self, name):
        """
        For each member using the given schedule, get the name and public key
        DER of the member's key.

        :param str name: The name of the schedule.
        :return: a new dictionary where the dictionary's key is the Name of the
          public key and the value is the Blob of the public key DER. Note that
          the member's identity name is keyName.getPrefix(-1). If the schedule
          name is not found, the dictionary is empty.
        :rtype: dictionary<Name, Blob>
        :raises GroupManagerDb.Error: For a database error.
        """
        raise RuntimeError("GroupManagerDb.getScheduleMembers is not implemented")

    def addSchedule(self, name, schedule):
        """
        Add a schedule with the given name.

        :param str name: The name of the schedule. The name cannot be empty.
        :param Schedule schedule: The Schedule to add.
        :raises GroupManagerDb.Error: If a schedule with the same name already
          exists, if the name is empty, or other database error.
        """
        raise RuntimeError("GroupManagerDb.addSchedule is not implemented")

    def deleteSchedule(self, name):
        """
        Delete the schedule with the given name. Also delete members which use
        this schedule. If there is no schedule with the name, then do nothing.

        :param str name: The name of the schedule.
        :raises GroupManagerDb.Error: For a database error.
        """
        raise RuntimeError("GroupManagerDb.deleteSchedule is not implemented")

    def renameSchedule(self, oldName, newName):
        """
        Rename a schedule with oldName to newName.

        :param str oldName: The name of the schedule to be renamed.
        :param str newName: The new name of the schedule. The name cannot be
          empty.
        :raises GroupManagerDb.Error: If a schedule with newName already exists,
          if the schedule with oldName does not exist, if newName is empty, or
          other database error.
        """
        raise RuntimeError("GroupManagerDb.renameSchedule is not implemented")

    def updateSchedule(self, name, schedule):
        """
        Update the schedule with name and replace the old object with the given
        schedule. Otherwise, if no schedule with name exists, a new schedule
        with name and the given schedule will be added to database.

        :param str name: The name of the schedule. The name cannot be empty.
        :param Schedule schedule: The Schedule to update or add.
        :raises GroupManagerDb.Error: If the name is empty, or other database
          error.
        """
        raise RuntimeError("GroupManagerDb.updateSchedule is not implemented")

    #################################################### Member management.

    def hasMember(self, identity):
        """
        Check if there is a member with the given identity name.

        :param Name identity: The member's identity name.
        :return: True if there is a member.
        :rtype: bool
        :raises GroupManagerDb.Error: For a database error.
        """
        raise RuntimeError("GroupManagerDb.hasMember is not implemented")

    def listAllMembers(self):
        """
        List all the members.

        :return: A new List of Name with the names of all members.
        :rtype: Array<Name>
        :raises GroupManagerDb.Error: For a database error.
        """
        raise RuntimeError("GroupManagerDb.listAllMembers is not implemented")

    def getMemberSchedule(self, identity):
        """
        Get the name of the schedule for the given member's identity name.

        :param Name identity: The member's identity name.
        :return: The name of the schedule.
        :rtype: str
        :raises GroupManagerDb.Error: If there's no member with the given
          identity name in the database, or other database error.
        """
        raise RuntimeError("GroupManagerDb.getMemberSchedule is not implemented")

    def addMember(self, scheduleName, keyName, key):
        """
        Add a new member with the given key named keyName into a schedule named
        scheduleName. The member's identity name is keyName.getPrefix(-1).

        :param str scheduleName: The schedule name.
        :param Name keyName: The name of the key.
        :param Blob key: A Blob of the public key DER.
        :raises GroupManagerDb.Error: If there's no schedule named scheduleName,
          if the member's identity name already exists, or other database error.
        """
        raise RuntimeError("GroupManagerDb.addMember is not implemented")

    def updateMemberSchedule(self, identity, scheduleName):
        """
        Change the name of the schedule for the given member's identity name.

        :param Name identity: The member's identity name.
        :param str scheduleName: The new schedule name.
        :raises GroupManagerDb.Error: If there's no member with the given
          identity name in the database, or there's no schedule named
          scheduleName, or other database error.
        """
        raise RuntimeError("GroupManagerDb.updateMemberSchedule is not implemented")

    def deleteMember(self, identity):
        """
        Delete a member with the given identity name. If there is no member with
        the identity name, then do nothing.

        :param Name identity: The member's identity name.
        :raises GroupManagerDb.Error: For a database error.
        """
        raise RuntimeError("GroupManagerDb.deleteMember is not implemented")

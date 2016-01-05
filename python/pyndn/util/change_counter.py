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
This module defines the ChangeCounter class which keeps a target object whose
change count is tracked by a local change count.  You can set to a new target
which updates the local change count, and you can call checkChanged
to check if the target (or one of the target's targets) has been changed.
The target object must have a method getChangeCount.
"""

class ChangeCounter(object):
    """
    Create a new ChangeCounter to track the given target. If target is not None,
    this sets the local change counter to target.getChangeCount().

    :param target: The target to track.
    :type target: An type with method getChangeCount()
    """
    def __init__(self, target):
        self._target = target
        self._changeCount = (0 if target == None else target.getChangeCount())

    def get(self):
        """
        Get the target object.  If the target is changed, then checkChanged will
        detect it.

        :return: The target object.
        :rtype: An type with method getChangeCount()
        """
        return self._target

    def set(self, target):
        """
        Set the target to the given target. If target is not None, this sets the
        local change counter to target.getChangeCount().

        :param target: The target to track.
        :type target: An type with method getChangeCount()
        """
        self._target = target
        self._changeCount = (0 if target == None else target.getChangeCount())

    def checkChanged(self):
        """
        If the target's change count is different than the local change count,
        then update the local change count and return True.  Otherwise return
        False, meaning that the target has not changed. Also, if the target is
        None, simply return false. This is useful since the target (or one of
        the target's targets) may be changed and you need to find out.

        :return: True if the change count has been updated, false if not.
        :rtype: bool
        """
        if self._target == None:
            return False

        targetChangeCount = self._target.getChangeCount()
        if self._changeCount != targetChangeCount:
            self._changeCount = targetChangeCount
            return True
        else:
            return False

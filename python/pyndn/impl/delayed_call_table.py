# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2016 Regents of the University of California.
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
This module defines DelayedCallTable which is an internal class used by the Node
implementation of callLater to store callbacks and call them when they time out.
"""

from pyndn.util.common import Common

class DelayedCallTable(object):
    def __init__(self):
        self._table = [] # of _Entry

    def callLater(self, delayMilliseconds, callback):
        """
        Call callback() after the given delay. This adds to the delayed call
        table which is used by callTimedOut().

        :param float delayMilliseconds: The delay in milliseconds.
        :param callback: This calls callback() after the delay.
        :type callback: function object
        """
        entry = DelayedCallTable._Entry(delayMilliseconds, callback)
        # Insert into _table, sorted on getCallTime().
        # Search from the back since we expect it to go there.
        i = len(self._table) - 1
        while i >= 0:
            if (self._table[i].getCallTime() <= entry.getCallTime()):
                break
            i -= 1

        # Element i is the greatest less than or equal to
        # entry.getCallTime(), so insert after it.
        self._table.insert(i + 1, entry)

    def callTimedOut(self):
        """
        Call and remove timed-out callback entries. Since callLater does a
        sorted insert into the delayed call table, the check for timed-out
        entries is quick and does not require searching the entire table.
        """
        now = Common.getNowMilliseconds()
        # _table is sorted on _callTime, so we only need to process the
        # timed-out entries at the front, then quit.
        while (len(self._table) > 0 and self._table[0].getCallTime() <= now):
            entry = self._table[0]
            del self._table[0]
            entry.callCallback()

    class _Entry(object):
        """
        _Entry holds the callback and other fields for an entry in the delayed
        call table. Create a new DelayedCallTable.Entry and set the call time
        based on the current time and the delayMilliseconds.

        :param float delayMilliseconds: The delay in milliseconds.
        :param callback: This calls callback() after the delay.
        :type callback: function object
        """
        def __init__(self, delayMilliseconds, callback):
            self._callback = callback
            self._callTime = Common.getNowMilliseconds() + delayMilliseconds

        def getCallTime(self):
            """
            Get the time at which the callback should be called.

            :return: The call time in milliseconds, similar to
              Common.getNowMilliseconds().
            :rtype: float
            """
            return self._callTime

        def callCallback(self):
            """
            Call the callback given to the constructor. This does not catch
            exceptions.
            """
            self._callback()

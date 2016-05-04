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
This module defines PendingInterestTable which is an internal class to hold a
list of pending interests with their callbacks.
"""

import logging

class PendingInterestTable(object):
    def __init__(self):
        self._table = []  # of Entry
        self._removeRequests = [] # of int

    class Entry(object):
        """
        Create a new Entry with the given fields. Note: You should not call this
        directly but call PendingInterestTable.add.

        :param int pendingInterestId: A unique ID for this entry, which you
          should get with Node.getNextEntryId().
        :param Interest interest: The interest.
        :param onData: A function object to call when a matching data packet is
          received.
        :type onData: function object
        :param onTimeout: A function object to call if the interest times out.
          If onTimeout is None, this does not use it.
        :type onTimeout: function object
        :param onNetworkNack: A function object to call when a network Nack
          packet is received.
        :type onNetworkNack: function object
        """
        def __init__(
          self, pendingInterestId, interest, onData, onTimeout, onNetworkNack):
            self._pendingInterestId = pendingInterestId
            self._interest = interest
            self._onData = onData
            self._onTimeout = onTimeout
            self._onNetworkNack = onNetworkNack
            self._isRemoved = False

        def getPendingInterestId(self):
            """
            Get the pendingInterestId given to the constructor.

            :return: The pending interest ID.
            :rtype: int
            """
            return self._pendingInterestId

        def getInterest(self):
            """
            Get the interest given to the constructor.

            :return: The interest.
            :rtype: int
            """
            return self._interest

        def getOnData(self):
            """
            Get the onData function object given to the constructor.

            :return: The onData function object.
            :rtype: function object
            """
            return self._onData

        def getOnNetworkNack(self):
            """
            Get the onNetworkNack function object given to the constructor.

            :return: The onNetworkNack function object.
            :rtype: function object
            """
            return self._onNetworkNack

        def callTimeout(self):
            """
            Call _onTimeout (if defined).  This ignores exceptions from
            _onTimeout.
            """
            if self._onTimeout:
                try:
                    self._onTimeout(self._interest)
                except:
                    logging.exception("Error in onTimeout")

        def setIsRemoved(self):
            """
            Set the isRemoved flag which is returned by getIsRemoved().
            """
            self._isRemoved = True

        def getIsRemoved(self):
            """
            Check if setIsRemoved() was called.

            :return: True if setIsRemoved() was called.
            :rtype: bool
            """
            return self._isRemoved

    def add(
      self, pendingInterestId, interestCopy, onData, onTimeout, onNetworkNack):
        """
        Add a new entry to the pending interest table. However, if
        removePendingInterest was already called with the pendingInterestId,
        don't add an entry and return None.

        :param int pendingInterestId: A unique ID for this entry, which you
          should get with Node.getNextEntryId().
        :param Interest interest: The interest which was sent, which has already
          been copied by expressInterest.
        :param onData: A function object to call when a matching data packet is
          received.
        :type onData: function object
        :param onTimeout: A function object to call if the interest times out.
          If onTimeout is None, this does not use it.
        :type onTimeout: function object
        :param onNetworkNack: A function object to call when a network Nack
          packet is received.
        :type onNetworkNack: function object
        :return: The new PendingInterestTable.Entry, or None if
          removePendingInterest was already called with the pendingInterestId.
        :rtype: PendingInterestTable.Entry
        """
        try:
            removeRequestIndex = self._removeRequests.index(pendingInterestId)
            # removePendingInterest was called with the pendingInterestId returned by
            #   expressInterest before we got here, so don't add a PIT entry.
            del self._removeRequests[removeRequestIndex]
            return None
        except ValueError:
            pass

        entry = PendingInterestTable.Entry(
          pendingInterestId, interestCopy, onData, onTimeout, onNetworkNack)
        self._table.append(entry)
        return entry

    def extractEntriesForExpressedInterest(self, name, entries):
        """
        Find all entries from the pending interest table where the name conforms
        to the entry's interest selectors, remove the entries from the table,
        set each entry's isRemoved flag, and add to the entries list.

        :param Name name: The name to find the interest for (from the incoming
          data packet).
        :param List<PendingInterestTable.Entry> entries: Add matching
          PendingInterestTable.Entry from the pending interest table. The caller
          should pass in an empty list.
        """
        # Go backwards through the list so we can erase entries.
        i = len(self._table) - 1
        while i >= 0:
            pendingInterest = self._table[i]

            if pendingInterest.getInterest().matchesName(name):
                entries.append(pendingInterest)
                # We let the callback from callLater call _processInterestTimeout,
                # but for efficiency, mark this as removed so that it returns
                # right away.
                self._table.pop(i)
                pendingInterest.setIsRemoved()
            i -= 1

    def extractEntriesForNackInterest(self, interest, entries):
        """
        Find all entries from the pending interest table where the OnNetworkNack
        callback is not null and the entry's interest is the same as the given
        interest, remove the entries from the table, set each entry's isRemoved
        flag, and add to the entries list. (We don't remove the entry if the
        OnNetworkNack callback is None so that OnTimeout will be called later.)
        The interests are the same if their default wire encoding is the same
        (which has everything including the name, nonce, link object and
        selectors).

        :param Interest interest: The Interest to search for (typically from a
          Nack packet).
        :param List<PendingInterestTable.Entry> entries: Add matching
          PendingInterestTable.Entry from the pending interest table. The caller
          should pass in an empty list.
        """
        encoding = interest.wireEncode()

        # Go backwards through the list so we can erase entries.
        i = len(self._table) - 1
        while i >= 0:
            pendingInterest = self._table[i]
            if pendingInterest.getOnNetworkNack() != None:
                # wireEncode returns the encoding cached when the interest was
                # sent (if it was the default wire encoding).
                if pendingInterest.getInterest().wireEncode().equals(encoding):
                    entries.append(pendingInterest)
                    # We let the callback from callLater call _processInterestTimeout,
                    # but for efficiency, mark this as removed so that it returns
                    # right away.
                    self._table.pop(i)
                    pendingInterest.setIsRemoved()

            i -= 1

    def removePendingInterest(self, pendingInterestId):
        """
        Remove the pending interest entry with the pendingInterestId from the
        pending interest table and set its isRemoved flag. This does not affect
        another pending interest with a different pendingInterestId, even if it
        has the same interest name. If there is no entry with the
        pendingInterestId, do nothing.

        :param int pendingInterestId: The ID returned from expressInterest.
        """
        count = 0
        # Go backwards through the list so we can erase entries.
        # Remove all entries even though pendingInterestId should be unique.
        i = len(self._table) - 1
        while i >= 0:
            if (self._table[i].getPendingInterestId() ==
                  pendingInterestId):
                count += 1
                # For efficiency, mark this as removed so that
                # _processInterestTimeout doesn't look for it.
                self._table[i].setIsRemoved()
                self._table.pop(i)
            i -= 1

        if count == 0:
            logging.getLogger(__name__).debug(
              "removePendingInterest: Didn't find pendingInterestId " +
              str(pendingInterestId))

        if count == 0:
            # The pendingInterestId was not found. Perhaps this has been called before
            #   the callback in expressInterest can add to the PIT. Add this
            #   removal request which will be checked before adding to the PIT.
            try:
                self._removeRequests.index(pendingInterestId)
            except ValueError:
                # Not already requested, so add the request.
                self._removeRequests.append(pendingInterestId)

    def removeEntry(self, pendingInterest):
        """
        Remove the specific pendingInterest entry from the table and set its
        isRemoved flag. However, if the pendingInterest isRemoved flag is
        already True or the entry is not in the pending interest table then do
        nothing.

        :param PendingInterestTable.Entry pendingInterest: The Entry from the
          pending interest table.
        :return: True if the entry was removed, False if not.
        :rtype: bool
        """
        if pendingInterest.getIsRemoved():
            # extractEntriesForExpressedInterest or removePendingInterest has
            # removed pendingInterest from the table, so we don't need to look
            # for it. Do nothing.
            return False

        try:
            index = self._table.index(pendingInterest)
        except ValueError:
            # The pending interest has been removed. Do nothing.
            return False

        pendingInterest.setIsRemoved()
        del self._table[index]
        return True


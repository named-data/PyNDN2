# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
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
This modules defines the InMemoryStorageFace which extends Face to hold an
InMemoryStorageRetaining and use it in expressInterest to instantly reply to an
Interest. It also allows calls to registerPrefix to remember the
OnInterestCallback. This also keeps a local DelayedCallTable (to use for
callLater) so that you can call its _setNowOffsetMilliseconds for testing.
"""

from pyndn import Interest, Data, Face, InterestFilter
from pyndn.impl.interest_filter_table import InterestFilterTable
from pyndn.impl.delayed_call_table import DelayedCallTable

class InMemoryStorageFace(Face):
    """
    Create an InMemoryStorageFace to use the given storage.

    :param InMemoryStorageRetaining storage: The InMemoryStorageRetaining used
      by expressInterest. If the Data packet for the Interest is found,
      expressInterest immediately calls onData, otherwise it immediately calls
      onTimeout.
    """
    def __init__(self, storage):
        self._storage = storage

        self._sentInterests = []
        self._sentData = []

        self._interestFilterTable = InterestFilterTable()
        # Use _delayedCallTable here so that we can call _setNowOffsetMilliseconds().
        self._delayedCallTable = DelayedCallTable()

    def expressInterest(self, interest, onData, onTimeout, onNetworkNack):
        # Make a copy of the interest.
        self._sentInterests.append(Interest(interest))

        data = self._storage.find(interest)
        if data != None:
            self._sentData.append(Data(data))
            onData(interest, data)
        else:
            onTimeout(interest)

        return 0

    def registerPrefix(self,
      prefix, onInterest, onRegisterFailed, onRegisterSuccess = None,
      flags = None, wireFormat = None):
        self._interestFilterTable.setInterestFilter(
          0, InterestFilter(prefix), onInterest, self)

        if onRegisterSuccess != None:
            onRegisterSuccess(prefix, 0)

        return 0

    def putData(self, data, wireFormat = None):
        self._sentData.append(Data(data))

    def callLater(self, delayMilliseconds, callback):
        self._delayedCallTable.callLater(delayMilliseconds, callback)

    def processEvents(self):
        self._delayedCallTable.callTimedOut()

    def receive(self, interest):
        """
        For each entry from calls to registerPrefix where the Interest matches
          the prefix, call its OnInterest callback.

        :param Interest interest: The Interest to receive and possibly call the
          OnInterest callback.
        """
        matchedFilters = []
        self._interestFilterTable.getMatchedFilters(interest, matchedFilters)
        for i in range(len(matchedFilters)):
            entry = matchedFilters[i]
            entry.getOnInterest()(
              entry.getFilter().getPrefix(), interest, entry.getFace(),
              entry.getInterestFilterId(), entry.getFilter())

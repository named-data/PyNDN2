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
This module defines InterestFilterTable which is an internal class to hold a
list of entries with an interest Filter and its OnInterestCallback.
"""

import logging

class InterestFilterTable(object):
    def __init__(self):
        self._table = [] # of Entry

    class Entry(object):
        """
        An Entry holds an interestFilterId, an InterestFilter and the
        OnInterestCallback with its related Face.
        Create a new InterestFilterEntry with the given values.

        :param int interestFilterId: The ID from Node.getNextEntryId().
        :param InterestFilter filter: The InterestFilter for this entry.
        :param onInterest: The callback to call.
        :type onInterest: function object
        :param Face face: The face on which was called registerPrefix or
          setInterestFilter which is passed to the onInterest callback.
        """
        def __init__(self, interestFilterId, filter, onInterest, face):
            self._interestFilterId = interestFilterId
            self._filter = filter
            self._onInterest = onInterest
            self._face = face

        def getInterestFilterId(self):
            """
            Get the interestFilterId given to the constructor.

            :return: The interestFilterId.
            :rtype: int
            """
            return self._interestFilterId

        def getFilter(self):
            """
            Get the InterestFilter given to the constructor.

            :return: The InterestFilter.
            :rtype: InterestFilter
            """
            return self._filter

        def getOnInterest(self):
            """
            Get the OnInterestCallback given to the constructor.

            :return: The OnInterestCallback.
            :rtype: function object
            """
            return self._onInterest

        def getFace(self):
            """
            Get the Face given to the constructor.

            :return: The Face.
            :rtype: Face
            """
            return self._face

    def setInterestFilter(self, interestFilterId, filterCopy, onInterest, face):
        """
        Add an entry to the table.

        :param int interestFilterId: The ID from Node.getNextEntryId().
        :param InterestFilter filterCopy: The InterestFilter for this entry.
        :param onInterest: The callback to call.
        :type onInterest: function object
        :param Face face: The face which is passed to the onInterest callback.
        """
        self._table.append(InterestFilterTable.Entry
          (interestFilterId, filterCopy, onInterest, face))

    def getMatchedFilters(self, interest, matchedFilters):
        """
        Find all entries from the interest filter table where the interest
        conforms to the entry's filter, and add to the matchedFilters list.

        :param Interest interest: The interest which may match the filter in
          multiple entries.
        :param List<InterestFilterTable.Entry> matchedFilters: Add each matching
          InterestFilterTable.Entry from the interest filter table.  The caller
          should pass in an empty list.
        """
        for i in range(len(self._table)):
            entry = self._table[i]
            if entry.getFilter().doesMatch(interest.getName()):
                matchedFilters.append(entry)

    def unsetInterestFilter(self, interestFilterId):
        """
        Remove the interest filter entry which has the interestFilterId from the
        interest filter table. This does not affect another interest filter with
        a different interestFilterId, even if it has the same prefix name. If
        there is no entry with the interestFilterId, do nothing.

        :param int interestFilterId: The ID returned from setInterestFilter.
        """
        count = 0
        # Go backwards through the list so we can erase entries.
        # Remove all entries even though interestFilterId should be unique.
        i = len(self._table) - 1
        while i >= 0:
            if (self._table[i].getInterestFilterId() == interestFilterId):
                count += 1
                self._table.pop(i)
            i -= 1

        if count == 0:
            logging.getLogger(__name__).debug(
              "unsetInterestFilter: Didn't find interestFilterId " +
              str(interestFilterId))

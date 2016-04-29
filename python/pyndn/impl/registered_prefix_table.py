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
This module defines RegisteredPrefixTable which is an internal class to hold a
list of registered prefixes with information necessary to remove the
registration later.
"""

import logging

class RegisteredPrefixTable(object):
    """
    Create a new RegisteredPrefixTable with an empty table.

    :param InterestFilterTable interestFilterTable: See removeRegisteredPrefix(),
      which may call interestFilterTable.unsetInterestFilter().
    """
    def __init__(self, interestFilterTable):
        self._table = [] # of _entry
        self._interestFilterTable = interestFilterTable
        self._removeRequests = [] # of int

    def add(self, registeredPrefixId, prefix, relatedInterestFilterId):
        """
        Add a new entry to the table.

        :param int registeredPrefixId: The ID from Node.getNextEntryId().
        :param Name prefix: The name prefix.
        :param int relatedInterestFilterId: (optional) The related
          interestFilterId for the filter set in the same registerPrefix
          operation. If omitted, set to 0.
        :return: True if added an entry, false if removeRegisteredPrefix was
          already called with the registeredPrefixId.
        :rtype: bool
        """
        try:
            removeRequestIndex = self._removeRequests.index(registeredPrefixId)
            # removeRegisteredPrefix was called with the registeredPrefixId
            #   returned by registerPrefix before we got here, so don't add a
            #   registered prefix table entry.
            del self._removeRequests[removeRequestIndex]
            return False
        except ValueError:
            pass

        self._table.append(RegisteredPrefixTable._Entry
          (registeredPrefixId, prefix, relatedInterestFilterId))
        return True

    def removeRegisteredPrefix(self, registeredPrefixId):
        """
        Remove the registered prefix entry with the registeredPrefixId from the
        registered prefix table. This does not affect another registered prefix
        with a different registeredPrefixId, even if it has the same prefix
        name. If an interest filter was automatically created by registerPrefix,
        also remove it. If there is no entry with the registeredPrefixId, do
        nothing.

        :param int registeredPrefixId: The ID returned from registerPrefix.
        """
        count = 0
        # Go backwards through the list so we can erase entries.
        # Remove all entries even though registeredPrefixId should be unique.
        i = len(self._table) - 1
        while i >= 0:
            entry = self._table[i]
            if (entry.getRegisteredPrefixId() == registeredPrefixId):
                count += 1

                if entry.getRelatedInterestFilterId() > 0:
                    # Remove the related interest filter.
                    self._interestFilterTable.unsetInterestFilter(
                      entry.getRelatedInterestFilterId())

                self._table.pop(i)
            i -= 1

        if count == 0:
            logging.getLogger(__name__).debug(
              "removeRegisteredPrefix: Didn't find registeredPrefixId " +
              str(registeredPrefixId))

        if count == 0:
            # The registeredPrefixId was not found. Perhaps this has been called
            #   before the callback in registerPrefix can add to the registered
            #   prefix table. Add this removal request which will be checked
            #   before adding to the registered prefix table.
            try:
                self._removeRequests.index(registeredPrefixId)
            except ValueError:
                # Not already requested, so add the request.
                self._removeRequests.append(registeredPrefixId)

    class _Entry(object):
        """
        A RegisteredPrefixTable._Entry holds a registeredPrefixId and
        information necessary to remove the registration later. It optionally
        holds a related interestFilterId if the InterestFilter was set in the
        same registerPrefix operation.
        Create a RegisteredPrefixTable.Entry with the given values.

        :param int registeredPrefixId: The ID from Node.getNextEntryId().
        :param Name prefix: The name prefix.
        :param int relatedInterestFilterId: (optional) The related
          interestFilterId for the filter set in the same registerPrefix
          operation. If omitted, set to 0.
        """
        def __init__(self, registeredPrefixId, prefix, relatedInterestFilterId):
            self._registeredPrefixId = registeredPrefixId
            self._prefix = prefix
            self._relatedInterestFilterId = relatedInterestFilterId

        def getRegisteredPrefixId(self):
            """
            Get the registeredPrefixId given to the constructor.

            :return: The registered prefix ID.
            :rtype: int
            """
            return self._registeredPrefixId

        def getPrefix(self):
            """
            Get the name prefix to the constructor.

            :return: The name prefix.
            :rtype: Name
            """
            return self._prefix

        def getRelatedInterestFilterId(self):
            """
            Get the related interestFilterId given to the constructor.

            :return: The related interestFilterId.
            :rtype: int
            """
            return self._relatedInterestFilterId

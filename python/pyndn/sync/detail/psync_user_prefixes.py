# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From the PSync library https://github.com/named-data/PSync/blob/master/PSync/detail/user-prefixes.cpp
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
This module defines the PSyncUserPrefixes class which holds the _prefixes map
from prefix to sequence number, used by PSyncPartialProducer and
FullPSync2017WithUsers.
"""

import logging

class PSyncUserPrefixes(object):
    def __init__(self):
        # The key is the prefix Name. The value is the int sequence number for the prefix.
        self._prefixes = {}

    def isUserNode(self, prefix):
        """
        Check if the prefix is in _prefixes.

        :param Name prefix: The prefix to check.
        :return: True if the prefix is in _prefixes.
        :rtype: bool
        """
        return prefix in self._prefixes

    def getSequenceNo(self, prefix):
        """
        Return the current sequence number of the given prefix.

        :param Name prefix: The prefix for the sequence number.
        :return: The sequence number for the prefix, or -1 if not found.
        :rtype: int
        """
        if self.isUserNode(prefix):
            return self._prefixes[prefix]
        else:
            return -1

    def addUserNode(self, prefix):
        """
        Add a user node for synchronization based on the prefix Name, and
        initialize the sequence number to zero. However, if the prefix Name 
        already exists, then do nothing and return False. This does not add 
        sequence number zero to the IBLT because, if a large number of user 
        nodes are added, then decoding the difference between our own IBLT and 
        the other IBLT will not be possible.

        :param Name prefix: The prefix Name of the user node to be added.
        :return: True if the user node with the prefix Name was added, False if
          the prefix Name already exists.
        :rtype: bool
        """
        if not self.isUserNode(prefix):
            self._prefixes[prefix] = 0
            return True
        else:
            return False

    def removeUserNode(self, prefix):
        """
        Remove the user node from synchronization. If the prefix is not in
        _prefixes, then do nothing. The caller should first check
        isUserNode(prefix) and erase the prefix from the IBLT and other maps if
        needed.

        :param Name prefix: The prefix Name of the user node to be removed.
        """
        try:
            del self._prefixes[prefix]
        except KeyError:
            pass

    def updateSequenceNo(self, prefix, sequenceNo, oldSequenceNo):
        """
        Update prefixes_ with the given prefix and sequence number. This does
        not update the IBLT. This logs a message for the update. Whoever calls
        this needs to make sure that isUserNode(prefix) is true.

        :param Name prefix: The prefix of the update.
        :param int sequenceNo: The sequence number of the update.
        :param Array<int> oldSequenceNo: This sets oldSequenceNo[0] to the old
          sequence number for the prefix. If this method returns True and
          oldSequenceNo is not zero, the caller can remove the old prefix from
          the IBLT.
        :return True if the sequence number was updated, False if the prefix was
          not in _prefixes, or if the sequenceNo is less than or equal to the
          old sequence number. If this returns False, the caller should not
          update the IBLT.
        :rtype: bool
        """
        oldSequenceNo[0] = 0
        logging.getLogger(__name__).debug("updateSequenceNo: " + prefix.toUri() +
          " " + str(sequenceNo))

        if prefix in self._prefixes:
            oldSequenceNo[0] = self._prefixes[prefix]
        else:
            logging.getLogger(__name__).info(
              "The prefix was not found in _prefixes")
            return False

        if oldSequenceNo[0] >= sequenceNo:
            logging.getLogger(__name__).info(
              "The update has a lower/equal sequence number for the prefix. Doing nothing!")
            return False

        # Insert the new sequence number.
        self._prefixes[prefix] = sequenceNo
        return True

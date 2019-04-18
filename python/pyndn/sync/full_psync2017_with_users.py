# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From the PSync library https://github.com/named-data/PSync/blob/master/PSync/full-producer.cpp
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
This module defines the FullPSync2017WithUsers class which uses FullPSync2017 to
implement the full sync logic of PSync to synchronize with other nodes, where
all nodes want to sync the sequence number of all users based on their user
prefix. The application should call publishName whenever it wants to let
consumers know that new data with a new sequence number is available for the
user prefix. Multiple user prefixes can be added by using addUserNode.
Currently, fetching and publishing the data (named by the user prefix plus the
sequence number) needs to be handled by the application. See FullPSync2017 for
details on the Full PSync protocol. The Full PSync protocol is described in
Section G "Full-Data Synchronization" of:
https://named-data.net/wp-content/uploads/2017/05/scalable_name-based_data_synchronization.pdf
(Note: In the PSync library, this class is called FullProducer. But because
the class actually handles both producing and consuming, we omit "producer"
in the name to avoid confusion.)
"""

import logging
from pyndn.name import Name
from pyndn.security.signing_info import SigningInfo
from pyndn.sync.full_psync2017 import FullPSync2017
from pyndn.sync.psync_missing_data_info import PSyncMissingDataInfo
from pyndn.sync.detail.psync_user_prefixes import PSyncUserPrefixes
from pyndn.sync.detail.invertible_bloom_lookup_table import InvertibleBloomLookupTable
from pyndn.util.common import Common

class FullPSync2017WithUsers(object):
    """
    Create a FullPSync2017WithUsers.

    :param int expectedNEntries: The expected number of entries in the IBLT.
    :param Face face: The application's Face.
    :param Name syncPrefix: The prefix Name of the sync group, which is copied.
    :param Name userPrefix: The prefix Name of the first user in the group,
      which is copied. However, if this Name is None or empty, it is not added
      and you must call addUserNode.
    :param onUpdate: When there is new data, this calls onUdate(updates) where
      updates is a list of PSyncMissingDataInfo.
      NOTE: The library will log any exceptions thrown by this callback, but for
      better error handling the callback should catch and properly handle any
      exceptions.
    :type onUpdate: function object
    :param KeyChain keyChain: The KeyChain for signing Data packets.
    :param float syncInterestLifetime: (optional) The Interest lifetime for the
      sync Interests, in milliseconds. If omitted or None, use
      FullPSync2017.DEFAULT_SYNC_INTEREST_LIFETIME.
    :param float syncReplyFreshnessPeriod: (optional) The freshness period of
      the sync Data packet, in milliseconds. If omitted or None, use
      FullPSync2017.DEFAULT_SYNC_REPLY_FRESHNESS_PERIOD.
    :param SigningInfo signingInfo: (optional) The SigningInfo for signing Data
      packets, which is copied. If omitted or None, use the default SigningInfo().
    """
    def __init__(self, expectedNEntries, face, syncPrefix, userPrefix,
      onUpdate, keyChain,
      syncInterestLifetime = FullPSync2017.DEFAULT_SYNC_INTEREST_LIFETIME,
      syncReplyFreshnessPeriod = FullPSync2017.DEFAULT_SYNC_REPLY_FRESHNESS_PERIOD,
      signingInfo = SigningInfo()):
        self._onUpdate = onUpdate
        self._prefixes = PSyncUserPrefixes()

        self._fullPSync = FullPSync2017(
           expectedNEntries, face, syncPrefix, self._onNamesUpdate,
           keyChain, syncInterestLifetime, syncReplyFreshnessPeriod, signingInfo,
           self._isNotFutureHash, self._canAddReceivedName)

        if userPrefix != None and userPrefix.size() > 0:
            self.addUserNode(userPrefix)

    def getSequenceNo(self, prefix):
        """
        Return the current sequence number of the given user prefix.

        :param Name prefix: The user prefix for the sequence number.
        :return: The sequence number for the user prefix, or -1 if not found.
        :rtype: int
        """
        return self._prefixes.getSequenceNo(prefix)

    def addUserNode(self, prefix):
        """
        Add a user node for synchronization based on the prefix Name, and
        initialize the sequence number to zero. However, if the prefix Name
        already exists, then do nothing and return false. This does not add
        sequence number zero to the IBLT because, if a large number of user
        nodes are added, then decoding the difference between our own IBLT and
        the other IBLT will not be possible.

        :param Name prefix: The prefix Name of the user node to be added.
        :return: True if the user node with the prefix Name was added, False if
          the prefix Name already exists.
        """
        return self._prefixes.addUserNode(prefix)

    def removeUserNode(self, prefix):
        """
        Remove the user node from the synchronization. This erases the prefix
        from the IBLT and other tables.

        :param Name prefix: The prefix Name of the user node to be removed. If
          there is no user node with this prefix, do nothing.
        """
        if self._prefixes.isUserNode(prefix):
            sequenceNo = self._prefixes._prefixes[prefix]
            self._prefixes.removeUserNode(prefix)
            self._fullPSync.removeName(Name(prefix).appendNumber(sequenceNo))

    def publishName(self, prefix, sequenceNo = -1):
        """
        Publish the sequence number for the prefix Name to inform the others.
        (addUserNode needs to be called before this to add the prefix, if it was
        not already added via the constructor.)

        :param Name prefix: the prefix Name to be updated.
        :param int sequenceNo: (optional) The sequence number of the user prefix
          to be set in the IBLT. However, if sequenceNo is omitted or -1, then
          the existing sequence number is incremented by 1.
        """
        if not self._prefixes.isUserNode(prefix):
            logging.getLogger(__name__).error(
              "Prefix not added: " + prefix.toUri())
            return

        newSequenceNo = (sequenceNo if sequenceNo >= 0 else
                         self._prefixes._prefixes.get(prefix, 0) + 1)

        logging.getLogger(__name__).info(
          "Publish: " + prefix.toUri() + "/" + str(newSequenceNo))
        if self._updateSequenceNo(prefix, newSequenceNo):
            # Insert the new sequence number.
            self._fullPSync.publishName(Name(prefix).appendNumber(newSequenceNo))

    def _canAddReceivedName(self, name):
        """
        This is called when new names are received to check if the name can be
        added to the IBLT.

        :param Name name: The Name to check.
        :return: True if the received name can be added.
        :rtype: bool
        """
        prefix = name.getPrefix(-1)
        sequenceNo = name.get(-1).toNumber()

        havePrefix = self._prefixes.isUserNode(prefix)
        if not havePrefix or self._prefixes._prefixes[prefix] < sequenceNo:
            if havePrefix:
                oldSequenceNo = self._prefixes._prefixes.get(prefix, 0)
                if oldSequenceNo != 0:
                    # Remove the old sequence number from the IBLT before the
                    # caller adds the new one.
                    self._fullPSync.removeName(
                      Name(prefix).appendNumber(oldSequenceNo))

            return True
        else:
            return False

    def _onNamesUpdate(self, names):
        """
        This is called when new names are received. Update _prefixes, create the
        list of PSyncMissingDataInfo and call the _onUpdate callback.

        :param Array<Name> names: The new received names.
        """
        updates = []

        for name in names:
            prefix = name.getPrefix(-1)
            sequenceNo = name.get(-1).toNumber()

            updates.append(PSyncMissingDataInfo(
              prefix, self._prefixes._prefixes.get(prefix, 0) + 1, sequenceNo))

            # _canAddReceivedName already made sure that the new sequenceNo is
            # greater than the old one, and removed the old one from the IBLT.
            self._prefixes._prefixes[prefix] = sequenceNo

        try:
            self._onUpdate(updates)
        except:
            logging.exception("Error in onUpdate")

    def _isNotFutureHash(self, name, negative):
        """
        Get the prefix from the name and check if hash(prefix + 1) is in the
        negative set. (Sometimes the Interest from the other side gets to us
        before the Data.)

        :param Name name: The Name to check.
        :param Set<int> negative: The negative set of hashes.
        :return: True if hash(prefix + 1) is NOT in the negative set (meaning
          that it is not a future hash), or False if it IS in the negative set.
        :rtype: bool
        """
        prefix = name.getPrefix(-1)

        uri = Name(prefix).appendNumber(
          self._prefixes._prefixes.get(prefix, 0) + 1).toUri()
        nextHash = Common.murmurHash3Blob(
          InvertibleBloomLookupTable.N_HASHCHECK, uri)

        for negativeHash in negative:
            if negativeHash == nextHash:
                return False

        return True

    def _updateSequenceNo(self, prefix, sequenceNo):
        """
        Update _prefixes and _iblt with the given prefix and sequence number.
        Whoever calls this needs to make sure that prefix is in _prefixes.
        We remove an already-existing prefix/sequence number from _iblt (unless
        sequenceNo is zero because we don't insert a zero sequence number into
        the IBLT.) Then we update _prefixes. If this returns True, the caller
        should update _nameToHash, _hashToName and _iblt .

        :param Name prefix: The prefix of the sequence number to update.
        :param int sequenceNumber: The new sequence number.
        :return: True if the _prefixes were updated, False if not.
        :rtype: bool
        """
        oldSequenceNo = [0]
        if not self._prefixes.updateSequenceNo(prefix, sequenceNo, oldSequenceNo):
            return False

        # Delete the old sequence number from the IBLT. If oldSequenceNo is zero,
        # we don't need to delete it, because we don't insert a prefix with
        # sequence number zero in the IBLT.
        if oldSequenceNo[0] != 0:
            self._fullPSync.removeName(Name(prefix).appendNumber(oldSequenceNo[0]))

        return True

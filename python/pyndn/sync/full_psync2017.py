# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From the PSync library https://github.com/named-data/PSync/blob/master/PSync/full-producer-arbitrary.cpp
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
This modules defines the FullPSync2017 class which extends PSyncProducerBase to
implement the full sync logic of PSync to synchronize with other nodes, where
all nodes want to sync all the names. The application should call publishName
whenever it wants to let consumers know that a new name is available. Currently,
fetching and publishing the data given by the announced name needs to be handled
by the application. The Full PSync protocol is described in Section G "Full-Data
Synchronization" of:
https://named-data.net/wp-content/uploads/2017/05/scalable_name-based_data_synchronization.pdf
(Note: In the PSync library, this class is called FullProducerArbitrary. But
because the class actually handles both producing and consuming, we omit
"producer" in the name to avoid confusion.)
"""

import logging
from random import SystemRandom
from pyndn.name import Name
from pyndn.interest import Interest
from pyndn.security.signing_info import SigningInfo
from pyndn.util.segment_fetcher import SegmentFetcher
from pyndn.sync.psync_producer_base import PSyncProducerBase
from pyndn.sync.detail.invertible_bloom_lookup_table import InvertibleBloomLookupTable
from pyndn.sync.detail.psync_segment_publisher import PSyncSegmentPublisher
from pyndn.sync.detail.psync_state import PSyncState

class FullPSync2017(PSyncProducerBase):
    DEFAULT_SYNC_INTEREST_LIFETIME = 1000.0
    DEFAULT_SYNC_REPLY_FRESHNESS_PERIOD = 1000.0

    """
    Create a FullPSync2017.

    :param int expectedNEntries: The expected number of entries in the IBLT.
    :param Face face: The application's Face.
    :param Name syncPrefix: The prefix Name of the sync group, which is copied.
    :param onNamesUpdate: When there are new names, this calls
      onNamesUpdate(names) where names is a list of Names. However, see the
      canAddReceivedName callback which can control which names are added.
      NOTE: The library will log any exceptions thrown by this callback, but for
      better error handling the callback should catch and properly handle any
      exceptions.
    :type onNamesUpdate: function object
    :param KeyChain keyChain: The KeyChain for signing Data packets.
    :param float syncInterestLifetime: (optional) The Interest lifetime for the
      sync Interests, in milliseconds. If omitted or None, use
      DEFAULT_SYNC_INTEREST_LIFETIME.
    :param float syncReplyFreshnessPeriod: (optional) The freshness period of
      the sync Data packet, in milliseconds. If omitted or None, use
      DEFAULT_SYNC_REPLY_FRESHNESS_PERIOD.
    :param SigningInfo signingInfo: (optional) The SigningInfo for signing Data
      packets, which is copied. If omitted or None, use the default SigningInfo().
    :param canAddToSyncData: (optional) When a new IBLT is received in a sync
      Interest, this calls canAddToSyncData(name, negative) where Name is the
      candidate Name to add to the response Data packet of Names, and negative
      is the set of names that the other's user's Name set, but not in our own
      Name set. If the callback returns False, then this does not report the
      Name to the other user. However, if canAddToSyncData is omitted or None,
      then each name is reported.
    :type canAddToSyncData: function object
    :param canAddReceivedName: (optional) When new names are received, this
      calls canAddReceivedName(name) for each name. If the callback returns
      False, then this does not add to the IBLT or report to the application
      with onNamesUpdate. However, if canAddReceivedName is omitted or None,
      then each name is added.
    :type canAddReceivedName: function object
    """
    def __init__(self, expectedNEntries, face, syncPrefix, onNamesUpdate,
      keyChain, syncInterestLifetime = DEFAULT_SYNC_INTEREST_LIFETIME,
      syncReplyFreshnessPeriod = DEFAULT_SYNC_REPLY_FRESHNESS_PERIOD,
      signingInfo = SigningInfo(), canAddToSyncData = None,
      canAddReceivedName = None):
        super(FullPSync2017, self).__init__(
          expectedNEntries, syncPrefix, syncReplyFreshnessPeriod)

        self._face = face
        self._keyChain = keyChain
        self._syncInterestLifetime = syncInterestLifetime
        self._signingInfo = SigningInfo(signingInfo)
        self._onNamesUpdate = onNamesUpdate
        self._canAddToSyncData = canAddToSyncData
        self._canAddReceivedName = canAddReceivedName
        self._segmentPublisher = PSyncSegmentPublisher(self._face, self._keyChain)

        # The key is the Name. The values is a _PendingEntryInfoFull.
        self._pendingEntries = {}
        self._outstandingInterestName = Name()

        self._registeredPrefix = self._face.registerPrefix(
          self._syncPrefix, self._onSyncInterest,
          PSyncProducerBase.onRegisterFailed)

        # TODO: Should we do this after the registerPrefix onSuccess callback?
        self._sendSyncInterest()

    def publishName(self, name):
        """
        Publish the Name to inform the others. However, if the Name has already
        been published, do nothing.

        :param Name name: The Name to publish.
        """
        if name in self._nameToHash:
            logging.getLogger(__name__).debug("Already published, ignoring: " +
              name.toUri())
            return

        logging.getLogger(__name__).info("Publish: " + name.toUri())
        self.insertIntoIblt(name)
        self._satisfyPendingInterests()

    def removeName(self, name):
        """
        Remove the Name from the IBLT so that it won't be announced to other
        users.

        :param Name name: The Name to remove.
        """
        self.removeFromIblt(name)

    class _PendingEntryInfoFull(object):
        def __init__(self, iblt):
            self._iblt = iblt
            self._isRemoved = False

    def _sendSyncInterest(self):
        """
        Send the sync interest for full synchronization. This forms the interest
        name: /<sync-prefix>/<own-IBLT>. This cancels any pending sync interest
        we sent earlier on the face.
        """
        # Debug: Implement stopping an ongoing fetch.
        ## If we send two sync interest one after the other
        ## since there is no new data in the network yet,
        ## when data is available it may satisfy both of them
        #if self._fetcher != None:
        #    self._fetcher.stop()

        # Sync Interest format for full sync: /<sync-prefix>/<ourLatestIBF>
        syncInterestName = Name(self._syncPrefix)

        # Append our latest IBLT.
        syncInterestName.append(self._iblt.encode())

        self._outstandingInterestName = syncInterestName

        # random1 is from 0.0 to 1.0.
        random1 = self._systemRandom.random()
        # Get a jitter of +/- syncInterestLifetime_ * 0.2 .
        jitter = (random1 - 0.5) * (self._syncInterestLifetime * 0.2)

        self._face.callLater(
          self._syncInterestLifetime / 2 + jitter, self._sendSyncInterest)

        syncInterest = Interest(syncInterestName)
        syncInterest.setInterestLifetimeMilliseconds(self._syncInterestLifetime)
        syncInterest.refreshNonce()

        SegmentFetcher.fetch(
          self._face, syncInterest, None,
          lambda content: self._onSyncData(content, syncInterest),
          FullPSync2017._onError)

        logging.getLogger(__name__).debug("sendFullSyncInterest, nonce: " +
          syncInterest.getNonce().toHex() + ", hash: " +
          str(abs(hash(syncInterestName))))

    @staticmethod
    def _onError(errorCode, message):
        logging.getLogger(__name__).info("Cannot fetch sync data, error: " +
        str(errorCode) + " message: " + message)

    def _onSyncInterest(self, prefixName, interest, face, interestFilterId, filter):
        """
        Process a sync interest received from another party.
        This gets the difference between our IBLT and the IBLT in the other sync
        interest. If we cannot get the difference successfully, then send an
        application Nack. If we have some things in our IBLT that the other side
        does not have, then reply with the content. Or, if the number of
        different items is greater than threshold or equals zero, then send a
        Nack. Otherwise add the sync interest into the pendingEntries_ map with
        the interest name as the key and a PendingEntryInfoFull as the value.

        :param Name prefixName: The prefix Name for the sync group which we
          registered.
        :param Interest interest: The the received Interest.
        """
        if self._segmentPublisher.replyFromStore(interest.getName()):
            return

        nameWithoutSyncPrefix = interest.getName().getSubName(prefixName.size())

        if nameWithoutSyncPrefix.size() == 1:
            # Get /<prefix>/IBLT from /<prefix>/IBLT
            interestName = interest.getName()
        elif nameWithoutSyncPrefix.size() == 3:
            # Get /<prefix>/IBLT from /<prefix>/IBLT/<version>/<segment-no>
            interestName = interest.getName().getPrefix(-2)
        else:
            return

        ibltName = interestName.get(-1)

        logging.getLogger(__name__).debug("Full Sync Interest received, nonce: " +
          interest.getNonce().toHex() + ", hash:" + str(abs(hash(interestName))))

        iblt = InvertibleBloomLookupTable(self._expectedNEntries)
        try:
            iblt.initialize(ibltName.getValue())
        except Exception as ex:
            logging.getLogger(__name__).error(
              "Error in iblt.initialize: %s", str(ex))
            return

        difference = self._iblt.difference(iblt)
        positive = set()
        negative = set()

        if not difference.listEntries(positive, negative):
            logging.getLogger(__name__).info("Cannot decode differences, positive: " +
              str(len(positive)) + " negative: " + str(len(negative)) +
              " _threshold: " + str(self._threshold))

            # Send all data if greater then the threshold, or if there are
            # neither positive nor negative differences. Otherwise, continue
            # below and send the positive as usual.
            if (len(positive) + len(negative) >= self._threshold or
                 (len(positive) == 0 and len(negative) == 0)):
                state1 = PSyncState()
                for name in self._nameToHash.keys():
                    state1.addContent(name)

                if len(state1.getContent()) > 0:
                    self._segmentPublisher.publish(
                      interest.getName(), interest.getName(), state1.wireEncode(),
                      self._syncReplyFreshnessPeriod, self._signingInfo)

                return

        state  = PSyncState()
        for hashValue in positive:
            name = self._hashToName[hashValue]

            if name in self._nameToHash:
                if (self._canAddToSyncData == None or
                     self._canAddToSyncData(name, negative)):
                    state.addContent(name)

        if len(state.getContent()) > 0:
            logging.getLogger(__name__).debug("Sending sync content: " +
              state.toString())
            self._sendSyncData(interestName, state.wireEncode())
            return

        entry = FullPSync2017._PendingEntryInfoFull(iblt)
        self._pendingEntries[interestName] = entry
        self._face.callLater(
           interest.getInterestLifetimeMilliseconds(),
           lambda: self._delayedRemovePendingEntry
             (interest.getName(), entry, interest.getNonce()))

    def _sendSyncData(self, name, content):
        """
        Send the sync Data. Check if the data will satisfy our own pending
        Interest. If it does, then remove it and then renew the sync interest.
        Otherwise, just send the Data.

        :param Name name: The basis to use for the Data name.
        :param Blob content: The content of the Data.
        """
        logging.getLogger(__name__).debug(
          "Checking if the Data will satisfy our own pending interest")

        nameWithIblt = Name()
        nameWithIblt.append(self._iblt.encode())

        # Append the hash of our IBLT so that the Data name should be different
        # for each node. Use abs() since hash() can return negative.
        dataName = Name(name).appendNumber(abs(hash(nameWithIblt)))

        # Check if our own Interest got satisfied.
        if self._outstandingInterestName.equals(name):
            logging.getLogger(__name__).debug("Satisfies our own pending Interest")
            # Remove the outstanding interest.
            # Debug: Implement stopping an ongoing fetch.
            #if self._fetcher != None:
            #    logging.getLogger(__name__).debug(
            #      "Removing our pending interest from the Face (stopping fetcher)")
            #    self._fetcher.stop()
            #    self._outstandingInterestName = Name()
            self._outstandingInterestName = Name()

            logging.getLogger(__name__).debug("Sending sync Data")

            # Send Data after removing the pending sync interest on the Face.
            self._segmentPublisher.publish(
              name, dataName, content, self._syncReplyFreshnessPeriod,
              self._signingInfo)

            logging.getLogger(__name__).info("sendSyncData: Renewing sync interest")
            self._sendSyncInterest()
        else:
            logging.getLogger(__name__).debug(
              "Sending Sync Data for not our own Interest")
            self._segmentPublisher.publish(
              name, dataName, content, self._syncReplyFreshnessPeriod,
              self._signingInfo)

    def _onSyncData(self, encodedContent, interest):
        """
        Process the sync data after the content is assembled by the
        SegmentFetcher. Call _deletePendingInterests to delete any pending sync
        Interest with the Interest name, which would have been satisfied by the
        forwarder once it got the data. For each name in the data content, check
        that we don't already have the name, and call _canAddReceivedName (which
        may process the name as a prefix/sequenceNo). Call _onUpdate to notify
        the application about the updates. Call _sendSyncInterest because the
        last one was satisfied by the incoming data.

        :param Blob encodedContent: The encoded sync data content that was
          assembled by the SegmentFetcher.
        :param Interest interest: The Interest for which we got the data.
        """
        self._deletePendingInterests(interest.getName())

        state = PSyncState(encodedContent)
        names = []

        logging.getLogger(__name__).debug("Sync Data Received: " + state.toString())

        for contentName in state.getContent():
            if not (contentName in self._nameToHash):
              logging.getLogger(__name__).debug("Checking whether to add " + 
                contentName.toUri())
              if (self._canAddReceivedName == None or
                  self._canAddReceivedName(contentName)):
                  logging.getLogger(__name__).debug("Adding name " +
                    contentName.toUri())
                  # The Name is freshly created by PSyncState decode, so don't copy.
                  names.append(contentName)
                  self.insertIntoIblt(contentName)

              # We should not call _satisfyPendingSyncInterests here because we
              # just got data and deleted pending interests by calling
              # _deletePendingInterests. But we might have interests which don't
              # match this interest that might not have been deleted from the
              # pending sync interests.

        # We just got the data, so send a new sync Interest.
        if len(names) > 0:
            try:
                self._onNamesUpdate(names)
            except:
                logging.exception("Error in onUpdate")

            logging.getLogger(__name__).info("onSyncData: Renewing sync interest")
            self._sendSyncInterest()
        else:
            logging.getLogger(__name__).info("No new update, interest nonce: " +
              interest.getNonce().toHex() + " , hash: " +
              str(abs(hash(interest.getName()))))

    def _satisfyPendingInterests(self):
        """
        Satisfy pending sync Interests. For a pending sync interests, if the
        IBLT of the sync Interest has any difference from our own IBLT, then
        send a Data back. If we can't decode the difference from the stored IBLT,
        then delete it.
        """
        logging.getLogger(__name__).debug("Satisfying full sync Interest: " +
          str(len(self._pendingEntries)))

        # Copy the keys before iterating se we can erase entries.
        for keyName in list(self._pendingEntries.keys()):
            pendingEntry = self._pendingEntries[keyName]

            entryIblt = pendingEntry._iblt
            difference = self._iblt.difference(entryIblt)
            positive = set()
            negative = set()

            if not difference.listEntries(positive, negative):
                logging.getLogger(__name__).info(
                  "Decode failed for pending interest")
                if (len(positive) + len(negative) >= self._threshold or
                     (len(positive) == 0 and len(negative) == 0)):
                  logging.getLogger(__name__).info(
                    "positive + negative > threshold or no difference can be found. Erase pending interest.")
                  # Prevent delayedRemovePendingEntry from removing a new entry
                  # with the same Name.
                  pendingEntry._isRemoved = True
                  del self._pendingEntries[keyName]
                  continue

            state = PSyncState()
            for hashValue in positive:
                name = self._hashToName[hashValue]

                if name in self._nameToHash:
                    state.addContent(name)
  
            if len(state.getContent()) > 0:
                logging.getLogger(__name__).debug("Satisfying sync content: " +
                  state.toString())
                self._sendSyncData(keyName, state.wireEncode())
                # Prevent _delayedRemovePendingEntry from removing a new entry
                # with the same Name.
                pendingEntry._isRemoved = True
                del self._pendingEntries[keyName]

    def _deletePendingInterests(self, interestName):
        """
        Delete pending sync Interests that match the given name.

        :param Name interestName:
        """
        # Copy the keys before iterating se we can erase entries.
        for keyName in list(self._pendingEntries.keys()):
            if keyName.equals(interestName):
                logging.getLogger(__name__).info("Delete pending interest: " +
                  interestName.toUri())
                # Prevent _delayedRemovePendingEntry from removing a new entry
                # with the same Name.
                self._pendingEntries[keyName]._isRemoved = True
                del self._pendingEntries[keyName]

    def _delayedRemovePendingEntry(self, name, entry, nonce):
        """
        Remove the entry from _pendingEntries which has the name. However, if
        entry._isRemoved is True, do nothing. Therefore, if an entry is
        directly removed from _pendingEntries, it should set _isRemoved.

        :param Name name: The key in the _pendingEntries map for the entry to
          remove.
        :param _PendingEntryInfoFull entry: A (possibly earlier and removed)
          entry from when it was inserted into the _pendingEntries map.
        :param Blob nonce: This is only used for the log message.
        """
        if entry._isRemoved:
            # A previous operation already removed this entry, so don't try
            # again to remove the entry with the Name in case it is a new entry.
            return

        logging.getLogger(__name__).info("Remove Pending Interest " + nonce.toHex())
        entry._isRemoved = True
        try:
            del self._pendingEntries[name]
        except KeyError:
            pass

    _systemRandom = SystemRandom()

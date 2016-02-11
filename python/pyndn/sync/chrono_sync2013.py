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
This module defines the ChronoSync2013 class which implements the NDN ChronoSync
protocol as described in the 2013 paper "Let's ChronoSync: Decentralized Dataset
State Synchronization in Named Data Networking".
http://named-data.net/publications/chronosync .
Note: The support for ChronoSync is experimental and the API is not finalized.
See the API docs for more detail at
http://named-data.net/doc/ndn-ccl-api/chrono-sync2013.html .
"""

# This include is produced by:
# protoc --python_out=. sync-state.proto
import sync_state_pb2
import logging
from pyndn.name import Name
from pyndn.interest import Interest
from pyndn.data import Data
from pyndn.util.blob import Blob
from pyndn.util.memory_content_cache import MemoryContentCache
from pyndn.sync.digest_tree import DigestTree

# Define this here once and suppress pylint errors.
#pylint: disable=E1103
SyncState_UPDATE = sync_state_pb2.SyncState.UPDATE
#pylint: enable=E1103

class ChronoSync2013(object):
    """
    Create a new ChronoSync2013 to communicate using the given face. Initialize
    the digest log with a digest of "00" and and empty content. Register the
    applicationBroadcastPrefix to receive interests for sync state messages and
    express an interest for the initial root digest "00".
    Note: Your application must call processEvents. Since processEvents
    modifies the internal ChronoSync data structures, your application should
    make sure that it calls processEvents in the same thread as this
    constructor (which also modifies the data structures).

    :param onReceivedSyncState: When ChronoSync receives a sync state message,
      this calls onReceivedSyncState(syncStates, isRecovery) where syncStates is
      the list of SyncState messages and isRecovery is true if this is the initial
      list of SyncState messages or from a recovery interest. (For example, if
      isRecovery is true, a chat application would not want to re-display all
      the associated chat messages.) The callback should send interests to fetch
      the application data for the sequence numbers in the sync state.
      NOTE: The library will log any exceptions raised by this callback, but
      for better error handling the callback should catch and properly
      handle any exceptions.
    :type onReceivedSyncState: function object
    :param onInitialized: This calls onInitialized() when the first sync data is
      received (or the interest times out because there are no other publishers
      yet).
      NOTE: The library will log any exceptions raised by this callback, but
      for better error handling the callback should catch and properly
      handle any exceptions.
    :type onInitialized: function object
    :param Name applicationDataPrefix: The prefix used by this application instance
      for application data. For example, "/my/local/prefix/ndnchat4/0K4wChff2v".
      This is used when sending a sync message for a new sequence number.
      In the sync message, this uses applicationDataPrefix.toUri().
    :param Name applicationBroadcastPrefix: The broadcast name prefix including the
      application name. For example, "/ndn/broadcast/ChronoChat-0.3/ndnchat1".
      This makes a copy of the name.
    :param int sessionNo: The session number used with the applicationDataPrefix
      in sync state messages.
    :param Face face: The Face for calling registerPrefix and expressInterest. The
       Face object must remain valid for the life of this ChronoSync2013 object.
    :param KeyChain keyChain: To sign a data packet containing a sync state
      message, this calls keyChain.sign(data, certificateName).
    :param Name certificateName: The certificate name of the key to use for
      signing a data packet containing a sync state message.
    :param float syncLifetime: The interest lifetime in milliseconds for sending
      sync interests.
    :param onRegisterFailed: If failed to register the prefix to receive
      interests for the applicationBroadcastPrefix, this calls
      onRegisterFailed(applicationBroadcastPrefix).
      NOTE: The library will log any exceptions raised by this callback, but
      for better error handling the callback should catch and properly
      handle any exceptions.
    :type onRegisterFailed: function object
    """
    def __init__(self, onReceivedSyncState, onInitialized,
      applicationDataPrefix, applicationBroadcastPrefix, sessionNo, face,
      keyChain, certificateName, syncLifetime, onRegisterFailed):
        self._onReceivedSyncState = onReceivedSyncState
        self._onInitialized = onInitialized
        self._applicationDataPrefixUri = applicationDataPrefix.toUri()
        self._applicationBroadcastPrefix = Name(applicationBroadcastPrefix)
        self._sessionNo = sessionNo
        self._face = face
        self._keyChain = keyChain
        self._certificateName = Name(certificateName)
        self._syncLifetime = syncLifetime
        self._contentCache = MemoryContentCache(face)

        self._digestLog = [] # of _DigestLogEntry
        self._digestTree = DigestTree()
        self._sequenceNo = -1
        self._enabled = True

        emptyContent = sync_state_pb2.SyncStateMsg()
        # Use getattr to avoid pylint errors.
        self._digestLog.append(self._DigestLogEntry("00", getattr(emptyContent, "ss")))

        # Register the prefix with the contentCache_ and use our own onInterest
        #   as the onDataNotFound fallback.
        self._contentCache.registerPrefix(
          self._applicationBroadcastPrefix, onRegisterFailed, self._onInterest)

        interest = Interest(self._applicationBroadcastPrefix)
        interest.getName().append("00")
        interest.setInterestLifetimeMilliseconds(1000)
        interest.setMustBeFresh(True)
        face.expressInterest(interest, self._onData, self._initialTimeOut)
        logging.getLogger(__name__).info("initial sync expressed")
        logging.getLogger(__name__).info("%s", interest.getName().toUri())

    class SyncState(object):
        """
        A SyncState holds the values of a sync state message which is passed to
        the onReceivedSyncState callback which was given to the ChronoSyn2013
        constructor. Note: this has the same info as the Protobuf class
        sync_state_pb2.SyncState, but we make a separate class so
        that we don't need the Protobuf definition in the ChronoSync API.
        """
        def __init__(self, dataPrefixUri, sessionNo, sequenceNo):
            self._dataPrefixUri = dataPrefixUri
            self._sessionNo = sessionNo
            self._sequenceNo = sequenceNo

        def getDataPrefix(self):
            """
            Get the application data prefix for this sync state message.

            :return: The application data prefix as a Name URI string.
            :rtype: str
            """
            return self._dataPrefixUri

        def getSessionNo(self):
            """
            Get the session number associated with the application data prefix
            for this sync state message.

            :return: The session number.
            :rtype: int
            """
            return self._sessionNo

        def getSequenceNo(self):
            """
            Get the sequence number for this sync state message.

            :return: The sequence number.
            :rtype: int
            """
            return self._sequenceNo

    def getProducerSequenceNo(self, dataPrefix, sessionNo):
        """
        Get the current sequence number in the digest tree for the given
        producer dataPrefix and sessionNo.

        :param std dataPrefix: The producer data prefix as a Name URI string.
        :param int sessionNo: The producer session number.
        :return: The current producer sequence number, or -1 if the producer
          namePrefix and sessionNo are not in the digest tree.
        :rtype: int
        """
        index = self._digestTree.find(dataPrefix, sessionNo)
        if index < 0:
          return -1
        else:
          return self._digestTree.get(index).getSequenceNo()

    def publishNextSequenceNo(self):
        """
        Increment the sequence number, create a sync message with the new
        sequence number and publish a data packet where the name is
        the applicationBroadcastPrefix + the root digest of the current digest
        tree. Then add the sync message to the digest tree and digest log which
        creates a new root digest. Finally, express an interest for the next sync
        update with the name applicationBroadcastPrefix + the new root digest.
        After this, your application should publish the content for the new
        sequence number. You can get the new sequence number with getSequenceNo().
        Note: Your application must call processEvents. Since processEvents
        modifies the internal ChronoSync data structures, your application should
        make sure that it calls processEvents in the same thread as
        publishNextSequenceNo() (which also modifies the data structures).
        """
        self._sequenceNo += 1

        syncMessage = sync_state_pb2.SyncStateMsg()
        content = getattr(syncMessage, "ss").add()
        content.name = self._applicationDataPrefixUri
        content.type = SyncState_UPDATE
        content.seqno.seq = self._sequenceNo
        content.seqno.session = self._sessionNo

        self._broadcastSyncState(self._digestTree.getRoot(), syncMessage)

        if not self._update(getattr(syncMessage, "ss")):
          # Since we incremented the sequence number, we expect there to be a
          #   new digest log entry.
          raise RuntimeError(
            "ChronoSync: update did not create a new digest log entry")

        # TODO: Should we have an option to not express an interest if this is the
        #   final publish of the session?
        interest = Interest(self._applicationBroadcastPrefix)
        interest.getName().append(self._digestTree.getRoot())
        interest.setInterestLifetimeMilliseconds(self._syncLifetime)
        self._face.expressInterest(interest, self._onData, self._syncTimeout)

    def getSequenceNo(self):
        """
        Get the sequence number of the latest data published by this application
        instance.

        :return: The sequence number.
        :rtype: int
        """
        return self._sequenceNo

    def shutdown(self):
        """
        Unregister callbacks so that this does not respond to interests anymore.
        If you will discard this ChronoSync2013 object while your application is
        still running, you should call shutdown() first.  After calling this, you
        should not call publishNextSequenceNo() again since the behavior will be
        undefined.
        Note: Because this modifies internal ChronoSync data structures, your
        application should make sure that it calls processEvents in the same
        thread as shutdown() (which also modifies the data structures).
        """
        self._enabled = False
        self._contentCache.unregisterAll()

    class _DigestLogEntry(object):
        def __init__(self, digest, data):
            self._digest = digest
            # Copy.
            self._data = data[:]

        def getDigest(self):
            return self._digest

        def getData(self):
            """
            Get the data.

            :return: The data as a list.
            :rtype: array of sync_state_pb2.SyncState.
            """
            return self._data

    def _broadcastSyncState(self, digest, syncMessage):
        """
        Make a data packet with the syncMessage and with name
        applicationBroadcastPrefix_ + digest. Sign and send.

        :param str digest: The root digest as a hex string for the data packet
          name.
        :param sync_state_pb2.SyncState syncMessage:
        """
        data = Data(self._applicationBroadcastPrefix)
        data.getName().append(digest)
        # TODO: Check if this works in Python 3.
        data.setContent(Blob(syncMessage.SerializeToString()))
        self._keyChain.sign(data, self._certificateName)
        self._contentCache.add(data)

    def _update(self, content):
        """
        Update the digest tree with the messages in content. If the digest tree
        root is not in the digest log, also add a log entry with the content.

        :param content: The list of SyncState.
        :type content: array of sync_state_pb2.SyncState
        :return: True if added a digest log entry (because the updated digest
          tree root was not in the log), False if didn't add a log entry.
        :rtype: bool
        """
        for i in range(len(content)):
            syncState = content[i]

            if syncState.type == SyncState_UPDATE:
                if self._digestTree.update(
                  syncState.name, syncState.seqno.session,
                  syncState.seqno.seq):
                    # The digest tree was updated.
                    if self._applicationDataPrefixUri == syncState.name:
                        self._sequenceNo = syncState.seqno.seq

        if self._logFind(self._digestTree.getRoot()) == -1:
            self._digestLog.append(
              self._DigestLogEntry(self._digestTree.getRoot(), content))
            return True
        else:
            return False

    def _logFind(self, digest):
        """
        Search the digest log by digest.
        """
        for i in range(len(self._digestLog)):
            if digest == self._digestLog[i].getDigest():
                return i

        return -1

    def _onInterest(self, prefix, interest, face, interestFilterId, filter):
        """
        Process the sync interest from the applicationBroadcastPrefix. If we
        can't satisfy the interest, add it to the pending interest table in
        the _contentCache so that a future call to contentCacheAdd may satisfy it.
        """
        if not self._enabled:
            # Ignore callbacks after the application calls shutdown().
            return

        # Search if the digest already exists in the digest log.
        logging.getLogger(__name__).info("Sync Interest received in callback.")
        logging.getLogger(__name__).info("%s", interest.getName().toUri())

        syncDigest = interest.getName().get(
          self._applicationBroadcastPrefix.size()).toEscapedString()
        if interest.getName().size() == self._applicationBroadcastPrefix.size() + 2:
            # Assume this is a recovery interest.
            syncDigest = interest.getName().get(
              self._applicationBroadcastPrefix.size() + 1).toEscapedString()
        logging.getLogger(__name__).info("syncDigest: %s", syncDigest)
        if (interest.getName().size() == self._applicationBroadcastPrefix.size() + 2 or
             syncDigest == "00"):
            # Recovery interest or newcomer interest.
            self._processRecoveryInterest(interest, syncDigest, face)
        else:
            self._contentCache.storePendingInterest(interest, face)

            if syncDigest != self._digestTree.getRoot():
                index = self._logFind(syncDigest)
                if index == -1:
                    # To see whether there is any data packet coming back, wait
                    #   2 seconds using the Interest timeout mechanism.
                    # TODO: Are we sure using a "/local/timeout" interest is the
                    #   best future call approach?
                    timeout = Interest(Name("/local/timeout"))
                    timeout.setInterestLifetimeMilliseconds(2000)
                    self._face.expressInterest(
                      timeout, self._dummyOnData,
                      self._makeJudgeRecovery(syncDigest, face))
                    logging.getLogger(__name__).info("set timer recover")
                else:
                    # common interest processing
                    self._processSyncInterest(index, syncDigest, face)

    def _onData(self, interest, data):
        """
        Process Sync Data.
        """
        if not self._enabled:
            # Ignore callbacks after the application calls shutdown().
            return

        logging.getLogger(__name__).info(
          "Sync ContentObject received in callback")
        logging.getLogger(__name__).info(
            "name: %s", data.getName().toUri())
        # TODO: Check if this works in Python 3.
        tempContent = sync_state_pb2.SyncStateMsg()
#pylint: disable=E1103
        tempContent.ParseFromString(data.getContent().toRawStr())
#pylint: enable=E1103
        content = getattr(tempContent, "ss")
        if self._digestTree.getRoot() == "00":
            isRecovery = True
            #processing initial sync data
            self._initialOndata(content)
        else:
            self._update(content)
            if (interest.getName().size() ==
                self._applicationBroadcastPrefix.size() + 2):
                # Assume this is a recovery interest.
                isRecovery = True
            else:
                isRecovery = False

        # Send the interests to fetch the application data.
        syncStates = []
        for i in range(len(content)):
            syncState = content[i]

            # Only report UPDATE sync states.
            if syncState.type == SyncState_UPDATE:
                syncStates.append(self.SyncState(
                  syncState.name, syncState.seqno.session,
                  syncState.seqno.seq))

        try:
            self._onReceivedSyncState(syncStates, isRecovery)
        except:
            logging.exception("Error in onReceivedSyncState")

        name = Name(self._applicationBroadcastPrefix)
        name.append(self._digestTree.getRoot())
        syncInterest = Interest(name)
        syncInterest.setInterestLifetimeMilliseconds(self._syncLifetime)
        self._face.expressInterest(syncInterest, self._onData, self._syncTimeout)
        logging.getLogger(__name__).info("Syncinterest expressed:")
        logging.getLogger(__name__).info("%s", name.toUri())

    def _initialTimeOut(self, interest):
        """
        Initial sync interest timeout, which means there are no other publishers
        yet.
        """
        if not self._enabled:
            # Ignore callbacks after the application calls shutdown().
            return

        logging.getLogger(__name__).info("initial sync timeout")
        logging.getLogger(__name__).info("no other people")
        self._sequenceNo += 1
        if self._sequenceNo != 0:
            # Since there were no other users, we expect sequence no 0.
            raise RuntimeError(
              "ChronoSync: sequenceNo_ is not the expected value of 0 for first use.")

        tempContent = sync_state_pb2.SyncStateMsg()
        content = getattr(tempContent, "ss").add()
        content.name = self._applicationDataPrefixUri
        content.type = SyncState_UPDATE
        content.seqno.seq = self._sequenceNo
        content.seqno.session = self._sessionNo
        self._update(getattr(tempContent, "ss"))

        try:
            self._onInitialized()
        except:
            logging.exception("Error in onInitialized")

        name = Name(self._applicationBroadcastPrefix)
        name.append(self._digestTree.getRoot())
        retryInterest = Interest(name)
        retryInterest.setInterestLifetimeMilliseconds(self._syncLifetime)
        self._face.expressInterest(retryInterest, self._onData, self._syncTimeout)
        logging.getLogger(__name__).info("Syncinterest expressed:")
        logging.getLogger(__name__).info("%s", name.toUri())

    def _processRecoveryInterest(self, interest, syncDigest, face):
        logging.getLogger(__name__).info("processRecoveryInterest")
        if self._logFind(syncDigest) != -1:
            tempContent = sync_state_pb2.SyncStateMsg()
            for i in range(self._digestTree.size()):
                content = getattr(tempContent, "ss").add()
                content.name = self._digestTree.get(i).getDataPrefix()
                content.type = SyncState_UPDATE
                content.seqno.seq = self._digestTree.get(i).getSequenceNo()
                content.seqno.session = self._digestTree.get(i).getSessionNo()

            if len(getattr(tempContent, "ss")) != 0:
                # TODO: Check if this works in Python 3.
#pylint: disable=E1103
                array = tempContent.SerializeToString()
#pylint: enable=E1103
                data = Data(interest.getName())
                data.setContent(Blob(array))
                if interest.getName().get(-1).toEscapedString() == "00":
                    # Limit the lifetime of replies to interest for "00" since
                    # they can be different.
                    data.getMetaInfo().setFreshnessPeriod(1000)

                self._keyChain.sign(data, self._certificateName)
                try:
                    face.putData(data)
                except Exception as ex:
                    logging.getLogger(__name__).error(
                      "Error in face.putData: %s", str(ex))
                    return

                logging.getLogger(__name__).info("send recovery data back")
                logging.getLogger(__name__).info("%s", interest.getName().toUri())

    def _processSyncInterest(self, index, syncDigest, face):
        """
        Common interest processing, using digest log to find the difference
        after syncDigest.

        :return: True if sent a data packet to satisfy the interest, otherwise
          False.
        :rtype: bool
        """
        nameList = []       # of str
        sequenceNoList = [] # of int
        sessionNoList = []  # of int
        for j in range(index + 1, len(self._digestLog)):
            temp = self._digestLog[j].getData() # array of sync_state_pb2.SyncState.
            for i in range(len(temp)):
                syncState = temp[i]
                if syncState.type != SyncState_UPDATE:
                    continue

                if self._digestTree.find(
                      syncState.name, syncState.seqno.session) != -1:
                    n = -1
                    for k in range(len(nameList)):
                        if nameList[k] == syncState.name:
                            n = k
                            break

                    if n == -1:
                        nameList.append(syncState.name)
                        sequenceNoList.append(syncState.seqno.seq)
                        sessionNoList.append(syncState.seqno.session)
                    else:
                        sequenceNoList[n] = syncState.seqno.seq
                        sessionNoList[n] = syncState.seqno.session

        tempContent = sync_state_pb2.SyncStateMsg()
        for i in range(len(nameList)):
            content = getattr(tempContent, "ss").add()
            content.name = nameList[i]
            content.type = SyncState_UPDATE
            content.seqno.seq = sequenceNoList[i]
            content.seqno.session = sessionNoList[i]

        sent = False
        if len(getattr(tempContent, "ss")) != 0:
            name = Name(self._applicationBroadcastPrefix)
            name.append(syncDigest)
            # TODO: Check if this works in Python 3.
#pylint: disable=E1103
            array = tempContent.SerializeToString()
#pylint: enable=E1103
            data = Data(name)
            data.setContent(Blob(array))
            self._keyChain.sign(data, self._certificateName)

            try:
                face.putData(data)
            except Exception as ex:
                logging.getLogger(__name__).error(
                  "Error in face.putData: %s", str(ex))
                return

            sent = True
            logging.getLogger(__name__).info("Sync Data send")
            logging.getLogger(__name__).info("%s", name.toUri())

        return sent

    def _sendRecovery(self, syncDigest):
        """
        Send Recovery Interest.
        """
        logging.getLogger(__name__).info("unknown digest: ")
        name = Name(self._applicationBroadcastPrefix)
        name.append("recovery").append(syncDigest)
        interest = Interest(name)
        interest.setInterestLifetimeMilliseconds(self._syncLifetime)
        self._face.expressInterest(interest, self._onData, self._syncTimeout)
        logging.getLogger(__name__).info("Recovery Syncinterest expressed:")
        logging.getLogger(__name__).info("%s", name.toUri())

    def _makeJudgeRecovery(self, syncDigest, face):
        """
        Return a function for onTimeout which calls _judgeRecovery.
        """
        def f(interest):
            self._judgeRecovery(interest, syncDigest, face)
        return f

    def _judgeRecovery(self, interest, syncDigest, face):
        """
        This is called by _onInterest after a timeout to check if a recovery is
        needed.
        """
        if not self._enabled:
            # Ignore callbacks after the application calls shutdown().
            return

        index2 = self._logFind(syncDigest)
        if index2 != -1:
            if syncDigest != self._digestTree.getRoot():
                self._processSyncInterest(index2, syncDigest, face)
        else:
            self._sendRecovery(syncDigest)

    def _syncTimeout(self, interest):
        """
        Sync interest time out.  If the interest is the static one send again.
        """
        if not self._enabled:
            # Ignore callbacks after the application calls shutdown().
            return

        logging.getLogger(__name__).info("Sync Interest time out.")
        logging.getLogger(__name__).info(
          "Sync Interest name: %s", interest.getName().toUri())
        component = interest.getName().get(4).toEscapedString()
        if component == self._digestTree.getRoot():
            name = Name(interest.getName())
            retryInterest = Interest(interest.getName())
            retryInterest.setInterestLifetimeMilliseconds(self._syncLifetime)
            self._face.expressInterest(
              retryInterest, self._onData, self._syncTimeout)

            logging.getLogger(__name__).info("Syncinterest expressed:")
            logging.getLogger(__name__).info("%s", name.toUri())

    def _initialOndata(self, content):
        """
        Process initial data which usually includes all other publisher's info,
        and send back the new comer's own info.
        """
        # The user is a new comer and receive data of all other people in the group.
        self._update(content)
        digest = self._digestTree.getRoot()
        for i in range(len(content)):
            syncState = content[i]
            if (syncState.name == self._applicationDataPrefixUri and
                  syncState.seqno.session == self._sessionNo):
                # If the user was an old comer, after add the static log he
                #   needs to increase his sequence number by 1.
                tempContent = sync_state_pb2.SyncStateMsg()
                # Use getattr to avoid pylint errors.
                content2 = getattr(tempContent, "ss").add()
                content2.name = self._applicationDataPrefixUri
                content2.type = SyncState_UPDATE
                content2.seqno.seq = syncState.seqno.seq + 1
                content2.seqno.session = self._sessionNo

                if self._update(getattr(tempContent, "ss")):
                    try:
                        self._onInitialized()
                    except:
                        logging.exception("Error in onInitialized")

        tempContent2 = sync_state_pb2.SyncStateMsg()
        if self._sequenceNo >= 0:
            # Send the data packet with the new sequence number back.
            content2 = getattr(tempContent2, "ss").add()
            content2.name = self._applicationDataPrefixUri
            content2.type = SyncState_UPDATE
            content2.seqno.seq = self._sequenceNo
            content2.seqno.session = self._sessionNo
        else:
            content2 = getattr(tempContent2, "ss").add()
            content2.name = self._applicationDataPrefixUri
            content2.type = SyncState_UPDATE
            content2.seqno.seq = 0
            content2.seqno.session = self._sessionNo

        self._broadcastSyncState(digest, tempContent2)

        if (self._digestTree.find(self._applicationDataPrefixUri, self._sessionNo)
             == -1):
            # The user hasn't put himself in the digest tree.
            logging.getLogger(__name__).info("initial state")
            self._sequenceNo += 1
            tempContent = sync_state_pb2.SyncStateMsg()
            content2 = getattr(tempContent, "ss").add()
            content2.name = self._applicationDataPrefixUri
            content2.type = SyncState_UPDATE
            content2.seqno.seq = self._sequenceNo
            content2.seqno.session = self._sessionNo

            if self._update(getattr(tempContent, "ss")):
                try:
                    self._onInitialized()
                except:
                    logging.exception("Error in onInitialized")

    @staticmethod
    def _dummyOnData(interest, data):
        """
        This is a do-nothing onData for using expressInterest for timeouts.
        This should never be called.
        """
        pass

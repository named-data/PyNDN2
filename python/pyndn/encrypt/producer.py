# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt src/producer https://github.com/named-data/ndn-group-encrypt
# Author: excludeRange from ndn-cxx https://github.com/named-data/ndn-cxx/blob/master/src/exclude.cpp
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
This module defines the Producer class which manages content keys used to
encrypt a data packet in the group-based encryption protocol.
Note: This class is an experimental feature. The API may change.
"""

import logging
import math
from pyndn.name import Name
from pyndn.exclude import Exclude
from pyndn.interest import Interest
from pyndn.data import Data
from pyndn.exclude import Exclude
from pyndn.security.key_params import AesKeyParams
from pyndn.encrypt.schedule import Schedule
from pyndn.encrypt.encrypt_error import EncryptError
from pyndn.encrypt.algo.aes_algorithm import AesAlgorithm
from pyndn.encrypt.algo.encryptor import Encryptor
from pyndn.encrypt.algo.encrypt_params import EncryptParams, EncryptAlgorithmType

class Producer(object):
    """
    Create a Producer to use the given ProducerDb, Face and other values.

    A producer can produce data with a naming convention:
      <prefix>/SAMPLE/<dataType>/[timestamp]

    The produced data packet is encrypted with a content key,
    which is stored in the ProducerDb database.

    A producer also needs to produce data containing a content key
    encrypted with E-KEYs. A producer can retrieve E-KEYs through the face,
    and will re-try for at most repeatAttemps times when E-KEY retrieval fails.

    :param Name prefix: The producer name prefix. This makes a copy of the Name.
    :param Name dataType: The dataType portion of the producer name. This makes
      a copy of the Name.
    :param Face face: The face used to retrieve keys.
    :param KeyChain keyChain: The keyChain used to sign data packets.
    :param ProducerDb database: The ProducerDb database for storing keys.
    :param int repeatAttempts: (optional) The maximum retry for retrieving
      keys. If omitted, use a default value of 3.
    """
    def __init__(self, prefix, dataType, face, keyChain, database,
                 repeatAttempts = None):
        self._face = face
        self._keyChain = keyChain
        self._database = database
        self._maxRepeatAttempts = (3 if repeatAttempts == None else repeatAttempts)

        # The dictionary key is the key Name The value is a Producer._KeyInfo.
        self._eKeyInfo = {}
        # The dictionary key is the float time stamp. The value is a Producer._KeyRequest.
        self._keyRequests = {}

        fixedPrefix = Name(prefix)
        fixedDataType = Name(dataType)

        # Fill _ekeyInfo with all permutations of dataType, including the 'E-KEY'
        # component of the name. This will be used in createContentKey to send
        # interests without reconstructing names every time.
        fixedPrefix.append(Encryptor.NAME_COMPONENT_READ)
        while fixedDataType.size() > 0:
            nodeName = Name(fixedPrefix)
            nodeName.append(fixedDataType)
            nodeName.append(Encryptor.NAME_COMPONENT_E_KEY)

            self._eKeyInfo[nodeName] = Producer._KeyInfo()
            fixedDataType = fixedDataType.getPrefix(-1)

        fixedPrefix.append(dataType)
        self._namespace = Name(prefix)
        self._namespace.append(Encryptor.NAME_COMPONENT_SAMPLE)
        self._namespace.append(dataType)

    @staticmethod
    def defaultOnError(errorCode, message):
        """
        The default onError callback which does nothing.
        """
        # Do nothing.
        pass

    def createContentKey(self, timeSlot, onEncryptedKeys, onError = defaultOnError):
        """
        Create the content key corresponding to the timeSlot. This first checks
        if the content key exists. For an existing content key, this returns the
        content key name directly. If the key does not exist, this creates one
        and encrypts it using the corresponding E-KEYs. The encrypted content
        keys are passed to the onEncryptedKeys callback.

        :param float timeSlot: The time slot as milliseconds since Jan 1,
          1970 UTC.
        :param onEncryptedKeys: If this creates a content key, then this calls
          onEncryptedKeys(keys) where keys is a list of encrypted content key
          Data packets. If onEncryptedKeys is None, this does not use it.
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onEncryptedKeys: function object
        :param onError: (optional) This calls  errorCode, message) for an
          error, where errorCode is from EncryptError.ErrorCode and message is a
          str. If omitted, use a default callback which does nothing.
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onError: function object
        :return: The content key name.
        :rtype: Name
        """
        hourSlot = Producer._getRoundedTimeSlot(timeSlot)

        # Create the content key name.
        contentKeyName = Name(self._namespace)
        contentKeyName.append(Encryptor.NAME_COMPONENT_C_KEY)
        contentKeyName.append(Schedule.toIsoString(hourSlot))

        # Check if we have created the content key before.
        if self._database.hasContentKey(timeSlot):
            # We have created the content key. Return its name directly.
            return contentKeyName

        # We haven't created the content key. Create one and add it into the
        # database.
        aesParams = AesKeyParams(128)
        contentKeyBits = AesAlgorithm.generateKey(aesParams).getKeyBits()
        self._database.addContentKey(timeSlot, contentKeyBits)

        # Now we need to retrieve the E-KEYs for content key encryption.
        timeCount = round(timeSlot)
        self._keyRequests[timeCount] = Producer._KeyRequest(len(self._eKeyInfo))
        keyRequest = self._keyRequests[timeCount]

        # Check if the current E-KEYs can cover the content key.
        timeRange = Exclude()
        Producer.excludeAfter(
          timeRange, Name.Component(Schedule.toIsoString(timeSlot)))
        # Send interests for all nodes in the tree.
        for keyName in self._eKeyInfo:
            # For each current E-KEY.
            keyInfo = self._eKeyInfo[keyName]
            if (timeSlot < keyInfo.beginTimeSlot or
                timeSlot >= keyInfo.endTimeSlot):
                # The current E-KEY cannot cover the content key, so retrieve one.
                keyRequest.repeatAttempts[keyName] = 0
                self._sendKeyInterest(
                  Interest(keyName).setExclude(timeRange).setChildSelector(1),
                  timeSlot, onEncryptedKeys, onError)
            else:
                # The current E-KEY can cover the content key.
                # Encrypt the content key directly.
                eKeyName = Name(keyName)
                eKeyName.append(Schedule.toIsoString(keyInfo.beginTimeSlot))
                eKeyName.append(Schedule.toIsoString(keyInfo.endTimeSlot))
                self._encryptContentKey(
                  keyInfo.keyBits, eKeyName, timeSlot, onEncryptedKeys, onError)

        return contentKeyName

    def produce(self, data, timeSlot, content, onError = defaultOnError):
        """
        Encrypt the given content with the content key that covers timeSlot, and
        update the data packet with the encrypted content and an appropriate
        data name.

        :param Data data: An empty Data object which is updated.
        :param float timeSlot: The time slot as milliseconds since Jan 1, 1970 UTC.
        :param Blob content: The content to encrypt.
        :param onError: (optional) This calls onError(errorCode, message) for an
          error, where errorCode is from EncryptError.ErrorCode and message is a
          str. If omitted, use a default callback which does nothing.
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onError: function object
        """
        # Get a content key.
        contentKeyName = Name(self.createContentKey(timeSlot, None, onError))
        contentKey = self._database.getContentKey(timeSlot)

        # Produce data.
        dataName = Name(self._namespace)
        dataName.append(Schedule.toIsoString(timeSlot))

        data.setName(dataName)
        params = EncryptParams(EncryptAlgorithmType.AesCbc, 16)
        Encryptor.encryptData(data, content, contentKeyName, contentKey, params)
        self._keyChain.sign(data)

    class _KeyInfo(object):
        def __init__(self):
            self.beginTimeSlot = 0.0
            self.endTimeSlot = 0.0
            self.keyBits = None # Blob

    class _KeyRequest(object):
        def __init__(self, interests):
            self.interestCount = interests # int
            # The dictionary key is the Name. The value is an int count.
            self.repeatAttempts = {}
            self.encryptedKeys = [] # of Data

    @staticmethod
    def _getRoundedTimeSlot(timeSlot):
        """
        Round timeSlot to the nearest whole hour, so that we can store content
        keys uniformly (by start of the hour).

        :param float timeSlot: The time slot as milliseconds since Jan 1,
          1970 UTC.
        :return: The start of the hour as milliseconds since Jan 1, 1970 UTC.
        :rtype: float
        """
        return round(math.floor(round(timeSlot) / 3600000.0) * 3600000.0)

    def _sendKeyInterest(self, interest, timeSlot, onEncryptedKeys, onError):
        """
        Send an interest with the given name through the face with callbacks to
          _handleCoveringKey and _handleTimeout.

        :param Interest interest: The interest to send.
        :param float timeSlot: The time slot, passed to _handleCoveringKey and
          _handleTimeout.
        :param onEncryptedKeys: The OnEncryptedKeys callback, passed to
          _handleCoveringKey and _handleTimeout.
        :type onEncryptedKeys: function object
        :param onError: This calls onError(errorCode, message) for an error.
        :type onError: function object
        """
        def onKey(interest, data):
            self._handleCoveringKey(
              interest, data, timeSlot, onEncryptedKeys, onError)

        def onTimeout(interest):
            self._handleTimeout(interest, timeSlot, onEncryptedKeys, onError)

        self._face.expressInterest(interest, onKey, onTimeout)

    def _handleTimeout(self, interest, timeSlot, onEncryptedKeys, onError):
        """
        This is called from an expressInterest timeout to update the state of
        keyRequest.

        :param Interest interest: The timed-out interest.
        :param float timeSlot: The time slot as milliseconds since Jan 1, 1970 UTC.
        :param onEncryptedKeys: When there are no more interests to process,
          this calls onEncryptedKeys(keys) where keys is a list of encrypted
          content key Data packets. If onEncryptedKeys is None, this does not
          use it.
        :type onEncryptedKeys: function object
        :param onError: This calls onError(errorCode, message) for an error.
        :type onError: function object
        """
        timeCount = round(timeSlot)
        keyRequest = self._keyRequests[timeCount]

        interestName = interest.getName()
        if keyRequest.repeatAttempts[interestName] < self._maxRepeatAttempts:
            # Increase the retrial count.
            keyRequest.repeatAttempts[interestName] += 1
            self._sendKeyInterest(interest, timeSlot, onEncryptedKeys, onError)
        else:
            # No more retrials.
            self._updateKeyRequest(keyRequest, timeCount, onEncryptedKeys)

    def _updateKeyRequest(self, keyRequest, timeCount, onEncryptedKeys):
        """
        Decrease the count of outstanding E-KEY interests for the C-KEY for
        timeCount. If the count decreases to 0, invoke onEncryptedKeys.

        :param Producer._KeyRequest keyRequest: The KeyRequest with the
          interestCount to update.
        :param float timeCount: The time count for indexing keyRequests_.
        :param onEncryptedKeys: When there are no more interests to process,
          this calls onEncryptedKeys(keys) where keys is a list of encrypted
          content key Data packets. If onEncryptedKeys is None, this does not
          use it.
        :type onEncryptedKeys: function object
        """
        keyRequest.interestCount -= 1
        if keyRequest.interestCount == 0 and onEncryptedKeys != None:
            try:
                onEncryptedKeys(keyRequest.encryptedKeys)
            except:
                logging.exception("Error in onEncryptedKeys")
            if timeCount in self._keyRequests:
                del self._keyRequests[timeCount]

    def _handleCoveringKey(
          self, interest, data, timeSlot, onEncryptedKeys, onError):
        """
        This is called from an expressInterest OnData to check that the
        encryption key contained in data fits the timeSlot. This sends a refined
        interest if required.

        :param Interest interest: The interest given to expressInterest.
        :param Data data: The fetched Data packet.
        :param float timeSlot: The time slot as milliseconds since Jan 1, 1970 UTC.
        :param onEncryptedKeys: When there are no more interests to process,
          this calls onEncryptedKeys(keys) where keys is a list of encrypted
          content key Data packets. If onEncryptedKeys is None, this does not
          use it.
        :type onEncryptedKeys: function object
        :param onError: This calls onError(errorCode, message) for an error.
        :type onError: function object
        """
        timeCount = round(timeSlot)
        keyRequest = self._keyRequests[timeCount]

        interestName = interest.getName()
        keyName = data.getName()

        begin = Schedule.fromIsoString(
          str(keyName.get(Producer.START_TIME_STAMP_INDEX).getValue()))
        end = Schedule.fromIsoString(
          str(keyName.get(Producer.END_TIME_STAMP_INDEX).getValue()))

        if timeSlot >= end:
            # If the received E-KEY covers some earlier period, try to retrieve
            # an E-KEY covering a later one.
            timeRange = Exclude(interest.getExclude())
            Producer.excludeBefore(timeRange, keyName.get(Producer.START_TIME_STAMP_INDEX))
            keyRequest.repeatAttempts[interestName] = 0
            self._sendKeyInterest(
              Interest(interestName).setExclude(timeRange).setChildSelector(1),
              timeSlot, onEncryptedKeys, onError)
        else:
            # If the received E-KEY covers the content key, encrypt the content.
            encryptionKey = data.getContent()
            # If everything is correct, save the E-KEY as the current key.
            if self._encryptContentKey(
              encryptionKey, keyName, timeSlot, onEncryptedKeys, onError):
                keyInfo = self._eKeyInfo[interestName]
                keyInfo.beginTimeSlot = begin
                keyInfo.endTimeSlot = end
                keyInfo.keyBits = encryptionKey

    def _encryptContentKey(self, encryptionKey, eKeyName, timeSlot,
                           onEncryptedKeys, onError):
        """
        Get the content key from the database_ and encrypt it for the timeSlot
          using encryptionKey.

        :param Blob encryptionKey: The encryption key value.
        :param Name eKeyName: The key name for the EncryptedContent.
        :param float timeSlot: The time slot as milliseconds since Jan 1, 1970 UTC.
        :param onEncryptedKeys: When there are no more interests to process,
           this calls onEncryptedKeys(keys) where keys is a list of encrypted
           content key Data packets. If onEncryptedKeys is None, this does not
           use it.
        :type onEncryptedKeys: function object
        :param onError: This calls onError(errorCode, message) for an error.
        :type onError: function object
        :return: True if encryption succeeds, otherwise False.
        :rtype: bool
        """
        timeCount = round(timeSlot)
        keyRequest = self._keyRequests[timeCount]

        keyName = Name(self._namespace)
        keyName.append(Encryptor.NAME_COMPONENT_C_KEY)
        keyName.append(
          Schedule.toIsoString(Producer._getRoundedTimeSlot(timeSlot)))

        contentKey = self._database.getContentKey(timeSlot)

        cKeyData = Data()
        cKeyData.setName(keyName)
        params = EncryptParams(EncryptAlgorithmType.RsaOaep)
        try:
            Encryptor.encryptData(
              cKeyData, contentKey, eKeyName, encryptionKey, params)
        except Exception as ex:
            try:
                onError(EncryptError.ErrorCode.EncryptionFailure,
                        "encryptData error: " + repr(ex))
            except:
                logging.exception("Error in onError")
            return False

        self._keyChain.sign(cKeyData)
        keyRequest.encryptedKeys.append(cKeyData)
        self._updateKeyRequest(keyRequest, timeCount, onEncryptedKeys)
        return True

    # TODO: Move this to be the main representation inside the Exclude object.
    class ExcludeEntry(object):
        """
        Create a new ExcludeEntry.

        :param Name.Component component:
        :param bool anyFollowsComponent:
        """
        def __init__(self, component, anyFollowsComponent):
            self._component = component
            self._anyFollowsComponent = anyFollowsComponent

    @staticmethod
    def getExcludeEntries(exclude):
        """
        Create a list of ExcludeEntry from the Exclude object.

        :param Exclude exclude: The Exclude object to read.
        :return: A new array of ExcludeEntry.
        :rtype: Array<ExcludeEntry>
        """
        entries = []

        for i in range(exclude.size()):
            if exclude.get(i).getType() == Exclude.ANY:
                if len(entries) == 0:
                    # Add a "beginning ANY".
                    entries.append(Producer.ExcludeEntry(Name.Component(), True))
                else:
                    # Set anyFollowsComponent of the final component.
                    entries[len(entries) - 1]._anyFollowsComponent = True
            else:
                entries.append(
                  Producer.ExcludeEntry(exclude.get(i).getComponent(), False))

        return entries

    @staticmethod
    def setExcludeEntries(exclude, entries):
        """
        Set the Exclude object from the array of ExcludeEntry.

        :param Exclude exclude: The Exclude object to update.
        :param Array<ExcludeEntry> entries: The array of ExcludeEntry.
        """
        exclude.clear()

        for i in range(len(entries)):
            entry = entries[i]

            if (i == 0 and entry._component.getValue().size() == 0 and
                  entry._anyFollowsComponent):
                # This is a "beginning ANY".
                exclude.appendAny()
            else:
                exclude.appendComponent(entry._component)
                if entry._anyFollowsComponent:
                    exclude.appendAny()

    @staticmethod
    def findEntryBeforeOrAt(entries, component):
        """
        Get the latest entry in the array whose component is less than or equal
        to component.

        :param Array<ExcludeEntry> entries: The array of ExcludeEntry.
        :param Name.Component component: The component to compare.
        :return: The index of the found entry, or -1 if not found.
        :rtype: int
        """
        i = len(entries) - 1
        while i >= 0:
            if entries[i]._component.compare(component) <= 0:
                break
            i -= 1

        return i

    @staticmethod
    def excludeAfter(exclude, fromComponent):
        """
        Exclude all components in the range beginning at "fromComponent".

        :param Exclude exclude: The Exclude object to update.
        :param Name.Component fromComponent: The first component in the exclude
          range.
        """
        entries = Producer.getExcludeEntries(exclude)

        iFoundFrom = Producer.findEntryBeforeOrAt(entries, fromComponent)
        if iFoundFrom < 0:
            # There is no entry before "fromComponent" so insert at the beginning.
            entries.insert(0, Producer.ExcludeEntry(fromComponent, True))
            iNewFrom = 0
        else:
            foundFrom = entries[iFoundFrom]

            if not foundFrom._anyFollowsComponent:
                if foundFrom._component.equals(fromComponent):
                    # There is already an entry with "fromComponent", so just
                    #   set the "ANY" flag.
                    foundFrom._anyFollowsComponent = True
                    iNewFrom = iFoundFrom
                else:
                    # Insert following the entry before "fromComponent".
                    entries.insert(iFoundFrom + 1,
                      Producer.ExcludeEntry(fromComponent, True))
                    iNewFrom = iFoundFrom + 1
            else:
                # The entry before "fromComponent" already has an "ANY" flag,
                #   so do nothing.
                iNewFrom = iFoundFrom

        # Remove intermediate entries since they are inside the range.
        iRemoveBegin = iNewFrom + 1
        entries[iRemoveBegin:] = []

        Producer.setExcludeEntries(exclude, entries)

    @staticmethod
    def excludeBefore(exclude, to):
        """
        Exclude all components in the range ending at "to".

        :param Exclude exclude: The Exclude object to update.
        :param Name.Component to: The last component in the exclude range.
        """
        Producer.excludeRange(exclude, Name.Component(), to)

    @staticmethod
    def excludeRange(exclude, fromComponent, to):
        """
        Exclude all components in the range beginning at "fromComponent" and
        ending at "to".

        :param Exclude exclude: The Exclude object to update.
        :param Name.Component fromComponent: The first component in the exclude
          range.
        :param Name.Component to: The last component in the exclude range.
        """
        if fromComponent.compare(to) >= 0:
            if fromComponent.compare(to) == 0:
                raise RuntimeError(
                  "excludeRange: from == to. To exclude a single component, sue excludeOne.")
            else:
                raise RuntimeError(
                  "excludeRange: from must be less than to. Invalid range: [" +
                  fromComponent.toEscapedString() + ", " + to.toEscapedString() + "]")

        entries = Producer.getExcludeEntries(exclude)

        iFoundFrom = Producer.findEntryBeforeOrAt(entries, fromComponent)
        if iFoundFrom < 0:
            # There is no entry before "fromComponent" so insert at the beginning.
            entries.insert(0, Producer.ExcludeEntry(fromComponent, True))
            iNewFrom = 0
        else:
            foundFrom = entries[iFoundFrom]

            if not foundFrom._anyFollowsComponent:
                if foundFrom._component.equals(fromComponent):
                    # There is already an entry with "fromComponent", so just
                    #   set the "ANY" flag.
                    foundFrom._anyFollowsComponent = True
                    iNewFrom = iFoundFrom
                else:
                    # Insert following the entry before "fromComponent".
                    entries.insert(iFoundFrom + 1,
                      Producer.ExcludeEntry(fromComponent, True))
                    iNewFrom = iFoundFrom + 1
            else:
                # The entry before "fromComponent" already has an "ANY" flag,
                #   so do nothing.
                iNewFrom = iFoundFrom

        # We have at least one "fromComponent" before "to", so we know this will
        #   find an entry.
        iFoundTo = Producer.findEntryBeforeOrAt(entries, to)
        foundTo = entries[iFoundTo]
        if iFoundTo == iNewFrom:
            # Insert the "to" immediately after the "fromComponent".
            entries.insert(iNewFrom + 1, Producer.ExcludeEntry(to, False))
        else:
            if not foundTo._anyFollowsComponent:
                if foundTo._component.equals(to):
                    # The "to" entry already exists. Remove up to it.
                    iRemoveEnd = iFoundTo
                else:
                    # Insert following the previous entry, which will be removed.
                    entries.insert(iFoundTo + 1, Producer.ExcludeEntry(to, False))
                    iRemoveEnd = iFoundTo + 1
            else:
                # "to" follows a component which is already followed by "ANY",
                #   meaning the new range now encompasses it, so remove the component.
                iRemoveEnd = iFoundTo + 1

            # Remove intermediate entries since they are inside the range.
            iRemoveBegin = iNewFrom + 1
            entries[iRemoveBegin:iRemoveEnd] = []

        Producer.setExcludeEntries(exclude, entries)

    START_TIME_STAMP_INDEX = -2
    END_TIME_STAMP_INDEX = -1

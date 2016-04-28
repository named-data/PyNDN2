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
This module defines the MemoryContentCache class which holds a set of Data
packets and answers an Interest to return the correct Data packet. The cache is
periodically cleaned up to remove each stale Data packet based on its
FreshnessPeriod (if it has one).
Note: This class is an experimental feature. See the API docs for more detail at
http://named-data.net/doc/ndn-ccl-api/memory-content-cache.html .
"""

import logging
import collections
from pyndn.forwarding_flags import ForwardingFlags
from pyndn.interest_filter import InterestFilter
from pyndn.encoding.wire_format import WireFormat
from pyndn.name import Name
from pyndn.util.common import Common

class MemoryContentCache(object):
    """
    Create a new MemoryContentCache to use the given Face.

    :param Face face: The Face to use to call registerPrefix and
      setInterestFilter, and which will call this object's OnInterest callback.
    :param float cleanupIntervalMilliseconds: (optional) The interval in
      milliseconds between each check to clean up stale content in the cache. If
      omitted, use a default of 1000 milliseconds. If this is a large number,
      then effectively the stale content will not be removed from the cache.
    """
    def __init__(self, face, cleanupIntervalMilliseconds = None):
        if cleanupIntervalMilliseconds == None:
            cleanupIntervalMilliseconds = 1000.0

        self._face = face
        self._cleanupIntervalMilliseconds = cleanupIntervalMilliseconds
        self._nextCleanupTime = (Common.getNowMilliseconds() +
          cleanupIntervalMilliseconds)

        # The map key is the prefix.toUri(). The value is an OnInterest function.
        self._onDataNotFoundForPrefix = {}
        # elements are int
        self._interestFilterIdList = []
        # elements are int
        self._registeredPrefixIdList = []
        # elements are MemoryContentCache._Content
        self._noStaleTimeCache = []
        # elements are MemoryContentCache.StaleTimeContent
        self._staleTimeCache = []
        self._emptyComponent = Name.Component()
        self._pendingInterestTable = [] # of PendingInterest

    def registerPrefix(
      self, prefix, onRegisterFailed, onRegisterSuccess = None,
        onDataNotFound = None, flags = None, wireFormat = None):
        """
        Call registerPrefix on the Face given to the constructor so that this
        MemoryContentCache will answer interests whose name has the prefix.
        Alternatively, if the Face's registerPrefix has already been called,
        then you can call this object's setInterestFilter.

        :param Name prefix: The Name for the prefix to register. This copies the
          Name.
        :param onRegisterFailed: If this fails to register the prefix for any
          reason, this calls onRegisterFailed(prefix) where prefix is the prefix
          given to registerPrefix.
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onRegisterFailed: function object
        :param onRegisterSuccess: (optional) This calls
          onRegisterSuccess[0](prefix, registeredPrefixId) when this receives a
          success message from the forwarder. If onRegisterSuccess is omitted or
          [None], this does not use it. (As a special case, this optional
          parameter is supplied as a list of one function object, instead of
          just a function object, in order to detect when it is used instead of
          the following optional onDataNotFound function object.)
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onRegisterSuccess: list of one function object
        :param onDataNotFound: (optional) If a data packet for an interest is
          not found in the cache, this forwards the interest by calling
          onDataNotFound(prefix, interest, face, interestFilterId, filter). Your
          callback can find the Data packet for the interest and call
          face.putData(data). If your callback cannot find the Data packet, it can
          optionally call storePendingInterest(interest, face) to store the
          pending interest in this object to be satisfied by a later call to
          add(data). If you want to automatically store all pending interests,
          you can simply use getStorePendingInterest() for onDataNotFound. If
          onDataNotFound is omitted or None, this does not use it.
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onDataNotFound: function object
        :param ForwardingFlags flags: (optional) See Face.registerPrefix.
        :param wireFormat: (optional) See Face.registerPrefix.
        :type wireFormat: A subclass of WireFormat
        """
        arg3 = onRegisterSuccess
        arg4 = onDataNotFound
        arg5 = flags
        arg6 = wireFormat
        # arg3,                arg4,            arg5,            arg6 may be:
        # [OnRegisterSuccess], OnDataNotFound,  ForwardingFlags, WireFormat
        # [OnRegisterSuccess], OnDataNotFound,  ForwardingFlags, None
        # [OnRegisterSuccess], OnDataNotFound,  WireFormat,      None
        # [OnRegisterSuccess], OnDataNotFound,  None,            None
        # [OnRegisterSuccess], ForwardingFlags, WireFormat,      None
        # [OnRegisterSuccess], ForwardingFlags, None,            None
        # [OnRegisterSuccess], WireFormat,      None,            None
        # [OnRegisterSuccess], None,            None,            None
        # OnDataNotFound,      ForwardingFlags, WireFormat,      None
        # OnDataNotFound,      ForwardingFlags, None,            None
        # OnDataNotFound,      WireFormat,      None,            None
        # OnDataNotFound,      None,            None,            None
        # ForwardingFlags,     WireFormat,      None,            None
        # ForwardingFlags,     None,            None,            None
        # WireFormat,          None,            None,            None
        # None,                None,            None,            None
        if type(arg3) is list and len(arg3) == 1:
          onRegisterSuccess = arg3[0]
        else:
          onRegisterSuccess = None

        if isinstance(arg3, collections.Callable):
          onDataNotFound = arg3
        elif isinstance(arg4, collections.Callable):
          onDataNotFound = arg4
        else:
          onDataNotFound = None

        if isinstance(arg3, ForwardingFlags):
            flags = arg3
        elif isinstance(arg4, ForwardingFlags):
            flags = arg4
        elif isinstance(arg5, ForwardingFlags):
            flags = arg5
        else:
            flags = ForwardingFlags()

        if isinstance(arg3, WireFormat):
            wireFormat = arg3
        elif isinstance(arg4, WireFormat):
            wireFormat = arg4
        elif isinstance(arg5, WireFormat):
            wireFormat = arg5
        elif isinstance(arg6, WireFormat):
            wireFormat = arg6
        else:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        if onDataNotFound != None:
            self._onDataNotFoundForPrefix[prefix.toUri()] = onDataNotFound
        registeredPrefixId = self._face.registerPrefix(
          prefix, self._onInterest, onRegisterFailed, onRegisterSuccess,
          flags, wireFormat)
        self._registeredPrefixIdList.append(registeredPrefixId)

    def setInterestFilter(self, filterOrPrefix, onDataNotFound = None):
        """
        Call setInterestFilter on the Face given to the constructor so that this
        MemoryContentCache will answer interests whose name matches the filter.
        There are two forms of setInterestFilter.
        The first form uses the exact given InterestFilter:
        setInterestFilter(filter, [onDataNotFound]).
        The second form creates an InterestFilter from the given prefix Name:
        setInterestFilter(prefix, [onDataNotFound]).

        :param InterestFilter filter: The InterestFilter with a prefix and
          optional regex filter used to match the name of an incoming Interest.
          This makes a copy of filter.
        :param Name prefix: The Name prefix used to match the name of an
          incoming Interest. This makes a copy of the Name.
        :param onDataNotFound: (optional) If a data packet for an interest is
          not found in the cache, this forwards the interest by calling
          onDataNotFound(prefix, interest, face, interestFilterId, filter). Your
          callback can find the Data packet for the interest and call
          face.putData(data). If your callback cannot find the Data packet, it can
          optionally call storePendingInterest(interest, face) to store the
          pending interest in this object to be satisfied by a later call to
          add(data). If you want to automatically store all pending interests,
          you can simply use getStorePendingInterest() for onDataNotFound. If
          onDataNotFound is omitted or None, this does not use it.
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onDataNotFound: function object
        """
        if onDataNotFound != None:
            if type(filterOrPrefix) is InterestFilter:
                prefix = filterOrPrefix.getPrefix()
            else:
                prefix = filterOrPrefix
            self._onDataNotFoundForPrefix[prefix.toUri()] = onDataNotFound
        interestFilterId = self._face.setInterestFilter(
          filterOrPrefix, self._onInterest)
        self._interestFilterIdList.append(interestFilterId)

    def unregisterAll(self):
        """
        Call Face.unsetInterestFilter and Face.removeRegisteredPrefix for all
        the prefixes given to the setInterestFilter and registerPrefix method on
        this MemoryContentCache object so that it will not receive interests any
        more. You can call this if you want to "shut down" this
        MemoryContentCache while your application is still running.
        """
        for interestFilterId in self._interestFilterIdList:
            self._face.unsetInterestFilter(interestFilterId)
        self._interestFilterIdList = []

        for registeredPrefixId in self._registeredPrefixIdList:
            self._face.removeRegisteredPrefix(registeredPrefixId)
        self._registeredPrefixIdList = []

        # Also clear each onDataNotFoundForPrefix given to registerPrefix.
        self._onDataNotFoundForPrefix = {}

    def add(self, data):
        """
        Add the Data packet to the cache so that it is available to use to
        answer interests. If data.getMetaInfo().getFreshnessPeriod() is not None,
        set the staleness time to now plus data.getMetaInfo().getFreshnessPeriod(),
        which is checked during cleanup to remove stale content. This also
        checks if  cleanupIntervalMilliseconds milliseconds have passed and
        removes stale content from the cache. After removing stale content,
        remove timed-out pending interests from storePendingInterest(), then if
        the added Data packet satisfies any interest, send it through the
        face and remove the interest from the pending interest table.

        :param Data data: The Data packet object to put in the cache. This
          copies the fields from the object.
        """
        self._doCleanup()

        if (data.getMetaInfo().getFreshnessPeriod() != None and
              data.getMetaInfo().getFreshnessPeriod() >= 0.0):
            # The content will go stale, so use staleTimeCache.
            content = MemoryContentCache._StaleTimeContent(data)
            # Insert into _staleTimeCache, sorted on content._staleTimeMilliseconds.
            # Search from the back since we expect it to go there.
            i = len(self._staleTimeCache) - 1
            while i >= 0:
                if (self._staleTimeCache[i]._staleTimeMilliseconds <=
                      content._staleTimeMilliseconds):
                    break
                i -= 1

            # Element i is the greatest less than or equal to
            # content._staleTimeMilliseconds, so insert after it.
            self._staleTimeCache.insert(i + 1, content)
        else:
            # The data does not go stale, so use _noStaleTimeCache.
            self._noStaleTimeCache.append(MemoryContentCache._Content(data))

        # Remove timed-out interests and check if the data packet matches any
        #   pending interest.
        # Go backwards through the list so we can erase entries.
        nowMilliseconds = Common.getNowMilliseconds()
        for i in range(len(self._pendingInterestTable) - 1, -1, -1):
            pendingInterest = self._pendingInterestTable[i]
            if pendingInterest.isTimedOut(nowMilliseconds):
                self._pendingInterestTable.pop(i)
                continue

            if pendingInterest.getInterest().matchesName(data.getName()):
                try:
                    # Send to the same face from the original call to onInterest.
                    # wireEncode returns the cached encoding if available.
                    pendingInterest.getFace().send(data.wireEncode())
                except Exception as ex:
                    logging.getLogger(__name__).error(
                      "Error in face.send: %s", str(ex))
                    return

                # The pending interest is satisfied, so remove it.
                self._pendingInterestTable.pop(i)

    def storePendingInterest(self, interest, face):
        """
        Store an interest from an OnInterest callback in the internal pending
        interest table (normally because there is no Data packet available yet
        to satisfy the interest). add(data) will check if the added Data packet
        satisfies any pending interest and send it through the face.

        :param Interest interest: The Interest for which we don't have a Data
          packet yet. You should not modify the interest after calling this.
        :param Face face: The Face with the connection which
          received the interest. This comes from the OnInterest callback.
        """
        self._pendingInterestTable.append(
          self._PendingInterest(interest, face))

    def getStorePendingInterest(self):
        """
        Return a callback to use for onDataNotFound in registerPrefix which
        simply calls storePendingInterest() to store the interest that doesn't
        match a Data packet. add(data) will check if the added Data packet
        satisfies any pending interest and send it.

        :return: A callback to use for onDataNotFound in registerPrefix().
        :rtype: function object
        """
        return self._storePendingInterestCallback

    def _storePendingInterestCallback(
          self, prefix, interest, face, interestFilterId, filter):
        """
        This is a private method to return from getStorePendingInterest(). We
        need a separate method because the arguments are different from
        storePendingInterest.
        """
        self.storePendingInterest(interest, face)

    def _onInterest(self, prefix, interest, face, interestFilterId, filter):
        """
        This is the OnInterest callback which is called when the library
        receives an interest whose name has the prefix given to registerPrefix.
        First check if cleanupIntervalMilliseconds milliseconds have passed and
        remove stale content from the cache. Then search the cache for the Data
        packet, matching any interest selectors including ChildSelector, and
        send the Data packet to the face. If no matching Data packet is in
        the cache, call the callback in onDataNotFoundForPrefix (if defined).
        """
        self._doCleanup()

        selectedComponent = 0
        selectedEncoding = None
        # We need to iterate over both arrays.
        totalSize = len(self._staleTimeCache) + len(self._noStaleTimeCache)
        for i in range(totalSize):
            if i < len(self._staleTimeCache):
                content = self._staleTimeCache[i]
            else:
                # We have iterated over the first array. Get from the second.
                content = self._noStaleTimeCache[i - len(self._staleTimeCache)]

            if (interest.matchesName(content.getName())):
                if (interest.getChildSelector() < 0):
                    # No child selector, so send the first match that we have found.
                    face.send(content.getDataEncoding())
                    return
                else:
                    # Update selectedEncoding based on the child selector.
                    if (content.getName().size() > interest.getName().size()):
                        component = content.getName().get(interest.getName().size())
                    else:
                        component = self._emptyComponent

                    gotBetterMatch = False
                    if selectedEncoding == None:
                        # Save the first match.
                        gotBetterMatch = True
                    else:
                        if interest.getChildSelector() == 0:
                            # Leftmost child.
                            if component.compare(selectedComponent) < 0:
                                gotBetterMatch = True
                        else:
                            # Rightmost child.
                            if component.compare(selectedComponent) > 0:
                                gotBetterMatch = True

                    if gotBetterMatch:
                        selectedComponent = component
                        selectedEncoding = content.getDataEncoding()

        if selectedEncoding != None:
            # We found the leftmost or rightmost child.
            face.send(selectedEncoding)
        else:
            # Call the onDataNotFound callback (if defined).
            if prefix.toUri() in self._onDataNotFoundForPrefix:
                try:
                    self._onDataNotFoundForPrefix[prefix.toUri()](
                      prefix, interest, face, interestFilterId, filter)
                except:
                    logging.exception("Error in onDataNotFound")

    def _doCleanup(self):
        """
        Check if now is greater than nextCleanupTime and, if so, remove stale
        content from staleTimeCache and reset nextCleanupTime based on
        cleanupIntervalMilliseconds. Since add(Data) does a sorted insert into
        staleTimeCache, the check for stale data is quick and does not require
        searching the entire staleTimeCache.
        """
        now = Common.getNowMilliseconds()
        if now >= self._nextCleanupTime:
            # staleTimeCache is sorted on staleTimeMilliseconds, so we only need
            # to erase the stale entries at the front, then quit.
            while (len(self._staleTimeCache) > 0 and
                   self._staleTimeCache[0].isStale(now)):
                del self._staleTimeCache[0]

            self._nextCleanupTime = now + self._cleanupIntervalMilliseconds

    """
    _Content is a private class to hold the name and encoding for each entry in
    the cache. This base class is for a Data packet without a FreshnessPeriod.
    """
    class _Content(object):
        """
        Create a new Content entry to hold data's name and wire encoding.

        :param Data data: The Data packet whose name and wire encoding are
          copied.
        """
        def __init__(self, data):
            # Copy the name.
            self._name = Name(data.getName())
            # wireEncode returns the cached encoding if available.
            self._dataEncoding = data.wireEncode().buf()

        def getName(self):
            return self._name

        def getDataEncoding(self):
            return self._dataEncoding

    """
    _StaleTimeContent extends _Content to include the staleTimeMilliseconds for
    when this entry should be cleaned up from the cache.
    """
    class _StaleTimeContent(_Content):
        """
        Create a new StaleTimeContent to hold data's name and wire encoding as
        well as the staleTimeMilliseconds which is now plus
        data.getMetaInfo().getFreshnessPeriod().

        :param Data data: The Data packet whose name and wire encoding are
          copied.
        """
        def __init__(self, data):
            super(MemoryContentCache._StaleTimeContent, self).__init__(data)
            # Set up staleTimeMilliseconds which is The time when the content
            # becomse stale in milliseconds according to
            # Common.getNowMilliseconds().
            self._staleTimeMilliseconds = (Common.getNowMilliseconds() +
              data.getMetaInfo().getFreshnessPeriod())

        def isStale(self, nowMilliseconds):
            """
            Check if this content is stale.

            :param float nowMilliseconds: The current time in milliseconds from
              Common.getNowMilliseconds().
            :return: True if this content is stale, otherwise False.
            :rtype: bool
            """
            return self._staleTimeMilliseconds <= nowMilliseconds

    class _PendingInterest(object):
        """
        A PendingInterest holds an interest which onInterest received but could
        not satisfy. When we add a new data packet to the cache, we will also
        check if it satisfies a pending interest.

        Create a new PendingInterest and set the _timeoutTime based on the
        current time and the interest lifetime.

        :param Interest interest: The interest.
        :param Face face: The face from the onInterest callback.
          If the interest is satisfied later by a new data packet, we will send
          the data packet to the face.
        """
        def __init__(self, interest, face):
            self._interest = interest
            self._face = face

            # Set up _timeoutTimeMilliseconds.
            if self._interest.getInterestLifetimeMilliseconds() >= 0.0:
              self._timeoutTimeMilliseconds = (Common.getNowMilliseconds() +
                self._interest.getInterestLifetimeMilliseconds())
            else:
              # No timeout.
              self._timeoutTimeMilliseconds = -1.0

        def getInterest(self):
            """
            Return the interest given to the constructor.
            """
            return self._interest

        def getFace(self):
            """
            Return the face given to the constructor.
            """
            return self._face

        def isTimedOut(self, nowMilliseconds):
            """
            Check if this interest is timed out.

            :param float nowMilliseconds: The current time in milliseconds from
              Common.getNowMilliseconds.
            :return: True if this interest timed out, otherwise False.
            :rtype: bool
            """
            return (self._timeoutTimeMilliseconds >= 0.0 and
                    nowMilliseconds >= self._timeoutTimeMilliseconds)

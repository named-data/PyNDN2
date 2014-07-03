# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
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
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU General Public License is in the file COPYING.

"""
This module defines the MemoryContentCache class which holds a set of Data
packets and answers an Interest to return the correct Data packet. The cache is
periodically cleaned up to remove each stale Data packet based on its
FreshnessPeriod (if it has one).
Note: This class is an experimental feature. See the API docs for more detail at
http://named-data.net/doc/ndn-ccl-api/memory-content-cache.html .
"""

from pyndn.name import Name
from pyndn.util.common import Common

class MemoryContentCache(object):
    """
    Create a new MemoryContentCache to use the given Face.

    :param Face face: The Face to use to call registerPrefix and which will call
      the OnInterest callback.
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
        #  elements are MemoryContentCache._Content
        self._noStaleTimeCache = []
        # elements are MemoryContentCache.StaleTimeContent
        self._staleTimeCache = []
        self._emptyComponent = Name.Component()

    def registerPrefix(
      self, prefix, onRegisterFailed, onDataNotFound = None, flags = None,
      wireFormat = None):
        """
        Call registerPrefix on the Face given to the constructor so that this
        MemoryContentCache will answer interests whose name has the prefix.

        :param Name prefix: The Name for the prefix to register. This copies the
          Name.
        :param onRegisterFailed: If this fails to register the prefix for any
          reason, this calls onRegisterFailed(prefix) where prefix is the prefix
          given to registerPrefix.
        :type onRegisterFailed: function object
        :param onDataNotFound: If a data packet is not found in the cache, this
          calls onInterest(prefix, interest, transport) to forward the interest.
          If omitted, this does not use it.
        :type onDataNotFound: function object
        :param ForwardingFlags flags: (optional) See Face.registerPrefix.
        :param wireFormat: (optional) See Face.registerPrefix.
        :type wireFormat: A subclass of WireFormat
        """
        if onDataNotFound != None:
            self._onDataNotFoundForPrefix[prefix.toUri()] = onDataNotFound
        self._face.registerPrefix(
          prefix, self._onInterest, onRegisterFailed, flags, wireFormat)

    def add(self, data):
        """
        Add the Data packet to the cache so that it is available to use to
        answer interests. If data.getFreshnessPeriod() is not None, set the
        staleness time to now plus data.getFreshnessPeriod(), which is checked
        during cleanup to remove stale content. This also checks if
        cleanupIntervalMilliseconds milliseconds have passed and removes stale
        content from the cache.

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

    def _onInterest(self, prefix, interest, transport, registeredPrefixId):
        """
        This is the OnInterest callback which is called when the library 
        receives an interest whose name has the prefix given to registerPrefix.
        First check if cleanupIntervalMilliseconds milliseconds have passed and
        remove stale content from the cache. Then search the cache for the Data
        packet, matching any interest selectors including ChildSelector, and
        send the Data packet to the transport. If no matching Data packet is in
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
                    transport.send(content.getDataEncoding())
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
            transport.send(selectedEncoding)
        else:
            # Call the onDataNotFound callback (if defined).
            if prefix.toUri() in self._onDataNotFoundForPrefix:
                # TODO: Include registeredPrefixId.
                self._onDataNotFoundForPrefix[prefix.toUri()](
                  prefix, interest, transport, 0)

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
            :return: true if this interest is stale, otherwise false.
            :rtype: bool
            """
            return self._staleTimeMilliseconds <= nowMilliseconds

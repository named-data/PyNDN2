# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2015 Regents of the University of California.
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
This module defines the ThreadsafeFace class which extends Face to provide the
main methods for NDN communication in a thread-safe manner.
"""

from pyndn.face import Face

class ThreadsafeFace(Face):
    """
    Create a new ThreadsafeFace to use the asyncio loop to process events and
    schedule communication calls. This constructor schedules the event loop
    to process events, but you must start the loop on the thread in which
    you want the library to call communication callbacks such as onData and
    onInterest.
    In Python <= 3.2, you must have the prerequisite Trollius library. See the
    INSTALL file for installation details. For usage, see the example
    test_get_async_threadsafe.py.
    """
    def __init__(self, loop, arg1, arg2 = None):
        super(ThreadsafeFace, self).__init__(arg1, arg2)
        self._loop = loop

        # Schedule the main processEvents service.
        self._loop.call_soon(self._processEventsCallback)

    def expressInterest(
      self, interestOrName, arg2, arg3 = None, arg4 = None, arg5 = None):
        """
        Override to use the event loop given to the constructor to schedule
        expressInterest to be called in a thread-safe manner. See
        Face.expressInterest for calling details.
        """
        pendingInterestId = self._node.getNextEntryId()

        self._loop.call_soon_threadsafe(
            self._expressInterestHelper, pendingInterestId, interestOrName, arg2,
            arg3, arg4, arg5)

        return pendingInterestId

    def removePendingInterest(self, pendingInterestId):
        """
        Override to use the event loop given to the constructor to schedule
        removePendingInterest to be called in a thread-safe manner. See
        Face.removePendingInterest for calling details.
        """
        self._loop.call_soon_threadsafe(
            super(ThreadsafeFace, self).removePendingInterest,
            pendingInterestId)

    def registerPrefix(
      self, prefix, onInterest, onRegisterFailed, flags = None,
      wireFormat = None):
        """
        Override to use the event loop given to the constructor to schedule
        registerPrefix to be called in a thread-safe manner. See
        Face.registerPrefix for calling details.
        """
        registeredPrefixId = self._node.getNextEntryId()

        self._loop.call_soon_threadsafe(
            self._registerPrefixHelper, registeredPrefixId, prefix, onInterest,
            onRegisterFailed, flags, wireFormat)

        return registeredPrefixId

    def removeRegisteredPrefix(self, registeredPrefixId):
        """
        Override to use the event loop given to the constructor to schedule
        removeRegisteredPrefix to be called in a thread-safe manner. See
        Face.removeRegisteredPrefix for calling details.
        """
        self._loop.call_soon_threadsafe(
            super(ThreadsafeFace, self).removeRegisteredPrefix,
            registeredPrefixId)

    def setInterestFilter(self, filterOrPrefix, onInterest):
        """
        Override to use the event loop given to the constructor to schedule
        setInterestFilter to be called in a thread-safe manner. See
        Face.setInterestFilter for calling details.
        """
        interestFilterId = self._node.getNextEntryId()

        self._loop.call_soon_threadsafe(
            self._setInterestFilterHelper, interestFilterId, filterOrPrefix,
            onInterest)

        return interestFilterId

    def unsetInterestFilter(self, interestFilterId):
        """
        Override to use the event loop given to the constructor to schedule
        unsetInterestFilter to be called in a thread-safe manner. See
        Face.unsetInterestFilter for calling details.
        """
        self._loop.call_soon_threadsafe(
            super(ThreadsafeFace, self).unsetInterestFilter, interestFilterId)

    def send(self, encoding):
        """
        Override to use the event loop given to the constructor to schedule
        send to be called in a  manner. See
        Face.send for calling details.
        """
        self._loop.call_soon_threadsafe(
            super(ThreadsafeFace, self).send, encoding)

    def shutdown(self):
        """
        Unschedule the process events from being called in the event loop,
        then call Face.shutdown.
        """
        # This will shut down _processEventsCallback.
        self._loop == None
        super(ThreadsafeFace, self).shutdown()

    def callLater(self, delayMilliseconds, callback):
        """
        Override to call callback() after the given delay, using
        self._loop.call_later. This means that processEvents() is not needed to
        handle interest timeouts. Even though this is public, it is not part of
        the public API of Face.

        :param float delayMilliseconds: The delay in milliseconds.
        :param callback: This calls callback() after the delay.
        :type callback: function object
        """
        # Convert milliseconds to seconds.
        self._loop.call_later(delayMilliseconds / 1000.0, callback)

    def _processEventsCallback(self):
        """
        Repeatedly call self.processEvents() using self._loop. However, if
        self._loop is None (because of shutdown), don't repeatedly call
        anymore.
        """
        if self._loop != None:
            try:
                self.processEvents()
            finally:
                # Call again, even if processEvents raised an exception.
                self._loop.call_later(0.01, self._processEventsCallback)

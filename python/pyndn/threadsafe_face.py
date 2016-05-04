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
This module defines the ThreadsafeFace class which extends Face to provide the
main methods for NDN communication in a thread-safe manner.
"""

from pyndn.util.common import Common
from pyndn.transport.async_tcp_transport import AsyncTcpTransport
from pyndn.transport.async_unix_transport import AsyncUnixTransport
from pyndn.name import Name
from pyndn.interest_filter import InterestFilter
from pyndn.face import Face

class ThreadsafeFace(Face):
    """
    Create a new ThreadsafeFace to use the asyncio loop to process events and
    schedule communication calls. You must start the loop on the thread in which
    you want the library to call communication callbacks such as onData and
    onInterest.
    In Python <= 3.2, you must have the prerequisite Trollius library. See the
    INSTALL file for installation details. For usage, see the example
    test_get_async_threadsafe.py.
    This constructor has the forms ThreadsafeFace(loop),
    ThreadsafeFace(loop, transport, connectionInfo) or
    ThreadsafeFace(loop, host, port). If the default Face(loop) constructor is
    used, if the forwarder's Unix socket file exists then connect using
    AsyncUnixTransport, otherwise connect to "localhost" on port 6363 using
    AsyncTcpTransport. You do not need to call processEvents since the
    asyncio loop does all processing. (Exception: If you pass a transport that
    is not an async transport like AsyncTcpTransport, then your application
    needs to call processEvents.)

    :param loop: The event loop, for example from asyncio.get_event_loop(). It
      is the responsibility of the application to start and stop the loop.
    :param Transport transport: An object of a subclass of Transport used for
      communication. If you do not want to call processEvents, then the
      transport should be an async transport like AsyncTcpTransport, in which
      case the transport should use the same loop.
    :param Transport.ConnectionInfo connectionInfo: An object of a subclass of
      Transport.ConnectionInfo to be used to connect to the transport.
    :param str host: In the Face(host, port) form of the constructor, host is
      the host of the NDN hub to connect using TcpTransport.
    :param int port: (optional) In the Face(host, port) form of the constructor,
      port is the port of the NDN hub. If omitted. use 6363.
    """
    def __init__(self, loop, arg1 = None, arg2 = None):
        self._loop = loop

        # Imitate the Face constructor, but use AsyncTcpTransport, etc.
        if arg1 == None or Common.typeIsString(arg1):
            filePath = ""
            if arg1 == None and arg2 == None:
                # Check if we can connect using UnixSocket.
                filePath = self._getUnixSocketFilePathForLocalhost()

            if filePath == "":
                transport = AsyncTcpTransport(loop)
                host = arg1 if arg1 != None else "localhost"
                connectionInfo = AsyncTcpTransport.ConnectionInfo(
                  host, arg2 if type(arg2) is int else 6363)
            else:
                transport = AsyncUnixTransport(loop)
                connectionInfo = AsyncUnixTransport.ConnectionInfo(filePath)
        else:
            transport = arg1
            connectionInfo = arg2
        super(ThreadsafeFace, self).__init__(transport, connectionInfo)

    def expressInterest(
      self, interestOrName, arg2, arg3 = None, arg4 = None, arg5 = None,
      arg6 = None):
        """
        Override to use the event loop given to the constructor to schedule
        expressInterest to be called in a thread-safe manner. See
        Face.expressInterest for calling details.
        """
        args = self._getExpressInterestArgs(
          interestOrName, arg2, arg3, arg4, arg5, arg6)
        self._loop.call_soon_threadsafe(
          self._node.expressInterest, args['pendingInterestId'],
          args['interestCopy'], args['onData'], args['onTimeout'],
          args['onNetworkNack'], args['wireFormat'], self)

        return args['pendingInterestId']

    def removePendingInterest(self, pendingInterestId):
        """
        Override to use the event loop given to the constructor to schedule
        removePendingInterest to be called in a thread-safe manner. See
        Face.removePendingInterest for calling details.
        """
        self._loop.call_soon_threadsafe(
          self._node.removePendingInterest, pendingInterestId)

    def registerPrefix(
      self, prefix, onInterest, onRegisterFailed, onRegisterSuccess = None,
      flags = None, wireFormat = None):
        """
        Override to use the event loop given to the constructor to schedule
        registerPrefix to be called in a thread-safe manner. See
        Face.registerPrefix for calling details.
        """
        registeredPrefixId = self._node.getNextEntryId()

        # Node.registerPrefix requires a copy of the prefix.
        # We make a copy so that the caller can change the original object while
        # call_soon_threadsafe is waiting to process.
        self._loop.call_soon_threadsafe(
          self._registerPrefixHelper, registeredPrefixId, Name(prefix),
          onInterest, onRegisterFailed, onRegisterSuccess, flags, wireFormat)

        return registeredPrefixId

    def removeRegisteredPrefix(self, registeredPrefixId):
        """
        Override to use the event loop given to the constructor to schedule
        removeRegisteredPrefix to be called in a thread-safe manner. See
        Face.removeRegisteredPrefix for calling details.
        """
        self._loop.call_soon_threadsafe(
          self._node.removeRegisteredPrefix, registeredPrefixId)

    def setInterestFilter(self, filterOrPrefix, onInterest):
        """
        Override to use the event loop given to the constructor to schedule
        setInterestFilter to be called in a thread-safe manner. See
        Face.setInterestFilter for calling details.
        """
        interestFilterId = self._node.getNextEntryId()

        # If filterOrPrefix is already an InterestFilter, the InterestFilter
        # constructor will make a copy as required by Node.setInterestFilter.
        # We make a copy so that the caller can change the original object while
        # call_soon_threadsafe is waiting to process.
        filterCopy = InterestFilter(filterOrPrefix)

        self._loop.call_soon_threadsafe(
          self._node.setInterestFilter, interestFilterId, filterCopy,
          onInterest, self)

        return interestFilterId

    def unsetInterestFilter(self, interestFilterId):
        """
        Override to use the event loop given to the constructor to schedule
        unsetInterestFilter to be called in a thread-safe manner. See
        Face.unsetInterestFilter for calling details.
        """
        self._loop.call_soon_threadsafe(
          self._node.unsetInterestFilter, interestFilterId)

    def send(self, encoding):
        """
        Override to use the event loop given to the constructor to schedule
        send to be called in a  manner. See
        Face.send for calling details.
        """
        self._loop.call_soon_threadsafe(
            super(ThreadsafeFace, self).send, encoding)

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

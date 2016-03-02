# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2016 Regents of the University of California.
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
This module defines the AsyncSocketTransport class which extends Transport and
is a helper base class for AsyncTcpTransport and AsyncUnixTransport to implement
common socket communication tasks using Python's asyncio.
"""

try:
    # Use builtin asyncio on Python 3.4+, or Tulip on Python 3.3
    import asyncio
except ImportError:
    # Use Trollius on Python <= 3.2
    import trollius as asyncio
import logging
from pyndn.transport.transport import Transport
from pyndn.encoding.element_reader import ElementReader

class AsyncSocketTransport(Transport):
    """
    Create a new AsyncSocketTransport in the unconnected state. This will use the
    asyncio loop to create the connection and communicate asynchronously.

    :param loop: The event loop, for example from asyncio.get_event_loop(). It
      is the responsibility of the application to start and stop the loop.
    """
    def __init__(self, loop):
        self._loop = loop
        self._transport = None
        self._elementReader = None

    def _connectHelper(self, elementListener, connectCoroutine):
        """
        This is a protected helper method to Connect using the connectCoroutine,
        and use elementListener.

        :param elementListener: The elementListener must remain valid during the
          life of this object.
        :type elementListener: An object with onReceivedElement
        :param coroutine connectionInfo: The connect coroutine which uses
          _ReceiveProtocol, e.g. self._loop.create_connection(
          lambda: AsyncSocketTransport._ReceiveProtocol(self, onConnected), host, port).
        :type onConnected: function object
        """
        self.close()
        asyncio.async(connectCoroutine, loop = self._loop)
        self._elementReader = ElementReader(elementListener)

    class _ReceiveProtocol(asyncio.Protocol):
        def __init__(self, parent, onConnected):
            self._parent = parent
            self._onConnected = onConnected

        def connection_made(self, transport):
            # Need to catch and log exceptions at this async entry point.
            try:
                self._parent._transport = transport
                self._onConnected()
            except:
                logging.exception("Error in connection_made")

        def data_received(self, data):
            # Need to catch and log exceptions at this async entry point.
            try:
                self._parent._elementReader.onReceivedData(data)
            except:
                logging.exception("Error in data_received")

    # This will be set True if send gets a TypeError.
    _sendNeedsStr = False
    def send(self, data):
        """
        Send data to the host. To be thread-safe, this must be called from a
        dispatch to the loop which was given to the constructor, as is done by
        ThreadsafeFace.

        :param data: The buffer of data to send.
        :type data: An array type accepted by Transport.write.
        """
        if AsyncSocketTransport._sendNeedsStr:
            # This version of write can't use a memoryview, etc., so convert.
            self._transport.write(str(bytearray(data)))
        else:
            try:
                self._transport.write(data)
            except TypeError:
                # Assume we need to convert to a str.
                AsyncSocketTransport._sendNeedsStr = True
                self.send(data)

    def processEvents(self):
        """
        Do nothing since the async loop reads the socket.
        """
        pass

    def getIsConnected(self):
        """
        Check if the transport is connected.

        :return: True if connected.
        :rtype: bool
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        if self._transport == None:
            return False

        # Assume we are still connected.  TODO: Do a test receive?
        return True

    def close(self):
        if self._transport != None:
            self._transport.close()
            self._transport = None

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015 Regents of the University of California.
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
This module defines the AsyncTcpTransport class which extends Transport for
async communication over TCP using Python's asyncio. This only uses asyncio for
communication. To make this thread-safe, you must dispatch calls to send(), etc.
to the asyncio loop using, e.g., call_soon_threadsafe, as is done by
ThreadsafeFace. To use this, you do not need to call processEvents.
"""

try:
    # Use builtin asyncio on Python 3.4+, or Tulip on Python 3.3
    import asyncio
except ImportError:
    # Use Trollius on Python <= 3.2
    import trollius as asyncio
from pyndn.transport.transport import Transport
from pyndn.transport.tcp_transport import TcpTransport
from pyndn.encoding.element_reader import ElementReader

class AsyncTcpTransport(Transport):
    """
    Create a new AsyncTcpTransport in the unconnected state. This will use the
    asyncio loop to create the connection and communicate asynchronously.

    :param loop: The event loop, for example from asyncio.get_event_loop(). It 
      is the responsibility of the application to start and stop the loop.
    """
    def __init__(self, loop):
        self._loop = loop

        self._transport = None
        self._elementReader = None
        self._connectionInfo = None
        self._isLocal = False

    class ConnectionInfo(Transport.ConnectionInfo):
        """
        Create a new AsyncTcpTransport.ConnectionInfo which extends
        Transport.ConnectionInfo to hold the host and port info for the TCP
        connection.

        :param str host: The host for the connection.
        :param int port: (optional) The port number for the connection. If
          omitted, use 6363.
        """
        def __init__(self, host, port = 6363):
            self._host = host
            self._port = port

        def getHost(self):
            """
            Get the host given to the constructor.

            :return: The host.
            :rtype: str
            """
            return self._host

        def getPort(self):
            """
            Get the port given to the constructor.

            :return: The port.
            :rtype: int
            """
            return self._port

    def isLocal(self, connectionInfo):
        """
        Determine whether this transport connecting according to connectionInfo
        is to a node on the current machine; results are cached. According to
        http://redmine.named-data.net/projects/nfd/wiki/ScopeControl#local-face,
        TCP transports with a loopback address are local. If connectionInfo
        contains a host name, this will do a blocking DNS lookup; otherwise
        this will parse the IP address and examine the first octet to determine
        if it is a loopback address (e.g. the first IPv4 octet is 127 or IPv6 is
        "::1").

        :param TcpTransport.ConnectionInfo connectionInfo: A
          TcpTransport.ConnectionInfo with the host to check.
        :return: True if the host is local, False if not.
        :rtype bool:
        """
        if (self._connectionInfo == None or
            self._connectionInfo.getHost() != connectionInfo.getHost()):
            # Cache the result in _isLocal and save _connectionInfo for next time.
            self._isLocal = TcpTransport.getIsLocal(connectionInfo.getHost())
            self._connectionInfo = connectionInfo

        return self._isLocal

    def connect(self, connectionInfo, elementListener, onConnected):
        """
        Connect according to the info in connectionInfo, and use
        elementListener. To be thread-safe, this must be called from a dispatch
        to the loop which was given to the constructor, as is done by
        ThreadsafeFace.

        :param AsyncTcpTransport.ConnectionInfo connectionInfo: An
          AsyncTcpTransport.ConnectionInfo.
        :param elementListener: The elementListener must remain valid during the
          life of this object.
        :type elementListener: An object with onReceivedElement
        :param onConnected: This calls onConnected() when the connection is
          established.
        :type onConnected: function object
        """
        self.close()

        connectCoroutine = self._loop.create_connection(
          lambda: AsyncTcpTransport._ReceiveProtocol(self, onConnected),
          connectionInfo.getHost(), connectionInfo.getPort())
        asyncio.async(connectCoroutine, loop = self._loop)

        self._elementReader = ElementReader(elementListener)

    class _ReceiveProtocol(asyncio.Protocol):
        def __init__(self, parent, onConnected):
            self._parent = parent
            self._onConnected = onConnected

        def connection_made(self, transport):
            self._parent._transport = transport
            self._onConnected()
            
        def data_received(self, data):
            self._parent._elementReader.onReceivedData(data)

    # This will be set True if send gets a TypeError.
    _sendNeedsStr = False
    def send(self, data):
        """
        Set data to the host. To be thread-safe, this must be called from a
        dispatch to the loop which was given to the constructor, as is done by
        ThreadsafeFace.

        :param data: The buffer of data to send.
        :type data: An array type accepted by Transport.write.
        """
        if AsyncTcpTransport._sendNeedsStr:
            # This version of write can't use a memoryview, etc., so convert.
            self._transport.write(str(bytearray(data)))
        else:
            try:
                self._transport.write(data)
            except TypeError:
                # Assume we need to convert to a str.
                AsyncTcpTransport._sendNeedsStr = True
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

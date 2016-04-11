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
This module defines the AsyncUnixTransport class which extends
AsyncSocketTransport for async communication over a Unix socket using Python's
asyncio. This only uses asyncio for communication. To make this thread-safe, you
must dispatch calls to send(), etc. to the asyncio loop using, e.g.,
call_soon_threadsafe, as is done by ThreadsafeFace. To use this, you do not need
to call processEvents.
"""

from pyndn.transport.transport import Transport
from pyndn.transport.async_socket_transport import AsyncSocketTransport

class AsyncUnixTransport(AsyncSocketTransport):
    """
    Create a new AsyncUnixTransport in the unconnected state. This will use the
    asyncio loop to create the connection and communicate asynchronously.

    :param loop: The event loop, for example from asyncio.get_event_loop(). It
      is the responsibility of the application to start and stop the loop.
    """
    def __init__(self, loop):
        super(AsyncUnixTransport, self).__init__(loop)

        self._loop = loop

    class ConnectionInfo(Transport.ConnectionInfo):
        """
        Create a new AsyncUnixTransport.ConnectionInfo which extends
        Transport.ConnectionInfo to hold the socket file path for the Unix
        socket connection.

        :param str filePath: The file path of the Unix socket file.
        """
        def __init__(self, filePath):
            self._filePath = filePath

        def getFilePath(self):
            """
            Get the filePath given to the constructor.

            :return: The file path.
            :rtype: str
            """
            return self._filePath

    def isLocal(self, connectionInfo):
        """
        Determine whether this transport connecting according to connectionInfo
        is to a node on the current machine. Unix transports are always local.

        :param UnixTransport.ConnectionInfo connectionInfo: This is ignored.
        :return: True because Unix transports are always local.
        :rtype: bool
        """
        return True

    def isAsync(self):
        """
        Override to return true since connect needs to use the onConnected
        callback.

        :return: True
        :rtype bool:
        """
        return True

    def connect(self, connectionInfo, elementListener, onConnected):
        """
        Connect according to the info in connectionInfo, and use
        elementListener. To be thread-safe, this must be called from a dispatch
        to the loop which was given to the constructor, as is done by
        ThreadsafeFace.

        :param AsyncUnixTransport.ConnectionInfo connectionInfo: An
          AsyncUnixTransport.ConnectionInfo.
        :param elementListener: The elementListener must remain valid during the
          life of this object.
        :type elementListener: An object with onReceivedElement
        :param onConnected: This calls onConnected() when the connection is
          established.
        :type onConnected: function object
        """
        self._connectHelper(
          elementListener, self._loop.create_unix_connection(
          lambda: AsyncSocketTransport._ReceiveProtocol(self, onConnected),
          connectionInfo.getFilePath()))


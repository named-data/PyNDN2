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
This module defines the UdpTransport class which extends Transport for
communication over UDP.
"""

import socket
from pyndn.util.blob import Blob, Common
from pyndn.transport.transport import Transport
from pyndn.transport.socket_poller import SocketPoller
from pyndn.encoding.element_reader import ElementReader

class UdpTransport(Transport):
    """
    Create a new UdpTransport in the unconnected state.
    """
    def __init__(self):
        self._socket = None
        self._socketPoller = None
        self._buffer = bytearray(Common.MAX_NDN_PACKET_SIZE)
        # Create a Blob and take its buf() since this creates a memoryview
        #   which is more efficient for slicing.
        self._bufferView = Blob(self._buffer, False).buf()
        self._elementReader = None

    class ConnectionInfo(Transport.ConnectionInfo):
        """
        Create a new UdpTransport.ConnectionInfo which extends
        Transport.ConnectionInfo to hold the host and port info for the UDP
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
        is to a node on the current machine. UDP transports are always non-local.

        :param UdpTransport.ConnectionInfo connectionInfo: This is ignored.
        :return: False because UDP transports are always non-local.
        :rtype: bool
        """
        return False

    def isAsync(self):
        """
        Override to return false since connect does not need to use the
        onConnected callback.

        :return: False
        :rtype bool:
        """
        return False

    def connect(self, connectionInfo, elementListener, onConnected):
        """
        Connect according to the info in connectionInfo, and use
        elementListener.

        :param UdpTransport.ConnectionInfo connectionInfo: A
          UdpTransport.ConnectionInfo.
        :param elementListener: The elementListener must remain valid during the
          life of this object.
        :type elementListener: An object with onReceivedElement
        :param onConnected: This calls onConnected() when the connection is
          established.
        :type onConnected: function object
        """
        self.close()
        # Save the _address to use in sendto.
        self._address = (connectionInfo.getHost(), connectionInfo.getPort())
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self._socketPoller = SocketPoller(self._socket)
        self._elementReader = ElementReader(elementListener)

        if onConnected != None:
            onConnected()

    # This will be set True if send gets a TypeError.
    _sendNeedsStr = False
    def send(self, data):
        """
        Send data to the host.

        :param data: The buffer of data to send.
        :type data: An array type accepted by socket.send
        """
        if UdpTransport._sendNeedsStr:
            # This version of sendall can't use a memoryview, etc., so convert.
            self._socket.sendto(str(bytearray(data)), self._address)
        else:
            try:
                self._socket.sendto(data, self._address)
            except TypeError:
                # Assume we need to convert to a str.
                UdpTransport._sendNeedsStr = True
                self.send(data)

    def processEvents(self):
        """
        Process any data to receive.  For each element received, call
        elementListener.onReceivedElement.
        This is non-blocking and will silently time out after a brief period if
        there is no data to receive.
        You should repeatedly call this from an event loop.
        You should normally not call this directly since it is called by
        Face.processEvents.
        If you call this from an main event loop, you may want to catch and
        log/disregard all exceptions.
        """
        if not self.getIsConnected():
            return

        # Loop until there is no more data in the receive buffer.
        while True:
            if not self._socketPoller.isReady():
                # There is no data waiting.
                return

            nBytesRead, _ = self._socket.recvfrom_into(self._buffer)
            if nBytesRead <= 0:
                # Since we checked for data ready, we don't expect this.
                return

            # _bufferView is a memoryview, so we can slice efficienty.
            self._elementReader.onReceivedData(self._bufferView[0:nBytesRead])

    def getIsConnected(self):
        """
        For UDP, there really is no connection, but just return True if
        connect has been called.

        :return: True if connected.
        :rtype: bool
        """
        if self._socket == None:
            return False

        # Assume we are still connected.  TODO: Do a test receive?
        return True

    def close(self):
        """
        Close the connection.  If not connected, this does nothing.
        """
        if self._socketPoller != None:
            self._socketPoller.close()
            self._socketPoller = None

        if self._socket != None:
            self._socket.close()
            self._socket = None

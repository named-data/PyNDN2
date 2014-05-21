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
This module defines the TcpTransport class which extends Transport for
communication over TCP.
"""

import socket
import select
from pyndn.util import Blob
from pyndn.transport.transport import Transport
from pyndn.encoding.element_reader import ElementReader

class TcpTransport(Transport):
    """
    Create a new TcpTransport in the unconnected state.
    """
    def __init__(self):
        self._socket = None
        self._poll = None
        self._kqueue = None
        self._kevents = None
        self._buffer = bytearray(8000)
        # Create a Blob and take its buf() since this creates a memoryview
        #   which is more efficient for slicing.
        self._bufferView = Blob(self._buffer, False).buf()
        self._elementReader = None

    class ConnectionInfo(Transport.ConnectionInfo):
        """
        Create a new TcpTransport.ConnectionInfo which extends 
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
                
    def connect(self, connectionInfo, elementListener):
        """
        Connect according to the info in connectionInfo, and use 
        elementListener.
        
        :param TcpTransport.ConnectionInfo connectionInfo: A 
          TcpTransport.ConnectionInfo.
        :param elementListener: The elementListener must remain valid during the 
          life of this object.
        :type elementListener: An object with onReceivedData
        """
        self.close()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect(
          (connectionInfo.getHost(), connectionInfo.getPort()))
          
        if hasattr(select, "poll"):
            # Set up _poll.  (Ubuntu, etc.)
            self._poll = select.poll()
            self._poll.register(self._socket.fileno(), select.POLLIN)
        elif hasattr(select, "kqueue"):
            ## Set up _kqueue. (BSD and OS X)
            self._kqueue = select.kqueue()
            self._kevents = [select.kevent(
              self._socket.fileno(), filter = select.KQ_FILTER_READ,
              flags = select.KQ_EV_ADD | select.KQ_EV_ENABLE | 
                      select.KQ_EV_CLEAR)]
        elif not hasattr(select, "select"):
            # Most Python implementations have this fallback, so we
            #   don't expect this error.
            raise RuntimeError("Cannot find a polling utility for sockets")
          
        self._elementReader = ElementReader(elementListener)
    
    # This will be set True if send gets a TypeError.
    _sendNeedsStr = False
    def send(self, data):
        """
        Set data to the host.
        
        :param data: The buffer of data to send.
        :type data: An array type accepted by socket.send
        """
        if TcpTransport._sendNeedsStr:
            # This version of sendall can't use a memoryview, etc., so convert.
            self._socket.sendall(str(bytearray(data)))
        else:
            try:
                self._socket.sendall(data)
            except TypeError:
                # Assume we need to convert to a str.
                TcpTransport._sendNeedsStr = True
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
            if self._poll != None:
                isReady = False
                # Set timeout to 0 for an immediate check.
                for (fd, pollResult) in self._poll.poll(0):
                    if pollResult > 0 and pollResult & select.POLLIN != 0:
                        isReady = True
                        break
                if not isReady:
                    # There is no data waiting.
                    return
            elif self._kqueue != None:
                # Set timeout to 0 for an immediate check.
                if len(self._kqueue.control(self._kevents, 1, 0)) == 0:
                    # There is no data waiting.
                    return
            else:
                # Use the select fallback which is less efficient.
                # Set timeout to 0 for an immediate check.
                isReady, _, _ = select.select([self._socket], [], [], 0)
                if len(isReady) == 0:
                    # There is no data waiting.
                    return
            
            nBytesRead = self._socket.recv_into(self._buffer)
            if nBytesRead <= 0:
                # Since we checked for data ready, we don't expect this.
                return

            # _bufferView is a memoryview, so we can slice efficienty.
            self._elementReader.onReceivedData(self._bufferView[0:nBytesRead])

    def getIsConnected(self):
        """
        Check if the transport is connected.
        
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
        if self._socket != None:
            if self._poll != None:
                self._poll.unregister(self._socket.fileno())
                self._poll = None
                
            self._kqueue = None
            self._kevents = None
            
            self._socket.close()
            self._socket = None            
            

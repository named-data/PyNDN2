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
This module defines the Transport class which is a base class for specific
transport classes such as UnixTransport.
"""

class Transport(object):
    class ConnectionInfo(object):
        """
        A Transport.ConnectionInfo is a base class for connection information
        used by subclasses of Transport.
        """
        pass

    def isLocal(self, connectionInfo):
        """
        Determine whether this transport connecting according to connectionInfo
        is to a node on the current machine. This affects the processing of
        Face.registerPrefix(): if the NFD is local, registration occurs with the
        '/localhost/nfd...' prefix; if non-local, the library will attempt to
        use remote prefix registration using '/localhop/nfd...'

        :param connectionInfo: A ConnectionInfo with the host to check.
        :type connectionInfo: A subclass of ConnectionInfo
        :return: True if the host is local, False if not.
        :rtype bool:
        """
        raise RuntimeError("isLocal is not implemented")

    def isAsync(self):
        """
        Check if this transport is async where connect needs to use the
        onConnected callback.

        :return: True if transport connect is async, False if not.
        :rtype bool:
        """
        raise RuntimeError("isAsync is not implemented")

    def connect(self, connectionInfo, elementListener, onConnected):
        """
        Connect according to the info in ConnectionInfo, and use
        elementListener.

        :param connectionInfo: An object of a subclass of ConnectionInfo.
        :type connectionInfo: A subclass of ConnectionInfo
        :param elementListener: The elementListener must remain valid during the
          life of this object.
        :type elementListener: An object with onReceivedData
        :param onConnected: This calls onConnected() when the connection is
          established.
        :type onConnected: function object
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("connect is not implemented")

    def send(self, data):
        """
        Send data to the host.

        :param data: The buffer of data to send.
        :type data: An array type
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("send is not implemented")

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

        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("processEvents is not implemented")

    def getIsConnected(self):
        """
        Check if the transport is connected.

        :return: True if connected.
        :rtype: bool
        :raises RuntimeError: for unimplemented if the derived class does not
          override.
        """
        raise RuntimeError("getIsConnected is not implemented")

    def close(self):
        """
        Close the connection.  This base class implementation does nothing, but
          your derived class can override.
        """
        pass

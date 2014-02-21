# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the Face class which provides the main methods for NDN 
communication.
"""

from pyndn.encoding import WireFormat
from pyndn.transport.tcp_transport import TcpTransport
from pyndn.node import Node

class Face(object):
    """
    Create a new Face for communication with an NDN hub.  This constructor
    has the forms Face(transport, connectionInfo) or 
    Face(host, port)
    
    :param transport: An object of a subclass of Transport used for 
      communication.
    :type transport: Transport
    :param connectionInfo: An object of a subclass of Transport.ConnectionInfo
      to be used to connect to the transport.
    :type connectionInfo: Transport.ConnectionInfo
    :param host: In the Face(host, port) form of the constructor, host is
      the host of the NDN hub with a TcpTransport.
    :type host: str
    :param port: (optional) In the Face(host, port) form of the constructor, 
      port is the port of the NDN hub. If omitted. use 6363.
    :type port: int
    """
    def __init__(self, arg1, arg2 = None):
        if type(arg1) is str:
            transport = TcpTransport()
            connectionInfo = TcpTransport.ConnectionInfo(
              arg1, arg2 if type(arg2) is int else 6363)
        else:
            transport = arg1
            connectionInfo = arg2
            
        self._node = Node(transport, connectionInfo)
            
    def expressInterest(
      self, interest, onData, onTimeout = None, wireFormat = None):
        """
        Send the Interest through the transport, read the entire response and 
        call onData(interest, data).
        
        :param interest: The Interest. This copies the Interest.
        :type interest: Interest
        :param onData: A function object to call when a matching data packet is 
          received.
        :type onData: function object
        :param onTimeout: (optional) A function object to call if the interest 
          times out. If onTimeout is None or omitted, this does not use it.
        :type onTimeout: function object
        :param wireFormat: (optional) A WireFormat object used to encode the 
           message. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat.
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        return self._node.expressInterest(
          interest, onData, onTimeout, wireFormat)
          
    # TODO: Fully implement expressInterest that takes a Name.

    def removePendingInterest(self, pendingInterestId):
        """
        Remove the pending interest entry with the pendingInterestId from the 
        pending interest table. This does not affect another pending interest 
        with a different pendingInterestId, even it if has the same interest 
        name. If there is no entry with the pendingInterestId, do nothing.
        
        :param pendingInterestId: The ID returned from expressInterest.
        :type pendingInterestId: int
        """
        self._node.removePendingInterest(pendingInterestId)
        
    # TODO: registerPrefix
    
    def removeRegisteredPrefix(self, registeredPrefixId):
        """
        Remove the registered prefix entry with the registeredPrefixId from the
        pending interest table. This does not affect another registered prefix 
        with a different registeredPrefixId, even it if has the same prefix 
        name. If there is no entry with the registeredPrefixId, do nothing.
        
        :param registeredPrefixId: The ID returned from registerPrefix.
        :type registeredPrefixId: int
        """
        self._node.removeRegisteredPrefix(registeredPrefixId)
        
    def processEvents(self):
        """
        Process any data to receive.  For each element received, call 
        onReceivedElement. This is non-blocking and will return immediately if 
        there is no data to receive. You should repeatedly call this from an 
        event loop, with calls to sleep as needed so that the loop doesn't use 
        100% of the CPU.
        
        :raises: This may raise an exception for reading data or in the callback
          for processing the data.  If you call this from an main event loop, 
          you may want to catch and log/disregard all exceptions.
        """
        # Just call Node's processEvents.
        self._node.processEvents()
        
    def shutdown(self):
        """
        Shut down and disconnect this Face.
        """
        self._node.shutdown()
        
# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the Node class which provides functionality for the Face
class.
"""

from pyndn.name import Name
from pyndn.interest import Interest
from pyndn.data import Data
from pyndn.util.common import Common
from pyndn.encoding.tlv.tlv import Tlv
from pyndn.encoding.tlv.tlv_decoder import TlvDecoder
from pyndn.encoding.tlv_wire_format import TlvWireFormat

SELFREG_PUBLIC_KEY_DER = bytearray([
0x30, 0x81, 0x9F, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81,
0x8D, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xE1, 0x7D, 0x30, 0xA7, 0xD8, 0x28, 0xAB, 0x1B, 0x84, 0x0B, 0x17,
0x54, 0x2D, 0xCA, 0xF6, 0x20, 0x7A, 0xFD, 0x22, 0x1E, 0x08, 0x6B, 0x2A, 0x60, 0xD1, 0x6C, 0xB7, 0xF5, 0x44, 0x48, 0xBA,
0x9F, 0x3F, 0x08, 0xBC, 0xD0, 0x99, 0xDB, 0x21, 0xDD, 0x16, 0x2A, 0x77, 0x9E, 0x61, 0xAA, 0x89, 0xEE, 0xE5, 0x54, 0xD3,
0xA4, 0x7D, 0xE2, 0x30, 0xBC, 0x7A, 0xC5, 0x90, 0xD5, 0x24, 0x06, 0x7C, 0x38, 0x98, 0xBB, 0xA6, 0xF5, 0xDC, 0x43, 0x60,
0xB8, 0x45, 0xED, 0xA4, 0x8C, 0xBD, 0x9C, 0xF1, 0x26, 0xA7, 0x23, 0x44, 0x5F, 0x0E, 0x19, 0x52, 0xD7, 0x32, 0x5A, 0x75,
0xFA, 0xF5, 0x56, 0x14, 0x4F, 0x9A, 0x98, 0xAF, 0x71, 0x86, 0xB0, 0x27, 0x86, 0x85, 0xB8, 0xE2, 0xC0, 0x8B, 0xEA, 0x87,
0x17, 0x1B, 0x4D, 0xEE, 0x58, 0x5C, 0x18, 0x28, 0x29, 0x5B, 0x53, 0x95, 0xEB, 0x4A, 0x17, 0x77, 0x9F, 0x02, 0x03, 0x01,
0x00, 0x01  
  ])

SELFREG_PRIVATE_KEY_DER = bytearray([
0x30, 0x82, 0x02, 0x5d, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xe1, 0x7d, 0x30, 0xa7, 0xd8, 0x28, 0xab, 0x1b, 0x84,
0x0b, 0x17, 0x54, 0x2d, 0xca, 0xf6, 0x20, 0x7a, 0xfd, 0x22, 0x1e, 0x08, 0x6b, 0x2a, 0x60, 0xd1, 0x6c, 0xb7, 0xf5, 0x44,
0x48, 0xba, 0x9f, 0x3f, 0x08, 0xbc, 0xd0, 0x99, 0xdb, 0x21, 0xdd, 0x16, 0x2a, 0x77, 0x9e, 0x61, 0xaa, 0x89, 0xee, 0xe5,
0x54, 0xd3, 0xa4, 0x7d, 0xe2, 0x30, 0xbc, 0x7a, 0xc5, 0x90, 0xd5, 0x24, 0x06, 0x7c, 0x38, 0x98, 0xbb, 0xa6, 0xf5, 0xdc,
0x43, 0x60, 0xb8, 0x45, 0xed, 0xa4, 0x8c, 0xbd, 0x9c, 0xf1, 0x26, 0xa7, 0x23, 0x44, 0x5f, 0x0e, 0x19, 0x52, 0xd7, 0x32,
0x5a, 0x75, 0xfa, 0xf5, 0x56, 0x14, 0x4f, 0x9a, 0x98, 0xaf, 0x71, 0x86, 0xb0, 0x27, 0x86, 0x85, 0xb8, 0xe2, 0xc0, 0x8b,
0xea, 0x87, 0x17, 0x1b, 0x4d, 0xee, 0x58, 0x5c, 0x18, 0x28, 0x29, 0x5b, 0x53, 0x95, 0xeb, 0x4a, 0x17, 0x77, 0x9f, 0x02,
0x03, 0x01, 0x00, 0x01, 0x02, 0x81, 0x80, 0x1a, 0x4b, 0xfa, 0x4f, 0xa8, 0xc2, 0xdd, 0x69, 0xa1, 0x15, 0x96, 0x0b, 0xe8,
0x27, 0x42, 0x5a, 0xf9, 0x5c, 0xea, 0x0c, 0xac, 0x98, 0xaa, 0xe1, 0x8d, 0xaa, 0xeb, 0x2d, 0x3c, 0x60, 0x6a, 0xfb, 0x45,
0x63, 0xa4, 0x79, 0x83, 0x67, 0xed, 0xe4, 0x15, 0xc0, 0xb0, 0x20, 0x95, 0x6d, 0x49, 0x16, 0xc6, 0x42, 0x05, 0x48, 0xaa,
0xb1, 0xa5, 0x53, 0x65, 0xd2, 0x02, 0x99, 0x08, 0xd1, 0x84, 0xcc, 0xf0, 0xcd, 0xea, 0x61, 0xc9, 0x39, 0x02, 0x3f, 0x87,
0x4a, 0xe5, 0xc4, 0xd2, 0x07, 0x02, 0xe1, 0x9f, 0xa0, 0x06, 0xc2, 0xcc, 0x02, 0xe7, 0xaa, 0x6c, 0x99, 0x8a, 0xf8, 0x49,
0x00, 0xf1, 0xa2, 0x8c, 0x0c, 0x8a, 0xb9, 0x4f, 0x6d, 0x73, 0x3b, 0x2c, 0xb7, 0x9f, 0x8a, 0xa6, 0x7f, 0x9b, 0x9f, 0xb7,
0xa1, 0xcc, 0x74, 0x2e, 0x8f, 0xb8, 0xb0, 0x26, 0x89, 0xd2, 0xe5, 0x66, 0xe8, 0x8e, 0xa1, 0x02, 0x41, 0x00, 0xfc, 0xe7,
0x52, 0xbc, 0x4e, 0x95, 0xb6, 0x1a, 0xb4, 0x62, 0xcc, 0xd8, 0x06, 0xe1, 0xdc, 0x7a, 0xa2, 0xb6, 0x71, 0x01, 0xaa, 0x27,
0xfc, 0x99, 0xe5, 0xf2, 0x54, 0xbb, 0xb2, 0x85, 0xe1, 0x96, 0x54, 0x2d, 0xcb, 0xba, 0x86, 0xfa, 0x80, 0xdf, 0xcf, 0x39,
0xe6, 0x74, 0xcb, 0x22, 0xce, 0x70, 0xaa, 0x10, 0x00, 0x73, 0x1d, 0x45, 0x0a, 0x39, 0x51, 0x84, 0xf5, 0x15, 0x8f, 0x37,
0x76, 0x91, 0x02, 0x41, 0x00, 0xe4, 0x3f, 0xf0, 0xf4, 0xde, 0x79, 0x77, 0x48, 0x9b, 0x9c, 0x28, 0x45, 0x26, 0x57, 0x3c,
0x71, 0x40, 0x28, 0x6a, 0xa1, 0xfe, 0xc3, 0xe5, 0x37, 0xa1, 0x03, 0xf6, 0x2d, 0xbe, 0x80, 0x64, 0x72, 0x69, 0x2e, 0x9b,
0x4d, 0xe3, 0x2e, 0x1b, 0xfe, 0xe7, 0xf9, 0x77, 0x8c, 0x18, 0x53, 0x9f, 0xe2, 0xfe, 0x00, 0xbb, 0x49, 0x20, 0x47, 0xdf,
0x01, 0x61, 0x87, 0xd6, 0xe3, 0x44, 0xb5, 0x03, 0x2f, 0x02, 0x40, 0x54, 0xec, 0x7c, 0xbc, 0xdd, 0x0a, 0xaa, 0xde, 0xe6,
0xc9, 0xf2, 0x8d, 0x6c, 0x2a, 0x35, 0xf6, 0x3c, 0x63, 0x55, 0x29, 0x40, 0xf1, 0x32, 0x82, 0x9f, 0x53, 0xb3, 0x9e, 0x5f,
0xc1, 0x53, 0x52, 0x3e, 0xac, 0x2e, 0x28, 0x51, 0xa1, 0x16, 0xdb, 0x90, 0xe3, 0x99, 0x7e, 0x88, 0xa4, 0x04, 0x7c, 0x92,
0xae, 0xd2, 0xe7, 0xd4, 0xe1, 0x55, 0x20, 0x90, 0x3e, 0x3c, 0x6a, 0x63, 0xf0, 0x34, 0xf1, 0x02, 0x41, 0x00, 0x84, 0x5a,
0x17, 0x6c, 0xc6, 0x3c, 0x84, 0xd0, 0x93, 0x7a, 0xff, 0x56, 0xe9, 0x9e, 0x98, 0x2b, 0xcb, 0x5a, 0x24, 0x4a, 0xff, 0x21,
0xb4, 0x9e, 0x87, 0x3d, 0x76, 0xd8, 0x9b, 0xa8, 0x73, 0x96, 0x6c, 0x2b, 0x5c, 0x5e, 0xd3, 0xa6, 0xff, 0x10, 0xd6, 0x8e,
0xaf, 0xa5, 0x8a, 0xcd, 0xa2, 0xde, 0xcb, 0x0e, 0xbd, 0x8a, 0xef, 0xae, 0xfd, 0x3f, 0x1d, 0xc0, 0xd8, 0xf8, 0x3b, 0xf5,
0x02, 0x7d, 0x02, 0x41, 0x00, 0x8b, 0x26, 0xd3, 0x2c, 0x7d, 0x28, 0x38, 0x92, 0xf1, 0xbf, 0x15, 0x16, 0x39, 0x50, 0xc8,
0x6d, 0x32, 0xec, 0x28, 0xf2, 0x8b, 0xd8, 0x70, 0xc5, 0xed, 0xe1, 0x7b, 0xff, 0x2d, 0x66, 0x8c, 0x86, 0x77, 0x43, 0xeb,
0xb6, 0xf6, 0x50, 0x66, 0xb0, 0x40, 0x24, 0x6a, 0xaf, 0x98, 0x21, 0x45, 0x30, 0x01, 0x59, 0xd0, 0xc3, 0xfc, 0x7b, 0xae,
0x30, 0x18, 0xeb, 0x90, 0xfb, 0x17, 0xd3, 0xce, 0xb5
  ])

class Node(object):
    """
    Create a new Node for communication with an NDN hub with the given Transport
    object and connectionInfo.
    
    :param transport: An object of a subclass of Transport used for 
      communication.
    :type transport: Transport
    :param connectionInfo: An object of a subclass of Transport.ConnectionInfo
      to be used to connect to the transport.
    :type connectionInfo: Transport.ConnectionInfo
    """
    def __init__(self, transport, connectionInfo):
        self._transport = transport
        self._connectionInfo = connectionInfo
        # An array of PendintInterest
        self._pendingInterestTable = []
        # An array of RegisteredPrefix
        self._registeredPrefixTable = []
        self._ndndIdFetcherInterest = Interest(Name("/%C1.M.S.localhost/%C1.M.SRV/ndnd/KEY"))
        self._ndndIdFetcherInterest.setInterestLifetimeMilliseconds(4000.0)
        self._ndndId = None
        
    def expressInterest(self, interest, onData, onTimeout, wireFormat):
        """
        Send the Interest through the transport, read the entire response and 
        call onData(interest, data).
        
        :param interest: The Interest. This copies the Interest.
        :type interest: Interest
        :param onData: A function object to call when a matching data packet is 
          received.
        :type onData: function object
        :param onTimeout: A function object to call if the interest times out. 
          If onTimeout is None, this does not use it.
        :type onTimeout: function object
        :param wireFormat: A WireFormat object used to encode the message.
        :type wireFormat: a subclass of WireFormat
        """
        # TODO: Properly check if we are already connected to the expected host.
        if not self._transport.getIsConnected():
            self._transport.connect(self._connectionInfo, self)
  
        pendingInterestId = Node._PendingInterest.getNextPendingInterestId()
        self._pendingInterestTable.append(
          Node._PendingInterest(pendingInterestId, Interest(interest), onData, 
                          onTimeout))
        
        self._transport.send(interest.wireEncode(wireFormat).toBuffer())
        return pendingInterestId
    
    def removePendingInterest(self, pendingInterestId):
        """
        Remove the pending interest entry with the pendingInterestId from the 
        pending interest table. This does not affect another pending interest 
        with a different pendingInterestId, even it if has the same interest 
        name. If there is no entry with the pendingInterestId, do nothing.
        
        :param pendingInterestId: The ID returned from expressInterest.
        :type pendingInterestId: int
        """
        # Go backwards through the list so we can erase entries.
        # Remove all entries even though pendingInterestId should be unique.
        i = len(self._pendingInterestTable) - 1
        while i >= 0:
            if (self._pendingInterestTable[i].getPendingInterestId() == 
                  pendingInterestId):
                self._pendingInterestTable.pop(i)
            i -= 1
        
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
        # Go backwards through the list so we can erase entries.
        # Remove all entries even though registeredPrefixId should be unique.
        i = len(self._registeredPrefixTable) - 1
        while i >= 0:
            if (self._registeredPrefixTable[i].getRegisteredPrefixId() == 
                  registeredPrefixId):
                self._registeredPrefixTable.pop(i)
            i -= 1
        
    def processEvents(self):
        """
        Process any data to receive.  For each element received, call 
        onReceivedElement. This is non-blocking and will return immediately if 
        there is no data to receive. You should repeatedly call this from an 
        event loop, with calls to sleep as needed so that the loop doesn't use 
        100% of the CPU.
        """
        self._transport.processEvents()
        
        # Check for PIT entry timeouts. Go backwards through the list so we can
        #   erase entries.
        nowMilliseconds = Common.getNowMilliseconds()
        i = len(self._pendingInterestTable) - 1
        while i >= 0:
            if self._pendingInterestTable[i].isTimedOut(nowMilliseconds):
                # Save the PendingInterest and remove it from the PIT.  Then 
                #   call the callback.
                pendingInterest = self._pendingInterestTable[i]
                self._pendingInterestTable.pop(i)
                pendingInterest.callTimeout()
      
                # Refresh now since the timeout callback might have delayed.
                nowMilliseconds = Common.getNowMilliseconds()

            i -= 1
        
    def getTransport(self):
        """
        Get the transport object given to the constructor.
        
        :return: The transport object.
        :rtype: Transport
        """
        return self._transport
        
    def getConnectionInfo(self):
        """
        Get the connectionInfo object given to the constructor.
        
        :return: The connectionInfo object.
        :rtype: Transport.ConnectionInfo
        """
        return self._connectionInfo
        
    def onReceivedElement(self, element):
        """
        This is called by the transport's ElementReader to process an
        entire received Data or Interest element.
        
        :param element: The bytes of the incoming element.
        :type element: An array type with int elements
        """
        # First, decode as Interest or Data.
        interest = None
        data = None
        decoder = TlvDecoder(element)
        if decoder.peekType(Tlv.Interest, len(element)):
            interest = Interest()
            interest.wireDecode(element, TlvWireFormat.get())
        elif decoder.peekType(Tlv.Data, len(element)):
            data = Data()
            data.wireDecode(element, TlvWireFormat.get())

        # Now process as Interest or Data.
        if interest != None:
            entry = self._getEntryForRegisteredPrefix(interest.getName())
            if entry != None:
                entry.getOnInterest()(
                  entry.getPrefix(), interest, self._transport, 
                  entry.getRegisteredPrefixId())
        elif data != None:
            iPendingInterest = self._getEntryIndexForExpressedInterest(
              data.getName())
            if iPendingInterest >= 0:
                # Copy pointers to the needed objects and remove the PIT entry 
                #   before the calling the callback.
                onData = self._pendingInterestTable[iPendingInterest].getOnData()
                interest = self._pendingInterestTable[iPendingInterest].getInterest()
                self._pendingInterestTable.pop(iPendingInterest)
                onData(interest, data)
        
    def shutdown(self):
        """
        Call getTransport().close().
        """
        self._transport.close()
    
    def _getEntryIndexForExpressedInterest(self, name):
        """
        Find the entry from the _pendingInterestTable where the name conforms to
        the entry's interest selectors, and the entry interest name is the 
        longest that matches name.
        
        :param name: The name to find the interest for (from the incoming data 
          packet).
        :type name: Name
        :return: The index in _pendingInterestTable of the pit entry, or -1 if 
          not found.
        :rtype: int
        """
        iResult = -1
    
        for i in range(len(self._pendingInterestTable)):
            if self._pendingInterestTable[i].getInterest().matchesName(name):
                if (iResult < 0 or
                    self._pendingInterestTable[i].getInterest().getName().size() > 
                    self._pendingInterestTable[iResult].getInterest().getName().size()):
                    # Update to the longer match.
                    iResult = i
    
        return iResult
    
    def _getEntryForRegisteredPrefix(self, name):
        """
        Find the first entry from the _registeredPrefixTable where the entry 
        prefix is the longest that matches name.
        
        :param name: The name to find the RegisteredPrefix for (from the 
          incoming interest packet).
        :type name: Name
        :return: The registered prefix entry, or None of not found.
        :rtype: _RegisteredPrefix
        """
        iResult = -1
    
        for i in range(len(self._registeredPrefixTable)):
            if self._registeredPrefixTable[i].getPrefix().match(name):
                if (iResult < 0 or
                      self._registeredPrefixTable[i].getPrefix().size() > 
                      self._registeredPrefixTable[iResult].getPrefix().size()):
                    # Update to the longer match.
                    iResult = i
        
        if iResult >= 0:
            return self._registeredPrefixTable[iResult]
        else:
            return None
    
    class _PendingInterest(object):
        """
        _PendingInterest is a private class for the members of the 
        _pendingInterestTable.  Create a new PendingInterest and set the 
        _timeoutTime based on the current time and the interest lifetime.
        
        :param pendingInterestId: A unique ID for this entry, which you should 
          get with getNextPendingInteresId().
        :type pendingInterestId: int
        :param interest: The interest.
        :type interest: Interest
        :param onData: A function object to call when a matching data packet is 
          received.
        :type onData: function object
        :param onTimeout: A function object to call if the interest times out.  
          If onTimeout is None, this does not use it.
        :type onTimeout: function object
        """
        def __init__(self, pendingInterestId, interest, onData, onTimeout):
            self._pendingInterestId = pendingInterestId
            self._interest = interest
            self._onData = onData
            self._onTimeout = onTimeout
            
            # Set up _timeoutTimeMilliseconds.
            if (self._interest.getInterestLifetimeMilliseconds() != None and
                  self._interest.getInterestLifetimeMilliseconds() >= 0.0):
                self._timeoutTimeMilliseconds = (Common.getNowMilliseconds() + 
                  self._interest.getInterestLifetimeMilliseconds())
            else:
                # No timeout.
                self._timeoutTimeMilliseconds = None
            
        _lastPendingInterestId = 0
        
        @staticmethod
        def getNextPendingInterestId():
            """
            Get the next unique pending interest ID.
            
            :return: The next pending interest ID.
            :rtype: int
            """
            Node._PendingInterest._lastPendingInterestId += 1
            return Node._PendingInterest._lastPendingInterestId
            
        def getPendingInterestId(self):
            """
            Get the pendingInterestId given to the constructor.
            
            :return: The pending interest ID.
            :rtype: int
            """
            return self._pendingInterestId
            
        def getInterest(self):
            """
            Get the interest given to the constructor.
            
            :return: The interest.
            :rtype: int
            """
            return self._interest
        
        def getOnData(self):
            """
            Get the onData function object given to the constructor.
            
            :return: The onData function object.
            :rtype: function object
            """
            return self._onData
        
        def isTimedOut(self, nowMilliseconds):
            """
            Check if this interest is timed out.
            
            :param nowMilliseconds: The current time in milliseconds from 
              Common.getNowMilliseconds().
            :type nowMilliseconds: float
            :return: True if this interest timed out, otherwise False.
            :rtype: bool
            """
            return (self._timeoutTimeMilliseconds != None and 
                    nowMilliseconds >= self._timeoutTimeMilliseconds)
                    
        def callTimeout(self):
            """
            Call _onTimeout (if defined).  This ignores exceptions from 
            _onTimeout.
            """
            if self._onTimeout:
                # Ignore all exceptions.
                try:
                    self._onTimeout(self._interest)
                except:
                    pass
                
    class _RegisteredPrefix(object):
        """
        _RegisteredPrefix is a private class for the members of the
        _registeredPrefixTable. Create a new RegisteredPrefix with the
        given values.

        :param registeredPrefixId: A unique ID for this entry, which you should
          get with getNextRegisteredPrefixId().
        :type registeredPrefixId: int
        :param prefix: The name prefix.
        :type prefix: Name
        :param onInterest: A function object to call when a matching data packet
          is received.
        :type onInterest: function object
        """
        def __init__(self, registeredPrefixId, prefix, onInterest):
            self._registeredPrefixId = registeredPrefixId
            self._prefix = prefix
            self._onInterest = onInterest
            
        _lastRegisteredPrefixId = 0
        
        @staticmethod
        def getNextRegisteredPrefixId():
            """
            Get the next unique registered prefix ID.
            
            :return: The next registered prefix ID.
            :rtype: int
            """
            Node._RegisteredPrefix._lastRegisteredPrefixId += 1
            return Node._RegisteredPrefix._lastRegisteredPrefixId
            
        def getRegisteredPrefixId(self):
            """
            Get the registeredPrefixId given to the constructor.
            
            :return: The registered prefix ID.
            :rtype: int
            """
            return self._registeredPrefixId
                    
        def getPrefix(self):
            """
            Get the name prefix to the constructor.
            
            :return: The name prefix.
            :rtype: Name
            """
            return self._prefix
        
        def getOnInterest(self):
            """
            Get the onInterest function object given to the constructor.
            
            :return: The onInterest function object.
            :rtype: function object
            """
            return self._onInterest
            
        
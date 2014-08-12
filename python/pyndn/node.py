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
This module defines the Node class which provides functionality for the Face
class.
"""

import hashlib
from random import SystemRandom
from pyndn.name import Name
from pyndn.interest import Interest
from pyndn.data import Data
from pyndn.key_locator import KeyLocatorType
from pyndn.forwarding_entry import ForwardingEntry
from pyndn.control_parameters import ControlParameters
from pyndn.util.blob import Blob
from pyndn.util.common import Common
from pyndn.util.command_interest_generator import CommandInterestGenerator
from pyndn.encoding.tlv.tlv import Tlv
from pyndn.encoding.tlv.tlv_decoder import TlvDecoder
from pyndn.encoding.tlv_wire_format import TlvWireFormat

_systemRandom = SystemRandom()

class Node(object):
    """
    Create a new Node for communication with an NDN hub with the given Transport
    object and connectionInfo.
    
    :param Transport transport: An object of a subclass of Transport used for 
      communication.
    :param Transport.ConnectionInfo connectionInfo: An object of a subclass of 
      Transport.ConnectionInfo to be used to connect to the transport.
    """
    def __init__(self, transport, connectionInfo):
        self._transport = transport
        self._connectionInfo = connectionInfo
        # An array of PendintInterest
        self._pendingInterestTable = []
        # An array of RegisteredPrefix
        self._registeredPrefixTable = []
        self._ndndIdFetcherInterest = Interest(
          Name("/%C1.M.S.localhost/%C1.M.SRV/ndnd/KEY"))
        self._ndndIdFetcherInterest.setInterestLifetimeMilliseconds(4000.0)
        self._ndndId = None
        self._commandInterestGenerator = CommandInterestGenerator()
        
    def expressInterest(self, interest, onData, onTimeout, wireFormat):
        """
        Send the Interest through the transport, read the entire response and 
        call onData(interest, data).
        
        :param Interest interest: The Interest which is NOT copied for this 
          internal Node method.  The Face expressInterest is reponsible for 
          making a copy for Node to use.
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
          Node._PendingInterest(pendingInterestId, interest, onData, 
                          onTimeout))
        
        self._transport.send(interest.wireEncode(wireFormat).toBuffer())
        return pendingInterestId
    
    def removePendingInterest(self, pendingInterestId):
        """
        Remove the pending interest entry with the pendingInterestId from the 
        pending interest table. This does not affect another pending interest 
        with a different pendingInterestId, even if it has the same interest 
        name. If there is no entry with the pendingInterestId, do nothing.
        
        :param int pendingInterestId: The ID returned from expressInterest.
        """
        # Go backwards through the list so we can erase entries.
        # Remove all entries even though pendingInterestId should be unique.
        i = len(self._pendingInterestTable) - 1
        while i >= 0:
            if (self._pendingInterestTable[i].getPendingInterestId() == 
                  pendingInterestId):
                self._pendingInterestTable.pop(i)
            i -= 1
        
    def makeCommandInterest(self, interest, keyChain, certificateName, wireFormat):
        """
        Append a timestamp component and a random value component to interest's
        name. Then use the keyChain and certificateName to sign the interest. 
        If the interest lifetime is not set, this sets it.

        :param Interest interest: The interest whose name is append with 
          components.
        :param KeyChain keyChain: The KeyChain for calling sign.
        :param Name certificateName: The certificate name of the key to use for 
          signing.
        :param wireFormat: A WireFormat object used to encode the 
          SignatureInfo and to encode the interest name for signing.
        :type wireFormat: A subclass of WireFormat
        """
        self._commandInterestGenerator.generate( 
          interest, keyChain, certificateName, wireFormat)
        
    def registerPrefix(
      self, prefix, onInterest, onRegisterFailed, flags, wireFormat, 
      commandKeyChain, commandCertificateName):
        """
        Register prefix with the connected NDN hub and call onInterest when a 
        matching interest is received.
          
        :param Name prefix: The Name for the prefix to register which is NOT 
          copied for this internal Node method. The Face registerPrefix is 
          reponsible for making a copy for Node to use..
        :param onInterest: A function object to call when a matching interest is
          received.
        :type onInterest: function object
        :param onRegisterFailed: A function object to call if failed to retrieve
          the connected hub's ID or failed to register the prefix.
        :type onRegisterFailed: function object
        :param ForwardingFlags flags: The flags for finer control of which 
          interests are forwardedto the application.
        :param wireFormat: A WireFormat object used to encode the message.
        :type wireFormat: a subclass of WireFormat
        :param KeyChain commandKeyChain: The KeyChain object for signing 
          interests. If null, assume we are connected to a legacy NDNx forwarder.
        :param Name commandCertificateName: The certificate name for signing 
          interests.
        """
        # Get the registeredPrefixId now so we can return it to the caller.
        registeredPrefixId = Node._RegisteredPrefix.getNextRegisteredPrefixId()

        # If we have an _ndndId, we know we already connected to NDNx.
        if self._ndndId != None or commandKeyChain == None:
            # Assume we are connected to a legacy NDNx server.
            
            if self._ndndId == None:
                # First fetch the ndndId of the connected hub.
                fetcher = Node._NdndIdFetcher(
                  self, registeredPrefixId, prefix, onInterest, onRegisterFailed, 
                  flags, wireFormat)
                # We send the interest using the given wire format so that the hub 
                # receives (and sends) in the application's desired wire format.
                self.expressInterest(
                  self._ndndIdFetcherInterest, fetcher.onData, fetcher.onTimeout, 
                  wireFormat)
            else:
                _registerPrefixHelper(
                  registeredPrefixId, Name(prefix), onInterest, onRegisterFailed, 
                  flags, wireFormat)
        else:
            # The application set the KeyChain for signing NFD interests.
            self._nfdRegisterPrefix(
              registeredPrefixId, Name(prefix), onInterest, 
              onRegisterFailed, flags, commandKeyChain, commandCertificateName)
                
        return registeredPrefixId
    
    def removeRegisteredPrefix(self, registeredPrefixId):
        """
        Remove the registered prefix entry with the registeredPrefixId from the
        registered prefix table. This does not affect another registered prefix 
        with a different registeredPrefixId, even if it has the same prefix 
        name. If there is no entry with the registeredPrefixId, do nothing.
        
        :param int registeredPrefixId: The ID returned from registerPrefix.
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
        Process any packets to receive and call callbacks such as onData, 
        onInterest or onTimeout. This returns immediately if there is no data to 
        receive. This blocks while calling the callbacks. You should repeatedly 
        call this from an event loop, with calls to sleep as needed so that the 
        loop doesn't use 100% of the CPU. Since processEvents modifies the pending 
        interest table, your application should make sure that it calls 
        processEvents in the same thread as expressInterest (which also modifies 
        the pending interest table).
        
        :raises: This may raise an exception for reading data or in the callback
          for processing the data.  If you call this from an main event loop, 
          you may want to catch and log/disregard all exceptions.
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
        # The type codes for TLV Interest and Data packets are chosen to not
        #   conflict with the first byte of a binary XML packet, so we canjust 
        #   look at the first byte.
        if not (element[0] == Tlv.Interest or element[0] == Tlv.Data):
            # Ignore non-TLV elements.
            return

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
            pendingInterests = self._extractEntriesForExpressedInterest(
              data.getName())
            for pendingInterest in pendingInterests:
                pendingInterest.getOnData()(pendingInterest.getInterest(), data)
        
    def shutdown(self):
        """
        Call getTransport().close().
        """
        self._transport.close()
    
    def _extractEntriesForExpressedInterest(self, name):
        """
        Find all entries from the _pendingInterestTable where the name conforms 
        to the entry's interest selectors, remove the entries from the table
        and return them.
        
        :param Name name: The name to find the interest for (from the incoming 
          data packet).
        :return: The matching entries from the _pendingInterestTable, or []
          if none are found.
        :rtype: array of _PendingInterest
        """
        result = []
    
        # Go backwards through the list so we can erase entries.
        i = len(self._pendingInterestTable) - 1
        while i >= 0:
            if self._pendingInterestTable[i].getInterest().matchesName(name):
                result.append(self._pendingInterestTable[i])
                self._pendingInterestTable.pop(i)
            i -= 1
    
        return result
    
    def _getEntryForRegisteredPrefix(self, name):
        """
        Find the first entry from the _registeredPrefixTable where the entry 
        prefix is the longest that matches name.
        
        :param Name name: The name to find the RegisteredPrefix for (from the 
          incoming interest packet).
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
    
    def _registerPrefixHelper(
      self, registeredPrefixId, prefix, onInterest, onRegisterFailed, flags, 
      wireFormat):
        """
        Do the work of registerPrefix to register with NDNx once we have an 
        ndndId_.
        
        :param int registeredPrefixId: The 
          _RegisteredPrefix.getNextRegisteredPrefixId() which registerPrefix got
          so it could return it to the caller. If this is 0, then don't add to 
          _registeredPrefixTable (assuming it has already been done).
        """
        # Create a ForwardingEntry.
        # Note: ndnd ignores any freshness that is larger than 3600 seconds and 
        #   sets 300 seconds instead. To register "forever", (=2000000000 sec),
        #   the freshness period must be omitted.
        forwardingEntry = ForwardingEntry()
        forwardingEntry.setAction("selfreg")
        forwardingEntry.setPrefix(prefix)
        forwardingEntry.setForwardingFlags(flags)
        content = forwardingEntry.wireEncode(wireFormat)

        # Set the ForwardingEntry as the content of a Data packet and sign.
        data = Data()
        data.setContent(content)
        # Set the name to a random value so that each request is unique.
        nonce = bytearray(4)
        for i in range(len(nonce)):
            nonce[i] = _systemRandom.randint(0, 0xff)                
        data.getName().append(nonce)
        # The ndnd ignores the signature, so set to blank values.
        data.getSignature().getKeyLocator().setType(
          KeyLocatorType.KEY_LOCATOR_DIGEST)
        data.getSignature().getKeyLocator().setKeyData(
          Blob(bytearray(32), False))
        data.getSignature().setSignature(Blob(bytearray(128), False))
        encodedData = data.wireEncode(wireFormat)

        # Create an interest where the name has the encoded Data packet.
        interestName = Name().append("ndnx").append(self._ndndId).append(
          "selfreg").append(encodedData)

        interest = Interest(interestName)
        interest.setInterestLifetimeMilliseconds(4000.0)
        interest.setScope(1)
        encodedInterest = interest.wireEncode(wireFormat)

        if registeredPrefixId != 0:
            # Save the onInterest callback and send the registration interest.
            self._registeredPrefixTable.append(Node._RegisteredPrefix(
              registeredPrefixId, prefix, onInterest))

        response = Node._RegisterResponse(
          self, prefix, onInterest, onRegisterFailed, flags, wireFormat, False)
        self.expressInterest(
          interest, response.onData, response.onTimeout, wireFormat)
        
    def _nfdRegisterPrefix(
      self, registeredPrefixId, prefix, onInterest, onRegisterFailed, flags, 
      commandKeyChain, commandCertificateName):
        """
        Do the work of registerPrefix to register with NFD.
        
        :param int registeredPrefixId: The 
          _RegisteredPrefix.getNextRegisteredPrefixId() which registerPrefix got
          so it could return it to the caller. If this is 0, then don't add to 
          _registeredPrefixTable (assuming it has already been done).
        """
        if commandKeyChain == None:
            raise RuntimeError(
              "registerPrefix: The command KeyChain has not been set. You must call setCommandSigningInfo.")
        if commandCertificateName.size() == 0:
            raise RuntimeError(
              "registerPrefix: The command certificate name has not been set. You must call setCommandSigningInfo.")

        controlParameters = ControlParameters()
        controlParameters.setName(prefix)

        commandInterest = Interest(Name("/localhost/nfd/rib/register"))
        # NFD only accepts TlvWireFormat packets.
        commandInterest.getName().append(controlParameters.wireEncode(TlvWireFormat.get()))
        self.makeCommandInterest(
          commandInterest, commandKeyChain, commandCertificateName,
          TlvWireFormat.get())
        # The interest is answered by the local host, so set a short timeout.
        commandInterest.setInterestLifetimeMilliseconds(2000.0)

        if registeredPrefixId != 0:
            # Save the onInterest callback and send the registration interest.
            self._registeredPrefixTable.append(Node._RegisteredPrefix(
              registeredPrefixId, prefix, onInterest))

        response = Node._RegisterResponse(
          self, prefix, onInterest, onRegisterFailed, flags, 
          TlvWireFormat.get(), True)
        self.expressInterest(
          commandInterest, response.onData, response.onTimeout, 
          TlvWireFormat.get())    
        
    class _PendingInterest(object):
        """
        _PendingInterest is a private class for the members of the 
        _pendingInterestTable.  Create a new PendingInterest and set the 
        _timeoutTime based on the current time and the interest lifetime.
        
        :param int pendingInterestId: A unique ID for this entry, which you 
          should get with getNextPendingInteresId().
        :param Interest interest: The interest.
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
            
            :param float nowMilliseconds: The current time in milliseconds from 
              Common.getNowMilliseconds().
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

        :param int registeredPrefixId: A unique ID for this entry, which you
          should get with getNextRegisteredPrefixId().
        :param Name prefix: The name prefix.
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
            
    class _NdndIdFetcher(object):
        """
        An _NdndIdFetcher receives the Data packet with the publisher public key 
        digest for the connected NDN hub.
        """
        def __init__(self, node, registeredPrefixId, prefix, onInterest, 
                     onRegisterFailed, flags, wireFormat):
            self._node = node
            self._registeredPrefixId = registeredPrefixId
            self._prefix = prefix
            self._onInterest = onInterest
            self._onRegisterFailed = onRegisterFailed
            self._flags = flags
            self._wireFormat = wireFormat
            
        def onData(self, interest, ndndIdData):
            """
            We received the ndnd ID.
            """
            # Assume that the content is a DER encoded public key of the ndnd.  
            #   Do a quick check that the first byte is for DER encoding.
            if (ndndIdData.getContent().size() < 1 or 
                  ndndIdData.getContent().buf()[0] != 0x30):
                self._onRegisterFailed(self._prefix)
                return

            # Get the digest of the public key.
            digest = bytearray(
              hashlib.sha256(ndndIdData.getContent().toBuffer()).digest())

            # Set the _ndndId and continue.
            # TODO: If there are multiple connected hubs, the NDN ID is really 
            #   stored per connected hub.
            self._node._ndndId = Blob(digest, False)
            self._node._registerPrefixHelper(
              self._registeredPrefixId, self._prefix, self._onInterest, 
              self._onRegisterFailed, self._flags, self._wireFormat)

        def onTimeout(self, interest):
            """
            We timed out fetching the ndnd ID.
            """
            self._onRegisterFailed(self._prefix)
            
    class _RegisterResponse(object):
        """
        A _RegisterResponse receives the response Data packet from the register
        prefix interest sent to the connected NDN hub. If this gets a bad 
        response or a timeout, call onRegisterFailed.
        """
        def __init__(self, node, prefix, onInterest, onRegisterFailed, flags, 
                     wireFormat, isNfdCommand):
            self._node = node
            self._prefix = prefix
            self._onInterest = onInterest
            self._onRegisterFailed = onRegisterFailed
            self._flags = flags
            self._wireFormat = wireFormat
            self._isNfdCommand = isNfdCommand
            
        def onData(self, interest, responseData):
            """
            We received the response. Do a quick check of expected name 
            components.
            """
            if self._isNfdCommand:
                # Decode responseData->getContent() and check for a success code.
                # TODO: Move this into the TLV code.
                statusCode = None
                try:
                    decoder = TlvDecoder(responseData.getContent().buf())
                    decoder.readNestedTlvsStart(Tlv.NfdCommand_ControlResponse)
                    statusCode = decoder.readNonNegativeIntegerTlv(Tlv.NfdCommand_StatusCode)
                except ValueError:
                    # Error decoding the ControlResponse.
                    self._onRegisterFailed_(self._prefix)
                    return

                # Status code 200 is "OK".
                if statusCode != 200:
                  self._onRegisterFailed_(self._prefix)

                # Otherwise, silently succeed.
            else:
                expectedName = Name("/ndnx/.../selfreg")
                if (responseData.getName().size() < 4 or
                      responseData.getName()[0] != expectedName[0] or
                      responseData.getName()[2] != expectedName[2]):
                    self._onRegisterFailed(self._prefix)
                    return

                # Otherwise, silently succeed.

        def onTimeout(self, interest):
            """
            We timed out waiting for the response.
            """
            if self._isNfdCommand:
                # The application set the commandKeyChain, but we may be 
                #   connected to NDNx.
                if self._node._ndndId == None:
                    # First fetch the ndndId of the connected hub.
                    # Pass 0 for registeredPrefixId since the entry was already added to
                    #   _registeredPrefixTable on the first try.
                    fetcher = Node._NdndIdFetcher(
                      self._node, 0, self._prefix, self._onInterest,
                      self._onRegisterFailed, self._flags, self._wireFormat)
                    # We send the interest using the given wire format so that the hub 
                    # receives (and sends) in the application's desired wire format.
                    self._node.expressInterest(
                      self._node._ndndIdFetcherInterest, fetcher.onData, 
                      fetcher.onTimeout, self._wireFormat)
                else:
                    # Pass 0 for registeredPrefixId since the entry was already 
                    #   added to _registeredPrefixTable on the first try.
                    self._node._registerPrefixHelper(
                      0, self._prefix, self._onInterest, self._onRegisterFailed, 
                      self._flags, self._wireFormat)
            else:
                # An NDNx command was sent because there is no commandKeyChain, 
                #   so we can't try an NFD command. Or it was sent from this
                #   callback after trying an NFD command. Fail.
                self._onRegisterFailed(self._prefix)
            

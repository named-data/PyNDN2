# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2015 Regents of the University of California.
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
This module defines the Node class which provides functionality for the Face
class.
"""

import hashlib
import inspect
import logging
from random import SystemRandom
from pyndn.name import Name
from pyndn.interest import Interest
from pyndn.data import Data
from pyndn.key_locator import KeyLocatorType
from pyndn.forwarding_entry import ForwardingEntry
from pyndn.control_parameters import ControlParameters
from pyndn.interest_filter import InterestFilter
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
        # An array of InterestFilterEntry
        self._interestFilterTable = []
        self._ndndIdFetcherInterest = Interest(
          Name("/%C1.M.S.localhost/%C1.M.SRV/ndnd/KEY"))
        self._ndndIdFetcherInterest.setInterestLifetimeMilliseconds(4000.0)
        self._ndndId = None
        self._commandInterestGenerator = CommandInterestGenerator()
        self._timeoutPrefix = Name("/local/timeout")

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
        :throws: RuntimeError If the encoded interest size exceeds
          getMaxNdnPacketSize().
        """
        # TODO: Properly check if we are already connected to the expected host.
        if not self._transport.getIsConnected():
            self._transport.connect(self._connectionInfo, self)

        pendingInterestId = Node._PendingInterest.getNextPendingInterestId()
        self._pendingInterestTable.append(
          Node._PendingInterest(pendingInterestId, interest, onData,
                          onTimeout))

        # Special case: For _timeoutPrefix we don't actually send the interest.
        if not self._timeoutPrefix.match(interest.getName()):
            encoding = interest.wireEncode(wireFormat)
            if encoding.size() > self.getMaxNdnPacketSize():
                raise RuntimeError(
                  "The encoded interest size exceeds the maximum limit getMaxNdnPacketSize()")

            self._transport.send(encoding.toBuffer())

        return pendingInterestId

    def removePendingInterest(self, pendingInterestId):
        """
        Remove the pending interest entry with the pendingInterestId from the
        pending interest table. This does not affect another pending interest
        with a different pendingInterestId, even if it has the same interest
        name. If there is no entry with the pendingInterestId, do nothing.

        :param int pendingInterestId: The ID returned from expressInterest.
        """
        count = 0
        # Go backwards through the list so we can erase entries.
        # Remove all entries even though pendingInterestId should be unique.
        i = len(self._pendingInterestTable) - 1
        while i >= 0:
            if (self._pendingInterestTable[i].getPendingInterestId() ==
                  pendingInterestId):
                count += 1
                self._pendingInterestTable.pop(i)
            i -= 1

        if count == 0:
            logging.getLogger(__name__).debug(
              "removePendingInterest: Didn't find pendingInterestId " + pendingInterestId)

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
      commandKeyChain, commandCertificateName, face):
        """
        Register prefix with the connected NDN hub and call onInterest when a
        matching interest is received.

        :param Name prefix: The Name for the prefix to register which is NOT
          copied for this internal Node method. The Face registerPrefix is
          reponsible for making a copy for Node to use.
        :param onInterest: (optional) If not None, this creates an interest
          filter from prefix so that when an Interest is received which matches
          the filter, this calls
          onInterest(prefix, interest, face, interestFilterId, filter).
          NOTE: You must not change the prefix or filter objects - if you need to
          change them then make a copy. If onInterest is None, it is ignored and
          you must call setInterestFilter.
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
        :param Face face: The face which is passed to the onInterest callback.
          If onInterest is None, this is ignored.
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
                  flags, wireFormat, face)
                # We send the interest using the given wire format so that the hub
                # receives (and sends) in the application's desired wire format.
                self.expressInterest(
                  self._ndndIdFetcherInterest, fetcher.onData, fetcher.onTimeout,
                  wireFormat)
            else:
                self._registerPrefixHelper(
                  registeredPrefixId, Name(prefix), onInterest, onRegisterFailed,
                  flags, wireFormat, face)
        else:
            # The application set the KeyChain for signing NFD interests.
            self._nfdRegisterPrefix(
              registeredPrefixId, Name(prefix), onInterest,
              onRegisterFailed, flags, commandKeyChain, commandCertificateName,
              face)

        return registeredPrefixId

    def removeRegisteredPrefix(self, registeredPrefixId):
        """
        Remove the registered prefix entry with the registeredPrefixId from the
        registered prefix table. This does not affect another registered prefix
        with a different registeredPrefixId, even if it has the same prefix
        name. If an interest filter was automatically created by registerPrefix,
        also remove it. If there is no entry with the registeredPrefixId, do
        nothing.

        :param int registeredPrefixId: The ID returned from registerPrefix.
        """
        count = 0
        # Go backwards through the list so we can erase entries.
        # Remove all entries even though registeredPrefixId should be unique.
        i = len(self._registeredPrefixTable) - 1
        while i >= 0:
            entry = self._registeredPrefixTable[i]
            if (entry.getRegisteredPrefixId() == registeredPrefixId):
                count += 1

                if entry.getRelatedInterestFilterId() > 0:
                    # Remove the related interest filter.
                    self.unsetInterestFilter(entry.getRelatedInterestFilterId())

                self._registeredPrefixTable.pop(i)
            i -= 1

        if count == 0:
            logging.getLogger(__name__).debug(
              "removeRegisteredPrefix: Didn't find registeredPrefixId " + registeredPrefixId)

    def setInterestFilter(self, filter, onInterest, face):
        """
        Add an entry to the local interest filter table to call the onInterest
        callback for a matching incoming Interest. This method only modifies the
        library's local callback table and does not register the prefix with the
        forwarder. It will always succeed. To register a prefix with the
        forwarder, use registerPrefix.

        :param InterestFilter filter: The InterestFilter with a prefix an
          optional regex filter used to match the name of an incoming Interest.
          This makes a copy of filter.
        :param onInterest: When an Interest is received which matches the filter,
          this calls onInterest(prefix, interest, face, interestFilterId, filter).
        :type onInterest: function object
        :param Face face: The face which is passed to the onInterest callback.
        :return: The interest filter ID which can be used with unsetInterestFilter.
        :rtype: int
        """
        interestFilterId = Node._InterestFilterEntry.getNextInterestFilterId()
        self._interestFilterTable.append(Node._InterestFilterEntry
          (interestFilterId, InterestFilter(filter), onInterest, face))

        return interestFilterId

    def unsetInterestFilter(self, interestFilterId):
        """
        Remove the interest filter entry which has the interestFilterId from the
        interest filter table. This does not affect another interest filter with
        a different interestFilterId, even if it has the same prefix name. If
        there is no entry with the interestFilterId, do nothing.

        :param int interestFilterId: The ID returned from setInterestFilter.
        """
        count = 0
        # Go backwards through the list so we can erase entries.
        # Remove all entries even though registeredPrefixId should be unique.
        i = len(self._interestFilterTable) - 1
        while i >= 0:
            if (self._interestFilterTable[i].getInterestFilterId() ==
                  interestFilterId):
                count += 1
                self._interestFilterTable.pop(i)
            i -= 1

        if count == 0:
            logging.getLogger(__name__).debug(
              "unsetInterestFilter: Didn't find interestFilterId " + interestFilterId)

    def putData(self, data, wireFormat):
        """
        The OnInterest callback calls this to put a Data packet which satisfies
        an Interest.

        :param Data data: The Data packet which satisfies the interest.
        :param WireFormat wireFormat: A WireFormat object used to encode the
          Data packet.
        :throws: RuntimeError If the encoded Data packet size exceeds
          getMaxNdnPacketSize().
        """
        encoding = data.wireEncode(wireFormat)
        if encoding.size() > self.getMaxNdnPacketSize():
            raise RuntimeError(
              "The encoded Data packet size exceeds the maximum limit getMaxNdnPacketSize()")

        self._transport.send(encoding.toBuffer())

    def send(self, encoding):
        """
        Send the encoded packet out through the transport.

        :param encoding: The array of bytes for the encoded packet to send.
        :type encoding: An array type with int elements
        :throws: RuntimeError If the packet size exceeds getMaxNdnPacketSize().
        """
        if len(encoding) > self.getMaxNdnPacketSize():
            raise RuntimeError(
              "The encoded packet size exceeds the maximum limit getMaxNdnPacketSize()")

        self._transport.send(encoding)

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
            # Call all interest filter callbacks which match.
            for i in range(len(self._interestFilterTable)):
                entry = self._interestFilterTable[i]
                if entry.getFilter().doesMatch(interest.getName()):
                    includeFilter = True
                    # Use getcallargs to test if onInterest accepts 5 args.
                    try:
                        inspect.getcallargs(entry.getOnInterest(),
                          None, None, None, None, None)
                    except TypeError:
                        # Assume onInterest is old-style with 4 arguments.
                        includeFilter = False

                    if includeFilter:
                        entry.getOnInterest()(
                          entry.getFilter().getPrefix(), interest,
                          entry.getFace(), entry.getInterestFilterId(),
                          entry.getFilter())
                    else:
                        # Old-style onInterest without the filter argument. We
                        # still pass a Face instead of Transport since Face also
                        # has a send method.
                        entry.getOnInterest()(
                          entry.getFilter().getPrefix(), interest,
                          entry.getFace(), entry.getInterestFilterId())
        elif data != None:
            pendingInterests = self._extractEntriesForExpressedInterest(
              data.getName())
            for pendingInterest in pendingInterests:
                pendingInterest.getOnData()(pendingInterest.getInterest(), data)

    def isLocal(self):
        """
        Check if the face is local based on the current connection through the
        Transport; some Transport may cause network I/O (e.g. an IP host name
        lookup).

        :return: True if the face is local, False if not.
        :rtype bool:
        """
        return self._transport.isLocal(self._connectionInfo)

    def shutdown(self):
        """
        Call getTransport().close().
        """
        self._transport.close()

    @staticmethod
    def getMaxNdnPacketSize():
        """
        Get the practical limit of the size of a network-layer packet. If a packet
        is larger than this, the library or application MAY drop it.

        :return: The maximum NDN packet size.
        :rtype: int
        """
        return Common.MAX_NDN_PACKET_SIZE

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

    def _registerPrefixHelper(
      self, registeredPrefixId, prefix, onInterest, onRegisterFailed, flags,
      wireFormat, face):
        """
        Do the work of registerPrefix to register with NDNx once we have an
        _ndndId.

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

        if registeredPrefixId != 0:
            interestFilterId = 0
            if onInterest != None:
                # registerPrefix was call with the "combined" form that includes
                # the callback, so add an InterestFilterEntry.
                interestFilterId = self.setInterestFilter(
                  InterestFilter(prefix), onInterest, face)

            self._registeredPrefixTable.append(Node._RegisteredPrefix(
              registeredPrefixId, prefix, interestFilterId))

        # Send the registration interest.
        response = Node._RegisterResponse(
          self, prefix, onInterest, onRegisterFailed, flags, wireFormat, False,
          face)
        self.expressInterest(
          interest, response.onData, response.onTimeout, wireFormat)

    def _nfdRegisterPrefix(
      self, registeredPrefixId, prefix, onInterest, onRegisterFailed, flags,
      commandKeyChain, commandCertificateName, face):
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

        commandInterest = Interest()
        if self.isLocal():
            commandInterest.setName(Name("/localhost/nfd/rib/register"))
            # The interest is answered by the local host, so set a short timeout.
            commandInterest.setInterestLifetimeMilliseconds(2000.0)
        else:
            commandInterest.setName(Name("/localhop/nfd/rib/register"))
            # The host is remote, so set a longer timeout.
            commandInterest.setInterestLifetimeMilliseconds(4000.0)
        # NFD only accepts TlvWireFormat packets.
        commandInterest.getName().append(controlParameters.wireEncode(TlvWireFormat.get()))
        self.makeCommandInterest(
          commandInterest, commandKeyChain, commandCertificateName,
          TlvWireFormat.get())

        if registeredPrefixId != 0:
            interestFilterId = 0
            if onInterest != None:
                # registerPrefix was call with the "combined" form that includes
                # the callback, so add an InterestFilterEntry.
                interestFilterId = self.setInterestFilter(
                  InterestFilter(prefix), onInterest, face)

            self._registeredPrefixTable.append(Node._RegisteredPrefix(
              registeredPrefixId, prefix, interestFilterId))

        # Send the registration interest.
        response = Node._RegisterResponse(
          self, prefix, onInterest, onRegisterFailed, flags,
          TlvWireFormat.get(), True, face)
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
        A _RegisteredPrefix holds a registeredPrefixId and information necessary
        to remove the registration later. It optionally holds a related
        interestFilterId if the InterestFilter was set in the same
        registerPrefix operation.

        :param int registeredPrefixId: A unique ID for this entry, which you
          should get with getNextRegisteredPrefixId().
        :param Name prefix: The name prefix.
        :param int relatedInterestFilterId: (optional) The related
          interestFilterId for the filter set in the same registerPrefix
          operation. If omitted, set  * to 0.
        """
        def __init__(self, registeredPrefixId, prefix, relatedInterestFilterId):
            self._registeredPrefixId = registeredPrefixId
            self._prefix = prefix
            self._relatedInterestFilterId = relatedInterestFilterId

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

        def getRelatedInterestFilterId(self):
            """
            Get the related interestFilterId given to the constructor.

            :return: The related interestFilterId.
            :rtype: int
            """
            return self._relatedInterestFilterId

    class _InterestFilterEntry(object):
        """
        An _InterestFilterEntry holds an interestFilterId, an InterestFilter
        and the OnInterestCallback with its related Face.
        Create a new InterestFilterEntry with the given values.

        :param int interestFilterId: The ID from getNextInterestFilterId().
        :param InterestFilter filter: The InterestFilter for this entry.
        :param onInterest: The callback to call.
        :type onInterest: function object
        :param Face face: The face on which was called registerPrefix or
          setInterestFilter which is passed to the onInterest callback.
        """
        def __init__(self, interestFilterId, filter, onInterest, face):
            self._interestFilterId = interestFilterId
            self._filter = filter
            self._onInterest = onInterest
            self._face = face

        @staticmethod
        def getNextInterestFilterId():
            """
            Get the next interest filter ID. This just calls
            RegisteredPrefix.getNextRegisteredPrefixId() so that IDs come from
            the same pool and won't be confused when removing entries from the
            two tables.

            :return: The next ID.
            :rtype: int
            """
            return Node._RegisteredPrefix.getNextRegisteredPrefixId()

        def getInterestFilterId(self):
            """
            Get the interestFilterId given to the constructor.

            :return: The interestFilterId.
            :rtype: int
            """
            return self._interestFilterId

        def getFilter(self):
            """
            Get the InterestFilter given to the constructor.

            :return: The InterestFilter.
            :rtype: InterestFilter
            """
            return self._filter

        def getOnInterest(self):
            """
            Get the OnInterestCallback given to the constructor.

            :return: The OnInterestCallback.
            :rtype: function object
            """
            return self._onInterest

        def getFace(self):
            """
            Get the Face given to the constructor.

            :return: The Face.
            :rtype: Face
            """
            return self._face

    class _NdndIdFetcher(object):
        """
        An _NdndIdFetcher receives the Data packet with the publisher public key
        digest for the connected NDN hub.
        """
        def __init__(self, node, registeredPrefixId, prefix, onInterest,
                     onRegisterFailed, flags, wireFormat, face):
            self._node = node
            self._registeredPrefixId = registeredPrefixId
            self._prefix = prefix
            self._onInterest = onInterest
            self._onRegisterFailed = onRegisterFailed
            self._flags = flags
            self._wireFormat = wireFormat
            self._face = face

        def onData(self, interest, ndndIdData):
            """
            We received the ndnd ID.
            """
            # Assume that the content is a DER encoded public key of the ndnd.
            #   Do a quick check that the first byte is for DER encoding.
            if (ndndIdData.getContent().size() < 1 or
                  ndndIdData.getContent().buf()[0] != 0x30):
                logging.getLogger(__name__).info(
                  "Register prefix failed: The content returned when fetching the NDNx ID does not appear to be a public key")
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
              self._onRegisterFailed, self._flags, self._wireFormat, self._face)

        def onTimeout(self, interest):
            """
            We timed out fetching the ndnd ID.
            """
            logging.getLogger(__name__).info(
              "Register prefix failed: Timeout fetching the NDNx ID")
            self._onRegisterFailed(self._prefix)

    class _RegisterResponse(object):
        """
        A _RegisterResponse receives the response Data packet from the register
        prefix interest sent to the connected NDN hub. If this gets a bad
        response or a timeout, call onRegisterFailed.
        """
        def __init__(self, node, prefix, onInterest, onRegisterFailed, flags,
                     wireFormat, isNfdCommand, face):
            self._node = node
            self._prefix = prefix
            self._onInterest = onInterest
            self._onRegisterFailed = onRegisterFailed
            self._flags = flags
            self._wireFormat = wireFormat
            self._isNfdCommand = isNfdCommand
            self._face = face

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
                except ValueError as ex:
                    logging.getLogger(__name__).info(
                      "Register prefix failed: Error decoding the NFD response: %s",
                      str(ex))
                    self._onRegisterFailed(self._prefix)
                    return

                # Status code 200 is "OK".
                if statusCode != 200:
                  logging.getLogger(__name__).info(
                    "Register prefix failed: Expected NFD status code 200, got: %d",
                    statusCode)
                  self._onRegisterFailed(self._prefix)

                logging.getLogger(__name__).info(
                  "Register prefix succeeded with the NFD forwarder for prefix %s",
                  self._prefix.toUri())
            else:
                expectedName = Name("/ndnx/.../selfreg")
                if (responseData.getName().size() < 4 or
                      responseData.getName()[0] != expectedName[0] or
                      responseData.getName()[2] != expectedName[2]):
                    logging.getLogger(__name__).info(
                      "Register prefix failed: Unexpected name in NDNx response: %s",
                      responseData.getName().toUri())
                    self._onRegisterFailed(self._prefix)
                    return

                logging.getLogger(__name__).info(
                  "Register prefix succeeded with the NDNx forwarder for prefix %s",
                  self._prefix.toUri())

        def onTimeout(self, interest):
            """
            We timed out waiting for the response.
            """
            if self._isNfdCommand:
                logging.getLogger(__name__).info(
                  "Timeout for NFD register prefix command. Attempting an NDNx command...")
                # The application set the commandKeyChain, but we may be
                #   connected to NDNx.
                if self._node._ndndId == None:
                    # First fetch the ndndId of the connected hub.
                    # Pass 0 for registeredPrefixId since the entry was already added to
                    #   _registeredPrefixTable on the first try.
                    fetcher = Node._NdndIdFetcher(
                      self._node, 0, self._prefix, self._onInterest,
                      self._onRegisterFailed, self._flags, self._wireFormat,
                      self._face)
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
                logging.getLogger(__name__).info(
                  "Register prefix failed: Timeout waiting for the response from the register prefix interest")
                self._onRegisterFailed(self._prefix)


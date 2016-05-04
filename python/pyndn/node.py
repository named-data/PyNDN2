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
This module defines the Node class which provides functionality for the Face
class.
"""

import inspect
import logging
import threading
from random import SystemRandom
from pyndn.name import Name
from pyndn.interest import Interest
from pyndn.data import Data
from pyndn.control_parameters import ControlParameters
from pyndn.control_response import ControlResponse
from pyndn.interest_filter import InterestFilter
from pyndn.util.blob import Blob
from pyndn.util.common import Common
from pyndn.util.command_interest_generator import CommandInterestGenerator
from pyndn.encoding.tlv.tlv import Tlv
from pyndn.encoding.tlv.tlv_decoder import TlvDecoder
from pyndn.encoding.tlv_wire_format import TlvWireFormat
from pyndn.impl.delayed_call_table import DelayedCallTable
from pyndn.impl.interest_filter_table import InterestFilterTable
from pyndn.impl.pending_interest_table import PendingInterestTable
from pyndn.impl.registered_prefix_table import RegisteredPrefixTable
from pyndn.lp.lp_packet import LpPacket
from pyndn.network_nack import NetworkNack

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
        self._pendingInterestTable = PendingInterestTable()
        self._interestFilterTable = InterestFilterTable()
        self._registeredPrefixTable = RegisteredPrefixTable(self._interestFilterTable)
        self._delayedCallTable = DelayedCallTable()
        # An array of function objects
        self._onConnectedCallbacks = []
        self._commandInterestGenerator = CommandInterestGenerator()
        self._timeoutPrefix = Name("/local/timeout")
        self._lastEntryId = 0
        self._lastEntryIdLock = threading.Lock()
        self._connectStatus = Node._ConnectStatus.UNCONNECTED

    def expressInterest(
      self, pendingInterestId, interestCopy, onData, onTimeout, onNetworkNack,
      wireFormat, face):
        """
        Send the Interest through the transport, read the entire response and
        call onData, onTimeout or onNetworkNack as described below.

        :param int pendingInterestId: The getNextEntryId() for the pending
          interest ID which Face got so it could return it to the caller.
        :param Interest interestCopy: The Interest which is NOT copied for this
          internal Node method.  The Face expressInterest is responsible for
          making a copy for Node to use.
        :param onData: When a matching data packet is received, this calls
          onData(interest, data) where interest is the Interest given to
          expressInterest and data is the received Data object.
        :type onData: function object
        :param onTimeout: If the interest times out according to the interest
          lifetime, this calls onTimeout(interest) where interest is the
          Interest given to expressInterest. If onTimeout is None, this does not
          use it.
        :type onTimeout: function object
        :param onNetworkNack: When a network Nack packet for the interest is
          received and onNetworkNack is not None, this calls
          onNetworkNack(interest, networkNack) and does not call onTimeout.
          interest is the sent Interest and networkNack is the received
          NetworkNack. However, if a network Nack is received and onNetworkNack
          is None, do nothing and wait for the interest to time out.
        :type onNetworkNack: function object
        :param wireFormat: A WireFormat object used to encode the message.
        :type wireFormat: a subclass of WireFormat
        :param Face face: The face which has the callLater method, used for
          interest timeouts. The callLater method may be overridden in a
          subclass of Face.
        :throws: RuntimeError If the encoded interest size exceeds
          getMaxNdnPacketSize().
        """
        # Set the nonce in our copy of the Interest so it is saved in the PIT.
        interestCopy.setNonce(Node._nonceTemplate)
        interestCopy.refreshNonce()

        if self._connectStatus == self._ConnectStatus.CONNECT_COMPLETE:
            # We are connected. Simply send the interest.
            self._expressInterestHelper(
              pendingInterestId, interestCopy, onData, onTimeout, onNetworkNack,
              wireFormat, face)
            return

        # TODO: Properly check if we are already connected to the expected host.
        if not self._transport.isAsync():
            # The simple case: Just do a blocking connect and express.
            self._transport.connect(self._connectionInfo, self, None);
            self._expressInterestHelper(pendingInterestId,
              interestCopy, onData, onTimeout, onNetworkNack, wireFormat, face)
            # Make future calls to expressInterest send directly to the Transport.
            self._connectStatus = self._ConnectStatus.CONNECT_COMPLETE

            return

        # Handle the async case.
        if self._connectStatus == Node._ConnectStatus.UNCONNECTED:
            self._connectStatus = Node._ConnectStatus.CONNECT_REQUESTED

            # expressInterestHelper will be called by onConnected.
            self._onConnectedCallbacks.append(
              lambda: self._expressInterestHelper
                (pendingInterestId, interestCopy, onData, onTimeout,
                 onNetworkNack, wireFormat, face))

            def onConnected():
                # Assume that further calls to expressInterest dispatched to the
                # event loop are queued and won't enter expressInterest until
                # this method completes and sets CONNECT_COMPLETE.
                # Call each callback added while the connection was opening.
                for onConnectedCallback in self._onConnectedCallbacks:
                    onConnectedCallback()
                self._onConnectedCallbacks = []

                # Make future calls to expressInterest send directly to the
                # Transport.
                self._connectStatus = Node._ConnectStatus.CONNECT_COMPLETE

            self._transport.connect(self._connectionInfo, self, onConnected)
        elif self._connectStatus == self._ConnectStatus.CONNECT_REQUESTED:
            # Still connecting. add to the interests to express by onConnected.
            self._onConnectedCallbacks.append(
              lambda: self._expressInterestHelper
                (pendingInterestId, interestCopy, onData, onTimeout,
                 onNetworkNack, wireFormat, face))
        else:
            # Don't expect this to happen.
            raise RuntimeError(
              "Node: Unrecognized _connectStatus " + str(self._connectStatus))

    def removePendingInterest(self, pendingInterestId):
        """
        Remove the pending interest entry with the pendingInterestId from the
        pending interest table. This does not affect another pending interest
        with a different pendingInterestId, even if it has the same interest
        name. If there is no entry with the pendingInterestId, do nothing.

        :param int pendingInterestId: The ID returned from expressInterest.
        """
        self._pendingInterestTable.removePendingInterest(pendingInterestId)

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
      self, registeredPrefixId, prefixCopy, onInterest, onRegisterFailed,
      onRegisterSuccess, flags, wireFormat, commandKeyChain,
      commandCertificateName, face):
        """
        Register prefix with the connected NDN hub and call onInterest when a
        matching interest is received. To register a prefix with NFD, you must
        first call setCommandSigningInfo.

        :param int registeredPrefixId: The getNextEntryId() for the registered
          prefix ID which Face got so it could return it to the caller.
        :param Name prefixCopy: The Name for the prefix to register which is NOT
          copied for this internal Node method. The Face registerPrefix is
          responsible for making a copy for Node to use.
        :param onInterest: (optional) If not None, this creates an interest
          filter from prefixCopy so that when an Interest is received which matches
          the filter, this calls
          onInterest(prefix, interest, face, interestFilterId, filter).
          NOTE: You must not change the prefix or filter objects - if you need to
          change them then make a copy. If onInterest is None, it is ignored and
          you must call setInterestFilter.
        :type onInterest: function object
        :param onRegisterFailed: A function object to call if failed to retrieve
          the connected hub's ID or failed to register the prefix.
        :type onRegisterFailed: function object
        :param onRegisterSuccess: This calls
          onRegisterSuccess(prefix, registeredPrefixId) when this receives a
          success message from the forwarder. If onRegisterSuccess is None, this
          does not use it.
        :type onRegisterSuccess: function object
        :param ForwardingFlags flags: The flags for finer control of which
          interests are forwardedto the application.
        :param wireFormat: A WireFormat object used to encode the message.
        :type wireFormat: a subclass of WireFormat
        :param KeyChain commandKeyChain: The KeyChain object for signing
          interests.
        :param Name commandCertificateName: The certificate name for signing
          interests.
        :param Face face: The face which is passed to the onInterest callback.
          If onInterest is None, this is ignored.
        """
        self._nfdRegisterPrefix(
          registeredPrefixId, prefixCopy, onInterest,
          onRegisterFailed, onRegisterSuccess, flags, commandKeyChain,
          commandCertificateName, face)

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
        self._registeredPrefixTable.removeRegisteredPrefix(registeredPrefixId)

    def setInterestFilter(self, interestFilterId, filterCopy, onInterest, face):
        """
        Add an entry to the local interest filter table to call the onInterest
        callback for a matching incoming Interest. This method only modifies the
        library's local callback table and does not register the prefix with the
        forwarder. It will always succeed. To register a prefix with the
        forwarder, use registerPrefix.

        :param int interestFilterId: The getNextEntryId() for the interest
          filter ID which Face got so it could return it to the caller.
        :param InterestFilter filterCopy: The InterestFilter with a prefix and
          optional regex filter used to match the name of an incoming Interest,
          which is NOT copied for this internal Node method. The Face
          setInterestFilter is responsible for making a copy for Node to use.
        :param onInterest: When an Interest is received which matches the filter,
          this calls onInterest(prefix, interest, face, interestFilterId, filter).
        :type onInterest: function object
        :param Face face: The face which is passed to the onInterest callback.
        """
        self._interestFilterTable.setInterestFilter(
          interestFilterId, InterestFilter(filterCopy), onInterest, face)

    def unsetInterestFilter(self, interestFilterId):
        """
        Remove the interest filter entry which has the interestFilterId from the
        interest filter table. This does not affect another interest filter with
        a different interestFilterId, even if it has the same prefix name. If
        there is no entry with the interestFilterId, do nothing.

        :param int interestFilterId: The ID returned from setInterestFilter.
        """
        self._interestFilterTable.unsetInterestFilter(interestFilterId)

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

        # If Face.callLater is overridden to use a different mechanism, then
        # processEvents is not needed to check for delayed calls.
        self._delayedCallTable.callTimedOut();

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

        lpPacket = None
        if element[0] == Tlv.LpPacket_LpPacket:
            # Decode the LpPacket and replace element with the fragment.
            lpPacket = LpPacket()
            TlvWireFormat.get().decodeLpPacket(lpPacket, element)
            element = lpPacket.getFragmentWireEncoding().buf()

        # First, decode as Interest or Data.
        interest = None
        data = None
        decoder = TlvDecoder(element)
        if decoder.peekType(Tlv.Interest, len(element)):
            interest = Interest()
            interest.wireDecode(element, TlvWireFormat.get())

            if lpPacket != None:
                interest.setLpPacket(lpPacket)
        elif decoder.peekType(Tlv.Data, len(element)):
            data = Data()
            data.wireDecode(element, TlvWireFormat.get())

            if lpPacket != None:
                data.setLpPacket(lpPacket)

        if lpPacket != None:
            # We have decoded the fragment, so remove the wire encoding to save
            #   memory.
            lpPacket.setFragmentWireEncoding(Blob())

            networkNack = NetworkNack.getFirstHeader(lpPacket)
            if networkNack != None:
                if interest == None:
                    # We got a Nack but not for an Interest, so drop the packet.
                    return

                pendingInterests = []
                self._pendingInterestTable.extractEntriesForNackInterest(
                  interest, pendingInterests)
                for pendingInterest in pendingInterests:
                    try:
                        pendingInterest.getOnNetworkNack()(
                          pendingInterest.getInterest(), networkNack)
                    except:
                        logging.exception("Error in onNetworkNack")

                # We have process the network Nack packet.
                return

        # Now process as Interest or Data.
        if interest != None:
            # Call all interest filter callbacks which match.
            matchedFilters = []
            self._interestFilterTable.getMatchedFilters(interest, matchedFilters)
            for i in range(len(matchedFilters)):
                entry = matchedFilters[i]
                includeFilter = True
                # Use getcallargs to test if onInterest accepts 5 args.
                try:
                    inspect.getcallargs(entry.getOnInterest(),
                      None, None, None, None, None)
                except TypeError:
                    # Assume onInterest is old-style with 4 arguments.
                    includeFilter = False

                if includeFilter:
                    try:
                        entry.getOnInterest()(
                          entry.getFilter().getPrefix(), interest,
                          entry.getFace(), entry.getInterestFilterId(),
                          entry.getFilter())
                    except:
                        logging.exception("Error in onInterest")
                else:
                    # Old-style onInterest without the filter argument. We
                    # still pass a Face instead of Transport since Face also
                    # has a send method.
                    try:
                        entry.getOnInterest()(
                          entry.getFilter().getPrefix(), interest,
                          entry.getFace(), entry.getInterestFilterId())
                    except:
                        logging.exception("Error in onInterest")
        elif data != None:
            pendingInterests = []
            self._pendingInterestTable.extractEntriesForExpressedInterest(
              data.getName(), pendingInterests)
            for pendingInterest in pendingInterests:
                try:
                    pendingInterest.getOnData()(pendingInterest.getInterest(), data)
                except:
                    logging.exception("Error in onData")

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

    def _expressInterestHelper(
      self, pendingInterestId, interestCopy, onData, onTimeout, onNetworkNack,
      wireFormat, face):
        """
        Do the work of expressInterest once we know we are connected. Add the
        entry to the PIT, encode and send the interest.

        :param int pendingInterestId: The getNextEntryId() for the pending
          interest ID which Face got so it could return it to the caller.
        :param Interest interestCopy: The Interest to send, which has already
          been copied.
        :param onData: A function object to call when a matching data packet is
          received.
        :type onData: function object
        :param onTimeout: A function object to call if the interest times out.
          If onTimeout is None, this does not use it.
        :type onTimeout: function object
        :param onNetworkNack: A function object to call when a network Nack
          packet is received.
        :type onNetworkNack: function object
        :param wireFormat: A WireFormat object used to encode the message.
        :type wireFormat: a subclass of WireFormat
        :param Face face: The face which has the callLater method, used for
          interest timeouts. The callLater method may be overridden in a
          subclass of Face.
        :throws: RuntimeError If the encoded interest size exceeds
          getMaxNdnPacketSize().
        """
        pendingInterest = self._pendingInterestTable.add(
          pendingInterestId, interestCopy, onData, onTimeout, onNetworkNack)
        if pendingInterest == None:
            # removePendingInterest was already called with the pendingInterestId.
            return

        if (onTimeout or
            interestCopy.getInterestLifetimeMilliseconds() != None and
            interestCopy.getInterestLifetimeMilliseconds() >= 0.0):
            # Set up the timeout.
            delayMilliseconds = interestCopy.getInterestLifetimeMilliseconds()
            if delayMilliseconds == None or delayMilliseconds < 0.0:
                # Use a default timeout delay.
                delayMilliseconds = 4000.0

            face.callLater(delayMilliseconds,
                           lambda: self._processInterestTimeout(pendingInterest))

        # Special case: For _timeoutPrefix we don't actually send the interest.
        if not self._timeoutPrefix.match(interestCopy.getName()):
            encoding = interestCopy.wireEncode(wireFormat)
            if encoding.size() > self.getMaxNdnPacketSize():
                raise RuntimeError(
                  "The encoded interest size exceeds the maximum limit getMaxNdnPacketSize()")

            self._transport.send(encoding.toBuffer())

    def _nfdRegisterPrefix(
      self, registeredPrefixId, prefix, onInterest, onRegisterFailed,
      onRegisterSuccess, flags, commandKeyChain, commandCertificateName, face):
        """
        Do the work of registerPrefix to register with NFD.

        :param int registeredPrefixId: The getNextEntryId() which registerPrefix
          got so it could return it to the caller. If this is 0, then don't add
          to _registeredPrefixTable (assuming it has already been done).
        """
        if commandKeyChain == None:
            raise RuntimeError(
              "registerPrefix: The command KeyChain has not been set. You must call setCommandSigningInfo.")
        if commandCertificateName.size() == 0:
            raise RuntimeError(
              "registerPrefix: The command certificate name has not been set. You must call setCommandSigningInfo.")

        controlParameters = ControlParameters()
        controlParameters.setName(prefix)
        controlParameters.setForwardingFlags(flags)

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

        # Send the registration interest.
        response = Node._RegisterResponse(
          prefix, onRegisterFailed, onRegisterSuccess, registeredPrefixId, self,
          onInterest, face)
        self.expressInterest(
          self.getNextEntryId(), commandInterest, response.onData,
          response.onTimeout, None, TlvWireFormat.get(), face)

    def callLater(self, delayMilliseconds, callback):
        """
        Call callback() after the given delay. This adds to
        self._delayedCallTable which is used by processEvents().

        :param float delayMilliseconds: The delay in milliseconds.
        :param callback: This calls callback() after the delay.
        :type callback: function object
        """
        self._delayedCallTable.callLater(delayMilliseconds, callback)

    def _processInterestTimeout(self, pendingInterest):
        """
        This is used in callLater for when the pending interest expires. If
        the pendingInterest is still in the _pendingInterestTable, remove it and
        call its onTimeout callback.
        """
        if self._pendingInterestTable.removeEntry(pendingInterest):
            pendingInterest.callTimeout()

    def getNextEntryId(self):
        """
        Get the next unique entry ID for the pending interest table, interest
        filter table, etc. This uses a threading.Lock() to be thread safe. Most
        entry IDs are for the pending interest table (there usually are not many
        interest filter table entries) so we use a common pool to only have to
        do the thread safe lock in one method which is called by Face.

        :return: The next entry ID.
        :rtype: int
        """
        with self._lastEntryIdLock:
            self._lastEntryId += 1
            return self._lastEntryId

    class _ConnectStatus(object):
        UNCONNECTED = 1
        CONNECT_REQUESTED = 2
        CONNECT_COMPLETE = 3

    class _RegisterResponse(object):
        """
        A _RegisterResponse receives the response Data packet from the register
        prefix interest sent to the connected NDN hub. If this gets a bad
        response or a timeout, call onRegisterFailed.
        """
        def __init__(self, prefix, onRegisterFailed, onRegisterSuccess,
              registeredPrefixId, parent, onInterest, face):
            self._prefix = prefix
            self._onRegisterFailed = onRegisterFailed
            self._onRegisterSuccess = onRegisterSuccess
            self._registeredPrefixId = registeredPrefixId
            self._parent = parent
            self._onInterest = onInterest
            self._face = face

        def onData(self, interest, responseData):
            """
            We received the response.
            """
            # Decode responseData.getContent() and check for a success code.
            controlResponse = ControlResponse()
            try:
                controlResponse.wireDecode(responseData.getContent(), TlvWireFormat.get())
            except ValueError as ex:
                logging.getLogger(__name__).info(
                  "Register prefix failed: Error decoding the NFD response: %s",
                  str(ex))
                try:
                    self._onRegisterFailed(self._prefix)
                except:
                    logging.exception("Error in onRegisterFailed")
                return

            # Status code 200 is "OK".
            if controlResponse.getStatusCode() != 200:
                logging.getLogger(__name__).info(
                  "Register prefix failed: Expected NFD status code 200, got: %d",
                  controlResponse.getStatusCode())
                try:
                    self._onRegisterFailed(self._prefix)
                except:
                    logging.exception("Error in onRegisterFailed")
                return

            # Success, so we can add to the registered prefix table.
            if self._registeredPrefixId != 0:
                interestFilterId = 0
                if self._onInterest != None:
                    # registerPrefix was called with the "combined" form that includes
                    # the callback, so add an InterestFilterEntry.
                    interestFilterId = self._parent.getNextEntryId()
                    self._parent.setInterestFilter(
                      interestFilterId, InterestFilter(self._prefix),
                      self._onInterest, self._face)

                if not self._parent._registeredPrefixTable.add(
                      self._registeredPrefixId, self._prefix, interestFilterId):
                    # removeRegisteredPrefix was already called with the registeredPrefixId.
                    if interestFilterId > 0:
                        # Remove the related interest filter we just added.
                        self._parent.unsetInterestFilter(interestFilterId)

                    return

            logging.getLogger(__name__).info(
              "Register prefix succeeded with the NFD forwarder for prefix %s",
              self._prefix.toUri())
            if self._onRegisterSuccess != None:
                try:
                    self._onRegisterSuccess(self._prefix, self._registeredPrefixId)
                except:
                    logging.exception("Error in onRegisterSuccess")

        def onTimeout(self, interest):
            """
            We timed out waiting for the response.
            """
            logging.getLogger(__name__).info(
              "Timeout for NFD register prefix command.")
            try:
                self._onRegisterFailed(self._prefix)
            except:
                logging.exception("Error in onRegisterFailed")

    _nonceTemplate = Blob(bytearray(4), False)

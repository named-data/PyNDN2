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

import inspect
import logging
import threading
from random import SystemRandom
from pyndn.name import Name
from pyndn.interest import Interest
from pyndn.data import Data
from pyndn.control_parameters import ControlParameters
from pyndn.interest_filter import InterestFilter
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
        # An array of _PendingInterest
        self._pendingInterestTable = []
        # An array of _RegisteredPrefix
        self._registeredPrefixTable = []
        # An array of _InterestFilterEntry
        self._interestFilterTable = []
        # An array of _DelayedCall
        self._delayedCallTable = []
        # An array of function objects
        self._onConnectedCallbacks = []
        self._commandInterestGenerator = CommandInterestGenerator()
        self._timeoutPrefix = Name("/local/timeout")
        self._lastEntryId = 0
        self._lastEntryIdLock = threading.Lock()
        self._connectStatus = Node._ConnectStatus.UNCONNECTED

    def expressInterest(
      self, pendingInterestId, interestCopy, onData, onTimeout, wireFormat, face):
        """
        Send the Interest through the transport, read the entire response and
        call onData(interest, data).

        :param int pendingInterestId: The getNextEntryId() for the pending
          interest ID which Face got so it could return it to the caller.
        :param Interest interestCopy: The Interest which is NOT copied for this
          internal Node method.  The Face expressInterest is responsible for
          making a copy for Node to use.
        :param onData: A function object to call when a matching data packet is
          received.
        :type onData: function object
        :param onTimeout: A function object to call if the interest times out.
          If onTimeout is None, this does not use it.
        :type onTimeout: function object
        :param wireFormat: A WireFormat object used to encode the message.
        :type wireFormat: a subclass of WireFormat
        :param Face face: The face which has the callLater method, used for
          interest timeouts. The callLater method may be overridden in a
          subclass of Face.
        :throws: RuntimeError If the encoded interest size exceeds
          getMaxNdnPacketSize().
        """
        # TODO: Properly check if we are already connected to the expected host.
        if self._connectStatus == self._ConnectStatus.CONNECT_COMPLETE:
            # We are connected. Simply send the interest.
            self._expressInterestHelper(
              pendingInterestId, interestCopy, onData, onTimeout, wireFormat,
              face)
            return

        if self._connectStatus == Node._ConnectStatus.UNCONNECTED:
            self._connectStatus = Node._ConnectStatus.CONNECT_REQUESTED

            # expressInterestHelper will be called by onConnected.
            self._onConnectedCallbacks.append(
              lambda: self._expressInterestHelper
                (pendingInterestId, interestCopy, onData, onTimeout, wireFormat,
                 face))

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
                (pendingInterestId, interestCopy, onData, onTimeout, wireFormat,
                 face))
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
        count = 0
        # Go backwards through the list so we can erase entries.
        # Remove all entries even though pendingInterestId should be unique.
        i = len(self._pendingInterestTable) - 1
        while i >= 0:
            if (self._pendingInterestTable[i].getPendingInterestId() ==
                  pendingInterestId):
                count += 1
                # For efficiency, mark this as removed so that
                # _processInterestTimeout doesn't look for it.
                self._pendingInterestTable[i].setIsRemoved()
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
        self._interestFilterTable.append(Node._InterestFilterEntry
          (interestFilterId, filterCopy, onInterest, face))

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
        # Remove all entries even though interestFilterId should be unique.
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

        # Check for delayed calls. Since callLater does a sorted insert into
        # _delayedCallTable, the check for timeouts is quick and does not
        # require searching the entire table. If callLater is overridden to use
        # a different mechanism, then processEvents is not needed to check for
        # delayed calls.
        now = Common.getNowMilliseconds()
        # _delayedCallTable is sorted on _callTime, so we only need to process
        # the timed-out entries at the front, then quit.
        while (len(self._delayedCallTable) > 0 and
               self._delayedCallTable[0].getCallTime() <= now):
            delayedCall = self._delayedCallTable[0]
            del self._delayedCallTable[0]
            delayedCall.callCallback()

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

    def _expressInterestHelper(
      self, pendingInterestId, interestCopy, onData, onTimeout, wireFormat, face):
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
        :param wireFormat: A WireFormat object used to encode the message.
        :type wireFormat: a subclass of WireFormat
        :param Face face: The face which has the callLater method, used for
          interest timeouts. The callLater method may be overridden in a
          subclass of Face.
        :throws: RuntimeError If the encoded interest size exceeds
          getMaxNdnPacketSize().
        """
        pendingInterest = Node._PendingInterest(
          pendingInterestId, interestCopy, onData, onTimeout)
        self._pendingInterestTable.append(pendingInterest)
        if (interestCopy.getInterestLifetimeMilliseconds() != None and
            interestCopy.getInterestLifetimeMilliseconds() >= 0.0):
            # Set up the timeout.
            face.callLater(interestCopy.getInterestLifetimeMilliseconds(),
                           lambda: self._processInterestTimeout(pendingInterest))

        # Special case: For _timeoutPrefix we don't actually send the interest.
        if not self._timeoutPrefix.match(interestCopy.getName()):
            encoding = interestCopy.wireEncode(wireFormat)
            if encoding.size() > self.getMaxNdnPacketSize():
                raise RuntimeError(
                  "The encoded interest size exceeds the maximum limit getMaxNdnPacketSize()")

            self._transport.send(encoding.toBuffer())

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
            pendingInterest = self._pendingInterestTable[i]

            if pendingInterest.getInterest().matchesName(name):
                result.append(pendingInterest)
                # We let the callback from callLater call _processInterestTimeout,
                # but for efficiency, mark this as removed so that it returns
                # right away.
                self._pendingInterestTable.pop(i)
                pendingInterest.setIsRemoved()
            i -= 1

        return result

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

        if registeredPrefixId != 0:
            interestFilterId = 0
            if onInterest != None:
                # registerPrefix was called with the "combined" form that includes
                # the callback, so add an InterestFilterEntry.
                interestFilterId = self.getNextEntryId()
                self.setInterestFilter(
                  interestFilterId, InterestFilter(prefix), onInterest, face)

            self._registeredPrefixTable.append(Node._RegisteredPrefix(
              registeredPrefixId, prefix, interestFilterId))

        # Send the registration interest.
        response = Node._RegisterResponse(
          self, prefix, onInterest, onRegisterFailed, onRegisterSuccess, flags,
          TlvWireFormat.get(), face, registeredPrefixId)
        self.expressInterest(
          self.getNextEntryId(), commandInterest, response.onData,
          response.onTimeout, TlvWireFormat.get(), face)

    def callLater(self, delayMilliseconds, callback):
        """
        Call callback() after the given delay. This adds to
        self._delayedCallTable which is used by processEvents().

        :param float delayMilliseconds: The delay in milliseconds.
        :param callback: This calls callback() after the delay.
        :type callback: function object
        """
        delayedCall = Node._DelayedCall(delayMilliseconds, callback)
        # Insert into _delayedCallTable, sorted on delayedCall.getCallTime().
        # Search from the back since we expect it to go there.
        i = len(self._delayedCallTable) - 1
        while i >= 0:
            if (self._delayedCallTable[i].getCallTime() <= delayedCall.getCallTime()):
                break
            i -= 1

        # Element i is the greatest less than or equal to
        # delayedCall.getCallTime(), so insert after it.
        self._delayedCallTable.insert(i + 1, delayedCall)

    def _processInterestTimeout(self, pendingInterest):
        """
        This is used in callLater for when the pending interest expires. If
        the pendingInterest is still in the _pendingInterestTable, remove it and
        call its onTimeout callback.
        """
        if pendingInterest.getIsRemoved():
            # _extractEntriesForExpressedInterest or removePendingInterest has
            # removed pendingInterest from _pendingInterestTable, so we don't
            # need to look for it. Do nothing.
            return

        try:
            index = self._pendingInterestTable.index(pendingInterest)
        except ValueError:
            # The pending interest has been removed. Do nothing.
            return

        del self._pendingInterestTable[index]
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

    class _DelayedCall(object):
        """
        _DelayedCall is a private class for the members of the _delayedCallTable.
        Create a new _DelayedCall and set the call time based on the current
        time and the delayMilliseconds.

        :param float delayMilliseconds: The delay in milliseconds.
        :param callback: This calls callback() after the delay.
        :type callback: function object
        """
        def __init__(self, delayMilliseconds, callback):
            self._callback = callback
            self._callTime = Common.getNowMilliseconds() + delayMilliseconds

        def getCallTime(self):
            """
            Get the time at which the callback should be called.

            :return: The call time in milliseconds, similar to
              Common.getNowMilliseconds().
            :rtype: float
            """
            return self._callTime

        def callCallback(self):
            """
            Call the callback given to the constructor. This does not catch
            exceptions.
            """
            self._callback()

    class _PendingInterest(object):
        """
        _PendingInterest is a private class for the members of the
        _pendingInterestTable.

        :param int pendingInterestId: A unique ID for this entry, which you
          should get with getNextEntryId().
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
            self._isRemoved = False

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

        def setIsRemoved(self):
            """
            Set the isRemoved flag which is returned by getIsRemoved().
            """
            self._isRemoved = True

        def getIsRemoved(self):
            """
            Check if setIsRemoved() was called.

            :return: True if setIsRemoved() was called.
            :rtype: bool
            """
            return self._isRemoved

    class _RegisteredPrefix(object):
        """
        A _RegisteredPrefix holds a registeredPrefixId and information necessary
        to remove the registration later. It optionally holds a related
        interestFilterId if the InterestFilter was set in the same
        registerPrefix operation.

        :param int registeredPrefixId: A unique ID for this entry, which you
          should get with getNextEntryId().
        :param Name prefix: The name prefix.
        :param int relatedInterestFilterId: (optional) The related
          interestFilterId for the filter set in the same registerPrefix
          operation. If omitted, set to 0.
        """
        def __init__(self, registeredPrefixId, prefix, relatedInterestFilterId):
            self._registeredPrefixId = registeredPrefixId
            self._prefix = prefix
            self._relatedInterestFilterId = relatedInterestFilterId

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

        :param int interestFilterId: The ID from getNextEntryId().
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

    class _RegisterResponse(object):
        """
        A _RegisterResponse receives the response Data packet from the register
        prefix interest sent to the connected NDN hub. If this gets a bad
        response or a timeout, call onRegisterFailed.
        """
        def __init__(self, node, prefix, onInterest, onRegisterFailed,
                onRegisterSuccess, flags, wireFormat, face, registeredPrefixId):
            self._node = node
            self._prefix = prefix
            self._onInterest = onInterest
            self._onRegisterFailed = onRegisterFailed
            self._onRegisterSuccess = onRegisterSuccess
            self._flags = flags
            self._wireFormat = wireFormat
            self._face = face
            self._registeredPrefixId = registeredPrefixId

        def onData(self, interest, responseData):
            """
            We received the response. Do a quick check of expected name
            components.
            """
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
              return

            logging.getLogger(__name__).info(
              "Register prefix succeeded with the NFD forwarder for prefix %s",
              self._prefix.toUri())
            if self._onRegisterSuccess != None:
                self._onRegisterSuccess(self._prefix, self._registeredPrefixId)

        def onTimeout(self, interest):
            """
            We timed out waiting for the response.
            """
            logging.getLogger(__name__).info(
              "Timeout for NFD register prefix command.")
            self._onRegisterFailed(self._prefix)


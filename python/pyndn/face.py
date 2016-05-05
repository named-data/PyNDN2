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
This module defines the Face class which provides the main methods for NDN
communication.
"""

import os
import collections
from pyndn.name import Name
from pyndn.interest import Interest
from pyndn.forwarding_flags import ForwardingFlags
from pyndn.interest_filter import InterestFilter
from pyndn.encoding.wire_format import WireFormat
from pyndn.transport.tcp_transport import TcpTransport
from pyndn.transport.unix_transport import UnixTransport
from pyndn.util.blob import Blob
from pyndn.util.common import Common
from pyndn.node import Node

class Face(object):
    """
    Create a new Face for communication with an NDN hub.  This constructor
    has the forms Face(), Face(transport, connectionInfo) or
    Face(host, port). If the default Face() constructor is used, if the
    forwarder's Unix socket file exists then connect using UnixTransport,
    otherwise connect to "localhost" on port 6363 using TcpTransport.

    :param Transport transport: An object of a subclass of Transport used for
      communication.
    :param Transport.ConnectionInfo connectionInfo: An object of a subclass of
      Transport.ConnectionInfo to be used to connect to the transport.
    :param str host: In the Face(host, port) form of the constructor, host is
      the host of the NDN hub to connect using TcpTransport.
    :param int port: (optional) In the Face(host, port) form of the constructor,
      port is the port of the NDN hub. If omitted. use 6363.
    """
    def __init__(self, arg1 = None, arg2 = None):
        if arg1 == None or Common.typeIsString(arg1):
            filePath = ""
            if arg1 == None and arg2 == None:
                # Check if we can connect using UnixSocket.
                filePath = self._getUnixSocketFilePathForLocalhost()

            if filePath == "":
                transport = TcpTransport()
                host = arg1 if arg1 != None else "localhost"
                connectionInfo = TcpTransport.ConnectionInfo(
                  host, arg2 if type(arg2) is int else 6363)
            else:
                transport = UnixTransport()
                connectionInfo = UnixTransport.ConnectionInfo(filePath)
        else:
            transport = arg1
            connectionInfo = arg2

        self._node = Node(transport, connectionInfo)
        self._commandKeyChain = None
        self._commandCertificateName = Name()

    def expressInterest(
      self, interestOrName, arg2, arg3 = None, arg4 = None, arg5 = None,
      arg6 = None):
        """
        Send the Interest through the transport, read the entire response and
        call onData, onTimeout or onNetworkNack as described below.
        There are two forms of expressInterest.
        The first form takes the exact interest (including lifetime):
        expressInterest(interest, onData [, onTimeout] [, onNetworkNack] [, wireFormat]).
        The second form creates the interest from a name and optional
        interest template:
        expressInterest(name [, interestTemplate], onData [, onTimeout]
        [, onNetworkNack] [, wireFormat]).

        :param Interest interest: The Interest (if the first form is used). This
          copies the Interest.
        :param Name name: A name for the Interest (if the second form is used).
        :param Interest interestTemplate: (optional) if not None, copy interest
          selectors from the template (if the second form is used).  If omitted,
          use a default interest lifetime.
        :param onData: When a matching data packet is received, this calls
          onData(interest, data) where interest is the interest given to
          expressInterest and data is the received Data object. NOTE: You must
          not change the interest object - if you need to change it then make a
          copy.
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onData: function object
        :param onTimeout: (optional) If the interest times out according to the
          interest lifetime, this calls onTimeout(interest) where interest is
          the interest given to expressInterest. However, if onTimeout is None
          or omitted, this does not use it.
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onTimeout: function object
        :param onNetworkNack: (optional) When a network Nack packet for the
          interest is received and onNetworkNack is not None, this calls
          onNetworkNack(interest, networkNack) and does not call onTimeout.
          interest is the sent Interest and networkNack is the received
          NetworkNack. If onNetworkNack is supplied, then onTimeout must be
          supplied too. However, if a network Nack is received and onNetworkNack
          is null, do nothing and wait for the interest to time out. (Therefore,
          an application which does not yet process a network Nack reason treats
          a Nack the same as a timeout.)
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onNetworkNack: function object
        :param wireFormat: (optional) A WireFormat object used to encode the
           message. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        :return:  The pending interest ID which can be used with
          removePendingInterest.
        :rtype: int
        :throws: RuntimeError If the encoded interest size exceeds
          Face.getMaxNdnPacketSize().
        """
        args = self._getExpressInterestArgs(
          interestOrName, arg2, arg3, arg4, arg5, arg6)
        self._node.expressInterest(
          args['pendingInterestId'], args['interestCopy'], args['onData'],
          args['onTimeout'], args['onNetworkNack'], args['wireFormat'], self)

        return args['pendingInterestId']

    def _getExpressInterestArgs(self, interestOrName, arg2, arg3, arg4, arg5, arg6):
        """
        This is a protected helper method to resolve the different overloaded
        forms of Face.expressInterest and return the arguments to pass to
        Node.expressInterest. This is necessary to prepare arguments such as
        interestCopy before dispatching to Node.expressInterest.

        :return: A dictionary with the following keys: 'pendingInterestId',
          'interestCopy', 'onData', 'onTimeout', 'onNetworkNack' and 'wireFormat'.
        :rtype: dict
        """
        if type(interestOrName) is Interest:
            # Node.expressInterest requires a copy of the interest.
            interestCopy = Interest(interestOrName)
        else:
            # The first argument is a name. Make the interest from the name and
            #   possible template.
            if type(arg2) is Interest:
                template = arg2
                # Copy the template.
                interestCopy = Interest(template)
                interestCopy.setName(interestOrName)

                # Shift the remaining args to be processed below.
                arg2 = arg3
                arg3 = arg4
                arg4 = arg5
                arg5 = arg6
            else:
                # No template.
                interestCopy = Interest(interestOrName)
                # Set a default interest lifetime.
                interestCopy.setInterestLifetimeMilliseconds(4000.0)

        onData = arg2
        # arg3,       arg4,          arg5 may be:
        # OnTimeout,  OnNetworkNack, WireFormat
        # OnTimeout,  OnNetworkNack, None
        # OnTimeout,  WireFormat,    None
        # OnTimeout,  None,          None
        # WireFormat, None,          None
        # None,       None,          None
        if isinstance(arg3, collections.Callable):
            onTimeout = arg3
        else:
            onTimeout = None

        if isinstance(arg4, collections.Callable):
            onNetworkNack = arg4
        else:
            onNetworkNack = None

        if isinstance(arg3, WireFormat):
            wireFormat = arg3
        elif isinstance(arg4, WireFormat):
            wireFormat = arg4
        elif isinstance(arg5, WireFormat):
            wireFormat = arg5
        else:
            wireFormat = WireFormat.getDefaultWireFormat()

        return { 'pendingInterestId': self._node.getNextEntryId(),
          'interestCopy': interestCopy, 'onData': onData, 'onTimeout': onTimeout,
          'onNetworkNack': onNetworkNack, 'wireFormat': wireFormat }

    def removePendingInterest(self, pendingInterestId):
        """
        Remove the pending interest entry with the pendingInterestId from the
        pending interest table. This does not affect another pending interest
        with a different pendingInterestId, even if it has the same interest
        name. If there is no entry with the pendingInterestId, do nothing.

        :param int pendingInterestId: The ID returned from expressInterest.
        """
        self._node.removePendingInterest(pendingInterestId)

    def setCommandSigningInfo(self, keyChain, certificateName):
        """
        Set the KeyChain and certificate name used to sign command interests
        (e.g. for registerPrefix).

        :param KeyChain keyChain: The KeyChain object for signing interests,
          which must remain valid for the life of this Face. You must create the
          KeyChain object and pass it in. You can create a default KeyChain for
          your system with the default KeyChain constructor.
        :param Name certificateName: The certificate name for signing interests.
          This makes a copy of the Name. You can get the default certificate
          name with keyChain.getDefaultCertificateName() .
        """
        self._commandKeyChain = keyChain
        self._commandCertificateName = Name(certificateName)

    def setCommandCertificateName(self, certificateName):
        """
        Set the certificate name used to sign command interest (e.g. for
        registerPrefix), using the KeyChain that was set with
        setCommandSigningInfo.

        :param Name certificateName: The certificate name for signing interest.
          This makes a copy of the Name.
        """
        self._commandCertificateName = Name(certificateName)

    def makeCommandInterest(self, interest, wireFormat = None):
        """
        Append a timestamp component and a random value component to interest's
        name. Then use the keyChain and certificateName from
        setCommandSigningInfo to sign the interest. If the interest lifetime is
        not set, this sets it.
        :note: This method is an experimental feature. See the API docs for more
        detail at
        http://named-data.net/doc/ndn-ccl-api/face.html#face-makecommandinterest-method .

        :param Interest interest: The interest whose name is appended with
          components.
        :param wireFormat: (optional) A WireFormat object used to encode the
          SignatureInfo and to encode the interest name for signing. If omitted, use
          WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()
        self._node.makeCommandInterest(
          interest, self._commandKeyChain, self._commandCertificateName,
          wireFormat)

    def registerPrefix(
      self, prefix, onInterest, onRegisterFailed, onRegisterSuccess = None,
      flags = None, wireFormat = None):
        """
        Register prefix with the connected NDN hub and call onInterest when a
        matching interest is received. To register a prefix with NFD, you must
        first call setCommandSigningInfo.

        :param Name prefix: The Name for the prefix to register. This copies the
          Name.
        :param onInterest: If not None, this creates an interest filter from
          prefix so that when an Interest is received which matches the filter,
          this calls
          onInterest(prefix, interest, face, interestFilterId, filter).
          NOTE: You must not change the prefix or filter objects - if you need to
          change them then make a copy. If onInterest is None, it is ignored and
          you must call setInterestFilter.
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onInterest: function object
        :param onRegisterFailed: If register prefix fails for any reason, this
          calls onRegisterFailed(prefix).
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onRegisterFailed: function object
        :param onRegisterSuccess: (optional) This calls
          onRegisterSuccess(prefix, registeredPrefixId) when this receives a
          success message from the forwarder. If onRegisterSuccess is None or
          omitted, this does not use it. (The onRegisterSuccess parameter comes
          after onRegisterFailed because it can be None or omitted, unlike
          onRegisterFailed.)
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onRegisterSuccess: function object
        :param ForwardingFlags flags: (optional) The flags for finer control of
          which interests are forwardedto the application.
        :param wireFormat: (optional) A WireFormat object used to encode this
           ControlParameters. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        :raises: This raises an exception if setCommandSigningInfo has not been
          called to set the KeyChain, etc. for signing the command interest.
        """
        registeredPrefixId = self._node.getNextEntryId()

        # Node.registerPrefix requires a copy of the prefix.
        self._registerPrefixHelper(
          registeredPrefixId, Name(prefix), onInterest, onRegisterFailed,
          onRegisterSuccess, flags, wireFormat)

        return registeredPrefixId

    def _registerPrefixHelper(
      self, registeredPrefixId, prefixCopy, onInterest, onRegisterFailed,
      arg5 = None, arg6 = None, arg7 = None):
        """
        This is a protected helper method to do the work of registerPrefix to
        resolve the different overloaded forms. The registeredPrefixId is from
        getNextEntryId(). This has no return value and can be used in a callback.
        """
        # arg5, arg6, arg7 may be:
        # OnRegisterSuccess, ForwardingFlags, WireFormat
        # OnRegisterSuccess, ForwardingFlags, None
        # OnRegisterSuccess, WireFormat,      None
        # OnRegisterSuccess, None,            None
        # ForwardingFlags,   WireFormat,      None
        # ForwardingFlags,   None,            None
        # WireFormat,        None,            None
        # None,              None,            None
        if isinstance(arg5, collections.Callable):
            onRegisterSuccess = arg5
        else:
            onRegisterSuccess = None

        if isinstance(arg5, ForwardingFlags):
            flags = arg5
        elif isinstance(arg6, ForwardingFlags):
            flags = arg6
        else:
            flags = ForwardingFlags()

        if isinstance(arg5, WireFormat):
            wireFormat = arg5
        elif isinstance(arg6, WireFormat):
            wireFormat = arg6
        elif isinstance(arg7, WireFormat):
            wireFormat = arg7
        else:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        return self._node.registerPrefix(
          registeredPrefixId, prefixCopy, onInterest, onRegisterFailed,
          onRegisterSuccess, flags, wireFormat, self._commandKeyChain,
          self._commandCertificateName, self)

    def removeRegisteredPrefix(self, registeredPrefixId):
        """
        Remove the registered prefix entry with the registeredPrefixId from the
        registered prefix table. This does not affect another registered prefix
        with a different registeredPrefixId, even if it has the same prefix
        name. If there is no entry with the registeredPrefixId, do nothing.

        :param int registeredPrefixId: The ID returned from registerPrefix.
        """
        self._node.removeRegisteredPrefix(registeredPrefixId)

    def setInterestFilter(self, filterOrPrefix, onInterest):
        """
        Add an entry to the local interest filter table to call the onInterest
        callback for a matching incoming Interest. This method only modifies the
        library's local callback table and does not register the prefix with the
        forwarder. It will always succeed. To register a prefix with the
        forwarder, use registerPrefix. There are two forms of setInterestFilter.
        The first form uses the exact given InterestFilter:
        setInterestFilter(filter, onInterest).
        The second form creates an InterestFilter from the given prefix Name:
        setInterestFilter(prefix, onInterest).

        :param InterestFilter filter: The InterestFilter with a prefix and
          optional regex filter used to match the name of an incoming Interest.
          This makes a copy of filter.
        :param Name prefix: The Name prefix used to match the name of an
          incoming Interest. This makes a copy of the Name.
        :param onInterest: When an Interest is received which matches the filter,
          this calls onInterest(prefix, interest, face, interestFilterId, filter).
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onInterest: function object
        :return: The interest filter ID which can be used with unsetInterestFilter.
        :rtype: int
        """
        interestFilterId = self._node.getNextEntryId()

        # If filterOrPrefix is already an InterestFilter, the InterestFilter
        # constructor will make a copy as required by Node.setInterestFilter.
        filterCopy = InterestFilter(filterOrPrefix)

        self._node.setInterestFilter(
          interestFilterId, filterCopy, onInterest, self)

        return interestFilterId

    def unsetInterestFilter(self, interestFilterId):
        """
        Remove the interest filter entry which has the interestFilterId from the
        interest filter table. This does not affect another interest filter with
        a different interestFilterId, even if it has the same prefix name. If
        there is no entry with the interestFilterId, do nothing.

        :param int interestFilterId: The ID returned from setInterestFilter.
        """
        self._node.unsetInterestFilter(interestFilterId)

    def putData(self, data, wireFormat = None):
        """
        The OnInterest callback calls this to put a Data packet which satisfies
        an Interest.

        :param Data data: The Data packet which satisfies the interest.
        :param WireFormat wireFormat: (optional) A WireFormat object used to
          encode the Data packet. If omitted, use
          WireFormat.getDefaultWireFormat().
        :throws: RuntimeError If the encoded Data packet size exceeds
          getMaxNdnPacketSize().
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        # We get the encoding now before calling send because it may dispatch to
        # asyncio to be called later, and the caller may modify data before then.
        encoding = data.wireEncode(wireFormat)
        if encoding.size() > self.getMaxNdnPacketSize():
            raise RuntimeError(
              "The encoded Data packet size exceeds the maximum limit getMaxNdnPacketSize()")

        self.send(encoding)

    def send(self, encoding):
        """
        Send the encoded packet out through the face.

        :param encoding: The blob or array with the the encoded packet to send.
        :type encoding: Blob or an array type with int elements
        :throws: RuntimeError If the packet size exceeds getMaxNdnPacketSize().
        """
        # If encoding is a Blob, get its buf().
        encodingBuffer = encoding.buf() if isinstance(encoding, Blob) else encoding

        self._node.send(encodingBuffer)

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
        # Just call Node's processEvents.
        self._node.processEvents()

    def isLocal(self):
        """
        Check if the face is local based on the current connection through the
        Transport; some Transport may cause network I/O (e.g. an IP host name
        lookup).

        :return: True if the face is local, false if not.
        :rtype bool:
        """
        return self._node.isLocal()

    def shutdown(self):
        """
        Shut down and disconnect this Face.
        """
        self._node.shutdown()

    @staticmethod
    def getMaxNdnPacketSize():
        """
        Get the practical limit of the size of a network-layer packet. If a packet
        is larger than this, the library or application MAY drop it.

        :return: The maximum NDN packet size.
        :rtype: int
        """
        return Common.MAX_NDN_PACKET_SIZE

    def callLater(self, delayMilliseconds, callback):
        """
        Call callback() after the given delay. Even though this is public, it is
        not part of the public API of Face.This default implementation just
        calls Node.callLater, but a subclass can override.

        :param float delayMilliseconds: The delay in milliseconds.
        :param callback: This calls callback() after the delay.
        :type callback: function object
        """
        self._node.callLater(delayMilliseconds, callback)

    @staticmethod
    def _getUnixSocketFilePathForLocalhost():
        """
        If the forwarder's Unix socket file path exists, then return the file
        path. Otherwise return an empty string.

        :return: The Unix socket file path to use, or an empty string.
        :rtype: str
        """
        filePath = "/var/run/nfd.sock"
        # Use listdir because isfile doesn't see socket file types.
        if  (os.path.basename(filePath) in
             os.listdir(os.path.dirname(filePath))):
            return filePath
        else:
            filePath = "/tmp/.ndnd.sock"
            if  (os.path.basename(filePath) in
                 os.listdir(os.path.dirname(filePath))):
                return filePath
            else:
                return ""

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
This module defines the Face class which provides the main methods for NDN 
communication.
"""

import os
from pyndn.name import Name
from pyndn.interest import Interest
from pyndn.forwarding_flags import ForwardingFlags
from pyndn.encoding.wire_format import WireFormat
from pyndn.transport.tcp_transport import TcpTransport
from pyndn.transport.unix_transport import UnixTransport
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
                tryFilePath = "/var/run/nfd.sock"
                # Use listdir because isfile doesn't see socket file types.
                if  (os.path.basename(tryFilePath) in 
                     os.listdir(os.path.dirname(tryFilePath))):
                    filePath = tryFilePath
                else:
                    tryFilePath = "/tmp/.ndnd.sock"
                    if  (os.path.basename(tryFilePath) in 
                         os.listdir(os.path.dirname(tryFilePath))):
                        filePath = tryFilePath
            
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
      self, interestOrName, arg2, arg3 = None, arg4 = None, arg5 = None):
        """
        Send the Interest through the transport, read the entire response and 
        call onData(interest, data).  There are two forms of expressInterest.  
        The first form takes the exact interest (including lifetime):
        expressInterest(interest, onData [, onTimeout] [, wireFormat]).  
        The second form creates the interest from a name and optional 
        interest template:
        expressInterest(name [, interestTemplate], onData [, onTimeout] 
        [, wireFormat]).
        
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
        :type onData: function object
        :param onTimeout: (optional) If the interest times out according to the 
          interest lifetime, this calls onTimeout(interest) where interest is 
          the interest given to expressInterest. However, if onTimeout is None 
          or omitted, this does not use it.
        :type onTimeout: function object
        :param wireFormat: (optional) A WireFormat object used to encode the 
           message. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        :return:  The pending interest ID which can be used with 
          removePendingInterest.
        :rtype: int
        """
        # expressInterest(interest, onData)
        # expressInterest(interest, onData, wireFormat)
        # expressInterest(interest, onData, onTimeout)
        # expressInterest(interest, onData, onTimeout, wireFormat)
        if type(interestOrName) is Interest:
            # Node.expressInterest requires a copy of the interest.
            interest = Interest(interestOrName)
            onData = arg2
            if isinstance(arg3, WireFormat):
                onTimeout = None
                wireFormat = arg3
            else:
                onTimeout = arg3
                wireFormat = arg4
        else:
            # The first argument is a name. Make the interest from the name and 
            #   possible template.
            interest = Interest(interestOrName)
            
            # expressInterest(name, interestTemplate, onData) 
            # expressInterest(name, interestTemplate, onData, wireFormat) 
            # expressInterest(name, interestTemplate, onData, onTimeout) 
            # expressInterest(name, interestTemplate, onData, onTimeout, wireFormat) 
            if type(arg2) is Interest:
                template = arg2
                interest.setMinSuffixComponents(template.getMinSuffixComponents())
                interest.setMaxSuffixComponents(template.getMaxSuffixComponents())
                interest.setKeyLocator(template.getKeyLocator())
                interest.setExclude(template.getExclude())
                interest.setChildSelector(template.getChildSelector())
                interest.setMustBeFresh(template.getMustBeFresh())
                interest.setScope(template.getScope())
                interest.setInterestLifetimeMilliseconds(
                  template.getInterestLifetimeMilliseconds())
                # Don't copy the nonce.

                onData = arg3
                if isinstance(arg4, WireFormat):
                    onTimeout = None
                    wireFormat = arg4
                else:
                    onTimeout = arg4
                    wireFormat = arg5
            # expressInterest(name, onData) 
            # expressInterest(name, onData, wireFormat)
            # expressInterest(name, onData, onTimeout)
            # expressInterest(name, onData, onTimeout, wireFormat)
            else:
                # Set a default interest lifetime.
                interest.setInterestLifetimeMilliseconds(4000.0)
                onData = arg2
                if isinstance(arg3, WireFormat):
                    onTimeout = None
                    wireFormat = arg3
                else:
                    onTimeout = arg3
                    wireFormat = arg4
            
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        return self._node.expressInterest(
          interest, onData, onTimeout, wireFormat)

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
      self, prefix, onInterest, onRegisterFailed, flags = None, 
      wireFormat = None):
        """
        Register prefix with the connected NDN hub and call onInterest when a 
        matching interest is received. If you have not called 
        setCommandSigningInfo, this assumes you are connecting to NDNx. If you 
        have called setCommandSigningInfo, this first sends an NFD registration 
        request, and if that times out then this sends an NDNx registration 
        request. If need to register a prefix with NFD, you must first call 
        setCommandSigningInfo.
        
        :param Name prefix: The Name for the prefix to register which is NOT 
          copied for this internal Node method. The Face registerPrefix is 
          reponsible for making a copy for Node to use..
        :param onInterest: When an interest is received which matches the name 
          prefix, this calls 
          onInterest(prefix, interest, transport, registeredPrefixId). NOTE: 
          You must not change the prefix object - if you need to change it then 
          make a copy.
        :type onInterest: function object
        :param onRegisterFailed: If register prefix fails for any reason, this 
          calls onRegisterFailed(prefix).
        :type onRegisterFailed: function object
        :param ForwardingFlags flags: The flags for finer control of which 
          interests are forwardedto the application.
        :param wireFormat: (optional) A WireFormat object used to encode this 
           ControlParameters. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        :raises: This raises an exception if setCommandSigningInfo has not been 
          called to set the KeyChain, etc. for signing the command interest.
        """
        if flags == None:
            flags = ForwardingFlags()
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        # Node.expressInterest requires a copy of the prefix.
        self._node.registerPrefix(
          prefix, onInterest, onRegisterFailed, flags, wireFormat, 
          self._commandKeyChain, self._commandCertificateName)
        
    def removeRegisteredPrefix(self, registeredPrefixId):
        """
        Remove the registered prefix entry with the registeredPrefixId from the
        registered prefix table. This does not affect another registered prefix 
        with a different registeredPrefixId, even if it has the same prefix 
        name. If there is no entry with the registeredPrefixId, do nothing.
        
        :param int registeredPrefixId: The ID returned from registerPrefix.
        """
        self._node.removeRegisteredPrefix(registeredPrefixId)
        
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
        
    def shutdown(self):
        """
        Shut down and disconnect this Face.
        """
        self._node.shutdown()
        

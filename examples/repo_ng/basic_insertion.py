# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2018 Regents of the University of California.
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
This module shows an example of the repo-ng basic insertion protocol,
described here:
http://redmine.named-data.net/projects/repo-ng/wiki/Basic_Repo_Insertion_Protocol
See main() for more details.
"""

import time
from pyndn import Name
from pyndn import Data
from pyndn import Interest
from pyndn import Face
from pyndn.security import KeyChain
from pyndn.encoding import ProtobufTlv

# These imports are produced by:
# protoc --python_out=. repo-command-parameter.proto
# protoc --python_out=. repo-command-response.proto
import repo_command_parameter_pb2
import repo_command_response_pb2

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str else str(element)) + " "
    print(result)

def requestInsert(face, repoCommandPrefix, fetchName, onInsertStarted, onFailed,
      startBlockId = None, endBlockId = None):
    """
    Send a command interest for the repo to fetch the given fetchName and insert
    it in the repo.
    Since this calls expressInterest, your application must call face.processEvents.

    :param Face face: The Face used to call makeCommandInterest and expressInterest.
    :param Name repoCommandPrefix: The repo command prefix.
    :param Name fetchName: The name to fetch. If startBlockId and endBlockId are
      supplied, then the repo will request multiple segments by appending the
      range of block IDs (segment numbers).
    :param onInsertStarted: When the request insert command successfully returns,
      this calls onInsertStarted().
    :type onInsertStarted: function object
    :param onFailed: If the command fails for any reason, this prints an error
      and calls onFailed().
    :type onFailed: function object
    :param int startBlockId: (optional) The starting block ID (segment number)
      to fetch.
    :param int endBlockId: (optional) The end block ID (segment number)
      to fetch.
    """
    # repo_command_parameter_pb2 was produced by protoc.
    parameter = repo_command_parameter_pb2.RepoCommandParameterMessage()
    # Add the Name.
    for i in range(fetchName.size()):
        parameter.repo_command_parameter.name.component.append(
          fetchName[i].getValue().toBytes())
    # Add startBlockId and endBlockId if supplied.
    if startBlockId != None:
        parameter.repo_command_parameter.start_block_id = startBlockId
    if endBlockId != None:
        parameter.repo_command_parameter.end_block_id = endBlockId

    # Create the command interest.
    interest = Interest(Name(repoCommandPrefix).append("insert")
      .append(Name.Component(ProtobufTlv.encode(parameter))))
    face.makeCommandInterest(interest)

    # Send the command interest and get the response or timeout.
    def onData(interest, data):
        # repo_command_response_pb2 was produced by protoc.
        response = repo_command_response_pb2.RepoCommandResponseMessage()
        try:
            ProtobufTlv.decode(response, data.content)
        except:
            dump("Cannot decode the repo command response")
            onFailed()

        if response.repo_command_response.status_code == 100:
            onInsertStarted()
        else:
            dump("Got repo command error code", response.repo_command_response.status_code)
            onFailed()
    def onTimeout(interest):
        dump("Insert repo command timeout")
        onFailed()
    face.expressInterest(interest, onData, onTimeout)

class ProduceSegments(object):
    """
    This is an example class to supply the data requested by the repo-ng
    insertion process.  For you application, you would supply data in a
    different way.  This sends data packets until it has sent
    (endBlockId - startBlockId) + 1 packets.  It might be simpler to finish
    when onInterest has sent the packet for segment endBlockId, but there is no
    guarantee that the interests will arrive in order.  Therefore we send packets
    until the total is sent.

    :param KeyChain keyChain: This calls keyChain.sign.
    :param Name certificateName: The certificateName for keyChain.sign.
    :param int startBlockId: The startBlockId given to requestInsert().
    :param int endBlockId: The endBlockId given to requestInsert().
    :param onFinished: When the final segment has been sent, this calls
      onFinished().
    :type onFinished: function object
    """
    def __init__(self, keyChain, certificateName, startBlockId, endBlockId,
                 onFinished):
        self._keyChain = keyChain
        self._certificateName = certificateName
        self._startBlockId = startBlockId
        self._endBlockId = endBlockId
        self._nSegmentsSent = 0
        self._onFinished = onFinished

    def onInterest(self, prefix, interest, face, interestFilterId, filter):
        """
        Create and send a Data packet with the interest name.
        If the last packet is sent, then set self._enabled[0] = False.
        """
        dump("Got interest", interest.toUri())

        # Make and sign a Data packet with the interest name.
        data = Data(interest.name)
        content = "Data packet " + interest.name.toUri()
        data.content = content
        self._keyChain.sign(data, self._certificateName)

        face.putData(data)
        dump("Sent data packet", data.name.toUri())

        self._nSegmentsSent += 1
        if self._nSegmentsSent >= (self._endBlockId - self._startBlockId) + 1:
            # We sent the final segment.
            self._onFinished()

def main():
    """
    Call requestInsert and register a prefix so that ProduceSegments will answer
    interests from the repo to send the data packets. This assumes that repo-ng
    is already running (e.g. `sudo ndn-repo-ng`).
    """
    repoCommandPrefix = Name("/example/repo/1")
    repoDataPrefix = Name("/example/data/1")

    nowMilliseconds = int(time.time() * 1000.0)
    fetchPrefix = Name(repoDataPrefix).append("testinsert").appendVersion(nowMilliseconds)

    # The default Face will connect using a Unix socket, or to "localhost".
    face = Face()
    # Use the system default key chain and certificate name to sign commands.
    keyChain = KeyChain()
    face.setCommandSigningInfo(keyChain, keyChain.getDefaultCertificateName())

    # Register the prefix and send the repo insert command at the same time.
    startBlockId = 0
    endBlockId = 1
    enabled = [True]
    def onFinished():
        dump("All data was inserted.")
        enabled[0] = False
    produceSegments = ProduceSegments(
      keyChain, keyChain.getDefaultCertificateName(), startBlockId, endBlockId,
      onFinished)
    dump("Register prefix", fetchPrefix.toUri())
    def onRegisterFailed(prefix):
        dump("Register failed for prefix", prefix.toUri())
        enabled[0] = False
    face.registerPrefix(
      fetchPrefix, produceSegments.onInterest, onRegisterFailed)

    def onInsertStarted():
        dump("Insert started for", fetchPrefix.toUri())
    def onFailed():
        enabled[0] = False
    requestInsert(
      face, repoCommandPrefix, fetchPrefix, onInsertStarted, onFailed,
      startBlockId, endBlockId)

    # Run until all the data is sent.
    while enabled[0]:
        face.processEvents()
        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.01)

    face.shutdown()

main()

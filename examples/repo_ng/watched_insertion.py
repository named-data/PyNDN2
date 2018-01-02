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
This module shows an example of the repo-ng watched prefix insertion protocol,
described here:
http://redmine.named-data.net/projects/repo-ng/wiki/Watched_Prefix_Insertion_Protocol
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

def startRepoWatch(face, repoCommandPrefix, watchPrefix, onRepoWatchStarted, onFailed):
    """
    Send a command interest for the repo to start watching the given watchPrefix.
    Since this calls expressInterest, your application must call face.processEvents.

    :param Face face: The Face used to call makeCommandInterest and expressInterest.
    :param Name repoCommandPrefix: The repo command prefix.
    :param Name watchPrefix: The prefix that the repo will watch.
    :param onRepoWatchStarted: When the start watch command successfully returns,
      this calls onRepoWatchStarted().
    :type onRepoWatchStarted: function object
    :param onFailed: If the command fails for any reason, this prints an error
      and calls onFailed().
    :type onFailed: function object
    """
    # repo_command_parameter_pb2 was produced by protoc.
    parameter = repo_command_parameter_pb2.RepoCommandParameterMessage()
    for i in range(watchPrefix.size()):
        parameter.repo_command_parameter.name.component.append(
          watchPrefix[i].getValue().toBytes())

    # Create the command interest.
    interest = Interest(Name(repoCommandPrefix).append("watch").append("start")
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
            onRepoWatchStarted()
        else:
            dump("Got repo command error code", response.repo_command_response.status_code)
            onFailed()
    def onTimeout(interest):
        dump("Start repo watch command timeout")
        onFailed()
    face.expressInterest(interest, onData, onTimeout)

def stopRepoWatch(face, repoCommandPrefix, watchPrefix, onRepoWatchStopped, onFailed):
    """
    Send a command interest for the repo to stop watching the given watchPrefix.
    Since this calls expressInterest, your application must call face.processEvents.

    :param Face face: The Face used to call makeCommandInterest and expressInterest.
    :param Name repoCommandPrefix: The repo command prefix.
    :param Name watchPrefix: The prefix that the repo will stop watching.
    :param onRepoWatchStopped: When the stop watch command successfully returns,
      this calls onRepoWatchStopped().
    :type onRepoWatchStopped: function object
    :param onFailed: If the command fails for any reason, this prints an error
      and calls onFailed().
    :type onFailed: function object
    """
    # repo_command_parameter_pb2 was produced by protoc.
    parameter = repo_command_parameter_pb2.RepoCommandParameterMessage()
    for i in range(watchPrefix.size()):
        parameter.repo_command_parameter.name.component.append(
          watchPrefix[i].getValue().toBytes())

    # Create the command interest.
    interest = Interest(Name(repoCommandPrefix).append("watch").append("stop")
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

        if response.repo_command_response.status_code == 101:
            onRepoWatchStopped()
        else:
            dump("Got repo command error code", response.repo_command_response.status_code)
            onFailed()
    def onTimeout(interest):
        dump("Stop repo watch command timeout")
        onFailed()
    face.expressInterest(interest, onData, onTimeout)

class SendSegments(object):
    """
    This is an example class to supply the data requested by the repo-ng
    watched prefix process. For you application, you would supply data in a
    different way. Repo-ng sends interests for the watchPrefix given to
    startRepoWatch(). (The interest also has Exclude selectors but for
    simplicity we ignore them and assume that the exclude values increase along
    with the segment numbers that we send.) This sends data packets where the
    name has the prefix plus increasing segment numbers up to a maximum.

    :param KeyChain keyChain: This calls keyChain.sign.
    :param Name certificateName: The certificateName for keyChain.sign.
    :param onFinished: When the final segment has been sent, this calls
      onFinished().
    :type onFinished: function object
    """
    def __init__(self, keyChain, certificateName, onFinished):
        self._keyChain = keyChain
        self._certificateName = certificateName
        self._onFinished = onFinished
        self._segment = -1

    def onInterest(self, prefix, interest, face, interestFilterId, filter):
        """
        Append the next segment number to the prefix and send a new data packet.
        If the last packet is sent, then call self._onFinished().
        """
        maxSegment = 2
        if self._segment >= maxSegment:
            # We have already called self._onFinished().
            return

        dump("Got interest", interest.toUri())

        # Make and sign a Data packet for the segment.
        self._segment += 1
        data = Data(Name(prefix).appendSegment(self._segment))
        content = "Segment number " + repr(self._segment)
        data.content = content
        self._keyChain.sign(data, self._certificateName)

        face.putData(data)
        dump("Sent data packet", data.name.toUri())

        if self._segment >= maxSegment:
            # We sent the final data packet.
            self._onFinished()

def main():
    """
    Call startRepoWatch and register a prefix so that SendSegments will answer
    interests from the repo to send data packets for the watched prefix.  When
    all the data is sent (or an error), call stopRepoWatch. This assumes that
    repo-ng is already running (e.g. `sudo ndn-repo-ng`).
    """
    repoCommandPrefix = Name("/example/repo/1")
    repoDataPrefix = Name("/example/data/1")

    nowMilliseconds = int(time.time() * 1000.0)
    watchPrefix = Name(repoDataPrefix).append("testwatch").appendVersion(
      nowMilliseconds)

    # The default Face will connect using a Unix socket, or to "localhost".
    face = Face()
    # Use the system default key chain and certificate name to sign commands.
    keyChain = KeyChain()
    face.setCommandSigningInfo(keyChain, keyChain.getDefaultCertificateName())

    # Register the prefix and start the repo watch at the same time.
    enabled = [True]
    def onFinishedSending():
        stopRepoWatchAndQuit(face, repoCommandPrefix, watchPrefix, enabled)
    sendSegments = SendSegments(
      keyChain, keyChain.getDefaultCertificateName(), onFinishedSending)
    def onRegisterFailed(prefix):
        dump("Register failed for prefix", prefix.toUri())
        enabled[0] = False
    dump("Register prefix", watchPrefix.toUri())
    face.registerPrefix(watchPrefix, sendSegments.onInterest, onRegisterFailed)

    def onRepoWatchStarted():
        dump("Watch started for", watchPrefix.toUri())
    def onStartFailed():
        dump("startRepoWatch failed.")
        stopRepoWatchAndQuit(face, repoCommandPrefix, watchPrefix, enabled)
    startRepoWatch(
      face, repoCommandPrefix, watchPrefix, onRepoWatchStarted, onStartFailed)

    # Run until someone sets enabled[0] = False.
    enabled[0] = True
    while enabled[0]:
        face.processEvents()
        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.01)

    face.shutdown()

def stopRepoWatchAndQuit(face, repoCommandPrefix, watchPrefix, enabled):
    """
    Call stopRepoWatch and set enabled[0] = False.
    """
    def onRepoWatchStopped():
        dump("Watch stopped for", watchPrefix.toUri())
        enabled[0] = False
    def onStopFailed():
        dump("stopRepoWatch failed.")
        enabled[0] = False
    stopRepoWatch(
      face, repoCommandPrefix, watchPrefix, onRepoWatchStopped, onStopFailed)

main()

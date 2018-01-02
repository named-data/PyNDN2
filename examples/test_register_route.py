# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2018 Regents of the University of California.
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
This sends a /localhost/nfd/faces/query command to the local NFD to get the
face ID for a face url, and creates the face if it doesn't exist. Then this sends
a /localhost/nfd/rib/register command to register a prefix to the face ID.
This is equivalent to the NFD command line command "nfdc register".
See http://redmine.named-data.net/projects/nfd/wiki/Management .
"""

import time
from pyndn import Face
from pyndn import Name
from pyndn import Interest
from pyndn.util import Blob
from pyndn.security import KeyChain
from pyndn.encoding import ProtobufTlv
from pyndn.util.segment_fetcher import SegmentFetcher
# This module is produced by: protoc --python_out=. control-parameters.proto
import control_parameters_pb2
# This module is produced by: protoc --python_out=. face-query-filter.proto
import face_query_filter_pb2
# This module is produced by: protoc --python_out=. face-status.proto
import face_status_pb2

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str else str(element)) + " "
    print(result)

def main():
    prefix = Name("/nfd/edu/ucla/remap/test")
    # Route to aleph.ndn.ucla.edu.  Have to use the canonical name with an IP
    # address and port.
    uri = "udp4://128.97.98.7:6363"

    # The default Face connects to the local NFD.
    face = Face()

    # Use the system default key chain and certificate name to sign commands.
    keyChain = KeyChain()
    face.setCommandSigningInfo(keyChain, keyChain.getDefaultCertificateName())

    # Create the /localhost/nfd/faces/query command interest, including the
    # FaceQueryFilter. Construct the FaceQueryFilter using the structure in
    # face_query_filter_pb2 which was produced by protoc.
    message = face_query_filter_pb2.FaceQueryFilterMessage()
    filter = message.face_query_filter.add()
    filter.uri = uri
    encodedFilter = ProtobufTlv.encode(message)

    interest = Interest(Name("/localhost/nfd/faces/query"))
    interest.getName().append(encodedFilter)

    enabled = [True]

    def onComplete(content):
        processFaceStatus(content, prefix, uri, face, enabled)

    def onError(errorCode, message):
        enabled[0] = False
        dump(message)

    SegmentFetcher.fetch(face, interest, None, onComplete, onError)

    # Loop calling processEvents until a callback sets enabled[0] = False.
    while enabled[0]:
        face.processEvents()

        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.01)

def processFaceStatus(encodedFaceStatus, prefix, uri, face, enabled):
    """
    This is called when all the segments are received to decode the
    encodedFaceStatus as a TLV FaceStatus message. If the face ID exists for the
    face URL, use it to call registerRoute(), otherwise send a
    /localhost/nfd/faces/create command to create the face.

    :param Blob encodedFaceStatus: The TLV-encoded FaceStatus.
    :param Name prefix: The prefix name to register.
    :param str uri: The remote URI in case we need to tell NFD to create a face.
    :param Face face: The Face which is used to sign the command interest and
      call expressInterest.
    :param enabled: On success or error, set enabled[0] = False.
    :type enabled: An array with one bool element
    """
    if encodedFaceStatus.size() == 0:
        # No result, so we need to tell NFD to create the face.
        # Encode the ControlParameters.
        message = \
          control_parameters_pb2.ControlParametersTypes.ControlParametersMessage()
        message.control_parameters.uri = uri
        encodedControlParameters = ProtobufTlv.encode(message)

        interest = Interest(Name("/localhost/nfd/faces/create"))
        interest.getName().append(encodedControlParameters)
        interest.setInterestLifetimeMilliseconds(10000)

        def onData(localInterest, data):
            processCreateFaceResponse(data.getContent(), prefix, face, enabled)

        def onTimeout(localInterest):
            enabled[0] = False
            dump("Face create command timed out.")

        # Sign and express the interest.
        face.makeCommandInterest(interest)
        face.expressInterest(interest, onData, onTimeout)
    else:
        decodedFaceStatus = face_status_pb2.FaceStatusMessage()
        ProtobufTlv.decode(decodedFaceStatus, encodedFaceStatus)

        faceId = decodedFaceStatus.face_status[0].face_id

        dump("Found face ID ", faceId)
        registerRoute(prefix, faceId, face, enabled)

def processCreateFaceResponse(encodedControlResponse, prefix, face, enabled):
    """
    This is called when the face create command responds to decode the
    encodedControlResonse as a TLV ControlResponse message containing one
    ControlParameters. Get the face ID and call registerRoute().

    :param Blob encodedControlResponse: The TLV-encoded ControlResponse.
    """
    decodedControlResponse = \
      control_parameters_pb2.ControlParametersTypes.ControlParametersResponseMessage()
    ProtobufTlv.decode(decodedControlResponse, encodedControlResponse)
    controlResponse = decodedControlResponse.control_response

    lowestErrorCode = 400
    if controlResponse.status_code >= lowestErrorCode:
        dump(
          "Face create command got error, code " + str(controlResponse.status_code) +
           ": " + controlResponse.status_text)
        enabled[0] = False
        return
    if len(controlResponse.control_parameters) != 1:
        dump(
          "Face create command response does not have one ControlParameters")
        enabled[0] = False
        return

    faceId = controlResponse.control_parameters[0].face_id

    dump("Created face ID " + str(faceId))
    registerRoute(prefix, faceId, face, enabled)

def registerRoute(prefix, faceId, face, enabled):
    """
    Use /localhost/nfd/rib/register to register the prefix to the faceId.

    :param Name prefix: The prefix name to register.
    :param int faceId: The face ID.
    :param Face face: The Face which is used to sign the command interest and
      call expressInterest.
    :param enabled: On success or error, set enabled[0] = False.
    :type enabled: An array with one bool element
    """
    # Use default values
    origin = 255
    cost = 0
    CHILD_INHERIT = 1
    flags = CHILD_INHERIT

    message = control_parameters_pb2.ControlParametersTypes.ControlParametersMessage()
    for i in range(prefix.size()):
        message.control_parameters.name.component.append(prefix[i].getValue().toBytes())
    message.control_parameters.face_id = faceId
    message.control_parameters.origin = origin
    message.control_parameters.cost = cost
    message.control_parameters.flags = flags
    encodedControlParameters = ProtobufTlv.encode(message)
    interest = Interest(Name("/localhost/nfd/rib/register"))
    interest.getName().append(encodedControlParameters)
    interest.setInterestLifetimeMilliseconds(10000)

    # Sign and express the interest.
    face.makeCommandInterest(interest)

    def onData(localInterest, data):
        enabled[0] = False
        processRegisterResponse(data.getContent())

    def onTimeout(localInterest):
        enabled[0] = False
        dump("Register route command timed out.")

    face.expressInterest(interest, onData, onTimeout)

def processRegisterResponse(encodedControlResponse):
    """
    This is called when the register route command responds to decode the
    encodedControlResponse as a TLV ControlParametersResponse message
    containing one ControlParameters. On success, print the ControlParameters
    values which should be the same as requested.

    :param Blob encodedControlResponse: The TLV-encoded ControlParametersResponse.
    """
    decodedControlResponse = \
      control_parameters_pb2.ControlParametersTypes.ControlParametersResponseMessage()
    ProtobufTlv.decode(decodedControlResponse, encodedControlResponse)
    controlResponse = decodedControlResponse.control_response

    lowestErrorCode = 400
    if controlResponse.status_code >= lowestErrorCode:
      dump(
        "Face create command got error, code " + str(controlResponse.status_code) +
         ": " + controlResponse.status_text)
      return
    if len(controlResponse.control_parameters) != 1:
      dump(
        "Face create command response does not have one ControlParameters")
      return

    # Success. Print the ControlParameters response.
    controlParameters = controlResponse.control_parameters[0]
    dump(
      "Successful in name registration: ControlParameters(Name: " +
      ProtobufTlv.toName(controlParameters.name.component).toUri() +
      ", FaceId: " + str(controlParameters.face_id) +
      ", Origin: " + str(controlParameters.origin) +
      ", Cost: " + str(controlParameters.cost) +
      ", Flags: " + str(controlParameters.flags) + ")")

main()

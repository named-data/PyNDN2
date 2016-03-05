# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2016 Regents of the University of California.
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
This module defines the ControlResponse class which holds a status code, status
text and other fields for a ControlResponse which is used, for example, in the
response from sending a register prefix control command to a forwarder. See
http://redmine.named-data.net/projects/nfd/wiki/ControlCommand
"""

from pyndn.control_parameters import ControlParameters
from pyndn.encoding.wire_format import WireFormat
from pyndn.util.blob import Blob

class ControlResponse(object):
    """
    Create a new ControlResponse object, possibly copying values from another
    object.

    :param value: (optional) If value is a ControlResponse, copy its values.
      If value is omitted, all values are unspecified.
    :type value: ControlResponse
    """
    def __init__(self, value = None):
        if type(value) is ControlResponse:
            # Make a deep copy.
            self._bodyAsControlParameters = (None if
              value._bodyAsControlParameters == None
              else ControlParameters(value._bodyAsControlParameters))
            self._statusCode = value._statusCode
            self._statusText = value._statusText
        else:
            self._bodyAsControlParameters = None
            self._statusCode = None
            self._statusText = ""

    def clear(self):
        self._bodyAsControlParameters = None
        self._statusCode = None
        self._statusText = ""

    def wireEncode(self, wireFormat = None):
        """
        Encode this ControlResponse for a particular wire format.

        :param wireFormat: (optional) A WireFormat object used to encode this
           ControlParameters. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        :return: The encoded buffer.
        :rtype: Blob
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        return wireFormat.encodeControlResponse(self)

    def wireDecode(self, input, wireFormat = None):
        """
        Decode the input using a particular wire format and update this
        ControlResponse.

        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :param wireFormat: (optional) A WireFormat object used to decode this
           ControlParameters. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        # If input is a blob, get its buf().
        decodeBuffer = input.buf() if isinstance(input, Blob) else input
        wireFormat.decodeControlResponse(self, decodeBuffer)

    def getStatusCode(self):
        """
        Get the status code.

        :return: The status code. If not specified, return None.
        :rtype: int
        """
        return self._statusCode

    def getStatusText(self):
        """
        Get the status text.

        :return: The status text. If not specified, return "".
        :rtype: str
        """
        return self._statusText

    def getBodyAsControlParameters(self):
        """
        Get the control response body as a ControlParameters.

        :return: The ControlParameters, or None if the body is not specified or
          if it is not a ControlParameters.
        :rtype: ControlParameters
        """
        return self._bodyAsControlParameters

    def setStatusCode(self, statusCode):
        """
        Set the status code.

        :param int statusCode: The status code. If not specified, set to None.
        :return: This ControlResponse so that you can chain calls to update
          values.
        :rtype: ControlResponse
        """
        self._statusCode = statusCode
        return self

    def setStatusText(self, statusText):
        """
        Set the status text.

        :param str statusText: The status text. If not specified, set to "".
        :return: This ControlResponse so that you can chain calls to update
          values.
        :rtype: ControlResponse
        """
        self._statusText = statusText if type(statusText) is str else ""
        return self

    def setBodyAsControlParameters(self, controlParameters):
        """
        Set the control response body as a ControlParameters.

        :param ControlParameters controlParameters: The ControlParameters for
          the body. This makes a copy of the ControlParameters. If not specified
          or if the body is not a ControlParameters, set to None.
        :return: This ControlResponse so that you can chain calls to update
          values.
        :rtype: ControlResponse
        """
        self._bodyAsControlParameters = (ControlParameters(controlParameters) if
          type(controlParameters) is ControlParameters else None)
        return self

    # Create managed properties for read/write properties of the class for more pythonic syntax.
    statusCode = property(getStatusCode, setStatusCode)
    statusText = property(getStatusText, setStatusText)
    bodyAsControlParameters = property(getBodyAsControlParameters, setBodyAsControlParameters)

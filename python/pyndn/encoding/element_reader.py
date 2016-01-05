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
This module defines the ElementReader class which lets you call onReceivedData
multiple times which uses a TlvStructureDecoder to detect the end of a TLV
element, and calls elementListener.onReceivedElement(element) with the element.
This handles the case where a single call to onReceivedData may contain multiple
elements.
"""

from pyndn.util.blob import Blob
from pyndn.encoding.tlv.tlv_structure_decoder import TlvStructureDecoder
from pyndn.util.dynamic_byte_array import DynamicByteArray
from pyndn.util.common import Common

class ElementReader(object):
    """
    Create an ElementReader with the elementListener and an initial buffer for
    saving partial data.
    """
    def __init__(self, elementListener):
        self._elementListener = elementListener
        self._tlvStructureDecoder = TlvStructureDecoder()
        self._usePartialData = False
        self._partialData = DynamicByteArray(1000)
        self._partialDataLength = 0

    def onReceivedData(self, data):
        """
        Continue to read data until the end of an element, then call
        elementListener.onReceivedElement(element). The buffer passed to
        onReceivedElement is only valid during this call.  If you need the data
        later, you must copy.

        :param data: The buffer with the incoming element's bytes.
        :type data: An array type with int elements
        """
        # Create a Blob and take its buf() since this creates a memoryview
        #   which is more efficient for slicing.
        data = Blob(data, False).buf()

        # Process multiple objects in the data.
        while True:
            try:
                if not self._usePartialData:
                    # This is the beginning of an element.
                    if len(data) <= 0:
                        # Wait for more data.
                        return

                # Scan the input to check if a whole TLV element has been read.
                self._tlvStructureDecoder.seek(0)
                gotElementEnd = self._tlvStructureDecoder.findElementEnd(data)
                offset = self._tlvStructureDecoder.getOffset()
            except ValueError as ex:
                # Reset to read a new element on the next call.
                self._usePartialData = False
                self._tlvStructureDecoder = TlvStructureDecoder()

                raise ex

            if gotElementEnd:
                # Got the remainder of an element. Report to the caller.
                if self._usePartialData:
                    # We have partial data from a previous call, so append this
                    #   data and use partialData for onReceivedElement.
                    self._partialData.copy(
                      data[:offset], self._partialDataLength)
                    self._partialDataLength += offset

                    # Create a Blob and take its buf() since this creates a
                    #   memoryview which is more efficient for slicing.
                    partialDataView = Blob(
                      self._partialData.getArray(), False).buf()
                    element = partialDataView[:self._partialDataLength]
                    # Assume we don't need to use partialData anymore until
                    #   needed.
                    self._usePartialData = False
                else:
                    # We are not using partialData, so just point to the input
                    #   data buffer.
                    element = data[:offset]

                # Reset to read a new object. Do this before calling
                # onReceivedElement in case it throws an exception.
                data = data[offset:]
                self._tlvStructureDecoder = TlvStructureDecoder()

                self._elementListener.onReceivedElement(element)
                if len(data) == 0:
                    # No more data in the packet.
                    return

                # else loop back to decode.
            else:
                # Save remaining data for a later call.
                if not self._usePartialData:
                    self._usePartialData = True
                    self._partialDataLength = 0

                if self._partialDataLength + len(data) > Common.MAX_NDN_PACKET_SIZE:
                    # Reset to read a new element on the next call.
                    self._usePartialData = False
                    self._tlvStructureDecoder = TlvStructureDecoder()

                    raise ValueError(
                      "The incoming packet exceeds the maximum limit Face.getMaxNdnPacketSize()")

                self._partialData.copy(data, self._partialDataLength)
                self._partialDataLength += len(data)

                return

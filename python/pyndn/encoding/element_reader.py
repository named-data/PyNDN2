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
This module defines the ElementReader class which lets you call onReceivedData 
multiple times which uses a TlvStructureDecoder or BinaryXmlStructureDecoder as 
needed to detect the end of a TLV or Binary XML element, and calls 
elementListener.onReceivedElement(element) with the element. 
This handles the case where a single call to onReceivedData may contain multiple
elements.
"""

from pyndn.util import Blob
from pyndn.encoding.binary_xml_structure_decoder import BinaryXmlStructureDecoder
from pyndn.encoding.tlv.tlv import Tlv
from pyndn.encoding.tlv.tlv_structure_decoder import TlvStructureDecoder
from pyndn.util.dynamic_byte_array import DynamicByteArray

class ElementReader(object):
    """
    Create an ElementReader with the elementListener and an initial buffer for 
    saving partial data.
    """
    def __init__(self, elementListener):
        self._elementListener = elementListener
        self._binaryXmlStructureDecoder = BinaryXmlStructureDecoder()
        self._tlvStructureDecoder = TlvStructureDecoder()
        self._usePartialData = False
        self._partialData = DynamicByteArray(1000)
        self._useTlv = None

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
            if not self._usePartialData:
                # This is the beginning of an element. Check whether it is 
                #  Binary XML or TLV.
                if len(data) <= 0:
                    # Wait for more data.
                    return

                # The type codes for TLV Interest and Data packets are chosen to not
                #   conflict with the first byte of a binary XML packet, so we can
                #   just look at the first byte.
                if (data[0] == Tlv.Interest or data[0] == Tlv.Data or 
                    data[0] == 0x80):
                    self._useTlv = True
                else:
                    # Binary XML.
                    self._useTlv = False

            if self._useTlv:
                # Scan the input to check if a whole TLV element has been read.
                self._tlvStructureDecoder.seek(0)    
                gotElementEnd = self._tlvStructureDecoder.findElementEnd(data)
                offset = self._tlvStructureDecoder.getOffset()
            else:
                # Scan the input to check if a whole Binary XML element has been 
                #   read.
                self._binaryXmlStructureDecoder.seek(0)    
                gotElementEnd = self._binaryXmlStructureDecoder.findElementEnd(data)
                offset = self._binaryXmlStructureDecoder.getOffset()
            
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
                    self._elementListener.onReceivedElement(
                      partialDataView[:self._partialDataLength])
                    # Assume we don't need to use partialData anymore until 
                    #   needed.
                    self._usePartialData = False
                else:
                    # We are not using partialData, so just point to the input 
                    #   data buffer.
                    self._elementListener.onReceivedElement(data[:offset])

                # Need to read a new object.
                data = data[offset:]
                self._binaryXmlStructureDecoder = BinaryXmlStructureDecoder()
                self._tlvStructureDecoder = TlvStructureDecoder()
                if len(data) == 0:
                    # No more data in the packet.
                    return

                # else loop back to decode.
            else:
                # Save remaining data for a later call.
                if not self._usePartialData:
                    self._usePartialData = True
                    self._partialDataLength = 0

                self._partialData.copy(data, self._partialDataLength)
                self._partialDataLength += len(data)

                return

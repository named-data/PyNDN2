# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the BinaryXmlDecoder class which we include so that we can 
recognize and skip Binary XML packets.
"""

class BinaryXmlDecoder(object):
    """
    Create a new BinaryXmlDecoder to decode the input using Binary XML.
    
    :param input: The array with the bytes to decode.
    :type input: An array type with int elements
    """
    def __init__(self, input):
        self._input = input
        self._offset = 0

    EXT = 0x00   
    TAG = 0x01 
    DTAG = 0x02 
    ATTR = 0x03 
    DATTR = 0x04 
    BLOB = 0x05 
    UDATA = 0x06 
    CLOSE = 0x0

    TT_BITS = 3
    TT_MASK = ((1 << 3) - 1)
    TT_VALUE_BITS = 4
    TT_VALUE_MASK = ((1 << 4) - 1)
    REGULAR_VALUE_BITS = 7
    REGULAR_VALUE_MASK = ((1 << 7) - 1)
    TT_FINAL = 0x80

    def decodeTypeAndValue(self):
        """
        Decode the header's type and value from self's input starting at 
        self._offset. Update the offset.
        
        :return: The tuple (type, value)
        :rtype: (int, int)
        """
        value = 0
        gotFirstOctet = False

        while True:
            if self._offset >= len(self._input):
                raise ValueError("Read past the end of the input")

            octet = self._input[self._offset]
            self._offset += 1

            if not gotFirstOctet:
                if octet == BinaryXmlDecoder.CLOSE:
                    raise ValueError("The first header octet may not be zero")

                gotFirstOctet = True

            if octet & BinaryXmlDecoder.TT_FINAL:
                # Finished.
                type = octet & BinaryXmlDecoder.TT_MASK
                value = ((value << BinaryXmlDecoder.TT_VALUE_BITS) | 
                         ((octet >> BinaryXmlDecoder.TT_BITS) & 
                          BinaryXmlDecoder.TT_VALUE_MASK))
                break

            value = ((value << BinaryXmlDecoder.REGULAR_VALUE_BITS) | 
                     (octet & BinaryXmlDecoder.REGULAR_VALUE_MASK))

        return (type, value)
    
    def getOffset(self):
        """
        Get the offset into the input buffer, used for the next read.
        
        :return: The offset.
        :rtype: int
        """
        return self._offset
    
    def seek(self, offset):
        """
        Set the offset into the input, used for the next read.
        
        :param offset: The new offset.
        :type offset: int        
        """
        self._offset = offset

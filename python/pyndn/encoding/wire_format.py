# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the WireFormat class which is an abstract base class for 
encoding and decoding Interest, Data, etc. with a specific wire format.
You should use a derived class such as TlvWireFormat.
"""

class WireFormat(object):
    _defaultWireFormat = None
    
    def encodeInterest(self, interest):
        """
        Encode interest and return the encoding.  Your derived class should 
        override.

        :param interest: The Interest object to encode.
        :type interest: Interest
        :return: A Blob containing the encoding.
        :rtype: Blob
        :raises: RuntimeError for unimplemented if the derived class does not 
          override.
        """
        raise RuntimeError("encodeInterest is not implemented")
    
    def decodeInterest(self, interest, input):
        """
        Decode input as an interest and set the fields of the interest object.  
        Your derived class should override.
        
        :param interest: The Interest object whose fields are updated.
        :type interest: Interest
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :raises: RuntimeError for unimplemented if the derived class does not 
          override.
        """
        raise RuntimeError("decodeInterest is not implemented")

    def encodeData(self, data):
        """
        Encode data and return the encoding and signed offsets.  Your derived 
        class should override.

        :param data: The Data object to encode.
        :type data: Data
        :return: A Tuple of (encoding, signedPortionBeginOffset,
          signedPortionEndOffset) where encoding is a Blob containing the
          encoding, signedPortionBeginOffset is the offset in the encoding of 
          the beginning of the signed portion, and signedPortionEndOffset is
          the offset in the encoding of the end of the signed portion.
        :rtype: (Blob, int, int)
        :raises: RuntimeError for unimplemented if the derived class does not 
          override.
        """
        raise RuntimeError("encodeData is not implemented")
        
    def decodeData(self, data, input):
        """
        Decode input as a data packet, set the fields in the data object, and 
        return the signed offsets.  Your derived class should override.

        :param data: The Data object whose fields are updated.
        :type data: Data
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :return: A Tuple of (signedPortionBeginOffset, signedPortionEndOffset) 
          where signedPortionBeginOffset is the offset in the encoding of 
          the beginning of the signed portion, and signedPortionEndOffset is
          the offset in the encoding of the end of the signed portion.
        :rtype: (int, int)
        :raises: RuntimeError for unimplemented if the derived class does not 
          override.
        """
        raise RuntimeError("decodeData is not implemented")
        
    @classmethod
    def setDefaultWireFormat(self, wireFormat):
        """
        Set the static default WireFormat used by default encoding and decoding 
        methods.
        
        :param wireFormat: An object of a subclass of WireFormat.
        :type wireFormat: A subclass of WireFormat.
        """
        self._defaultWireFormat = wireFormat
        
    @classmethod
    def getDefaultWireFormat(self):
        """
        Return the default WireFormat used by default encoding and decoding 
        methods which was set with setDefaultWireFormat.
        
        :return: The WireFormat object.
        :rtype: A subclass of WireFormat.
        """
        return self._defaultWireFormat

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
        :type input: An array type with int elements.
        :raises: RuntimeError for unimplemented if the derived class does not 
          override.
        """
        raise RuntimeError("decodeInterest is not implemented")

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

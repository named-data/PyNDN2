# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

from pyndn.encoding.wire_format import WireFormat
from pyndn.encoding.tlv_0_1_wire_format import Tlv0_1WireFormat

"""
This module defines the TlvWireFormat class which extends Tlv0_1WireFormat to 
override its methods to implement encoding and decoding using the preferred 
implementation of NDN-TLV.
"""

class TlvWireFormat(Tlv0_1WireFormat):
    _instance = None
    
    @classmethod
    def get(self):
        """
        Get a singleton instance of a TlvWireFormat.  Assuming that the default 
        wire format was set with 
        WireFormat.setDefaultWireFormat(TlvWireFormat.get()), you can check if 
        this is the default wire encoding with
        if WireFormat.getDefaultWireFormat() == TlvWireFormat.get().
        
        :return: The singleton instance.
        :rtype: TlvWireFormat
        """
        if self._instance == None:
            self._instance = TlvWireFormat()
        return self._instance

# On loading this module, make this the default wire format.
# This module will be loaded because __init__.py loads it.
WireFormat.setDefaultWireFormat(TlvWireFormat.get())

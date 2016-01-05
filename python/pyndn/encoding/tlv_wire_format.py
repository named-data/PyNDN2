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

from pyndn.encoding.wire_format import WireFormat
from pyndn.encoding.tlv_0_1_1_wire_format import Tlv0_1_1WireFormat

"""
This module defines the TlvWireFormat class which extends WireFormat to override
its methods to implement encoding and decoding using the preferred
implementation of NDN-TLV.
"""

class TlvWireFormat(Tlv0_1_1WireFormat):
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

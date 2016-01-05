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
This module defines the Tlv0_1WireFormat class which extends Tlv0_1_1WireFormat
so that it is an alias in case any applications use Tlv0_1WireFormat directly.
These two wire formats are the same except that Tlv0_1_1WireFormat adds support
for Sha256WithEcdsaSignature.
"""

from pyndn.encoding.tlv_0_1_1_wire_format import Tlv0_1_1WireFormat

class Tlv0_1WireFormat(Tlv0_1_1WireFormat):
    _instance = None

    @classmethod
    def get(self):
        """
        Get a singleton instance of a Tlv0_1WireFormat.

        :return: The singleton instance.
        :rtype: Tlv0_1WireFormat
        """
        if self._instance == None:
            self._instance = Tlv0_1WireFormat()
        return self._instance

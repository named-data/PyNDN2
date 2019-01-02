# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2019 Regents of the University of California.
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
This module defines the CommandInterestGenerator class which keeps track of a
timestamp and generates command interests according to the NFD Signed Command
Interests protocol:
https://redmine.named-data.net/projects/ndn-cxx/wiki/CommandInterest
"""

from pyndn.security.command_interest_preparer import CommandInterestPreparer
from pyndn.encoding.wire_format import WireFormat

class CommandInterestGenerator(CommandInterestPreparer):
    """
    Create a new CommandInterestGenerator and initialize the timestamp to now.
    """
    def __init__(self):
        super(CommandInterestGenerator, self).__init__()

    def generate(self, interest, keyChain, certificateName, wireFormat = None):
        """
        Append a timestamp component and a random value component to interest's
        name. This ensures that the timestamp is greater than the timestamp used
        in the previous call. Then use keyChain to sign the interest which
        appends a SignatureInfo component and a component with the signature
        bits. If the interest lifetime is not set, this sets it.

        :param Interest interest: The interest whose name is append with
          components.
        :param KeyChain keyChain: The KeyChain for calling sign.
        :param Name certificateName: The certificate name of the key to use for
          signing.
        :param wireFormat: (optional) A WireFormat object used to encode the
          SignatureInfo and to encode interest name for signing. If omitted, use
          WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        self.prepareCommandInterestName(interest, wireFormat)
        keyChain.sign(interest, certificateName, wireFormat)

        if (interest.getInterestLifetimeMilliseconds() == None or
            interest.getInterestLifetimeMilliseconds()< 0):
          # The caller has not set the interest lifetime, so set it here.
          interest.setInterestLifetimeMilliseconds(1000.0)

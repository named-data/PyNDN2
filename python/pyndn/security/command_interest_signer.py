# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/command-interest-signer.cpp
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
This module defines the CommandInterestSigner class which is a helper class to
create command interests. This keeps track of a timestamp and generates command
interests by adding name components according to the NFD Signed Command
Interests protocol. See makeCommandInterest() for details.
https://redmine.named-data.net/projects/ndn-cxx/wiki/CommandInterest
"""

from pyndn.interest import Interest
from pyndn.encoding.wire_format import WireFormat
from pyndn.security.command_interest_preparer import CommandInterestPreparer

class CommandInterestSigner(CommandInterestPreparer):
    """
    Create a CommandInterestSigner to use the keyChain to sign.

    :param KeyChain keyChain: The KeyChain used to sign.
    """
    def __init__(self, keyChain):
        super(CommandInterestSigner, self).__init__()

        self._keyChain = keyChain

    POS_SIGNATURE_VALUE = -1
    POS_SIGNATURE_INFO =  -2
    POS_NONCE =           -3
    POS_TIMESTAMP =       -4

    MINIMUM_SIZE = 4

    def makeCommandInterest(self, name, params = None, wireFormat = None):
        """
        Append the timestamp and nonce name components to the supplied name,
        create an Interest object and signs it with the KeyChain given to the
        constructor. This ensures that the timestamp is greater than the
        timestamp used in the previous call.

        :param Name name: The Name for the Interest, which is copied.
        :param SigningInfo params: (optional) The signing parameters. If omitted,
          use a default SigningInfo().
        :param WireFormat wireFormat: (optional) A WireFormat object used to
          encode the SignatureInfo and to encode interest name for signing. If
          omitted, use WireFormat getDefaultWireFormat().
        :return: The new command Interest object.
        :rtype: Interest
        """
        arg2 = params
        arg3 = wireFormat
        if isinstance(arg2, SigningInfo):
            params = arg2
        else:
            params = None

        if isinstance(arg2, WireFormat):
            wireFormat = arg2
        elif isinstance(arg3, WireFormat):
            wireFormat = arg3
        else:
            wireFormat = None

        if params == None:
            params = SigningInfo()

        if wireFormat == None:
            wireFormat = WireFormat.getDefaultWireFormat()

        # This copies the Name.
        commandInterest = Interest(name)

        self.prepareCommandInterestName(commandInterest, wireFormat)
        self._keyChain.sign(commandInterest, params, wireFormat)

        return commandInterest

# Import this at the end of the file to avoid circular references.
from pyndn.security.signing_info import SigningInfo

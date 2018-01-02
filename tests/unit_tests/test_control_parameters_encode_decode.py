# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2018 Regents of the University of California.
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

import unittest as ut
from pyndn import Name, ControlParameters

class TestControlParametersEncodeDecode(ut.TestCase):
    def test_encode_decode(self):
        parameters = ControlParameters()
        parameters.setName(Name("/test/control/parameters"))
        parameters.setFaceId(1)
        # encode
        encoded = parameters.wireEncode()
        # decode
        decodedParameters = ControlParameters()
        decodedParameters.wireDecode(encoded)
        # compare
        self.assertEqual(parameters.getName().toUri(),
                  decodedParameters.getName().toUri())
        self.assertEqual(parameters.getFaceId(), decodedParameters.getFaceId())
        self.assertEqual(parameters.getUri(), decodedParameters.getUri())
        self.assertEqual(parameters.getForwardingFlags().getChildInherit(),
                  decodedParameters.getForwardingFlags().getChildInherit(),
                  "decoded forwarding flags childInherit is different")
        self.assertEqual(parameters.getForwardingFlags().getCapture(),
                  decodedParameters.getForwardingFlags().getCapture(),
                  "decoded forwarding flags capture is different")

    def test_encode_decode_with_no_name(self):
        parameters = ControlParameters()
        parameters.setStrategy(Name("/localhost/nfd/strategy/broadcast"))
        parameters.setUri("null://")
        # encode
        encoded = parameters.wireEncode()
        # decode
        decodedParameters = ControlParameters()
        decodedParameters.wireDecode(encoded)
        # compare
        self.assertEqual(decodedParameters.getName(), None)
        self.assertEqual(parameters.getStrategy().toUri(),
                  decodedParameters.getStrategy().toUri())
        self.assertEqual(parameters.getUri(), decodedParameters.getUri())

if __name__ == '__main__':
    ut.main(verbosity=2)

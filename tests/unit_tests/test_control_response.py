# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2016-2018 Regents of the University of California.
# Author: Andrew Brown <andrew.brown@intel.com>
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From jNDN TestControlResponse.
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
from pyndn import ControlParameters
from pyndn import ControlResponse
from pyndn.util import Blob

TestControlResponse1 = Blob(bytearray([
  0x65, 0x1c, # ControlResponse
    0x66, 0x02, 0x01, 0x94, # StatusCode
    0x67, 0x11, # StatusText
      0x4e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x20, 0x6e, 0x6f, 0x74, 0x20,
      0x66, 0x6f, 0x75, 0x6e, 0x64,
    0x68, 0x03, # ControlParameters
      0x69, 0x01, 0x0a # FaceId
]))

class TestControlResponse(ut.TestCase):
    def test_encode(self):
        response = ControlResponse()
        response.setStatusCode(404)
        response.setStatusText("Nothing not found")
        response.setBodyAsControlParameters(ControlParameters())
        response.getBodyAsControlParameters().setFaceId(10)
        wire = response.wireEncode()

        self.assertTrue(wire.equals(TestControlResponse1))

    def test_decode(self):
        response = ControlResponse()
        response.wireDecode(TestControlResponse1)

        self.assertEqual(response.getStatusCode(), 404);
        self.assertEqual(response.getStatusText(), "Nothing not found");
        self.assertEqual(response.getBodyAsControlParameters().getFaceId(), 10);

if __name__ == '__main__':
    ut.main(verbosity=2)

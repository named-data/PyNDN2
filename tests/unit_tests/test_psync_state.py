# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx NamingConventions unit tests:
# https://github.com/named-data/PSync/blob/master/tests/test-state.cpp
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
from pyndn import Name, Data
from pyndn.util import Blob
from pyndn.sync.detail.psync_state import PSyncState

class TestPSyncState(ut.TestCase):
    def testEncodeDecode(self):
        state = PSyncState()
        state.addContent(Name("test1"))
        state.addContent(Name("test2"))

        # Simulate getting a buffer of content from a segment fetcher.
        data = Data()
        encoding = state.wireEncode()
        expectedEncoding = [
          0x80, 0x12, # PSyncContent
            0x07, 0x07, 0x08, 0x05, 0x74, 0x65, 0x73, 0x74, 0x31, # Name = "/test1"
            0x07, 0x07, 0x08, 0x05, 0x74, 0x65, 0x73, 0x74, 0x32  # Name = "/test2"
        ]
        self.assertTrue(encoding.equals(Blob(expectedEncoding)))
        data.setContent(encoding)

        receivedState = PSyncState()
        receivedState.wireDecode(data.getContent())

        self.assertTrue(state.getContent() == receivedState.getContent())

    def testEmptyContent(self):
        state = PSyncState()

        # Simulate getting a buffer of content from a segment fetcher.
        data = Data()
        data.setContent(state.wireEncode())

        state2 = PSyncState(data.getContent())
        self.assertEqual(0, len(state2.getContent()))

if __name__ == '__main__':
    ut.main(verbosity=2)

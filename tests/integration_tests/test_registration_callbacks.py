# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From jNDN TestRegistrationCallbacks by Andrew Brown <andrew.brown@intel.com>
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

from pyndn import Name
from pyndn import Face

from pyndn.security import KeyChain

import unittest as ut
import time

# Use Python 3's mock library if it's available, else you'll have to
# pip install mock.
try:
    from unittest.mock import Mock
except ImportError:
    from mock import Mock

class TestRegistrationCallbacks(ut.TestCase):
    def setUp(self):
        self.face = Face()
        keyChain = KeyChain()
        self.face.setCommandSigningInfo(
          keyChain, keyChain.getDefaultCertificateName())

    def tearDown(self):
        self.face.shutdown()

    def test_registration_callbacks(self):
        onRegisterFailed = Mock()
        onRegisterSuccess = Mock()

        self.face.registerPrefix(
          Name("/test/register/callbacks"), None, onRegisterFailed,
          onRegisterSuccess)

        while True:
            self.face.processEvents()
            time.sleep(0.01)
            if (onRegisterSuccess.call_count > 0 or onRegisterFailed.call_count > 0):
                break

        self.assertEqual(
          onRegisterSuccess.call_count, 1,
          "Expected 1 onRegisterSuccess callback, got " +
            str(onRegisterSuccess.call_count))

if __name__ == '__main__':
    ut.main(verbosity=2)

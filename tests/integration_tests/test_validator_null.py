# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx unit tests:
# https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/validator-null.t.cpp
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
from pyndn import Name, Data, Interest
from pyndn.security import SigningInfo, ValidatorNull
from .identity_management_fixture import IdentityManagementFixture

class TestValidatorNull(ut.TestCase):
    def setUp(self):
        self._fixture = IdentityManagementFixture()

    def test_validate_data(self):
        identity = self._fixture.addIdentity(Name("/TestValidator/Null"))
        data = Data(Name("/Some/Other/Data/Name"))
        self._fixture._keyChain.sign(data, SigningInfo(identity))

        validator = ValidatorNull()

        successCount = [0]
        failureCount = [0]
        def successCallback(data):
            successCount[0] += 1
        def failureCallback(data, error):
            failureCount[0] += 1
        validator.validate(data, successCallback, failureCallback)
        self.assertTrue(successCount[0] == 1 and failureCount[0] == 0,
          "Validation should not have failed")

    def test_validate_interest(self):
        identity = self._fixture.addIdentity(Name("/TestValidator/Null"))
        interest = Interest(Name("/Some/Other/Interest/Name"))
        self._fixture._keyChain.sign(interest, SigningInfo(identity))

        validator = ValidatorNull()

        successCount = [0]
        failureCount = [0]
        def successCallback(interest):
            successCount[0] += 1
        def failureCallback(interest, error):
            failureCount[0] += 1
        validator.validate(interest, successCallback, failureCallback)
        self.assertTrue(successCount[0] == 1 and failureCount[0] == 0,
          "Validation should not have failed")

if __name__ == '__main__':
    ut.main(verbosity=2)

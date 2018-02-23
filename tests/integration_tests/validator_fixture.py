# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx unit tests:
# https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/validator-fixture.cpp
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

from pyndn import Interest
from pyndn.security.v2 import Validator
from pyndn.security.v2 import CertificateFetcherFromNetwork
from pyndn.security.v2 import CertificateCacheV2
from .identity_management_fixture import IdentityManagementFixture

class ValidatorFixture(IdentityManagementFixture):
    """
    :type policy: ValidationPolicy
    """
    def __init__(self, policy):
        super(ValidatorFixture, self).__init__()

        self._face = ValidatorFixture.TestFace()
        # Set maxLifetime to 100 days.
        self._cache = CertificateCacheV2(100 * 24 * 3600 * 1000.0)

        self._validator = Validator(policy, CertificateFetcherFromNetwork(self._face))
        self._policy = policy

        def processInterest(interest, onData, onTimeout, onNetworkNack):
            certificate = self._cache.find(interest)
            if certificate != None:
                onData(interest, certificate)
            else:
                onTimeout(interest)
        self._face._processInterest = processInterest

    class TestFace(object):
        """
        TestFace extends Face to instantly simulate a call to expressInterest.
        See expressInterest for details.
        """
        def __init__(self):
            self._processInterest = None
            self._sentInterests = []  # of Interest

        def expressInterest(self, interest, onData, onTimeout, onNetworkNack):
            """
            If _processInterest is not None, call
            processInterest_(interest, onData, onTimeout, onNetworkNack)
            which must call one of the callbacks to simulate the response. 
            Otherwise, just call onTimeout(interest) to simulate a timeout. 
            This adds a copy of the interest to _sentInterests .
            """
            # Make a copy of the interest.
            self._sentInterests.append(Interest(interest))

            if self._processInterest != None:
                self._processInterest(interest, onData, onTimeout, onNetworkNack)
            else:
                onTimeout(interest)

            return 0

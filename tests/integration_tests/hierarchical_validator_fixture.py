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

from pyndn import Name
from pyndn.security.v2 import CertificateV2
from .validator_fixture import ValidatorFixture

class HierarchicalValidatorFixture(ValidatorFixture):
    """
    :type policy: ValidationPolicy
    """
    def __init__(self, policy):
        super(HierarchicalValidatorFixture, self).__init__(policy)

        self._identity = self.addIdentity(Name("/Security/V2/ValidatorFixture"))
        self._subIdentity = self.addSubCertificate(
          Name("/Security/V2/ValidatorFixture/Sub1"), self._identity)
        self._subSelfSignedIdentity = self.addIdentity(
          Name("/Security/V2/ValidatorFixture/Sub1/Sub2"))
        self._otherIdentity = self.addIdentity(Name("/Security/V2/OtherIdentity"))

        self._validator.loadAnchor(
          "", CertificateV2(self._identity.getDefaultKey().getDefaultCertificate()))

        self._cache.insert(self._identity.getDefaultKey().getDefaultCertificate())
        self._cache.insert(self._subIdentity.getDefaultKey().getDefaultCertificate())
        self._cache.insert(
          self._subSelfSignedIdentity.getDefaultKey().getDefaultCertificate())
        self._cache.insert(
          self._otherIdentity.getDefaultKey().getDefaultCertificate())

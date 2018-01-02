# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx unit tests:
# https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/pib/certificate-container.t.cpp
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
from pyndn.security.pib.pib_memory import PibMemory
from pyndn import Name
from pyndn.security.pib.pib_certificate_container import PibCertificateContainer
from pyndn.security.pib.pib import Pib
from .pib_data_fixture import PibDataFixture

class TestPibCertificateContainer(ut.TestCase):
    def setUp(self):
        self.fixture = PibDataFixture()

    def test_basic(self):
        fixture = self.fixture
        pibImpl = PibMemory()

        # Start with an empty container.
        container = PibCertificateContainer(fixture.id1Key1Name, pibImpl)
        self.assertEquals(0, container.size())
        self.assertEquals(0, len(container._certificates))

        # Add a certificate.
        container.add(fixture.id1Key1Cert1)
        self.assertEquals(1, container.size())
        self.assertEquals(1, len(container._certificates))
        self.assertTrue(
          fixture.id1Key1Cert1.getName() in container._certificates)

        # Add the same certificate again.
        container.add(fixture.id1Key1Cert1)
        self.assertEquals(1, container.size())
        self.assertEquals(1, len(container._certificates))
        self.assertTrue(
          fixture.id1Key1Cert1.getName() in container._certificates)

        # Add another certificate.
        container.add(fixture.id1Key1Cert2)
        self.assertEquals(2, container.size())
        self.assertEquals(2, len(container._certificates))
        self.assertTrue(
          fixture.id1Key1Cert1.getName() in container._certificates)
        self. assertTrue(
          fixture.id1Key1Cert2.getName() in container._certificates)

        # Get the certificates.
        try:
            container.get(fixture.id1Key1Cert1.getName())
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))
        try:
            container.get(fixture.id1Key1Cert2.getName())
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))
        id1Key1Cert3Name = Name(fixture.id1Key1Name)
        id1Key1Cert3Name.append("issuer").appendVersion(3)
        try:
            container.get(id1Key1Cert3Name)
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        # Check the certificates.
        cert1 = container.get(fixture.id1Key1Cert1.getName())
        cert2 = container.get(fixture.id1Key1Cert2.getName())
        # Use the wire encoding to check equivalence.
        self.assertTrue(cert1.wireEncode().equals
          (fixture.id1Key1Cert1.wireEncode()))
        self.assertTrue(cert2.wireEncode().equals
          (fixture.id1Key1Cert2.wireEncode()))

        # Create another container with the same PibImpl. The cache should be empty.
        container2 = PibCertificateContainer(fixture.id1Key1Name, pibImpl)
        self.assertEquals(2, container2.size())
        self.assertEquals(0, len(container2._certificates))

        # Get a certificate. The cache should be filled.
        try:
            container2.get(fixture.id1Key1Cert1.getName())
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))
        self.assertEquals(2, container2.size())
        self.assertEquals(1, len(container2._certificates))

        try:
            container2.get(fixture.id1Key1Cert2.getName())
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))
        self.assertEquals(2, container2.size())
        self.assertEquals(2, len(container2._certificates))

        # Remove a certificate.
        container2.remove(fixture.id1Key1Cert1.getName())
        self.assertEquals(1, container2.size())
        self.assertEquals(1, len(container2._certificates))
        self.assertTrue(
          not (fixture.id1Key1Cert1.getName() in container2._certificates))
        self.assertTrue(
          fixture.id1Key1Cert2.getName() in container2._certificates)

        # Remove another certificate.
        container2.remove(fixture.id1Key1Cert2.getName())
        self.assertEquals(0, container2.size())
        self.assertEquals(0, len(container2._certificates))
        self.assertTrue(
          not (fixture.id1Key1Cert2.getName() in container2._certificates))

    def test_errors(self):
        fixture = self.fixture
        pibImpl = PibMemory()

        container = PibCertificateContainer(fixture.id1Key1Name, pibImpl)

        try:
            container.add(fixture.id1Key2Cert1)
            self.fail("Did not throw the expected exception")
        except ValueError:
            pass
        else:
            self.fail("Did not throw the expected exception")

        try:
            container.remove(fixture.id1Key2Cert1.getName())
            self.fail("Did not throw the expected exception")
        except ValueError:
            pass
        else:
            self.fail("Did not throw the expected exception")

        try:
            container.get(fixture.id1Key2Cert1.getName())
            self.fail("Did not throw the expected exception")
        except ValueError:
            pass
        else:
            self.fail("Did not throw the expected exception")

if __name__ == '__main__':
    ut.main(verbosity=2)

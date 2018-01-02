# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx unit tests:
# https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/pib/detail/key-impl.t.cpp
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
from pyndn.security import KeyType
from pyndn.security.pib.pib import Pib
from pyndn.security.pib.pib_memory import PibMemory
from pyndn.security.pib.detail.pib_key_impl import PibKeyImpl
from pyndn.security.v2.certificate_v2 import CertificateV2
from pyndn.util.common import Common
from pyndn.util import Blob
from pyndn import Name
from .pib_data_fixture import PibDataFixture

class TestPibKeyImpl(ut.TestCase):
    def setUp(self):
        self.fixture = PibDataFixture()

    def test_basic(self):
        fixture = self.fixture
        pibImpl = PibMemory()
        key11 = PibKeyImpl(
          fixture.id1Key1Name, fixture.id1Key1.toBytes(), pibImpl)

        self.assertTrue(fixture.id1Key1Name.equals(key11.getName()))
        self.assertTrue(fixture.id1.equals(key11.getIdentityName()))
        self.assertEquals(KeyType.RSA, key11.getKeyType())
        self.assertTrue(key11.getPublicKey().equals(fixture.id1Key1))

        key11FromBackend = PibKeyImpl(fixture.id1Key1Name, pibImpl)
        self.assertTrue(fixture.id1Key1Name.equals(key11FromBackend.getName()))
        self.assertTrue(fixture.id1.equals(key11FromBackend.getIdentityName()))
        self.assertEquals(KeyType.RSA, key11FromBackend.getKeyType())
        self.assertTrue(key11FromBackend.getPublicKey().equals(fixture.id1Key1))

    def test_certificate_operation(self):
        fixture = self.fixture
        pibImpl = PibMemory()
        key11 = PibKeyImpl(
          fixture.id1Key1Name, fixture.id1Key1.toBytes(), pibImpl)
        try:
            PibKeyImpl(fixture.id1Key1Name, pibImpl)
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        # The key should not have any certificates.
        self.assertEquals(0, key11._certificates.size())

        # Getting a non-existing certificate should throw Pib.Error.
        try:
            key11.getCertificate(fixture.id1Key1Cert1.getName())
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        # Getting the non-existing default certificate should throw Pib.Error.
        try:
            key11.getDefaultCertificate()
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        # Setting a non-existing certificate as the default should throw Pib.Error.
        try:
            key11.setDefaultCertificate(fixture.id1Key1Cert1.getName())
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        # Add a certificate.
        key11.addCertificate(fixture.id1Key1Cert1)
        try:
            key11.getCertificate(fixture.id1Key1Cert1.getName())
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        # The new certificate becomes the default when there was no default.
        try:
            key11.getDefaultCertificate()
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))
        defaultCert0 = key11.getDefaultCertificate()
        self.assertTrue(fixture.id1Key1Cert1.getName().equals
          (defaultCert0.getName()))
        # Use the wire encoding to check equivalence.
        self.assertTrue(fixture.id1Key1Cert1.wireEncode().equals
          (defaultCert0.wireEncode()))

        # Remove the certificate.
        key11.removeCertificate(fixture.id1Key1Cert1.getName())
        try:
            key11.getCertificate(fixture.id1Key1Cert1.getName())
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        try:
            key11.getDefaultCertificate()
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        # Set the default certificate directly.
        try:
            key11.setDefaultCertificate(fixture.id1Key1Cert1)
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        try:
            key11.getDefaultCertificate()
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        try:
            key11.getCertificate(fixture.id1Key1Cert1.getName())
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        # Check the default cert.
        defaultCert1 = key11.getDefaultCertificate()
        self.assertTrue(fixture.id1Key1Cert1.getName().equals
          (defaultCert1.getName()))
        self.assertTrue(defaultCert1.wireEncode().equals
          (fixture.id1Key1Cert1.wireEncode()))

        # Add another certificate.
        key11.addCertificate(fixture.id1Key1Cert2)
        self.assertEquals(2, key11._certificates.size())

        # Set the default certificate using a name.
        try:
            key11.setDefaultCertificate(fixture.id1Key1Cert2.getName())
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        try:
            key11.getDefaultCertificate()
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        defaultCert2 = key11.getDefaultCertificate()
        self.assertTrue(fixture.id1Key1Cert2.getName().equals
          (defaultCert2.getName()))
        self.assertTrue(defaultCert2.wireEncode().equals
          (fixture.id1Key1Cert2.wireEncode()))

        # Remove a certificate.
        key11.removeCertificate(fixture.id1Key1Cert1.getName())
        try:
            key11.getCertificate(fixture.id1Key1Cert1.getName())
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        self.assertEquals(1, key11._certificates.size())

        # Set the default certificate directly again, which should change the default.
        try:
            key11.setDefaultCertificate(fixture.id1Key1Cert1)
        except Exception as ex:
            self.fail("Unexpected exception: " + str(ex))

        defaultCert3 = key11.getDefaultCertificate()
        self.assertTrue(fixture.id1Key1Cert1.getName().equals
          (defaultCert3.getName()))
        self.assertTrue(defaultCert3.wireEncode().equals
          (fixture.id1Key1Cert1.wireEncode()))
        self.assertEquals(2, key11._certificates.size())

        # Remove all certificates.
        key11.removeCertificate(fixture.id1Key1Cert1.getName())
        try:
            key11.getCertificate(fixture.id1Key1Cert1.getName())
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        self.assertEquals(1, key11._certificates.size())
        key11.removeCertificate(fixture.id1Key1Cert2.getName())
        try:
            key11.getCertificate(fixture.id1Key1Cert2.getName())
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        try:
            key11.getDefaultCertificate()
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        self.assertEquals(0, key11._certificates.size())

    def test_overwrite(self):
        fixture = self.fixture
        pibImpl = PibMemory()

        try:
            PibKeyImpl(fixture.id1Key1Name, pibImpl)
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        PibKeyImpl(fixture.id1Key1Name, fixture.id1Key1.buf(), pibImpl)
        key1 = PibKeyImpl(fixture.id1Key1Name, pibImpl)

        # Overwriting the key should work.
        PibKeyImpl(fixture.id1Key1Name, fixture.id1Key2.buf(), pibImpl)
        key2 = PibKeyImpl(fixture.id1Key1Name, pibImpl)

        # key1 should have cached the original public key.
        self.assertTrue(not key1.getPublicKey().equals(key2.getPublicKey()))
        self.assertTrue(key2.getPublicKey().equals(fixture.id1Key2))

        key1.addCertificate(fixture.id1Key1Cert1)
        # Use the wire encoding to check equivalence.
        self.assertTrue(
          key1.getCertificate(fixture.id1Key1Cert1.getName()).wireEncode().equals
          (fixture.id1Key1Cert1.wireEncode()))

        otherCert = CertificateV2(fixture.id1Key1Cert1)
        otherCert.getSignature().getValidityPeriod().setPeriod(
          Common.getNowMilliseconds(), Common.getNowMilliseconds() + 1000)
        # Don't bother resigning so we don't have to load a private key.

        self.assertTrue(fixture.id1Key1Cert1.getName().equals(otherCert.getName()))
        self.assertTrue(otherCert.getContent().equals
          (fixture.id1Key1Cert1.getContent()))
        self.assertFalse(otherCert.wireEncode().equals
          (fixture.id1Key1Cert1.wireEncode()))

        key1.addCertificate(otherCert)

        self.assertTrue(
          key1.getCertificate(fixture.id1Key1Cert1.getName()).wireEncode().equals
          (otherCert.wireEncode()))

    def test_errors(self):
        fixture = self.fixture
        pibImpl = PibMemory()

        try:
            PibKeyImpl(fixture.id1Key1Name, pibImpl)
            self.fail("Did not throw the expected exception")
        except Pib.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

        key11 = PibKeyImpl(fixture.id1Key1Name, fixture.id1Key1.buf(), pibImpl)

        try:
            PibKeyImpl(Name("/wrong"), pibImpl)
            self.fail("Did not throw the expected exception")
        except ValueError:
            pass
        else:
            self.fail("Did not throw the expected exception")

        try:
            PibKeyImpl(Name("/wrong"), fixture.id1Key1.buf(), pibImpl)
            self.fail("Did not throw the expected exception")
        except ValueError:
            pass
        else:
            self.fail("Did not throw the expected exception")

        wrongKey = Blob("")
        try:
            PibKeyImpl(fixture.id1Key2Name, wrongKey.toBytes(), pibImpl)
            self.fail("Did not throw the expected exception")
        except ValueError:
            pass
        else:
            self.fail("Did not throw the expected exception")

        key11.addCertificate(fixture.id1Key1Cert1)
        try:
            key11.addCertificate(fixture.id1Key2Cert1)
            self.fail("Did not throw the expected exception")
        except ValueError:
            pass
        else:
            self.fail("Did not throw the expected exception")

        try:
            key11.removeCertificate(fixture.id1Key2Cert1.getName())
            self.fail("Did not throw the expected exception")
        except ValueError:
            pass
        else:
            self.fail("Did not throw the expected exception")

        try:
            key11.getCertificate(fixture.id1Key2Cert1.getName())
            self.fail("Did not throw the expected exception")
        except ValueError:
            pass
        else:
            self.fail("Did not throw the expected exception")

        try:
            key11.setDefaultCertificate(fixture.id1Key2Cert1)
            self.fail("Did not throw the expected exception")
        except ValueError:
            pass
        else:
            self.fail("Did not throw the expected exception")

        try:
            key11.setDefaultCertificate(fixture.id1Key2Cert1.getName())
            self.fail("Did not throw the expected exception")
        except ValueError:
            pass
        else:
            self.fail("Did not throw the expected exception")

if __name__ == '__main__':
    ut.main(verbosity=2)

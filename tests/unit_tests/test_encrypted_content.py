# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt unit tests
# https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/encrypted-content.t.cpp
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
from pyndn import KeyLocator, KeyLocatorType, Name
from pyndn.util import Blob
from pyndn.encrypt import EncryptedContent
from pyndn.encrypt.algo import EncryptAlgorithmType

encrypted = bytearray([
0x82, 0x30, # EncryptedContent
  0x1c, 0x16, # KeyLocator
    0x07, 0x14, # Name
      0x08, 0x04,
        0x74, 0x65, 0x73, 0x74, # 'test'
      0x08, 0x03,
        0x6b, 0x65, 0x79, # 'key'
      0x08, 0x07,
        0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72, # 'locator'
  0x83, 0x01, # EncryptedAlgorithm
    0x03,
  0x85, 0x0a, # InitialVector
    0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73,
  0x84, 0x07, # EncryptedPayload
    0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
])

encryptedNoIv = bytearray([
0x82, 0x24, # EncryptedContent
  0x1c, 0x16, # KeyLocator
    0x07, 0x14, # Name
      0x08, 0x04,
        0x74, 0x65, 0x73, 0x74, # 'test'
      0x08, 0x03,
        0x6b, 0x65, 0x79, # 'key'
      0x08, 0x07,
        0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72, # 'locator'
  0x83, 0x01, # EncryptedAlgorithm
    0x03,
  0x84, 0x07, # EncryptedPayload
    0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
])

message = bytearray([
  0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
])

iv = bytearray([
  0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73
])

class TestEncryptedContent(ut.TestCase):
    def test_constructor(self):
        # Check default settings.
        content = EncryptedContent()
        self.assertEqual(content.getAlgorithmType(), None)
        self.assertTrue(content.getPayload().isNull())
        self.assertTrue(content.getInitialVector().isNull())
        self.assertEqual(content.getKeyLocator().getType(), None)

        # Check an encrypted content with IV.
        keyLocator = KeyLocator()
        keyLocator.setType(KeyLocatorType.KEYNAME)
        keyLocator.getKeyName().set("/test/key/locator")
        rsaOaepContent = EncryptedContent()
        rsaOaepContent.setAlgorithmType(EncryptAlgorithmType.RsaOaep).setKeyLocator(
          keyLocator).setPayload(Blob(message, False)).setInitialVector(Blob(iv, False))

        self.assertEqual(rsaOaepContent.getAlgorithmType(), EncryptAlgorithmType.RsaOaep)
        self.assertTrue(rsaOaepContent.getPayload().equals(Blob(message, False)))
        self.assertTrue(rsaOaepContent.getInitialVector().equals(Blob(iv, False)))
        self.assertTrue(rsaOaepContent.getKeyLocator().getType() != None)
        self.assertTrue(rsaOaepContent.getKeyLocator().getKeyName().equals(
          Name("/test/key/locator")))

        # Encoding.
        encryptedBlob = Blob(encrypted, False)
        encoded = rsaOaepContent.wireEncode()

        self.assertTrue(encryptedBlob.equals(encoded))

        # Decoding.
        rsaOaepContent2 = EncryptedContent()
        rsaOaepContent2.wireDecode(encryptedBlob)
        self.assertEqual(rsaOaepContent2.getAlgorithmType(), EncryptAlgorithmType.RsaOaep)
        self.assertTrue(rsaOaepContent2.getPayload().equals(Blob(message, False)))
        self.assertTrue(rsaOaepContent2.getInitialVector().equals(Blob(iv, False)))
        self.assertTrue(rsaOaepContent2.getKeyLocator().getType() != None)
        self.assertTrue(rsaOaepContent2.getKeyLocator().getKeyName().equals(
          Name("/test/key/locator")))

        # Check the no IV case.
        rsaOaepContentNoIv = EncryptedContent()
        rsaOaepContentNoIv.setAlgorithmType(EncryptAlgorithmType.RsaOaep).setKeyLocator(
          keyLocator).setPayload(Blob(message, False))
        self.assertEqual(rsaOaepContentNoIv.getAlgorithmType(), EncryptAlgorithmType.RsaOaep)
        self.assertTrue(rsaOaepContentNoIv.getPayload().equals(Blob(message, False)))
        self.assertTrue(rsaOaepContentNoIv.getInitialVector().isNull())
        self.assertTrue(rsaOaepContentNoIv.getKeyLocator().getType() != None)
        self.assertTrue(rsaOaepContentNoIv.getKeyLocator().getKeyName().equals(
          Name("/test/key/locator")))

        # Encoding.
        encryptedBlob2 = Blob(encryptedNoIv, False)
        encodedNoIv = rsaOaepContentNoIv.wireEncode()
        self.assertTrue(encryptedBlob2.equals(encodedNoIv))

        # Decoding.
        rsaOaepContentNoIv2 = EncryptedContent()
        rsaOaepContentNoIv2.wireDecode(encryptedBlob2)
        self.assertEqual(rsaOaepContentNoIv2.getAlgorithmType(), EncryptAlgorithmType.RsaOaep)
        self.assertTrue(rsaOaepContentNoIv2.getPayload().equals(Blob(message, False)))
        self.assertTrue(rsaOaepContentNoIv2.getInitialVector().isNull())
        self.assertTrue(rsaOaepContentNoIv2.getKeyLocator().getType() != None)
        self.assertTrue(rsaOaepContentNoIv2.getKeyLocator().getKeyName().equals(
          Name("/test/key/locator")))

    def test_decoding_error(self):
        encryptedContent = EncryptedContent()

        errorBlob1 = Blob(bytearray([
          0x1f, 0x30, # Wrong EncryptedContent (0x82, 0x24)
            0x1c, 0x16, # KeyLocator
              0x07, 0x14, # Name
                0x08, 0x04,
                  0x74, 0x65, 0x73, 0x74,
                0x08, 0x03,
                  0x6b, 0x65, 0x79,
                0x08, 0x07,
                  0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72,
            0x83, 0x01, # EncryptedAlgorithm
              0x00,
            0x85, 0x0a, # InitialVector
              0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73,
            0x84, 0x07, # EncryptedPayload
              0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
        ]), False)
        self.assertRaises(ValueError,
          lambda: encryptedContent.wireDecode(errorBlob1))

        errorBlob2 = Blob(bytearray([
          0x82, 0x30, # EncryptedContent
            0x1d, 0x16, # Wrong KeyLocator (0x1c, 0x16)
              0x07, 0x14, # Name
                0x08, 0x04,
                  0x74, 0x65, 0x73, 0x74,
                0x08, 0x03,
                  0x6b, 0x65, 0x79,
                0x08, 0x07,
                  0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72,
            0x83, 0x01, # EncryptedAlgorithm
              0x00,
            0x85, 0x0a, # InitialVector
              0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73,
            0x84, 0x07, # EncryptedPayload
              0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
        ]), False)
        self.assertRaises(ValueError,
          lambda: encryptedContent.wireDecode(errorBlob2))

        errorBlob3 = Blob(bytearray([
          0x82, 0x30, # EncryptedContent
            0x1c, 0x16, # KeyLocator
              0x07, 0x14, # Name
                0x08, 0x04,
                  0x74, 0x65, 0x73, 0x74,
                0x08, 0x03,
                  0x6b, 0x65, 0x79,
                0x08, 0x07,
                  0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72,
            0x1d, 0x01, # Wrong EncryptedAlgorithm (0x83, 0x01)
              0x00,
            0x85, 0x0a, # InitialVector
              0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73,
            0x84, 0x07, # EncryptedPayload
              0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
        ]), False)
        self.assertRaises(ValueError,
          lambda: encryptedContent.wireDecode(errorBlob3))

        errorBlob4 = Blob(bytearray([
          0x82, 0x30, # EncryptedContent
            0x1c, 0x16, # KeyLocator
              0x07, 0x14, # Name
                0x08, 0x04,
                  0x74, 0x65, 0x73, 0x74, # 'test'
                0x08, 0x03,
                  0x6b, 0x65, 0x79, # 'key'
                0x08, 0x07,
                  0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72, # 'locator'
            0x83, 0x01, # EncryptedAlgorithm
              0x00,
            0x1f, 0x0a, # InitialVector (0x84, 0x0a)
              0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73,
            0x84, 0x07, # EncryptedPayload
              0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
        ]), False)
        self.assertRaises(ValueError,
          lambda: encryptedContent.wireDecode(errorBlob4))

        errorBlob5 = Blob(bytearray([
          0x82, 0x30, # EncryptedContent
            0x1c, 0x16, # KeyLocator
              0x07, 0x14, # Name
                0x08, 0x04,
                  0x74, 0x65, 0x73, 0x74, # 'test'
                0x08, 0x03,
                  0x6b, 0x65, 0x79, # 'key'
                0x08, 0x07,
                  0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72, # 'locator'
            0x83, 0x01, # EncryptedAlgorithm
              0x00,
            0x85, 0x0a, # InitialVector
              0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73,
            0x21, 0x07, # EncryptedPayload (0x85, 0x07)
              0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
        ]), False)
        self.assertRaises(ValueError,
          lambda: encryptedContent.wireDecode(errorBlob5))

        errorBlob6 = Blob(bytearray([
          0x82, 0x00 # Empty EncryptedContent
        ]), False)
        self.assertRaises(ValueError,
          lambda: encryptedContent.wireDecode(errorBlob6))

    def test_setter_getter(self):
        content = EncryptedContent()
        self.assertEqual(content.getAlgorithmType(), None)
        self.assertTrue(content.getPayload().isNull())
        self.assertTrue(content.getInitialVector().isNull())
        self.assertEqual(content.getKeyLocator().getType(), None)

        content.setAlgorithmType(EncryptAlgorithmType.RsaOaep)
        self.assertEqual(content.getAlgorithmType(), EncryptAlgorithmType.RsaOaep)
        self.assertTrue(content.getPayload().isNull())
        self.assertTrue(content.getInitialVector().isNull())
        self.assertEqual(content.getKeyLocator().getType(), None)

        keyLocator = KeyLocator()
        keyLocator.setType(KeyLocatorType.KEYNAME)
        keyLocator.getKeyName().set("/test/key/locator")
        content.setKeyLocator(keyLocator)
        self.assertTrue(content.getKeyLocator().getType() != None)
        self.assertTrue(content.getKeyLocator().getKeyName().equals(
          Name("/test/key/locator")))
        self.assertTrue(content.getPayload().isNull())
        self.assertTrue(content.getInitialVector().isNull())

        content.setPayload(Blob(message, False))
        self.assertTrue(content.getPayload().equals(Blob(message, False)))

        content.setInitialVector(Blob(iv, False))
        self.assertTrue(content.getInitialVector().equals(Blob(iv, False)))

        encoded = content.wireEncode()
        contentBlob = Blob(encrypted, False)
        self.assertTrue(contentBlob.equals(encoded))

if __name__ == '__main__':
    ut.main(verbosity=2)

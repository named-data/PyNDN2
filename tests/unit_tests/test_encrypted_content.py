# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2016 Regents of the University of California.
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

ENCRYPTED = bytearray([
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

ENCRYPTED_NO_IV = bytearray([
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

MESSAGE = bytearray([
  0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
])

IV = bytearray([
  0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73
])

class TestEncryptedContent(ut.TestCase):
    def test_constructor(self):
        content = EncryptedContent()
        self.assertEqual(content.getAlgorithmType(), None)
        self.assertTrue(content.getPayload().isNull())
        self.assertTrue(content.getInitialVector().isNull())
        self.assertEqual(content.getKeyLocator().getType(), None)

        payload = Blob(MESSAGE, False)
        initialVector = Blob(IV, False)

        keyLocator = KeyLocator()
        keyLocator.setType(KeyLocatorType.KEYNAME)
        keyLocator.getKeyName().set("/test/key/locator")
        content.setAlgorithmType(EncryptAlgorithmType.RsaOaep).setKeyLocator(
          keyLocator).setPayload(payload).setInitialVector(initialVector)

        # Test the copy constructor.
        sha256RsaContent = EncryptedContent(content)
        contentPayload = sha256RsaContent.getPayload()
        contentInitialVector = sha256RsaContent.getInitialVector()

        self.assertEqual(sha256RsaContent.getAlgorithmType(), EncryptAlgorithmType.RsaOaep)
        self.assertTrue(contentPayload.equals(payload))
        self.assertTrue(contentInitialVector.equals(initialVector))
        self.assertTrue(sha256RsaContent.getKeyLocator().getType() != None)
        self.assertTrue(sha256RsaContent.getKeyLocator().getKeyName().equals(
          Name("/test/key/locator")))

        encryptedBlob = Blob(ENCRYPTED, False)
        encoded = sha256RsaContent.wireEncode()

        self.assertTrue(encryptedBlob.equals(encoded))

        sha256RsaContent = EncryptedContent()
        sha256RsaContent.wireDecode(encryptedBlob)
        contentPayload = sha256RsaContent.getPayload()
        contentInitialVector = sha256RsaContent.getInitialVector()

        self.assertEqual(sha256RsaContent.getAlgorithmType(), EncryptAlgorithmType.RsaOaep)
        self.assertTrue(contentPayload.equals(payload))
        self.assertTrue(contentInitialVector.equals(initialVector))
        self.assertTrue(sha256RsaContent.getKeyLocator().getType() != None)
        self.assertTrue(sha256RsaContent.getKeyLocator().getKeyName().equals(
          Name("/test/key/locator")))

        # Test no IV.
        sha256RsaContent = EncryptedContent()
        sha256RsaContent.setAlgorithmType(EncryptAlgorithmType.RsaOaep).setKeyLocator(
          keyLocator).setPayload(payload)
        contentPayload = sha256RsaContent.getPayload()

        self.assertEqual(sha256RsaContent.getAlgorithmType(), EncryptAlgorithmType.RsaOaep)
        self.assertTrue(contentPayload.equals(payload))
        self.assertTrue(sha256RsaContent.getInitialVector().isNull())
        self.assertTrue(sha256RsaContent.getKeyLocator().getType() != None)
        self.assertTrue(sha256RsaContent.getKeyLocator().getKeyName().equals(
          Name("/test/key/locator")))

        encryptedBlob = Blob(ENCRYPTED_NO_IV, False)
        encodedNoIv = sha256RsaContent.wireEncode()

        self.assertTrue(encryptedBlob.equals(encodedNoIv))

        sha256RsaContent = EncryptedContent()
        sha256RsaContent.wireDecode(encryptedBlob)
        contentPayloadNoIV = sha256RsaContent.getPayload()

        self.assertEqual(sha256RsaContent.getAlgorithmType(), EncryptAlgorithmType.RsaOaep)
        self.assertTrue(contentPayloadNoIV.equals(payload))
        self.assertTrue(sha256RsaContent.getInitialVector().isNull())
        self.assertTrue(sha256RsaContent.getKeyLocator().getType() != None)
        self.assertTrue(sha256RsaContent.getKeyLocator().getKeyName().equals(
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

        payload = Blob(MESSAGE, False)
        content.setPayload(payload)

        contentPayload = content.getPayload()
        self.assertTrue(contentPayload.equals(payload))

        initialVector = Blob(IV, False)
        content.setInitialVector(initialVector)

        contentInitialVector = content.getInitialVector()
        self.assertTrue(contentInitialVector.equals(initialVector))

        encoded = content.wireEncode()
        contentBlob = Blob(ENCRYPTED, False)

        self.assertTrue(contentBlob.equals(encoded))

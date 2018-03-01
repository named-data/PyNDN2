# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2018 Regents of the University of California.
# Author: Adeola Bannis <thecodemaiden@gmail.com>
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

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from pyndn import Name
from pyndn import Data
from pyndn import ContentType
from pyndn import KeyLocatorType
from pyndn import Sha256WithRsaSignature
from pyndn import GenericSignature
from pyndn.util import Blob
from test_utils import dump, CredentialStorage
import unittest as ut

# use Python 3's mock library if it's available
try:
    from unittest.mock import Mock
except ImportError:
    from mock import Mock

codedData = Blob(bytearray([
0x06, 0xCE, # NDN Data
  0x07, 0x0A, 0x08, 0x03, 0x6E, 0x64, 0x6E, 0x08, 0x03, 0x61, 0x62, 0x63, # Name
  0x14, 0x0A, # MetaInfo
    0x19, 0x02, 0x13, 0x88, # FreshnessPeriod
    0x1A, 0x04, # FinalBlockId
      0x08, 0x02, 0x00, 0x09, # NameComponent
  0x15, 0x08, 0x53, 0x55, 0x43, 0x43, 0x45, 0x53, 0x53, 0x21, # Content
  0x16, 0x28, # SignatureInfo
    0x1B, 0x01, 0x01, # SignatureType
    0x1C, 0x23, # KeyLocator
      0x07, 0x21, # Name
        0x08, 0x08, 0x74, 0x65, 0x73, 0x74, 0x6E, 0x61, 0x6D, 0x65,
        0x08, 0x03, 0x4B, 0x45, 0x59,
        0x08, 0x07, 0x44, 0x53, 0x4B, 0x2D, 0x31, 0x32, 0x33,
        0x08, 0x07, 0x49, 0x44, 0x2D, 0x43, 0x45, 0x52, 0x54,
  0x17, 0x80, # SignatureValue
    0x1A, 0x03, 0xC3, 0x9C, 0x4F, 0xC5, 0x5C, 0x36, 0xA2, 0xE7, 0x9C, 0xEE, 0x52, 0xFE, 0x45, 0xA7,
    0xE1, 0x0C, 0xFB, 0x95, 0xAC, 0xB4, 0x9B, 0xCC, 0xB6, 0xA0, 0xC3, 0x4A, 0xAA, 0x45, 0xBF, 0xBF,
    0xDF, 0x0B, 0x51, 0xD5, 0xA4, 0x8B, 0xF2, 0xAB, 0x45, 0x97, 0x1C, 0x24, 0xD8, 0xE2, 0xC2, 0x8A,
    0x4D, 0x40, 0x12, 0xD7, 0x77, 0x01, 0xEB, 0x74, 0x35, 0xF1, 0x4D, 0xDD, 0xD0, 0xF3, 0xA6, 0x9A,
    0xB7, 0xA4, 0xF1, 0x7F, 0xA7, 0x84, 0x34, 0xD7, 0x08, 0x25, 0x52, 0x80, 0x8B, 0x6C, 0x42, 0x93,
    0x04, 0x1E, 0x07, 0x1F, 0x4F, 0x76, 0x43, 0x18, 0xF2, 0xF8, 0x51, 0x1A, 0x56, 0xAF, 0xE6, 0xA9,
    0x31, 0xCB, 0x6C, 0x1C, 0x0A, 0xA4, 0x01, 0x10, 0xFC, 0xC8, 0x66, 0xCE, 0x2E, 0x9C, 0x0B, 0x2D,
    0x7F, 0xB4, 0x64, 0xA0, 0xEE, 0x22, 0x82, 0xC8, 0x34, 0xF7, 0x9A, 0xF5, 0x51, 0x12, 0x2A, 0x84,
1
  ]))

experimentalSignatureType = 100
experimentalSignatureInfo = Blob(bytearray([
0x16, 0x08, # SignatureInfo
  0x1B, 0x01, experimentalSignatureType, # SignatureType
  0x81, 0x03, 1, 2, 3 # Experimental info
  ]))

experimentalSignatureInfoNoSignatureType = Blob(bytearray([
0x16, 0x05, # SignatureInfo
  0x81, 0x03, 1, 2, 3 # Experimental info
  ]))

experimentalSignatureInfoBadTlv = Blob(bytearray([
0x16, 0x08, # SignatureInfo
  0x1B, 0x01, experimentalSignatureType, # SignatureType
  0x81, 0x10, 1, 2, 3 # Bad TLV encoding (length 0x10 doesn't match the value length.
  ]))

def dumpData(data):
    result = []
    result.append(dump("name:", data.getName().toUri()))
    if len(data.getContent()) > 0:
        result.append(dump("content (raw):", str(data.getContent())))
        result.append(dump("content (hex):", data.getContent().toHex()))
    else:
        result.append(dump("content: <empty>"))
    if not data.getMetaInfo().getType() == ContentType.BLOB:
        result.append(dump("metaInfo.type:",
             "LINK" if data.getMetaInfo().getType() == ContentType.LINK
             else "KEY" if data.getMetaInfo().getType() == ContentType.KEY
             else "unknown"))
    result.append(dump("metaInfo.freshnessPeriod (milliseconds):",
         data.getMetaInfo().getFreshnessPeriod()
         if data.getMetaInfo().getFreshnessPeriod() >= 0 else "<none>"))
    result.append(dump("metaInfo.finalBlockId:",
         data.getMetaInfo().getFinalBlockId().toEscapedString()
         if len(data.getMetaInfo().getFinalBlockId().getValue()) > 0
         else "<none>"))
    signature = data.getSignature()
    if isinstance(signature, Sha256WithRsaSignature):
        result.append(dump("signature.signature:",
             "<none>" if len(signature.getSignature()) == 0
                      else signature.getSignature().toHex()))
        if signature.getKeyLocator().getType() is not None:
            if (signature.getKeyLocator().getType() ==
                KeyLocatorType.KEY_LOCATOR_DIGEST):
                result.append(dump("signature.keyLocator: KeyLocatorDigest:",
                     signature.getKeyLocator().getKeyData().toHex()))
            elif signature.getKeyLocator().getType() == KeyLocatorType.KEYNAME:
                result.append(dump("signature.keyLocator: KeyName:",
                     signature.getKeyLocator().getKeyName().toUri()))
            else:
                result.append(dump("signature.keyLocator: <unrecognized KeyLocatorType"))
        else:
            result.append(dump("signature.keyLocator: <none>"))
    return result



initialDump = ['name: /ndn/abc',
        'content (raw): SUCCESS!',
        'content (hex): 5355434345535321',
        'metaInfo.freshnessPeriod (milliseconds): 5000.0',
        'metaInfo.finalBlockId: %00%09',
        'signature.signature: 1a03c39c4fc55c36a2e79cee52fe45a7e10cfb95acb49bccb6a0c34aaa45bfbfdf0b51d5a48bf2ab45971c24d8e2c28a4d4012d77701eb7435f14dddd0f3a69ab7a4f17fa78434d7082552808b6c4293041e071f4f764318f2f8511a56afe6a931cb6c1c0aa40110fcc866ce2e9c0b2d7fb464a0ee2282c834f79af551122a84',
        'signature.keyLocator: KeyName: /testname/KEY/DSK-123/ID-CERT']


def dataDumpsEqual(d1, d2):
    #ignoring signature, see if two data dumps are equal
    unequal_set = set(d1) ^ set(d2)
    for field in unequal_set:
        if not field.startswith('signature.signature:'):
            return False
    return True

class TestDataDump(ut.TestCase):
    def setUp(self):
        self.credentials = CredentialStorage()
        self.freshData = self.createFreshData()

    def createFreshData(self):
        freshData = Data(Name("/ndn/abc"))
        freshData.setContent("SUCCESS!")
        freshData.getMetaInfo().setFreshnessPeriod(5000.0)
        freshData.getMetaInfo().setFinalBlockId(Name("/%00%09")[0])

        # Initialize the storage.
        return freshData

    def test_dump(self):
        data = Data()
        data.wireDecode(codedData)
        self.assertEqual(dumpData(data), initialDump, 'Initial dump does not have expected format')

    def test_encode_decode(self):
        data = Data()
        data.wireDecode(codedData)
        data.setContent(data.getContent())
        encoding = data.wireEncode()

        reDecodedData = Data()
        reDecodedData.wireDecode(encoding)
        self.assertEqual(dumpData(reDecodedData), initialDump, 'Re-decoded data does not match original dump')

    def test_empty_signature(self):
        # make sure nothing is set in the signature of newly created data
        data = Data()
        signature = data.getSignature()
        self.assertIsNone(signature.getKeyLocator().getType(), 'Key locator type on unsigned data should not be set')
        self.assertTrue(signature.getSignature().isNull(), 'Non-empty signature on unsigned data')

    def test_copy_fields(self):
        data = Data(self.freshData.getName())
        data.setContent(self.freshData.getContent())
        data.setMetaInfo(self.freshData.getMetaInfo())
        self.credentials.signData(data)
        freshDump = dumpData(data)
        self.assertTrue(dataDumpsEqual(freshDump, initialDump), 'Freshly created data does not match original dump')

    def test_verify(self):
        # we create 'mock' objects to replace callbacks
        # since we're not interested in the effect of the callbacks themselves
        failedCallback = Mock()
        verifiedCallback = Mock()

        self.credentials.signData(self.freshData)

        self.credentials.verifyData(self.freshData, verifiedCallback, failedCallback)
        self.assertEqual(failedCallback.call_count, 0, 'Signature verification failed')
        self.assertEqual(verifiedCallback.call_count, 1, 'Verification callback was not used.')

    def test_verify_ecdsa(self):
        # we create 'mock' objects to replace callbacks
        # since we're not interested in the effect of the callbacks themselves
        failedCallback = Mock()
        verifiedCallback = Mock()

        self.credentials.signData(self.freshData, self.credentials.ecdsaCertName)

        self.credentials.verifyData(self.freshData, verifiedCallback, failedCallback)
        self.assertEqual(failedCallback.call_count, 0, 'Signature verification failed')
        self.assertEqual(verifiedCallback.call_count, 1, 'Verification callback was not used.')

    def test_verify_digest_sha256(self):
        # We create 'mock' objects to replace callbacks since we're not
        # interested in the effect of the callbacks themselves.
        failedCallback = Mock()
        verifiedCallback = Mock()

        self.credentials.signDataWithSha256(self.freshData)

        self.credentials.verifyData(self.freshData, verifiedCallback, failedCallback)
        self.assertEqual(failedCallback.call_count, 0, 'Signature verification failed')
        self.assertEqual(verifiedCallback.call_count, 1, 'Verification callback was not used.')

    def test_generic_signature(self):
        # Test correct encoding.
        signature = GenericSignature()
        signature.setSignatureInfoEncoding(
          Blob(experimentalSignatureInfo, False), None)
        signatureValue = Blob([1, 2, 3, 4], False)
        signature.setSignature(signatureValue)

        self.freshData.setSignature(signature)
        encoding = self.freshData.wireEncode()

        decodedData = Data()
        decodedData.wireDecode(encoding)

        decodedSignature = decodedData.getSignature()
        self.assertEqual(decodedSignature.getTypeCode(), experimentalSignatureType)
        self.assertTrue(Blob(experimentalSignatureInfo, False).equals
                        (decodedSignature.getSignatureInfoEncoding()))
        self.assertTrue(signatureValue.equals(decodedSignature.getSignature()))

        # Test bad encoding.
        signature = GenericSignature()
        signature.setSignatureInfoEncoding(
          Blob(experimentalSignatureInfoNoSignatureType, False), None)
        signature.setSignature(signatureValue)
        self.freshData.setSignature(signature)
        gotError = True
        try:
            self.freshData.wireEncode()
            gotError = False
        except:
            pass
        if not gotError:
          self.fail("Expected encoding error for experimentalSignatureInfoNoSignatureType")

        signature = GenericSignature()
        signature.setSignatureInfoEncoding(
          Blob(experimentalSignatureInfoBadTlv, False), None)
        signature.setSignature(signatureValue)
        self.freshData.setSignature(signature)
        gotError = True
        try:
            self.freshData.wireEncode()
            gotError = False
        except:
            pass
        if not gotError:
          self.fail("Expected encoding error for experimentalSignatureInfoBadTlv")

    def test_full_name(self):
        data = Data()
        data.wireDecode(codedData)

        # Check the full name format.
        self.assertEqual(data.getFullName().size(), data.getName().size() + 1)
        self.assertEqual(data.getName(), data.getFullName().getPrefix(-1))
        self.assertEqual(data.getFullName().get(-1).getValue().size(), 32)

        # Check the independent digest calculation.
        sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
        sha256.update(Blob(codedData).toBytes())
        newDigest = Blob(bytearray(sha256.finalize()), False)
        self.assertTrue(newDigest.equals(data.getFullName().get(-1).getValue()))

        # Check the expected URI.
        self.assertEqual(
          data.getFullName().toUri(), "/ndn/abc/sha256digest=" +
            "96556d685dcb1af04be4ae57f0e7223457d4055ea9b3d07c0d337bef4a8b3ee9")

        # Changing the Data packet should change the full name.
        saveFullName = Name(data.getFullName())
        data.setContent(Blob())
        self.assertNotEqual(data.getFullName().get(-1), saveFullName.get(-1))

if __name__ == '__main__':
    ut.main(verbosity=2)

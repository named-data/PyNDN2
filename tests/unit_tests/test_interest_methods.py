# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
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

#####
# dump method taken from test_encode_decode_interest
#####
import unittest as ut
from pyndn import Name
from pyndn import Interest
from pyndn import Exclude
from pyndn import KeyLocatorType
from pyndn import InterestFilter
from pyndn.util import Blob
from pyndn.security import KeyChain
from pyndn.security.identity import IdentityManager
from pyndn.security.identity import MemoryIdentityStorage
from pyndn.security.identity import MemoryPrivateKeyStorage
from pyndn.security.policy import SelfVerifyPolicyManager

from test_utils import dump

# use Python 3's mock library if it's available
try:
    from unittest.mock import Mock
except ImportError:
    from mock import Mock

codedInterest = Blob(bytearray([
0x05, 0x50, # Interest
  0x07, 0x0A, 0x08, 0x03, 0x6E, 0x64, 0x6E, 0x08, 0x03, 0x61, 0x62, 0x63, # Name
  0x09, 0x38, # Selectors
    0x0D, 0x01, 0x04, # MinSuffixComponents
    0x0E, 0x01, 0x06, # MaxSuffixComponents
    0x0F, 0x22, # KeyLocator
      0x1D, 0x20, # KeyLocatorDigest
                  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x10, 0x07, # Exclude
      0x08, 0x03, 0x61, 0x62, 0x63, # NameComponent
      0x13, 0x00, # Any
    0x11, 0x01, 0x01, # ChildSelector
    0x12, 0x00, # MustBeFesh
  0x0A, 0x04, 0x61, 0x62, 0x61, 0x62,   # Nonce
  0x0C, 0x02, 0x75, 0x30, # InterestLifetime
1
  ]))

initialDump = ['name: /ndn/abc',
        'minSuffixComponents: 4',
        'maxSuffixComponents: 6',
        'keyLocator: KeyLocatorDigest: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        'exclude: abc,*',
        'childSelector: 1',
        'mustBeFresh: True',
        'nonce: 61626162',
        'lifetimeMilliseconds: 30000.0']


def dumpInterest(interest):
    result = []
    result.append(dump("name:", interest.getName().toUri()))
    result.append(dump("minSuffixComponents:",
         interest.getMinSuffixComponents()
         if interest.getMinSuffixComponents() is not None else "<none>"))
    result.append(dump("maxSuffixComponents:",
         interest.getMaxSuffixComponents()
         if interest.getMaxSuffixComponents() is not None else "<none>"))
    if interest.getKeyLocator().getType() is not None:
        if (interest.getKeyLocator().getType() ==
            KeyLocatorType.KEY_LOCATOR_DIGEST):
            result.append(dump("keyLocator: KeyLocatorDigest:",
                 interest.getKeyLocator().getKeyData().toHex()))
        elif interest.getKeyLocator().getType() == KeyLocatorType.KEYNAME:
            result.append(dump("keyLocator: KeyName:",
                 interest.getKeyLocator().getKeyName().toUri()))
        else:
            result.append(dump("keyLocator: <unrecognized KeyLocatorType"))
    else:
        result.append(dump("keyLocator: <none>"))
    result.append(dump("exclude:",
         interest.getExclude().toUri()
         if len(interest.getExclude()) > 0 else "<none>"))
    result.append(dump("childSelector:",
         interest.getChildSelector()
         if interest.getChildSelector() is not None else "<none>"))
    result.append(dump("mustBeFresh:", interest.getMustBeFresh()))
    result.append(dump("nonce:", "<none>" if len(interest.getNonce()) == 0
                            else interest.getNonce().toHex()))
    result.append(dump("lifetimeMilliseconds:",
         "<none>" if interest.getInterestLifetimeMilliseconds() is None
                  else interest.getInterestLifetimeMilliseconds()))
    return result

def interestDumpsEqual(dump1, dump2):
    # ignoring nonce, check that the dumped interests are equal
    unequal_set = set(dump1) ^ set(dump2)
    for s in unequal_set:
        if not s.startswith('nonce:'):
            return False
    return True

def createFreshInterest():
    freshInterest = (Interest(Name("/ndn/abc"))
      .setMustBeFresh(False)
      .setMinSuffixComponents(4)
      .setMaxSuffixComponents(6)
      .setInterestLifetimeMilliseconds(30000)
      .setChildSelector(1)
      .setMustBeFresh(True))
    freshInterest.getKeyLocator().setType(KeyLocatorType.KEY_LOCATOR_DIGEST)
    freshInterest.getKeyLocator().setKeyData(bytearray(
      [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F]))
    freshInterest.getExclude().appendComponent(Name("abc")[0]).appendAny()

    return freshInterest


class TestInterestDump(ut.TestCase):
    def setUp(self):
        self.referenceInterest = Interest()
        self.referenceInterest.wireDecode(codedInterest)

    def test_dump(self):
        # see if the dump format is the same as we expect
        decodedDump = dumpInterest(self.referenceInterest)
        self.assertEqual(initialDump, decodedDump, 'Initial dump does not have expected format')

    def test_redecode(self):
        # check that we encode and decode correctly
        encoding = self.referenceInterest.wireEncode()
        reDecodedInterest = Interest()
        reDecodedInterest.wireDecode(encoding)
        redecodedDump = dumpInterest(reDecodedInterest)
        self.assertEqual(initialDump, redecodedDump, 'Re-decoded interest does not match original')

    def test_create_fresh(self):
        freshInterest = createFreshInterest()
        freshDump = dumpInterest(freshInterest)
        self.assertTrue(interestDumpsEqual(initialDump, freshDump), 'Fresh interest does not match original')

        reDecodedFreshInterest = Interest()
        reDecodedFreshInterest.wireDecode(freshInterest.wireEncode())
        reDecodedFreshDump = dumpInterest(reDecodedFreshInterest)

        self.assertTrue(interestDumpsEqual(freshDump, reDecodedFreshDump), 'Redecoded fresh interest does not match original')

class TestInterestMethods(ut.TestCase):
    def setUp(self):
        self.referenceInterest = Interest()
        self.referenceInterest.wireDecode(codedInterest)

    def test_copy_constructor(self):
        interest = Interest(self.referenceInterest)
        self.assertTrue(interestDumpsEqual(dumpInterest(interest), dumpInterest(self.referenceInterest)), 'Interest constructed as deep copy does not match original')

    def test_empty_nonce(self):
        # make sure a freshly created interest has no nonce
        freshInterest = createFreshInterest()
        self.assertTrue(freshInterest.getNonce().isNull(), 'Freshly created interest should not have a nonce')

    def test_set_removes_nonce(self):
        # Ensure that changing a value on an interest clears the nonce.
        self.assertFalse(self.referenceInterest.getNonce().isNull())
        interest = Interest(self.referenceInterest)
        # Change a child object.
        interest.getExclude().clear()
        self.assertTrue(interest.getNonce().isNull(), 'Interest should not have a nonce after changing fields')

    def test_exclude_matches(self):
        exclude = Exclude()
        exclude.appendComponent(Name("%00%02").get(0))
        exclude.appendAny()
        exclude.appendComponent(Name("%00%20").get(0))

        component = Name("%00%01").get(0)
        self.assertFalse(exclude.matches(component),
          component.toEscapedString() + " should not match " + exclude.toUri())
        component = Name("%00%0F").get(0)
        self.assertTrue(exclude.matches(component),
          component.toEscapedString() + " should match " + exclude.toUri())
        component = Name("%00%21").get(0)
        self.assertFalse(exclude.matches(component),
          component.toEscapedString() + " should not match " + exclude.toUri())

    def test_verify_digest_sha256(self):
        # Create a KeyChain but we don't need to add keys.
        identityStorage = MemoryIdentityStorage()
        keyChain = KeyChain(
          IdentityManager(identityStorage, MemoryPrivateKeyStorage()),
          SelfVerifyPolicyManager(identityStorage))

        interest = Interest(Name("/test/signed-interest"))
        keyChain.signWithSha256(interest)

        # We create 'mock' objects to replace callbacks since we're not
        # interested in the effect of the callbacks themselves.
        failedCallback = Mock()
        verifiedCallback = Mock()

        keyChain.verifyInterest(interest, verifiedCallback, failedCallback)
        self.assertEqual(failedCallback.call_count, 0, 'Signature verification failed')
        self.assertEqual(verifiedCallback.call_count, 1, 'Verification callback was not used.')

    def test_interest_filter_matching(self):
        self.assertEqual(True,  InterestFilter("/a").doesMatch(Name("/a/b")))
        self.assertEqual(True,  InterestFilter("/a/b").doesMatch(Name("/a/b")))
        self.assertEqual(False, InterestFilter("/a/b/c").doesMatch(Name("/a/b")))

        self.assertEqual(True,  InterestFilter("/a", "<b>").doesMatch(Name("/a/b")))
        self.assertEqual(False, InterestFilter("/a/b", "<b>").doesMatch(Name("/a/b")))

        self.assertEqual(False, InterestFilter("/a/b", "<c>").doesMatch(Name("/a/b/c/d")))
        self.assertEqual(False, InterestFilter("/a/b", "<b>").doesMatch(Name("/a/b/c/b")))
        self.assertEqual(True,  InterestFilter("/a/b", "<>*<b>").doesMatch(Name("/a/b/c/b")))

        self.assertEqual(False, InterestFilter("/a", "<b>").doesMatch(Name("/a/b/c/d")))
        self.assertEqual(True,  InterestFilter("/a", "<b><>*").doesMatch(Name("/a/b/c/d")))
        self.assertEqual(True,  InterestFilter("/a", "<b><>*").doesMatch(Name("/a/b")))
        self.assertEqual(False, InterestFilter("/a", "<b><>+").doesMatch(Name("/a/b")))
        self.assertEqual(True,  InterestFilter("/a", "<b><>+").doesMatch(Name("/a/b/c")))

if __name__ == '__main__':
    ut.main(verbosity=2)


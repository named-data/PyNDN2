#####
# dump method taken from test_encode_decode_interest
#####
import unittest as ut
from pyndn import Name
from pyndn import Interest
from pyndn import KeyLocatorType
from pyndn.util import Blob

from test_utils import dump

codedInterest = Blob(bytearray([
0x05, 0x53, # Interest
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
  0x0B, 0x01, 0x02, # Scope
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
        'scope: 2',
        'lifetimeMilliseconds: 30000.0']


def dumpInterest(interest):
    result = []
    result.append(dump("name:", interest.getName().toUri()))
    result.append(dump("minSuffixComponents:",
         interest.getMinSuffixComponents()
         if interest.getMinSuffixComponents() != None else "<none>"))
    result.append(dump("maxSuffixComponents:",
         interest.getMaxSuffixComponents()
         if interest.getMaxSuffixComponents() != None else "<none>"))
    if interest.getKeyLocator().getType() != None:
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
         if interest.getExclude().size() > 0 else "<none>"))
    result.append(dump("childSelector:",
         interest.getChildSelector()
         if interest.getChildSelector() != None else "<none>"))
    result.append(dump("mustBeFresh:", interest.getMustBeFresh()))
    result.append(dump("nonce:", "<none>" if interest.getNonce().size() == 0
                            else interest.getNonce().toHex()))
    result.append(dump("scope:", "<none>" if interest.getScope() == None
                            else interest.getScope()))
    result.append(dump("lifetimeMilliseconds:",
         "<none>" if interest.getInterestLifetimeMilliseconds() == None
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
    freshInterest = Interest(Name("/ndn/abc"))
    freshInterest.setMustBeFresh(False)
    freshInterest.setMinSuffixComponents(4)
    freshInterest.setMaxSuffixComponents(6)
    freshInterest.getKeyLocator().setType(KeyLocatorType.KEY_LOCATOR_DIGEST)
    freshInterest.getKeyLocator().setKeyData(bytearray(
      [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F]))
    freshInterest.getExclude().appendComponent(Name("abc")[0]).appendAny()
    freshInterest.setInterestLifetimeMilliseconds(30000)
    freshInterest.setChildSelector(1)
    freshInterest.setMustBeFresh(True);
    freshInterest.setScope(2)

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
        # ensure that setting a value on an interest clears the nonce
        self.assertFalse(self.referenceInterest.getNonce().isNull())
        interest = Interest(self.referenceInterest)
        interest.setChildSelector(0)
        self.assertTrue(interest.getNonce().isNull(), 'Interest should not have a nonce after changing fields')


if __name__ == '__main__':
    ut.main(verbosity=2)


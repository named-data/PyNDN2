# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

from pyndn import Name
from pyndn import Interest
from pyndn import KeyLocatorType
from pyndn.util import Blob

TlvInterest = Blob(bytearray([
0x05, 0x53, # Interest
  0x07, 0x0A, 0x08, 0x03, 0x6E, 0x64, 0x6E, 0x08, 0x03, 0x61, 0x62, 0x63, # Name
  0x09, 0x38, # Selectors
    0x0D, 0x01, 0x04, # MinSuffixComponents
    0x0E, 0x01, 0x06, # MaxSuffixComponents
    0x1C, 0x22, # KeyLocator
      0x1D, 0x20, # KeyLocatorDigest
                  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x10, 0x07, # Exclude
      0x08, 0x03, 0x61, 0x62, 0x63, # NameComponent
      0x13, 0x00, # Any
    0x11, 0x01, 0x01, # ChildSelector
    0x12, 0x00, # MustBeFesh
  0x0A, 0x04, 0x61, 0x62, 0x61, 0x62,	# Nonce
  0x0B, 0x01, 0x02, # Scope
  0x0C, 0x02, 0x75, 0x30, # InterestLifetime
1
  ]))

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str else repr(element)) + " "
    print(result)

def dumpInterest(interest):
    dump("name:", interest.getName().toUri())
    dump("minSuffixComponents:",
         interest.getMinSuffixComponents()
         if interest.getMinSuffixComponents() != None else "<none>")
    dump("maxSuffixComponents:",
         interest.getMaxSuffixComponents()
         if interest.getMaxSuffixComponents() != None else "<none>")
    if interest.getKeyLocator().getType() != None:
        if (interest.getKeyLocator().getType() == 
            KeyLocatorType.KEY_LOCATOR_DIGEST):
            dump("keyLocator: KeyLocatorDigest:",
                 interest.getKeyLocator().getKeyData().toHex())
        elif interest.getKeyLocator().getType() == KeyLocatorType.KEYNAME:
            dump("keyLocator: KeyName:",
                 interest.getKeyLocator().getKeyName().toUri())
        else:
            dump("keyLocator: <unrecognized KeyLocatorType")
    else:
        dump("keyLocator: <none>")
    dump("exclude:",
         interest.getExclude().toUri()
         if interest.getExclude().size() > 0 else "<none>")
    dump("childSelector:",
         interest.getChildSelector()
         if interest.getChildSelector() != None else "<none>")
    dump("mustBeFresh:", interest.getMustBeFresh())
    dump("nonce:", "<none>" if interest.getNonce().size() == 0
                            else interest.getNonce().toHex())
    dump("scope:", "<none>" if interest.getScope() == None
                            else interest.getScope())
    dump("lifetimeMilliseconds:",
         "<none>" if interest.getInterestLifetimeMilliseconds() == None
                  else interest.getInterestLifetimeMilliseconds())
  
def main():
    interest = Interest()
    interest.wireDecode(TlvInterest)
    dump("Interest:")
    dumpInterest(interest)
    
    encoding = interest.wireEncode()
    dump("")
    dump("Re-encoded interest", encoding.toHex())
    
    reDecodedInterest = Interest()
    reDecodedInterest.wireDecode(encoding)
    dump("Re-decoded Interest:")
    dumpInterest(reDecodedInterest)

    freshInterest = Interest(Name("/ndn/abc"))
    freshInterest.setMustBeFresh(False)
    dump(freshInterest.toUri())
    freshInterest.setMinSuffixComponents(4)
    freshInterest.setMaxSuffixComponents(6)
    freshInterest.getKeyLocator().setType(KeyLocatorType.KEY_LOCATOR_DIGEST)
    freshInterest.getKeyLocator().setKeyData(bytearray(
      [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F]))
    freshInterest.getExclude().appendComponent(Name("abc")[0]).appendAny()
    freshInterest.setInterestLifetimeMilliseconds(30000)
    freshInterest.setChildSelector(1)
    freshInterest.setScope(2)

    reDecodedFreshInterest = Interest()
    reDecodedFreshInterest.wireDecode(freshInterest.wireEncode())
    dump("")
    dump("Re-decoded fresh Interest:")
    dumpInterest(reDecodedFreshInterest)

main()

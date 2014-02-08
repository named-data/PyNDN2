from time import *
from pyndn import Interest
from pyndn.util import Blob

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str else `element`) + " "
    print result

def dumpInterest(interest):
    dump("name:", interest.getName().toUri())
    dump("nonce:", "<none>" if interest.getNonce().size() == 0 \
                            else interest.getNonce().toHex())
    dump("scope:", "<none>" if interest.getScope() == None \
                            else interest.getScope())
    dump("lifetimeMilliseconds:", \
         "<none>" if interest.getInterestLifetimeMilliseconds() == None \
                  else interest.getInterestLifetimeMilliseconds())
    
interest = Interest()
interest.getName().append(bytearray([65, 66, 67]))
interest.getName().append(bytearray([68, 69, 70]))
interest.setScope(1)
interest.setInterestLifetimeMilliseconds(123456789012345.0)
encoding = interest.wireEncode()
decodedInterest = Interest()
decodedInterest.wireDecode(encoding)
dumpInterest(decodedInterest)

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

from pyndn import Interest

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str or type(element) is unicode
                   else repr(element)) + " "
    print(result)

def dumpInterest(interest):
    dump("name:", interest.getName().toUri())
    dump("nonce:", "<none>" if interest.getNonce().size() == 0
                            else interest.getNonce().toHex())
    dump("scope:", "<none>" if interest.getScope() == None
                            else interest.getScope())
    dump("lifetimeMilliseconds:",
         "<none>" if interest.getInterestLifetimeMilliseconds() == None
                  else interest.getInterestLifetimeMilliseconds())
    
interest = Interest()
interest.getName().append("ABC").append("DEF")
interest.setScope(1)
interest.setInterestLifetimeMilliseconds(123456789012345.0)
encoding = interest.wireEncode()
decodedInterest = Interest()
decodedInterest.wireDecode(encoding.buf())
dumpInterest(decodedInterest)

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

import time
from pyndn import Name
from pyndn import Face

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str else repr(element)) + " "
    print(result)

class Counter(object):
    def __init__(self):
        self._callbackCount = 0

    def onData(self, interest, data):
        self._callbackCount += 1
        dump("Got data packet with name", data.getName().toUri())
        # Use join to convert each byte to chr.
        dump(data.getContent().toRawStr())

    def onTimeout(self, interest):
        self._callbackCount += 1
        dump("Time out for interest", interest.getName().toUri()) 

def main():
    face = Face("borges.metwi.ucla.edu")
    
    counter = Counter()

    name1 = Name("/ndn/edu/ucla/remap/ndn-js-test/howdy.txt/%FD%052%A1%DF%5E%A4"); 
    dump("Express name ", name1.toUri())
    face.expressInterest(name1, counter.onData, counter.onTimeout)

    # Try to get anything.
    name2 = Name("/"); 
    dump("Express name ", name2.toUri())
    face.expressInterest(name2, counter.onData, counter.onTimeout)

    # Expect this to time out.
    name3 = Name("/test/timeout"); 
    dump("Express name ", name3.toUri())
    face.expressInterest(name3, counter.onData, counter.onTimeout)

    while counter._callbackCount < 3:
        face.processEvents()
        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.01)    

    face.shutdown()

main()

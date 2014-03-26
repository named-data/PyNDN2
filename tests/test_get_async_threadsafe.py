# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

import asyncio
from pyndn import Name
from pyndn import ThreadsafeFace

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
    loop = asyncio.get_event_loop()
    face = ThreadsafeFace(loop, "spurs.cs.ucla.edu")

    counter = Counter()
    face.stopWhen(lambda: counter._callbackCount >= 1)

    name1 = Name("/"); 
    dump("Express name ", name1.toUri())
    # This call to exressIinterest is thread safe because face is a ThreadsafeFace.
    face.expressInterest(name1, counter.onData, counter.onTimeout)

    # Run until stopWhen stops the loop.
    loop.run_forever()
    face.shutdown()

main()

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

import time
from pyndn import Name
from pyndn import Interest
from pyndn.transport import TcpTransport
from pyndn.node import Node
from pyndn.encoding.tlv_wire_format import TlvWireFormat

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
        dump("".join(map(chr, data.getContent().buf())))

    def onTimeout(self, interest):
        self._callbackCount += 1
        dump("Time out for interest", interest.getName().toUri()) 

def main():
    node = Node(TcpTransport(), TcpTransport.ConnectionInfo("localhost"))
    
    counter = Counter()

    name1 = Name("/testzzz");    
    dump("Express name ", name1.toUri())
    interest = Interest(name1)
    interest.setInterestLifetimeMilliseconds(4000.0)
    node.expressInterest(interest, counter.onData, counter.onTimeout, TlvWireFormat.get())

    while counter._callbackCount < 1:
        node.processEvents()
        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.01)    

    node.shutdown()

main()

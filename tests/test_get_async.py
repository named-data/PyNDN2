# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

import time
from pyndn import Interest
from pyndn import Data
from pyndn.transport import TcpTransport

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str else repr(element)) + " "
    print(result)

class Counter(object):
    def __init__(self):
        self._callbackCount = 0

    def onReceivedData(self, input):
        self._callbackCount += 1
        data = Data()
        data.wireDecode(input)
        dump("Got data packet with name", data.getName().toUri())
        dump(bytearray(data.getContent().buf()).decode('ascii'))

counter = Counter()
transport = TcpTransport()
transport.connect(TcpTransport.ConnectionInfo("localhost"), counter)

interest = Interest()
interest.getName().append("ndn").append("ucla.edu").append("apps").append(
  "ndn-js-test").append("hello.txt")
dump("Sending interest", interest.getName().toUri())
transport.send(interest.wireEncode().toBuffer())

while counter._callbackCount == 0:
    transport.processEvents()
    # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
    time.sleep(0.01)    

transport.close()

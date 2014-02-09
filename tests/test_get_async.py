# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

import time
from pyndn import Interest
from pyndn.transport import TcpTransport

class Counter(object):
    def __init__(self):
        self._callbackCount = 0

    def onReceivedData(self, data):
        print "received len", len(data)
        self._callbackCount += 1

counter = Counter()
transport = TcpTransport()
transport.connect(TcpTransport.ConnectionInfo("localhost"), counter)

interest = Interest()
transport.send(interest.wireEncode().buf()._view)

while counter._callbackCount == 0:
    transport.processEvents()
    # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
    time.sleep(0.01)    

transport.close()

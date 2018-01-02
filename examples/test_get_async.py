# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
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

import time
from pyndn import Name
from pyndn import Face

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str else str(element)) + " "
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
    face = Face("memoria.ndn.ucla.edu")

    counter = Counter()

    # Try to fetch anything.
    name1 = Name("/")
    dump("Express name ", name1.toUri())
    face.expressInterest(name1, counter.onData, counter.onTimeout)

    # Try to fetch using a known name.
    name2 = Name("/ndn/edu/ucla/remap/demo/ndn-js-test/hello.txt/%FDX%DC5%1F")
    dump("Express name ", name2.toUri())
    face.expressInterest(name2, counter.onData, counter.onTimeout)

    # Expect this to time out.
    name3 = Name("/test/timeout")
    dump("Express name ", name3.toUri())
    face.expressInterest(name3, counter.onData, counter.onTimeout)

    while counter._callbackCount < 3:
        face.processEvents()
        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.01)

    face.shutdown()

main()

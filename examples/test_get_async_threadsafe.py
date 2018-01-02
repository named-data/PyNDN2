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

"""
This uses ThreadsafeFace to call expressInterest and show the content of the
fetched data packets. Because it uses ThreadsafeFace, the application doesn't
need to call processEvents.
"""

try:
    # Use builtin asyncio on Python 3.4+, or Tulip on Python 3.3
    import asyncio
except ImportError:
    # Use Trollius on Python <= 3.2
    import trollius as asyncio
from pyndn import Name
# We must explicitly import from threadsafe_face. The pyndn module doesn't
# automatically load it since asyncio is optional.
from pyndn.threadsafe_face import ThreadsafeFace

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str else str(element)) + " "
    print(result)

class Counter(object):
    """
    Counter counts the number of calls to the onData or onTimeout callbacks.
    Create a Counter to call loop.stop() after maxCallbackCount calls to
    onData or onTimeout.
    """
    def __init__(self, loop, maxCallbackCount):
        self._loop = loop
        self._maxCallbackCount = maxCallbackCount
        self._callbackCount = 0

    def onData(self, interest, data):
        dump("Got data packet with name", data.getName().toUri())
        # Use join to convert each byte to chr.
        dump(data.getContent().toRawStr())

        self._callbackCount += 1
        if self._callbackCount >= self._maxCallbackCount:
            self._loop.stop()

    def onTimeout(self, interest):
        dump("Time out for interest", interest.getName().toUri())

        self._callbackCount += 1
        if self._callbackCount >= self._maxCallbackCount:
            self._loop.stop()

def main():
    loop = asyncio.get_event_loop()
    face = ThreadsafeFace(loop, "memoria.ndn.ucla.edu")

    # Counter will stop the ioService after callbacks for all expressInterest.
    counter = Counter(loop, 3)

    # Try to fetch anything.
    name1 = Name("/")
    dump("Express name ", name1.toUri())
    # These call to exressIinterest is thread safe because face is a ThreadsafeFace.
    face.expressInterest(name1, counter.onData, counter.onTimeout)

    # Try to fetch using a known name.
    name2 = Name("/ndn/edu/ucla/remap/demo/ndn-js-test/hello.txt/%FDX%DC5%1F")
    dump("Express name ", name2.toUri())
    face.expressInterest(name2, counter.onData, counter.onTimeout)

    # Expect this to time out.
    name3 = Name("/test/timeout")
    dump("Express name ", name3.toUri())
    face.expressInterest(name3, counter.onData, counter.onTimeout)

    # Run until the Counter calls stop().
    loop.run_forever()
    face.shutdown()

main()

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2015 Regents of the University of California.
# Author: Adeola Bannis <thecodemaiden@gmail.com>
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

from pyndn import Name
from pyndn import Interest
from pyndn import Face
from pyndn import Data
from pyndn import Blob

from pyndn.security import KeyChain

import unittest as ut
import gevent
import time

# use Python 3's mock library if it's available
# else you'll have to pip install mock
try:
    from unittest.mock import Mock
except ImportError:
    from mock import Mock

def getNowMilliseconds():
    return time.time() * 1000.0


class TestFaceInterestMethods(ut.TestCase):
    def setUp(self):
        self.face = Face("localhost")

    def tearDown(self):
        self.face.shutdown()

    def run_express_name_test(self, interestName, timeout=12):
        # returns the dataCallback and timeoutCallback mock objects so we can test timeout behavior
        # as well as a bool for if we timed out without timeoutCallback being called
        name = Name(interestName)
        dataCallback = Mock()
        timeoutCallback = Mock()
        self.face.expressInterest(name, dataCallback, timeoutCallback)

        while True:
            self.face.processEvents()
            time.sleep(0.01)
            if (dataCallback.call_count > 0 or timeoutCallback.call_count > 0):
                break

        return dataCallback, timeoutCallback

    def test_any_interest(self):
        uri = "/"
        (dataCallback, timeoutCallback) = self.run_express_name_test(uri)
        self.assertTrue(timeoutCallback.call_count == 0 , 'Timeout on expressed interest')

        # check that the callback was correct
        self.assertEqual(dataCallback.call_count, 1, 'Expected 1 onData callback, got '+str(dataCallback.call_count))

        onDataArgs = dataCallback.call_args[0] # the args are returned as ([ordered arguments], [keyword arguments])

        #just check that the interest was returned correctly?
        callbackInterest = onDataArgs[0]
        self.assertTrue(callbackInterest.getName() == (Name(uri)), 'Interest returned on callback had different name')

    # TODO: Replace this with a test that connects to a Face on localhost
    #def test_specific_interest(self):
    #    uri = "/ndn/edu/ucla/remap/ndn-js-test/howdy.txt/%FD%052%A1%DF%5E%A4"
    #    (dataCallback, timeoutCallback) = self.run_express_name_test(uri)
    #    self.assertTrue(timeoutCallback.call_count == 0, 'Unexpected timeout on expressed interest')
    #
    #    # check that the callback was correct
    #    self.assertEqual(dataCallback.call_count, 1, 'Expected 1 onData callback, got '+str(dataCallback.call_count))

    #    onDataArgs = dataCallback.call_args[0] # the args are returned as ([ordered arguments], [keyword arguments])

    #    #just check that the interest was returned correctly?
    #    callbackInterest = onDataArgs[0]
    #    self.assertTrue(callbackInterest.getName() == Name(uri), 'Interest returned on callback had different name')

    def test_timeout(self):
        uri = "/test/timeout"
        (dataCallback, timeoutCallback) = self.run_express_name_test(uri)

        # we're expecting a timeout callback, and only 1
        self.assertTrue(dataCallback.call_count == 0, 'Data callback called for invalid interest')

        self.assertTrue(timeoutCallback.call_count == 1, 'Expected 1 timeout call, got ' + str(timeoutCallback.call_count))

        #check that the interest was returned correctly
        onTimeoutArgs = timeoutCallback.call_args[0] # the args are returned as ([ordered arguments], [keyword arguments])

        #just check that the interest was returned correctly?
        callbackInterest = onTimeoutArgs[0]
        self.assertTrue(callbackInterest.getName() == (Name(uri)), 'Interest returned on callback had different name')

    def test_remove_pending(self):
        name = Name("/ndn/edu/ucla/remap/")
        dataCallback = Mock()
        timeoutCallback = Mock()

        interestID = self.face.expressInterest(name, dataCallback, timeoutCallback)

        self.face.removePendingInterest(interestID)

        timeout = 10000
        startTime = getNowMilliseconds()
        while True:
            self.face.processEvents()
            time.sleep(0.01)
            if getNowMilliseconds() - startTime >= timeout:
                break
            if (dataCallback.call_count > 0 or timeoutCallback.call_count > 0):
                break

        self.assertEqual(dataCallback.call_count, 0, 'Should not have called data callback after interest was removed')
        self.assertEqual(timeoutCallback.call_count, 0, 'Should not have called timeout callback after interest was removed')

    def test_max_ndn_packet_size(self):
        # Construct an interest whose encoding is one byte larger than getMaxNdnPacketSize.
        targetSize = Face.getMaxNdnPacketSize() + 1
        # Start with an interest which is almost the right size.
        interest = Interest()
        interest.getName().append(bytearray(targetSize))
        initialSize = interest.wireEncode().size()
        # Now replace the component with the desired size which trims off the extra encoding.
        interest.setName(
          (Name().append(bytearray(targetSize - (initialSize - targetSize)))))
        interestSize = interest.wireEncode().size()
        self.assertEqual(targetSize, interestSize,
          "Wrong interest size for MaxNdnPacketSize")

        with self.assertRaises(RuntimeError):
            # If no error is raised, then expressInterest didn't throw an
            # exception when the interest size exceeds getMaxNdnPacketSize()
            self.face.expressInterest(interest, Mock(), Mock())

class TestFaceRegisterMethods(ut.TestCase):
    def setUp(self):
        self.face_in = Face()
        self.face_out = Face()
        self.keyChain = KeyChain()

    def tearDown(self):
        self.face_in.shutdown()
        self.face_out.shutdown()

    def onInterestEffect(self, prefix, interest, transport, prefixID):
        data = Data(interest.getName())
        data.setContent("SUCCESS")
        self.keyChain.sign(data, self.keyChain.getDefaultCertificateName())
        encodedData = data.wireEncode()
        transport.send(encodedData.toBuffer())

    def test_register_prefix_response(self):
        # gotta sign it (WAT)
        prefixName = Name("/test")
        self.face_in.setCommandSigningInfo(self.keyChain,
                self.keyChain.getDefaultCertificateName())

        failedCallback = Mock()
        interestCallback = Mock(side_effect=self.onInterestEffect)

        self.face_in.registerPrefix(prefixName, interestCallback, failedCallback)
        server = gevent.spawn(self.face_process_events, self.face_in, [interestCallback, failedCallback], 'h')

        time.sleep(1) # give the 'server' time to register the interest

        # express an interest on another face
        dataCallback = Mock()
        timeoutCallback = Mock()

        # now express an interest on this new face, and see if onInterest is called
        # Add the timestamp so it is unique and we don't get a cached response.
        interestName = prefixName.append("hello" + repr(time.time()))
        self.face_out.expressInterest(interestName, dataCallback, timeoutCallback)

        client = gevent.spawn(self.face_process_events, self.face_out, [dataCallback, timeoutCallback], 'c')

        gevent.joinall([server, client], timeout=10)

        self.assertEqual(failedCallback.call_count, 0, 'Failed to register prefix at all')

        self.assertEqual(interestCallback.call_count, 1, 'Expected 1 onInterest callback, got '+str(interestCallback.call_count))

        self.assertEqual(dataCallback.call_count, 1, 'Expected 1 onData callback, got '+str(dataCallback.call_count))

        onDataArgs = dataCallback.call_args[0]
        # check the message content
        data = onDataArgs[1]
        expectedBlob = Blob(bytearray("SUCCESS"))
        self.assertTrue(expectedBlob == data.getContent(), 'Data received on face does not match expected format')

    def face_process_events(self, face, callbacks, name=None):
        # implemented as a 'greenlet': something like a thread, but semi-synchronous
        # callbacks should be a list
        done = False
        while not done:
            face.processEvents()
            gevent.sleep()
            for c in callbacks:

                if (c.call_count > 0):
                    done = True

if __name__ == '__main__':
    ut.main(verbosity=2)

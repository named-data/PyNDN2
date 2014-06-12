from pyndn import Name
from pyndn import Face

import unittest as ut
import gevent
import time

# use Python 3's mock library if it's available
# else you'll have to pip install mock
try:
    from unittest.mock import Mock
except ImportError:
    from mock import Mock


class TestFaceInterestMethods(ut.TestCase):
    def setUp(self):
        self.face = Face("aleph.ndn.ucla.edu")

    def tearDown(self):
        self.face.shutdown()

    def run_express_name_test(self, interestName, timeout=12):
        # returns the dataCallback and timeoutCallback mock objects so we can test timeout behavior
        # as well as a bool for if we timed out without timeoutCallback being called
        name = Name(interestName)
        dataCallback = Mock()
        timeoutCallback = Mock()
        startTime = time.clock()
        self.face.expressInterest(name, dataCallback, timeoutCallback)
        
        currentTime = startTime
        while currentTime < startTime + timeout:
            self.face.processEvents()
            time.sleep(0.01)
            currentTime = time.clock()

            if (dataCallback.call_count > 0 or timeoutCallback.call_count > 0):
                break
        
        didTimeout = currentTime - startTime >= timeout
        return dataCallback, timeoutCallback, didTimeout



    def test_any_interest(self):
        uri = "/"
        (dataCallback, timeoutCallback, didTimeout) = self.run_express_name_test(uri)
        self.assertTrue(timeoutCallback.call_count == 0 and not didTimeout , 'Timeout on expressed interest')
        
        # check that the callback was correct
        self.assertEqual(dataCallback.call_count, 1, 'Data callback called more than once')

        onDataArgs = dataCallback.call_args[0] # the args are returned as ([ordered arguments], [keyword arguments])

        #just check that the interest was returned correctly?
        callbackInterest = onDataArgs[0]
        self.assertTrue(callbackInterest.getName().equals(Name(uri)), 'Interest returned on callback had different name')
        
    def test_specific_interest(self):
        uri = "/ndn/edu/ucla/remap/ndn-js-test/howdy.txt/%FD%052%A1%DF%5E%A4"
        (dataCallback, timeoutCallback, didTimeout) = self.run_express_name_test(uri)
        self.assertTrue(timeoutCallback.call_count == 0 and not didTimeout , 'Unexpected timeout on expressed interest')
        
        # check that the callback was correct
        self.assertEqual(dataCallback.call_count, 1, 'Data callback called more than once')

        onDataArgs = dataCallback.call_args[0] # the args are returned as ([ordered arguments], [keyword arguments])

        #just check that the interest was returned correctly?
        callbackInterest = onDataArgs[0]
        self.assertTrue(callbackInterest.getName().equals(Name(uri)), 'Interest returned on callback had different name')

    def test_timeout(self):
        uri = "/test/timeout"
        (dataCallback, timeoutCallback, didTimeout) = self.run_express_name_test(uri)

        # we're expecting a timeout callback, and only 1
        self.assertTrue(dataCallback.call_count == 0, 'Data callback called for invalid interest')

        self.assertFalse(didTimeout, 'Timeout forced before timeout callback called')

        self.assertTrue(timeoutCallback.call_count == 1, 'Expected 1 timeout call, got ' + str(timeoutCallback.call_count))

        #check that the interest was returned correctly
        onTimeoutArgs = timeoutCallback.call_args[0] # the args are returned as ([ordered arguments], [keyword arguments])

        #just check that the interest was returned correctly?
        callbackInterest = onTimeoutArgs[0]
        self.assertTrue(callbackInterest.getName().equals(Name(uri)), 'Interest returned on callback had different name')

    def test_remove_pending(self):
        name = Name("/ndn/edu/ucla/remap/")
        dataCallback = Mock()
        timeoutCallback = Mock()

        interestID = self.face.expressInterest(name, dataCallback, timeoutCallback)
        startTime = time.clock()
        currentTime = startTime
        timeout = 0.2
        while currentTime < startTime + timeout:
            self.face.processEvents()
            time.sleep(0.01)
            # hopefully a response takes more that 0.01s to come back...
            self.face.removePendingInterest(interestID)
            currentTime = time.clock()
            if (dataCallback.call_count > 0 or timeoutCallback.call_count > 0):
                break
        
        didTimeout = currentTime - startTime >= timeout

        self.assertEqual(dataCallback.call_count, 0, 'Should not have called data callback after interest was removed')
        self.assertEqual(timeoutCallback.call_count, 0, 'Should not have called timeout callback after interest was removed')
        

if __name__ == '__main__':
    suite = ut.TestLoader().loadTestsFromTestCase(TestFaceInterestMethods)
    ut.TextTestRunner(verbosity=2).run(suite)

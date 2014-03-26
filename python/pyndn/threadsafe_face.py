# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the ThreadsafeFace class which extends Face to provide the 
main methods for NDN communication in a threadsafe manner.
"""

from pyndn.face import Face

class ThreadsafeFace(Face):
    """
    Create a new ThreadsafeFace to use the asyncio loop to process events and
    schedule communication calls. This constructor schedules the event loop
    to process events, but you must start the loop on the thread in which
    you want the library to call communication callbacks such as onData and
    onInterest.
    In Python 2.7, you must have the prerequisite Trollius library. See the
    INSTALL file for installation details.
    """
    def __init__(self, loop, arg1, arg2 = None):
        super(ThreadsafeFace, self).__init__(arg1, arg2)
        self._loop = loop
        self._stopWhenTest = None
        
        # Schedule the _stopWhenCallback service, but _stopWhenTest is None so 
        #   it won't do anything yet.
        self._loop.call_soon(self._stopWhenCallback)
        
        # Schedule the main processEvents service.
        self._loop.call_soon(self._processEventsCallback)
        
    def expressInterest(
      self, interestOrName, arg2, arg3 = None, arg4 = None, arg5 = None):
        """
        Use the event loop given to the constructor to schedule expressInterest
        to be called in a threadsafe manner. See Face.expressInterest for 
        calling details.
        """
        self._loop.call_soon_threadsafe(
            super(ThreadsafeFace, self).expressInterest, interestOrName, arg2,
            arg3, arg4, arg5)
        
    def removePendingInterest(self, pendingInterestId):
        """
        Use the event loop given to the constructor to schedule 
        removePendingInterest to be called in a threadsafe manner. See 
        Face.removePendingInterest for calling details.
        """
        self._loop.call_soon_threadsafe(
            super(ThreadsafeFace, self).removePendingInterest, 
            pendingInterestId)
        
    def registerPrefix(
      self, prefix, onInterest, onRegisterFailed, flags = None, 
      wireFormat = None):
        """
        Use the event loop given to the constructor to schedule registerPrefix
        to be called in a threadsafe manner. See Face.registerPrefix for 
        calling details.
        """
        self._loop.call_soon_threadsafe(
            super(ThreadsafeFace, self).registerPrefix, prefix, onInterest, 
            onRegisterFailed, flags, wireFormat)
            
    def removeRegisteredPrefix(self, registeredPrefixId):
        """
        Use the event loop given to the constructor to schedule 
        removeRegisteredPrefix to be called in a threadsafe manner. See 
        Face.removeRegisteredPrefix for calling details.
        """
        self._loop.call_soon_threadsafe(
            super(ThreadsafeFace, self).removeRegisteredPrefix, 
            registeredPrefixId)
        
    def shutdown(self):
        """
        Unschedule the process events from being called in the event loop,
        then call Face.shutdown.
        """
        # This will shut down _processEventsCallback.
        self._loop == None
        super(ThreadsafeFace, self).shutdown()
        
    def stopWhen(self, test):
        """
        This is a utility to repeatedly call test and when it returns true, call 
        loop.stop() on the event loop given to the constructor.
        
        :param test: This calls test() which returns true to stop the event 
          loop. If test is None, then don't call test().
        :type test: function object        
        """
        # The _stopWhenCallback service is already running, so just set (or
        #   change) the test.
        self._stopWhenTest = test
        
    def _stopWhenCallback(self):
        """
        Repeatedly call self._stopWhenTest() (if not None) and when it returns 
        true, call self._loop.stop(). However, if self._loop is None (because of 
        shutdown), don't repeatedly call anymore.
        """
        if self._loop != None:
            stop = False
            try:
                if self._stopWhenTest != None and self._stopWhenTest():
                    stop = True
                    self._loop.stop()
            finally:
                if not stop:
                    # Call again, even if _stopWhenTest raised an exception.
                    self._loop.call_later(0.5, self._stopWhenCallback)

    def _processEventsCallback(self):
        """
        Repeatedly call self.processEvents() using self._loop. However, if
        self._loop is None (because of shutdown), don't repeatedly call 
        anymore.
        """
        if self._loop != None:
            try:
                self.processEvents()
            finally:
                # Call again, even if processEvents raised an exception.
                self._loop.call_later(0.01, self._processEventsCallback)
        
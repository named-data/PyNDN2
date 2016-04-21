# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2016 Regents of the University of California.
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
This module defines the ExponentialReExpress class which uses an internal
onTimeout to express the interest again with double the interestLifetime. See
ExponentialReExpress.makeOnTimeout, which you should call instead of the private
constructor. Create a new ExponentialReExpress where onTimeout expresses the
interest again with double the interestLifetime. If the interesLifetime goes
over settings.maxInterestLifetime, then call the given onTimeout. If this
internally gets onData, just call the given onData.
"""

import logging
from pyndn.interest import Interest

class ExponentialReExpress(object):
    def __init__(self, face, onData, onTimeout, maxInterestLifetime):
        self._face = face
        self._callerOnData = onData
        self._callerOnTimeout = onTimeout
        self._maxInterestLifetime = maxInterestLifetime

    @staticmethod
    def makeOnTimeout(face, onData, onTimeout, maxInterestLifetime = None):
        """
        Return a function object to use in expressInterest for onTimeout which
        will express the interest again with double the interestLifetime. If the
        interesLifetime goes over maxInterestLifetime (see below), then call the
        provided onTimeout. If a Data packet is received, this calls the
        provided onData. Use it like this:
        def onData: ...
        def onTimeout ...
        face.expressInterest(interest, onData,
        ExponentialReExpress.makeOnTimeout(face, onData, onTimeout))

        :param Face face: This calls face.expressInterest.
        :param onData: When a matching data packet is received, this calls
          onData(interest, data) where interest is the interest given to
          expressInterest and data is the received Data object. This is normally
          the same onData you initially passed to expressInterest.
          NOTE: The library will log any exceptions thrown by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onData: function object
        :param onTimeout: If the interesLifetime goes over maxInterestLifetime,
          this calls onTimeout(interest). However, if onTimeout is None, this
          does not use it.
          NOTE: The library will log any exceptions thrown by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onTimeout: function object
        :param float maxInterestLifetime: (optional) The maximum lifetime in
          milliseconds for re-expressed interests. If omitted, use 16000.
        """
        if maxInterestLifetime == None:
            maxInterestLifetime = 16000

        reExpress = ExponentialReExpress(face, onData, onTimeout, maxInterestLifetime)
        return reExpress._onTimeout

    def _onTimeout(self, interest):
        interestLifetime = interest.getInterestLifetimeMilliseconds()
        if interestLifetime == None:
            # Can't re-express.
            if self._callerOnTimeout != None:
                try:
                    self._callerOnTimeout(interest)
                except:
                    logging.exception("Error in onTimeout")
            return

        nextInterestLifetime = interestLifetime * 2
        if nextInterestLifetime > self._maxInterestLifetime:
            if self._callerOnTimeout != None:
                try:
                    self._callerOnTimeout(interest)
                except:
                    logging.exception("Error in onTimeout")
            return

        nextInterest = Interest(interest)
        nextInterest.setInterestLifetimeMilliseconds(nextInterestLifetime)
        self._face.expressInterest(
          nextInterest, self._callerOnData, self._onTimeout)

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/validation-policy-command-interest.cpp
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
This module defines the ValidationPolicyCommandInterest class which extends
ValidationPolicy as a policy for stop-and-wait command Interests. See:
https://redmine.named-data.net/projects/ndn-cxx/wiki/CommandInterest

This policy checks the timestamp field of a stop-and-wait command Interest.
Signed Interest validation and Data validation requests are delegated to an
inner policy.
"""

from pyndn.name import Name
from pyndn.data import Data
from pyndn.util.common import Common
from pyndn.security.command_interest_signer import CommandInterestSigner
from pyndn.security.v2.validation_error import ValidationError
from pyndn.security.v2.validation_policy import ValidationPolicy

class ValidationPolicyCommandInterest(ValidationPolicy):
    """
    Create a ValidationPolicyCommandInterest.

    :param ValidationPolicy innerPolicy: a ValidationPolicy for signed Interest
      signature validation and Data validation. This must not be None.
    :param ValidationPolicyCommandInterest.Options options: (optional) The
      stop-and-wait command Interest validation options. If omitted, use a
      default Options().
    :raises: ValueError if innerPolicy is None.
    """
    def __init__(self, innerPolicy, options = None):
        super(ValidationPolicyCommandInterest, self).__init__()

        if options == None:
            self._options = ValidationPolicyCommandInterest.Options()
        else:
            # Copy the Options.
            self._options = ValidationPolicyCommandInterest.Options(options)

        self._container = [] # of ValidationPolicyCommandInterest.LastTimestampRecord
        self._nowOffsetMilliseconds = 0

        if innerPolicy == None:
            raise ValueError("inner policy is missing")

        self.setInnerPolicy(innerPolicy)

        if self._options._gracePeriod < 0.0:
            self._options._gracePeriod = 0.0

    class Options(object):
        """
        Create a ValidationPolicyCommandInterest.Options with the values.

        :param gracePeriodOrOptions: (optional) The tolerance of the initial
          timestamp in milliseconds. (However, if this is another
          ValidationPolicyCommandInterest.Options, then copy values from it.) If
          omitted, use a grace period of 2 minutes. A stop-and-wait command
          Interest is considered "initial" if the validator has not recorded the
          last timestamp from the same public key, or when such knowledge has
          been erased. For an initial command Interest, its timestamp is
          compared to the current system clock, and the command Interest is
          rejected if the absolute difference is greater than the grace
          interval. The grace period should be positive. Setting this option to
          0 or negative causes the validator to require exactly the same
          timestamp as the system clock, which most likely rejects all command
          Interests.
        :type gracePeriodOrOptions: float or ValidationPolicyCommandInterest.Options
        :param int maxRecords: (optional) The maximum number of distinct public
          keys of which to record the last timestamp. If omitted, use 1000. The
          validator records the last timestamps for every public key. For a
          subsequent command Interest using the same public key, its timestamp
          is compared to the last timestamp from that public key, and the
          command Interest is rejected if its timestamp is less than or equal to
          the recorded timestamp. This option limits the number of distinct
          public keys being tracked. If the limit is exceeded, then the oldest
          record is deleted. Setting max records to -1 allows tracking unlimited
          public keys. Setting max records to 0 disables using last timestamp
          records and causes every command Interest to be processed as initial.
        :param float recordLifetime: (optional) The maximum lifetime of a last
          timestamp record in milliseconds. If omitted, use 1 hour. A last
          timestamp record expires and can be deleted if it has not been
          refreshed within the record lifetime. Setting the record lifetime to 0
          or negative makes last timestamp records expire immediately and causes
          every command Interest to be processed as initial.
        """
        def __init__(self, gracePeriodOrOptions = None, maxRecords = None,
                     recordLifetime = None):
            if isinstance(gracePeriodOrOptions, ValidationPolicyCommandInterest.Options):
                # The copy constructor.
                options = gracePeriodOrOptions

                self._gracePeriod = options._gracePeriod
                self._maxRecords = options._maxRecords
                self._recordLifetime = options._recordLifetime
            else:
                gracePeriod = gracePeriodOrOptions

                if gracePeriod == None:
                    gracePeriod = 2 * 60 * 1000.0
                if maxRecords == None:
                    maxRecords = 1000
                if recordLifetime == None:
                    recordLifetime = 3600 * 1000.0

                self._gracePeriod = gracePeriod
                self._maxRecords = maxRecords
                self._recordLifetime = recordLifetime

    def checkPolicy(self, dataOrInterest, state, continueValidation):
        """
        :param dataOrInterest:
        :type dataOrInterest: Data or Interest
        :param ValidationState state:
        :param continueValidation:
        :type continueValidation: function object
        """
        if isinstance(dataOrInterest, Data):
            data = dataOrInterest
            self.getInnerPolicy().checkPolicy(data, state, continueValidation)
        else:
            interest = dataOrInterest

            keyName = [None]
            timestamp = [0]
            if not ValidationPolicyCommandInterest._parseCommandInterest(
                interest, state, keyName, timestamp):
                return

            if not self._checkTimestamp(state, keyName[0], timestamp[0]):
                return

            self.getInnerPolicy().checkPolicy(interest, state, continueValidation)

    def _setNowOffsetMilliseconds(self, nowOffsetMilliseconds):
        """
        Set the offset when _insertNewRecord() and _cleanUp() get the current
        time, which should only be used for testing.

        :param float nowOffsetMilliseconds: The offset in milliseconds.
        """
        self._nowOffsetMilliseconds = nowOffsetMilliseconds

    class LastTimestampRecord(object):
        """
        :param Name keyName:
        :param float timestamp:
        :param float lastRefreshed:
        """
        def __init__(self, keyName, timestamp, lastRefreshed):
            # Copy the Name.
            self._keyName = Name(keyName)
            self._timestamp = timestamp
            self._lastRefreshed = lastRefreshed

    def _cleanUp(self):
        # _nowOffsetMilliseconds is only used for testing.
        now = Common.getNowMilliseconds() + self._nowOffsetMilliseconds
        expiring = now - self._options._recordLifetime

        while ((len(self._container) > 0 and
                 self._container[0]._lastRefreshed <= expiring) or
               (self._options._maxRecords >= 0 and
                 len(self._container) > self._options._maxRecords)):
            self._container.pop(0)

    @staticmethod
    def _parseCommandInterest(interest, state, keyLocatorName, timestamp):
        """
        Get the keyLocatorName and timestamp from the command interest.

        :param Interest interest: The Interest to parse.
        :param ValidationState state: On error, this calls state.fail and
          returns False.
        :param Array<Name> keyLocatorName: Set keyLocatorName[0] to the
          KeyLocator name.
        :param Array<float> timestamp: Set timestamp[0] to the timestamp as
          milliseconds since Jan 1, 1970 UTC.
        :return: On success, return True. On error, call state.fail and return
          False.
        :rtype: bool
        """
        keyLocatorName[0] = Name()
        timestamp[0] = 0

        name = interest.getName()
        if name.size() < CommandInterestSigner.MINIMUM_SIZE:
            state.fail(ValidationError(ValidationError.POLICY_ERROR,
              "Command interest name `" + interest.getName().toUri() +
              "` is too short"))
            return False

        timestamp[0] = name.get(CommandInterestSigner.POS_TIMESTAMP).toNumber()

        keyLocatorName[0] = ValidationPolicy.getKeyLocatorName(interest, state)
        if state.isOutcomeFailed():
            # Already failed.
            return False

        return True

    def _checkTimestamp(self, state, keyName, timestamp):
        """
        :param ValidationState state: On error, this calls state.fail and
          returns False.
        :param Name keyName: The key name.
        :param float timestamp: The timestamp as milliseconds since Jan 1, 1970 UTC.
        :return: On success, return True. On error, call state.fail and return
          False.
        :rtype: bool
        """
        self._cleanUp()

        # _nowOffsetMilliseconds is only used for testing.
        now = Common.getNowMilliseconds() + self._nowOffsetMilliseconds
        if (timestamp < now - self._options._gracePeriod or
              timestamp > now + self._options._gracePeriod):
            state.fail(ValidationError(ValidationError.POLICY_ERROR,
              "Timestamp is outside the grace period for key " + keyName.toUri()))
            return False

        index = self._findByKeyName(keyName)
        if index >= 0:
            if timestamp <= self._container[index]._timestamp:
                state.fail(ValidationError(ValidationError.POLICY_ERROR,
                  "Timestamp is reordered for key " + keyName.toUri()))
                return False

        def successCallback(interest):
            self._insertNewRecord(interest, keyName, timestamp)

        state.addSuccessCallback(successCallback)

        return True

    def _insertNewRecord(self, interest, keyName, timestamp):
        """
        :param Interest interest:
        :param Name keyName:
        :param float timestamp:
        """
        # _nowOffsetMilliseconds is only used for testing.
        now = Common.getNowMilliseconds() + self._nowOffsetMilliseconds
        newRecord = ValidationPolicyCommandInterest.LastTimestampRecord(
          keyName, timestamp, now)

        index = self._findByKeyName(keyName)
        if index >= 0:
            # Remove the existing record so we can move it to the end.
            self._container.pop(index)

        self._container.append(newRecord)

    def _findByKeyName(self, keyName):
        """
        Find the record in container_ which has the keyName.

        :param Name keyName: The key name to search for.
        :return: The index in container_ of the record, or -1 if not found.
        :rtype: int
        """
        for i in range(len(self._container)):
            if self._container[i]._keyName.equals(keyName):
                return i

        return -1

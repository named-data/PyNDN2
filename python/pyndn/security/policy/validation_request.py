# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
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
This module defines the ValidationRequest class which is used to return
information from PolicyManager.checkVerificationPolicy.
"""

class ValidationRequest(object):
    """
    Create a new ValidationRequest with the given values.

    :param Interest interest: An interest for fetching more data.
    :param onVerified: If the signature is verified, this calls
      onVerified(data).
    :type onVerified: function object
    :param onVerifyFailed: If the signature check fails, this calls
      onVerifyFailed(data).
    :type onVerifyFailed: function object
    :param int retry:
    :param int stepCount: The number of verification steps that have been done,
       used to track the verification progress.
    """
    def __init__(self, interest, onVerified, onVerifyFailed, retry, stepCount):
        self.interest = interest
        self.onVerified = onVerified
        self.onVerifyFailed = onVerifyFailed
        self.retry = retry
        self.stepCount = stepCount

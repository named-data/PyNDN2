# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

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
        
# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

from pyndn.security.policy.policy_manager import PolicyManager

class NoVerifyPolicyManager(PolicyManager):

    def skipVerifyAndTrust(self, data):
        """
        Override to always skip verification and trust as valid.

        :param Data data: The received data packet.
        :return: True.
        :rtype: boolean
        """
        return True

    def requireVerify(self, data):
        """
        Override to return false for no verification rule for the received data.

        :param Data data: The received data packet.
        :return: False.
        :rtype: boolean
        """
        return False

    def checkVerificationPolicy(self, data, stepCount, onVerified, 
                                onVerifyFailed):
        """
        Override to call onVerified(data) and to indicate no further 
        verification step.

        :param Data data: The Data object with the signature to check.
        :param int stepCount: The number of verification steps that have been 
          done, used to track the verification progress. (stepCount is ignored.)
        :param onVerified: This does override to call onVerified(data).
        :type onVerified: function object
        :param onVerifyFailed: Override to ignore this.
        :type onVerifyFailed: function object
        :return: None for no further step for looking up a certificate chain.
        :rtype: ValidationRequest
        """
        onVerified(data)
        return None
          
    def checkSigningPolicy(self, dataName, certificateName):
        """
        Override to always indicate that the signing certificate name and data 
        name satisfy the signing policy.

        :param Name dataName: The name of data to be signed.
        :param Name certificateName: The name of signing certificate.
        :return: True to indicate that the signing certificate can be used to 
          sign the data.
        :rtype: boolean
        """
        return True
        
    def inferSigningIdentity(self, dataName):
        """
        Override to indicate that the signing identity cannot be inferred.

        :param Name dataName: The name of data to be signed.
        :return: An empty name because cannot infer. 
        :rtype: Name
        """
        return Name()

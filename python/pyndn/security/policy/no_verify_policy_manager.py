# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
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
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU General Public License is in the file COPYING.

from pyndn.security.policy.policy_manager import PolicyManager

class NoVerifyPolicyManager(PolicyManager):

    def skipVerifyAndTrust(self, dataOrInterest):
        """
        Override to always skip verification and trust as valid.

        :param dataOrInterest: The received data packet or interest.
        :type dataOrInterest: Data or Interest
        :return: True.
        :rtype: boolean
        """
        return True

    def requireVerify(self, dataOrInterest):
        """
        Override to return false for no verification rule for the received data
        or signed interest.

        :param dataOrInterest: The received data packet or interest.
        :type dataOrInterest: Data or Interest
        :return: False.
        :rtype: boolean
        """
        return False

    def checkVerificationPolicy(self, dataOrInterest, stepCount, onVerified,
                                onVerifyFailed, wireFormat = None):
        """
        Override to call onVerified(dataOrInterest) and to indicate no further
        verification step.

        :param dataOrInterest: The Data object or interest with the signature
          (to ignore).
        :type dataOrInterest: Data or Interest
        :param int stepCount: The number of verification steps that have been 
          done, used to track the verification progress. (stepCount is ignored.)
        :param onVerified: This does override to call onVerified(dataOrInterest).
        :type onVerified: function object
        :param onVerifyFailed: Override to ignore this.
        :type onVerifyFailed: function object
        :return: None for no further step for looking up a certificate chain.
        :rtype: ValidationRequest
        """
        onVerified(dataOrInterest)
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

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

"""
This module defines the PolicyManager class which is an abstract base class to 
represent the policy for verifying data packets. You must create an object of a 
subclass.
"""

class PolicyManager(object):
    def skipVerifyAndTrust(self, dataOrInterest):
        """
        Check if the received data packet or signed interest can escape from
        verification and be trusted as valid.
        Your derived class should override.

        :param dataOrInterest: The received data packet or interest.
        :type dataOrInterest: Data or Interest
        :return: True if the data or interest does not need to be verified to be
          trusted as valid, otherwise False.
        :rtype: boolean
        :raises RuntimeError: for unimplemented if the derived class does not 
          override.
        """
        raise RuntimeError("skipVerifyAndTrust is not implemented")

    def requireVerify(self, dataOrInterest):
        """
        Check if this PolicyManager has a verification rule for the received 
        data packet or signed interest.
        Your derived class should override.

        :param dataOrInterest: The received data packet or interest.
        :type dataOrInterest: Data or Interest
        :return: True if the data or interest must be verified, otherwise False.
        :rtype: boolean
        :raises RuntimeError: for unimplemented if the derived class does not 
          override.
        """
        raise RuntimeError("requireVerify is not implemented")

    def checkVerificationPolicy(self, dataOrInterest, stepCount, onVerified,
                                onVerifyFailed, wireFormat = None):
        """
        Check whether the received data packet complies with the verification 
        policy, and get the indication of the next verification step.
        Your derived class should override.

        :param dataOrInterest: The Data object or interest with the signature to
          check.
        :type dataOrInterest: Data or Interest
        :param int stepCount: The number of verification steps that have been 
          done, used to track the verification progress.
        :param onVerified: If the signature is verified, this calls 
          onVerified(dataOrInterest).
        :type onVerified: function object
        :param onVerifyFailed: If the signature check fails, this calls 
          onVerifyFailed(dataOrInterest).
        :type onVerifyFailed: function object
        :return: The indication of next verification step, or None if there is 
          no further step.
        :rtype: ValidationRequest
        :raises RuntimeError: for unimplemented if the derived class does not 
          override.
        """
        raise RuntimeError("checkVerificationPolicy is not implemented")
        
    def checkSigningPolicy(self, dataName, certificateName):
        """
        Check if the signing certificate name and data name satisfy the signing 
        policy.
        Your derived class should override.

        :param Name dataName: The name of data to be signed.
        :param Name certificateName: The name of signing certificate.
        :return: True if the signing certificate can be used to sign the data, 
          otherwise False.
        :rtype: boolean
        :raises RuntimeError: for unimplemented if the derived class does not 
          override.
        """
        raise RuntimeError("checkSigningPolicy is not implemented")
        
    def inferSigningIdentity(self, dataName):
        """
        Infer the signing identity name according to the policy. If the signing 
        identity cannot be inferred, return an empty name.
        Your derived class should override.

        :param Name dataName: The name of data to be signed.
        :return: The signing identity or an empty name if cannot infer. 
        :rtype: Name
        :raises RuntimeError: for unimplemented if the derived class does not 
          override.
        """
        raise RuntimeError("inferSigningIdentity is not implemented")

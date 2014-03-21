# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the KeyChain class which provides a set of interfaces to the
security library such as identity management, policy configuration  and packet 
signing and verification.
Note: This class is an experimental feature. See the API docs for more detail at
  http://named-data.net/doc/ndn-ccl-api/key-chain.html .
"""

class KeyChain(object):
    """
    Create a new KeyChain to use the identityManager and policyManager.
    
    :param IdentityManager identityManager: The identity manager as a subclass
      of IdentityManager.
    :param PolicyManager policyManager: The policy manager as a subclass of 
      PolicyManager.
    """
    def __init__(self, identityManager, policyManager):
        self._identityManager = identityManager
        self._policyManager = policyManager
        self._face = None
        self._maxSteps = 100
    
    def sign(self, data, certificateName, wireFormat = None):
        """
        Wire encode the Data object, sign it and set its signature.
        
        :param Data data: The Data object to be signed. This updates its 
          signature and key locator field and wireEncoding.
        :param Name certificateName: The certificate name of the key to use for 
          signing.
        :param wireFormat: (optional) A WireFormat object used to encode the 
           Data object. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        """
        self._identityManager.signByCertificate(
          data, certificateName, wireFormat)
          
          
    def verifyData(self, data, onVerified, onVerifyFailed, stepCount = 0):
        """
        Check the signature on the Data object and call either onVerify or 
        onVerifyFailed. We use callback functions because verify may fetch 
        information to check the signature.
        
        :param Data data: The Data object with the signature to check. It is an 
          error if data does not have a wireEncoding. To set the wireEncoding, 
          you can call data.wireDecode.
        :param onVerified: If the signature is verified, this calls 
          onVerified(data).
        :type onVerified: function object
        :param onVerifyFailed: If the signature check fails or can't find the 
          public key, this calls onVerifyFailed(data).
        :type onVerifyFailed: function object
        :param int stepCount: (optional) The number of verification steps that 
          have been done. If omitted, use 0.
        :return: 
        :rtype: boolean
        """
        if self._policyManager.requireVerify(data):
            nextStep = self._policyManager.checkVerificationPolicy(
              data, stepCount, onVerified, onVerifyFailed)
            if nextStep != None:
                self._face.expressInterest(
                  nextStep.interest, self._makeOnCertificateData(nextStep),
                  self._makeOnCertificateInterestTimeout(
                    nextStep.retry, onVerifyFailed, data, nextStep))
        elif self._policyManager.skipVerifyAndTrust(data):
            onVerified(data)
        else:
            onVerifyFailed(data)
            
    def _makeOnCertificateData(self, nextStep):
        """
        Make and return an onData callback to use in expressInterest.
        """
        def onData(interest, data):
            # Try to verify the certificate (data) according to the parameters 
            #   in nextStep.
            self.verifyData(data, nextStep.onVerified, nextStep.onVerifyFailed, 
                            nextStep.stepCount)
        return onData

    def _makeOnCertificateInterestTimeout(self, retry, onVerifyFailed, data, 
                                          nextStep):
        """
        Make and return an onTimeout callback to use in expressInterest.
        """
        def onTimeout(interest):
            if retry > 0:
                # Issue the same expressInterest as in verifyData except 
                #   decrement retry.
                self._face.expressInterest(
                  interest, self._makeOnCertificateData(nextStep), 
                     self._makeOnCertificateInterestTimeout(
                       retry, onVerifyFailed, data, nextStep))
            else:
                onVerifyFailed(data);
        return onTimeout
            
            
    def setFace(self, face):
        """
        Set the Face which will be used to fetch required certificates.
        
        :param Face face: The Face object.
        """
        self._face = face
        
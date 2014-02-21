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
"""

class KeyChain(object):
    """
    Create a new KeyChain to use the identityManager and policyManager.
    
    :param identityManager: The identity manager.
    :type identityManager: IdentityManager
    :param policyManager: The policy manager.
    :type policyManager: PolicyManager
    """
    def __init__(self, identityManager, policyManager):
        self._identityManager = identityManager
        self._policyManager = policyManager
        self._face = None
        self._maxSteps = 100
    
    def sign(self, data, certificateName, wireFormat = None):
        """
        Wire encode the Data object, sign it and set its signature.
        
        :param data: The Data object to be signed. This updates its signature 
          and key locator field and wireEncoding.
        :type data: Data
        :param certificateName: The certificate name of the key to use for 
          signing.
        :type certificateName: Name
        :param wireFormat: (optional) A WireFormat object used to encode the 
           Data object. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat.
        """
        self._identityManager.signByCertificate(
          data, certificateName, wireFormat)
          
    def setFace(self, face):
        """
        Set the Face which will be used to fetch required certificates.
        
        :param face: The Face object.
        :type face: Face
        """
        self._face = face
        
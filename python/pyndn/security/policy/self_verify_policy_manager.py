# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the SelfVerifyPolicyManager class which implements a 
PolicyManager to look in the IdentityStorage for the public key with the name in 
the KeyLocator (if available) and use it to verify the data packet, without 
searching a certificate chain. If the public key can't be found, the 
verification fails.
"""

import sys
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from pyndn.name import Name
from pyndn.util import Blob
from pyndn.key_locator import KeyLocatorType
from pyndn.sha256_with_rsa_signature import Sha256WithRsaSignature
from pyndn.security import SecurityException
from pyndn.security.policy import PolicyManager
from pyndn.security.certificate.identity_certificate import IdentityCertificate

class SelfVerifyPolicyManager(PolicyManager):
    """
    Create a new SelfVerifyPolicyManager which will look up the public key in 
    the given identityStorage.
    
    :param identityStorage: (optional) The IdentityStorage for looking up the 
      public key. This object must remain valid during the life of this 
      SelfVerifyPolicyManager. If omitted, then don't look for a public key 
      with the name in the KeyLocator and rely on the KeyLocator having the full 
      public key DER.
    :type identityStorage: IdentityStorage
    """
    def __init__(self, identityStorage = None):
        self._identityStorage = identityStorage
        
    def skipVerifyAndTrust(self, data):
        """
        Never skip verification.

        :param data: The received data packet.
        :type data: Data
        :return: False.
        :rtype: boolean
        """
        return False

    def requireVerify(self, data):
        """
        Always return true to use the self-verification rule for the received 
        data.

        :param data: The received data packet.
        :type data: Data
        :return: True.
        :rtype: boolean
        """
        return True

    def checkVerificationPolicy(self, data, stepCount, onVerified, 
                                onVerifyFailed):
        """
        Look in the IdentityStorage for the public key with the name in the 
        KeyLocator (if available) and use it to verify the data packet. If the 
        public key can't be found, call onVerifyFailed.

        :param data: The Data object with the signature to check.
        :type data: Data
        :param stepCount: The number of verification steps that have been done, 
           used to track the verification progress. (stepCount is ignored.)
        :type stepCount: int
        :param onVerified: If the signature is verified, this calls 
          onVerified(data).
        :type onVerified: function object
        :param onVerifyFailed: If the signature check fails or can't find the 
          public key, this calls onVerifyFailed(data).
        :type onVerifyFailed: function object
        :return: None for no further step for looking up a certificate chain.
        :rtype: ValidationRequest
        """
        signature = data.getSignature()
        if not isinstance(signature, Sha256WithRsaSignature):
            raise SecurityException(
           "SelfVerifyPolicyManager: Signature is not Sha256WithRsaSignature.")

        if (signature.getKeyLocator().getType() == KeyLocatorType.KEYNAME and 
            self._identityStorage != None):
            # Assume the key name is a certificate name.
            publicKeyDer = self._identityStorage.getKey(
              IdentityCertificate.certificateNameToPublicKeyName(
                signature.getKeyLocator().getKeyName()))
            if publicKeyDer.isNull():
                # Can't find the public key with the name.
                onVerifyFailed(data)

            if self._verifySha256WithRsaSignature(data, publicKeyDer):
                onVerified(data)
            else:
                onVerifyFailed(data) 
        else:
            # Can't find a key to verify.
            onVerifyFailed(data)

        # No more steps, so return a None.
        return None
          
    def checkSigningPolicy(self, dataName, certificateName):
        """
        Override to always indicate that the signing certificate name and data 
        name satisfy the signing policy.

        :param dataName: The name of data to be signed.
        :type dataName: Name
        :param certificateName: The name of signing certificate.
        :type certificateName: Name
        :return: True to indicate that the signing certificate can be used to 
          sign the data.
        :rtype: boolean
        """
        return True
        
    def inferSigningIdentity(self, dataName):
        """
        Override to indicate that the signing identity cannot be inferred.

        :param dataName: The name of data to be signed.
        :type dataName: Name
        :return: An empty name because cannot infer. 
        :rtype: Name
        """
        return Name()

    @staticmethod
    def _verifySha256WithRsaSignature(data, publicKeyDer):
        """
        Verify the signature on the data packet using the given public key. If 
        there is no data.getDefaultWireEncoding(), this calls data.wireEncode() 
        to set it.
        TODO: Move this general verification code to a more central location.
 
        :param data: The data packet with the signed portion and the signature 
          to verify. The data packet must have a Sha256WithRsaSignature.
        :type data: Data
        :param publicKeyDer: The DER-encoded public key used to verify the 
          signature.
        :type publicKeyDer: Blob
        :return: True if the signature verifies, False if not.
        :rtype: boolean
        :raises: SecurityException if data does not have a 
          Sha256WithRsaSignature.
        """
        signature = data.getSignature()
        if not type(signature) is Sha256WithRsaSignature:
          raise RuntimeError("signature is not Sha256WithRsaSignature.")

        # Set the data packet's default wire encoding if it is not already there.
        if data.getDefaultWireEncoding().isNull():
            data.wireEncode()

        # Get the public key.
        if _PyCryptoUsesStr:
            # PyCrypto in Python 2 requires a str.
            publicKeyDerBytes = publicKeyDer.toRawStr()
        else:
            publicKeyDerBytes = publicKeyDer.toBuffer()
        publicKey = RSA.importKey(publicKeyDerBytes)
        
        # Get the bytes to verify.
        signedPortion = data.getDefaultWireEncoding().toSignedBuffer()
        # Sign the hash of the data.
        if sys.version_info[0] == 2:
            # In Python 2.x, we need a str.  Use Blob to convert signedPortion.
            signedPortion = Blob(signedPortion, False).toRawStr()

        # Convert the signature bits to a raw string or bytes as required.
        if _PyCryptoUsesStr:
            signatureBits = signature.getSignature().toRawStr()
        else:
            signatureBits = bytes(signature.getSignature().buf())

        # Hash and verify.
        return PKCS1_v1_5.new(publicKey).verify(SHA256.new(signedPortion), 
                                                signatureBits)

# Depending on the Python version, PyCrypto uses str or bytes.
_PyCryptoUsesStr = type(SHA256.new().digest()) is str

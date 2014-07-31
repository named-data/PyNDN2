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
This module defines the SelfVerifyPolicyManager class which implements a 
PolicyManager to look in the IdentityStorage for the public key with the name in 
the KeyLocator (if available) and use it to verify the data packet or signed
interest, without searching a certificate chain. If the public key can't be
found, the verification fails.
"""

import sys
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from pyndn.name import Name
from pyndn.interest import Interest
from pyndn.data import Data
from pyndn.util import Blob
from pyndn.encoding import WireFormat
from pyndn.key_locator import KeyLocatorType
from pyndn.sha256_with_rsa_signature import Sha256WithRsaSignature
from pyndn.security.security_exception import SecurityException
from pyndn.security.policy.policy_manager import PolicyManager
from pyndn.security.certificate.identity_certificate import IdentityCertificate

class SelfVerifyPolicyManager(PolicyManager):
    """
    Create a new SelfVerifyPolicyManager which will look up the public key in 
    the given identityStorage.
    
    :param IdentityStorage identityStorage: (optional) The IdentityStorage for 
      looking up the public key. This object must remain valid during the life 
      of this SelfVerifyPolicyManager. If omitted, then don't look for a public 
      key with the name in the KeyLocator and rely on the KeyLocator having the 
      full public key DER.
    """
    def __init__(self, identityStorage = None):
        self._identityStorage = identityStorage
        
    def skipVerifyAndTrust(self, dataOrInterest):
        """
        Never skip verification.

        :param dataOrInterest: The received data packet or interest.
        :type dataOrInterest: Data or Interest
        :return: False.
        :rtype: boolean
        """
        return False

    def requireVerify(self, dataOrInterest):
        """
        Always return true to use the self-verification rule for the received 
        data packet or signed interest.

        :param dataOrInterest: The received data packet or interest.
        :type dataOrInterest: Data or Interest
        :return: True.
        :rtype: boolean
        """
        return True

    def checkVerificationPolicy(self, dataOrInterest, stepCount, onVerified,
                                onVerifyFailed, wireFormat = None):
        """
        Look in the IdentityStorage for the public key with the name in the 
        KeyLocator (if available) and use it to verify the data packet or
        signed interest. If the public key can't be found, call onVerifyFailed.

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
        :return: None for no further step for looking up a certificate chain.
        :rtype: ValidationRequest
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        if isinstance(dataOrInterest, Data):
            data = dataOrInterest
            # wireEncode returns the cached encoding if available.
            if self._verify(data.getSignature(), data.wireEncode()):
                onVerified(data)
            else:
                onVerifyFailed(data)
        elif isinstance(dataOrInterest, Interest):
            interest = dataOrInterest
            # Decode the last two name components of the signed interest
            signature = wireFormat.decodeSignatureInfoAndValue(
               interest.getName().get(-2).getValue().buf(),
               interest.getName().get(-1).getValue().buf())

            # wireEncode returns the cached encoding if available.
            if self._verify(signature, interest.wireEncode()):
                onVerified(interest)
            else:
                onVerifyFailed(interest)
        else:
            raise RuntimeError(
              "checkVerificationPolicy: unrecognized type for dataOrInterest")

        # No more steps, so return a None.
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

    def _verify(self, signatureInfo, signedBlob):
        """
        Check the type of signatureInfo to get the KeyLocator. Look in the
        IdentityStorage for the public key with the name in the KeyLocator and
        use it to verify the signedBlob. If the public key can't be found,
        return false. (This is a generalized method which can verify both a Data
        packet and an interest.)

        :param Signature signatureInfo: An object of a subclass of Signature,
          e.g. Sha256WithRsaSignature.
        :param SignedBlob signedBlob: the SignedBlob with the signed portion to
          verify.
        :return: True if the signature verifies, False if not.
        :rtype: boolean
        """
        signature = signatureInfo
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
                return False

            return self._verifySha256WithRsaSignature(
              signature, signedBlob, publicKeyDer)
        else:
            # Can't find a key to verify.
            return False

    @staticmethod
    def _verifySha256WithRsaSignature(signature, signedBlob, publicKeyDer):
        """
        Verify the signature on the SignedBlob using the given public key.
        TODO: Move this general verification code to a more central location.
 
        :param Sha256WithRsaSignature signature: The Sha256WithRsaSignature.
        :param SignedBlob signedBlob: the SignedBlob with the signed portion to
        verify.
        :param Blob publicKeyDer: The DER-encoded public key used to verify the 
          signature.
        :return: True if the signature verifies, False if not.
        :rtype: boolean
        """
        # Get the public key.
        if _PyCryptoUsesStr:
            # PyCrypto in Python 2 requires a str.
            publicKeyDerBytes = publicKeyDer.toRawStr()
        else:
            publicKeyDerBytes = publicKeyDer.toBuffer()
        publicKey = RSA.importKey(publicKeyDerBytes)
        
        # Get the bytes to verify.
        # wireEncode returns the cached encoding if available.
        signedPortion = signedBlob.toSignedBuffer()
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

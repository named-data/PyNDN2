# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
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
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU Lesser General Public License is in the file COPYING.

"""
This module defines the SelfVerifyPolicyManager class which implements a
PolicyManager to look in the IdentityStorage for the public key with the name in
the KeyLocator (if available) and use it to verify the data packet or signed
interest, without searching a certificate chain. If the public key can't be
found, the verification fails.
"""

import logging
from pyndn.name import Name
from pyndn.interest import Interest
from pyndn.data import Data
from pyndn.encoding.wire_format import WireFormat
from pyndn.util.blob import Blob
from pyndn.key_locator import KeyLocator, KeyLocatorType
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
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onVerified: function object
        :param onVerifyFailed: If the signature check fails, this calls
          onVerifyFailed(dataOrInterest).
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
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
                try:
                    onVerified(data)
                except:
                    logging.exception("Error in onVerified")
            else:
                try:
                    onVerifyFailed(data)
                except:
                    logging.exception("Error in onVerifyFailed")
        elif isinstance(dataOrInterest, Interest):
            interest = dataOrInterest
            # Decode the last two name components of the signed interest
            signature = wireFormat.decodeSignatureInfoAndValue(
               interest.getName().get(-2).getValue().buf(),
               interest.getName().get(-1).getValue().buf())

            # wireEncode returns the cached encoding if available.
            if self._verify(signature, interest.wireEncode()):
                try:
                    onVerified(interest)
                except:
                    logging.exception("Error in onVerified")
            else:
                try:
                    onVerifyFailed(interest)
                except:
                    logging.exception("Error in onVerifyFailed")
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
        publicKeyDer = None
        if KeyLocator.canGetFromSignature(signatureInfo):
            publicKeyDer = self._getPublicKeyDer(
              KeyLocator.getFromSignature(signatureInfo))
            if publicKeyDer.isNull():
                return False

        return self.verifySignature(
          signatureInfo, signedBlob, publicKeyDer)

    def _getPublicKeyDer(self, keyLocator):
        """
        Look in the IdentityStorage for the public key with the name in the
        KeyLocator. If the public key can't be found, return and empty Blob.

        :param KeyLocator keyLocator: The KeyLocator.
        :return: The public key DER or an empty Blob if not found.
        :rtype: Blob
        """
        if (keyLocator.getType() == KeyLocatorType.KEYNAME and
            self._identityStorage != None):
            try:
              # Assume the key name is a certificate name.
              return self._identityStorage.getKey(
                IdentityCertificate.certificateNameToPublicKeyName(
                  keyLocator.getKeyName()))
            except SecurityException as ex:
              # The storage doesn't have the key.
              return Blob()
        else:
            return Blob()

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2019 Regents of the University of California.
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
PolicyManager to look in the storage for the public key with the name in
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
from pyndn.security.identity.identity_storage import IdentityStorage

class SelfVerifyPolicyManager(PolicyManager):
    """
    Create a new SelfVerifyPolicyManager which will look up the public key in
    the given storage.

    :param storage: (optional) The IdentityStorage or PibImpl for looking up the
      public key. This object must remain valid during the life of this
      SelfVerifyPolicyManager. If omitted, then don't look for a public key with
      the name in the KeyLocator and rely on the KeyLocator having the full
      public key DER.
    :type storage: IdentityStorage or PibImpl
    """
    def __init__(self, storage = None):
        if isinstance(storage, IdentityStorage):
            self._identityStorage = storage
            self._pibImpl = None
        else:
            self._identityStorage = None
            self._pibImpl = storage

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
                                onValidationFailed, wireFormat = None):
        """
        Look in the storage for the public key with the name in the
        KeyLocator (if available) and use it to verify the data packet or
        signed interest. If the public key can't be found, call
        onValidationFailed.

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
        :param onValidationFailed: If the signature check fails, this calls
          onValidationFailed(dataOrInterest, reason).
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onValidationFailed: function object
        :return: None for no further step for looking up a certificate chain.
        :rtype: ValidationRequest
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        failureReason = ["unknown"]
        if isinstance(dataOrInterest, Data):
            data = dataOrInterest
            # wireEncode returns the cached encoding if available.
            if self._verify(data.getSignature(), data.wireEncode(), failureReason):
                try:
                    onVerified(data)
                except:
                    logging.exception("Error in onVerified")
            else:
                try:
                    onValidationFailed(data, failureReason[0])
                except:
                    logging.exception("Error in onValidationFailed")
        elif isinstance(dataOrInterest, Interest):
            interest = dataOrInterest

            if interest.getName().size() < 2:
                try:
                    onValidationFailed(interest,
                      "The signed interest has less than 2 components: " +
                      interest.getName().toUri())
                except:
                    logging.exception("Error in onValidationFailed")
                return

            # Decode the last two name components of the signed interest
            try:
                signature = wireFormat.decodeSignatureInfoAndValue(
                   interest.getName().get(-2).getValue().buf(),
                   interest.getName().get(-1).getValue().buf(), False)
            except Exception as ex:
                try:
                    onValidationFailed(interest,
                      "Error decoding the signed interest signature: " + str(ex))
                except:
                    logging.exception("Error in onValidationFailed")
                return

            # wireEncode returns the cached encoding if available.
            if self._verify(signature, interest.wireEncode(), failureReason):
                try:
                    onVerified(interest)
                except:
                    logging.exception("Error in onVerified")
            else:
                try:
                    onValidationFailed(interest, failureReason[0])
                except:
                    logging.exception("Error in onValidationFailed")
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

    def _verify(self, signatureInfo, signedBlob, failureReason):
        """
        Check the type of signatureInfo to get the KeyLocator. Look in the
        storage for the public key with the name in the KeyLocator and
        use it to verify the signedBlob. If the public key can't be found,
        return false. (This is a generalized method which can verify both a Data
        packet and an interest.)

        :param Signature signatureInfo: An object of a subclass of Signature,
          e.g. Sha256WithRsaSignature.
        :param SignedBlob signedBlob: the SignedBlob with the signed portion to
          verify.
        :param Array<str> failureReason: If verification fails, set
          failureReason[0] to the failure reason string.
        :return: True if the signature verifies, False if not.
        :rtype: boolean
        """
        publicKeyDer = None
        if KeyLocator.canGetFromSignature(signatureInfo):
            publicKeyDer = self._getPublicKeyDer(
              KeyLocator.getFromSignature(signatureInfo), failureReason)
            if publicKeyDer.isNull():
                return False

        if self.verifySignature(
              signatureInfo, signedBlob, publicKeyDer):
            return True
        else:
            failureReason[0] = (
              "The signature did not verify with the given public key")
            return False

    def _getPublicKeyDer(self, keyLocator, failureReason):
        """
        Look in the storage for the public key with the name in the
        KeyLocator. If the public key can't be found, return and empty Blob.

        :param KeyLocator keyLocator: The KeyLocator.
        :param Array<str> failureReason: If can't find the public key, set
          failureReason[0] to the failure reason string.
        :return: The public key DER or an empty Blob if not found.
        :rtype: Blob
        """
        if (keyLocator.getType() == KeyLocatorType.KEYNAME and
            self._identityStorage != None):
            try:
                # Assume the key name is a certificate name.
                keyName = IdentityCertificate.certificateNameToPublicKeyName(
                  keyLocator.getKeyName())
            except Exception:
                failureReason[0] = (
                  "Cannot get a public key name from the certificate named: " +
                  keyLocator.getKeyName().toUri())
                return Blob()
            try:
                return self._identityStorage.getKey(keyName)
            except SecurityException:
                failureReason[0] = (
                  "The identityStorage doesn't have the key named " +
                  keyName.toUri())
                return Blob()
        elif (keyLocator.getType() == KeyLocatorType.KEYNAME and
                self._pibImpl != None):
            try:
                return self._pibImpl.getKeyBits(keyLocator.getKeyName())
            except SecurityException:
                failureReason[0] = (
                  "The pibImpl doesn't have the key named " + keyName.toUri())
                return Blob()
        else:
            # Can't find a key to verify.
            failureReason[0] = "The signature KeyLocator doesn't have a key name"
            return Blob()

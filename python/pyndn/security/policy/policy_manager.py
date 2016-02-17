# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
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

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from pyndn.digest_sha256_signature import DigestSha256Signature
from pyndn.sha256_with_rsa_signature import Sha256WithRsaSignature
from pyndn.sha256_with_ecdsa_signature import Sha256WithEcdsaSignature
from pyndn.security.security_exception import SecurityException

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
        :rtype: bool
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
        :rtype: bool
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
        :rtype: bool
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

    @staticmethod
    def verifySignature(signature, signedBlob, publicKeyDer):
        """
        Check the type of signature and use the publicKeyDer to verify the
        signedBlob using the appropriate signature algorithm.

        :param Blob signature: An object of a subclass of Signature, e.g.
          Sha256WithRsaSignature.
        :param SignedBlob signedBlob: the SignedBlob with the signed portion to
          verify.
        :param Blob publicKeyDer: The DER-encoded public key used to verify the
          signature. This is ignored if the signature type does not require a
          public key.
        :return: True if the signature verifies, False if not.
        :rtype: bool
        :raises: SecurityException if the signature type is not recognized or if
          publicKeyDer can't be decoded.
        """
        if isinstance(signature, Sha256WithRsaSignature):
            if publicKeyDer.isNull():
                return False
            return PolicyManager._verifySha256WithRsaSignature(
              signature.getSignature(), signedBlob, publicKeyDer)
        elif isinstance(signature, Sha256WithEcdsaSignature):
            if publicKeyDer.isNull():
                return False
            return PolicyManager._verifySha256WithEcdsaSignature(
              signature.getSignature(), signedBlob, publicKeyDer)
        elif isinstance(signature, DigestSha256Signature):
            return PolicyManager._verifyDigestSha256Signature(
              signature.getSignature(), signedBlob)
        else:
            raise SecurityException(
              "PolicyManager.verify: Signature type is unknown")

    @staticmethod
    def _verifySha256WithRsaSignature(signature, signedBlob, publicKeyDer):
        """
        Verify the RSA signature on the SignedBlob using the given public key.

        :param Blob signature: The signature bits.
        :param SignedBlob signedBlob: the SignedBlob with the signed portion to
          verify.
        :param Blob publicKeyDer: The DER-encoded public key used to verify the
          signature.
        :return: True if the signature verifies, False if not.
        :rtype: bool
        """
        # Get the public key.
        publicKeyDerBytes = publicKeyDer.toBytes()
        try:
            publicKey = load_der_public_key(
              publicKeyDerBytes, backend = default_backend())
        except:
            raise SecurityException("Cannot decode the RSA public key")

        # Verify.
        verifier = publicKey.verifier(
          signature.toBytes(), padding.PKCS1v15(), hashes.SHA256())
        verifier.update(signedBlob.toSignedBytes())
        try:
            verifier.verify()
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def _verifySha256WithEcdsaSignature(signature, signedBlob, publicKeyDer):
        """
        Verify the ECDSA signature on the SignedBlob using the given public key.

        :param Blob signature: The signature bits.
        :param SignedBlob signedBlob: the SignedBlob with the signed portion to
          verify.
        :param Blob publicKeyDer: The DER-encoded public key used to verify the
          signature.
        :return: True if the signature verifies, False if not.
        :rtype: bool
        """
        # Get the public key.
        publicKeyDerBytes = publicKeyDer.toBytes()
        try:
            publicKey = load_der_public_key(
              publicKeyDerBytes, backend = default_backend())
        except:
            raise SecurityException("Cannot decode the ECDSA public key")

        # Verify.
        verifier = publicKey.verifier(
          signature.toBytes(), ec.ECDSA(hashes.SHA256()))
        verifier.update(signedBlob.toSignedBytes())
        try:
            verifier.verify()
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def _verifyDigestSha256Signature(signature, signedBlob):
        """
        Verify the DigestSha256 signature on the SignedBlob by verifying that
        the digest of SignedBlob equals the signature.

        :param Blob signature: The signature bits.
        :param SignedBlob signedBlob: the SignedBlob with the signed portion to
          verify.
        :return: True if the signature verifies, False if not.
        :rtype: bool
        """
        # Get the hash of the bytes to verify.
        sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
        sha256.update(signedBlob.toSignedBytes())
        signedPortionDigest = sha256.finalize()

        return signature.toBytes() == signedPortionDigest

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2015 Regents of the University of California.
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

import sys
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from pyndn.util.blob import Blob
from pyndn.digest_sha256_signature import DigestSha256Signature
from pyndn.sha256_with_rsa_signature import Sha256WithRsaSignature
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
        elif isinstance(signature, DigestSha256Signature):
            return PolicyManager._verifyDigestSha256Signature(
              signature.getSignature(), signedBlob)
        else:
            raise SecurityException(
              "PolicyManager.verify: Signature type is unknown")

    @staticmethod
    def _verifySha256WithRsaSignature(signature, signedBlob, publicKeyDer):
        """
        Verify the signature on the SignedBlob using the given public key.

        :param Blob signature: The signature bits.
        :param SignedBlob signedBlob: the SignedBlob with the signed portion to
          verify.
        :param Blob publicKeyDer: The DER-encoded public key used to verify the
          signature.
        :return: True if the signature verifies, False if not.
        :rtype: bool
        """
        # Get the public key.
        if _PyCryptoUsesStr:
            # PyCrypto in Python 2 requires a str.
            publicKeyDerBytes = publicKeyDer.toRawStr()
        else:
            publicKeyDerBytes = publicKeyDer.toBuffer()
        publicKey = None
        try:
            publicKey = RSA.importKey(publicKeyDerBytes)
        except:
            raise SecurityException("Cannot decode RSA public key")

        # Get the bytes to verify.
        signedPortion = signedBlob.toSignedBuffer()
        # Sign the hash of the data.
        if sys.version_info[0] == 2:
            # In Python 2.x, we need a str.  Use Blob to convert signedPortion.
            signedPortion = Blob(signedPortion, False).toRawStr()

        # Convert the signature bits to a raw string or bytes as required.
        if _PyCryptoUsesStr:
            signatureBits = signature.toRawStr()
        else:
            signatureBits = bytes(signature.buf())

        # Hash and verify.
        return PKCS1_v1_5.new(publicKey).verify(SHA256.new(signedPortion),
                                                signatureBits)

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
        # Get the bytes to verify.
        signedPortion = signedBlob.toSignedBuffer()
        # Sign the hash of the data.
        if sys.version_info[0] == 2:
            # In Python 2.x, we need a str.  Use Blob to convert signedPortion.
            signedPortion = Blob(signedPortion, False).toRawStr()

        signedPortionDigest = SHA256.new(signedPortion).digest()

        # Convert the signature bits to a raw string or bytes as required.
        if _PyCryptoUsesStr:
            signatureBits = signature.toRawStr()
        else:
            signatureBits = bytes(signature.buf())

        return signatureBits == signedPortionDigest

# Depending on the Python version, PyCrypto uses str or bytes.
_PyCryptoUsesStr = type(SHA256.new().digest()) is str

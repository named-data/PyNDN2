# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/verification-helpers.cpp
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
This module defines the VerificationHelpers which has static methods to verify
signatures and digests.
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives import hashes
from pyndn.security.security_types import DigestAlgorithm
from pyndn.security.certificate.public_key import PublicKey
from pyndn.security.security_types import KeyType
from pyndn.util.blob import Blob
from pyndn.encoding.wire_format import WireFormat
from pyndn.security.v2.certificate_v2 import CertificateV2

class VerificationHelpers(object):
    @staticmethod
    def verifySignature(buffer, signature, publicKey,
          digestAlgorithm = DigestAlgorithm.SHA256):
        """
        Verify the buffer against the signature using the public key.

        :param buffer: The input buffer to verify.
        :type buffer: Blob or an object which is the same as the bytes() operator
        :param signature: The signature bytes.
        :type signature: Blob or an object which is the same as the bytes()
          operator
        :param publicKey: The object containing the public key, or the public
          key DER which is used to make the PublicKey object.
        :type publicKey: PublicKey or Blob or  an object which is the same as
          the bytes() operator
        :param digestAlgorithm: (optional) The digest algorithm. If omitted, use
          DigestAlgorithm.SHA256.
        :type digestAlgorithm: int from DigestAlgorithm
        :return: True if verification succeeds, False if verification fails.
        :rtype: bool
        :raises: ValueError for an invalid public key type or digestAlgorithm.
        """
        if digestAlgorithm == None:
            digestAlgorithm = DigestAlgorithm.SHA256

        if isinstance(buffer, Blob):
            buffer = buffer.toBytes()
        if isinstance(signature, Blob):
            signature = signature.toBytes()
        if not isinstance(publicKey, PublicKey):
            # Turn publicKey into a PublicKey object.
            if not isinstance(publicKey, Blob):
                publicKey = Blob(publicKey)
            publicKey = PublicKey(publicKey)

        if digestAlgorithm == DigestAlgorithm.SHA256:
            if publicKey.getKeyType() == KeyType.RSA:
                # Get the public key.
                try:
                    cryptoPublicKey = load_der_public_key(
                      publicKey.getKeyDer().toBytes(),
                      backend = default_backend())
                except:
                    return False

                try:
                    cryptoPublicKey.verify(
                      signature, buffer, padding.PKCS1v15(), hashes.SHA256())
                    return True
                except:
                    return False
            elif publicKey.getKeyType() == KeyType.EC:
                # Get the public key.
                try:
                    cryptoPublicKey = load_der_public_key(
                      publicKey.getKeyDer().toBytes(),
                      backend = default_backend())
                except:
                    return False

                try:
                    cryptoPublicKey.verify(
                      signature, buffer, ec.ECDSA(hashes.SHA256()))
                    return True
                except:
                    return False
            else:
                raise ValueError("verifySignature: Invalid key type")
        else:
            raise ValueError("verifySignature: Invalid digest algorithm")

    @staticmethod
    def verifyDataSignature(
      data, publicKeyOrCertificate, digestAlgorithm = None, wireFormat = None):
        """
        Verify the Data packet using the public key. This does not check the
        type of public key or digest algorithm against the type of SignatureInfo
        in the Data packet such as Sha256WithRsaSignature.

        :param Data data: The Data packet to verify.
        :param publicKeyOrCertificate: The object containing the public key, or
          the public key DER which is used to make the PublicKey object, or the
          certificate containing the public key.
        :type publicKeyOrCertificate: Blob, or an object which is the same as
          the bytes() operator, or CertificateV2
        :param digestAlgorithm: (optional) The digest algorithm. If omitted, use
          DigestAlgorithm.SHA256.
        :param WireFormat wireFormat: (optional) A WireFormat object used to
          encode the Data packet. If omitted, use
          WireFormat.getDefaultWireFormat().
        :raises: ValueError for an invalid public key type or digestAlgorithm.
        """
        arg3 = digestAlgorithm
        arg4 = wireFormat

        if type(arg3) is int:
            digestAlgorithm = arg3
        else:
            digestAlgorithm = None

        if isinstance(arg3, WireFormat):
            wireFormat = arg3
        elif isinstance(arg4, WireFormat):
            wireFormat = arg4
        else:
            wireFormat = None

        if isinstance(publicKeyOrCertificate, CertificateV2):
          try:
              publicKey = publicKeyOrCertificate.getPublicKey()
          except:
              return False
        else:
            publicKey = publicKeyOrCertificate;

        encoding = data.wireEncode(wireFormat)
        return VerificationHelpers.verifySignature(
          encoding.toSignedBytes(), data.getSignature().getSignature(),
          publicKey, digestAlgorithm)


    @staticmethod
    def verifyInterestSignature(
      interest, publicKeyOrCertificate, digestAlgorithm = None, wireFormat = None):
        """
        Verify the Interest packet using the public key, where the last two name
        components are the SignatureInfo and signature bytes. This does not
        check the type of public key or digest algorithm against the type of
        SignatureInfo such as Sha256WithRsaSignature.

        :param Interest interest: The Interest packet to verify.
        :param publicKeyOrCertificate: The object containing the public key, or
          the public key DER which is used to make the PublicKey object, or the
          certificate containing the public key.
        :type publicKeyOrCertificate: Blob, or an object which is the same as
          the bytes() operator, or CertificateV2
        :param digestAlgorithm: (optional) The digest algorithm. If omitted, use
          DigestAlgorithm.SHA256.
        :param WireFormat wireFormat: (optional) A WireFormat object used to
          encode the Interest packet. If omitted, use
          WireFormat.getDefaultWireFormat().
        :raises: ValueError for an invalid public key type or digestAlgorithm.
        """
        arg3 = digestAlgorithm
        arg4 = wireFormat

        if type(arg3) is int:
            digestAlgorithm = arg3
        else:
            digestAlgorithm = None

        if isinstance(arg3, WireFormat):
            wireFormat = arg3
        elif isinstance(arg4, WireFormat):
            wireFormat = arg4
        else:
            wireFormat = None

        if isinstance(publicKeyOrCertificate, CertificateV2):
          try:
              publicKey = publicKeyOrCertificate.getPublicKey()
          except:
              return False
        else:
            publicKey = publicKeyOrCertificate;

        if wireFormat == None:
            wireFormat = WireFormat.getDefaultWireFormat()
        signature = VerificationHelpers._extractSignature(interest, wireFormat)
        if signature == None:
            return False

        encoding = interest.wireEncode(wireFormat)
        return VerificationHelpers.verifySignature(
          encoding.toSignedBytes(), signature.getSignature(), publicKey,
          digestAlgorithm)

    @staticmethod
    def verifyDigest(buffer, digest, digestAlgorithm):
        """
        Verify the buffer against the digest using the digest algorithm.

        :param buffer: The input buffer to verify.
        :type buffer: Blob or an object which is the same as the bytes() operator
        :param digest: The digest bytes.
        :type digest: Blob or an object which is the same as the bytes() operator
        :param digestAlgorithm: The digest algorithm.
        :type digestAlgorithm: int from DigestAlgorithm
        :return: True if verification succeeds, False if verification fails.
        :rtype: bool
        :raises: ValueError for an invalid digestAlgorithm.
        """
        if isinstance(buffer, Blob):
            buffer = buffer.toBytes()
        if isinstance(digest, Blob):
            digest = digest.toBytes()

        if digestAlgorithm == DigestAlgorithm.SHA256:
            # Get the hash of the bytes to verify.
            sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
            sha256.update(buffer)
            bufferDigest = sha256.finalize()

            return digest == bufferDigest
        else:
            raise ValueError("verifyDigest: Invalid digest algorithm")

    @staticmethod
    def _extractSignature(interest, wireFormat):
        """
        Extract the signature information from the interest name.

        :param Interest interest: The interest whose signature is needed.
        :param WireFormat wireFormat: The wire format used to decode signature
          information from the interest name.
        :return: The Signature object, or None if can't decode.
        :rtype: Signature
        """
        if interest.getName().size() < 2:
          return None

        try:
            return wireFormat.decodeSignatureInfoAndValue(
              interest.getName().get(-2).getValue().buf(),
              interest.getName().get(-1).getValue().buf(), False)
        except:
            return None

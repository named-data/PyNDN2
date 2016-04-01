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

"""
This module defines the KeyChain class which provides a set of interfaces to the
security library such as identity management, policy configuration  and packet
signing and verification.
Note: This class is an experimental feature. See the API docs for more detail at
http://named-data.net/doc/ndn-ccl-api/key-chain.html .
"""

import logging
from random import SystemRandom
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from pyndn.name import Name
from pyndn.interest import Interest
from pyndn.data import Data
from pyndn.util.blob import Blob
from pyndn.security.security_exception import SecurityException
from pyndn.security.key_params import RsaKeyParams
from pyndn.security.identity.identity_manager import IdentityManager
from pyndn.security.policy.no_verify_policy_manager import NoVerifyPolicyManager
from pyndn.security.certificate.identity_certificate import IdentityCertificate
from pyndn.encoding.wire_format import WireFormat

class KeyChain(object):
    """
    Create a new KeyChain to use the optional identityManager and policyManager.

    :param IdentityManager identityManager: (optional) The identity manager as a
      subclass of IdentityManager. If omitted, use the default IdentityManager
      constructor.
    :param PolicyManager policyManager: (optional) The policy manager as a
      subclass of PolicyManager. If omitted, use NoVerifyPolicyManager.
    """
    def __init__(self, identityManager = None, policyManager = None):
        if identityManager == None:
            identityManager = IdentityManager()
        if policyManager == None:
            policyManager = NoVerifyPolicyManager()

        self._identityManager = identityManager
        self._policyManager = policyManager
        self._face = None

    def createIdentityAndCertificate(self, identityName, params = None):
        """
        Create an identity by creating a pair of Key-Signing-Key (KSK) for this
        identity and a self-signed certificate of the KSK. If a key pair or
        certificate for the identity already exists, use it.

        :param Name identityName: The name of the identity.
        :param KeyParams params: (optional) The key parameters if a key needs to
          be generated for the identity. If omitted, use DEFAULT_KEY_PARAMS.
        :return: The name of the default certificate of the identity.
        :rtype: Name
        """
        if params == None:
            params = KeyChain.DEFAULT_KEY_PARAMS
        return self._identityManager.createIdentityAndCertificate(
          identityName, params)

    def createIdentity(self, identityName, params = None):
        """
        Create an identity by creating a pair of Key-Signing-Key (KSK) for this
        identity and a self-signed certificate of the KSK. If a key pair or
        certificate for the identity already exists, use it.

        :deprecated: Use createIdentityAndCertificate which returns the
          certificate name instead of the key name. You can use
          IdentityCertificate.certificateNameToPublicKeyName to convert the
          certificate name to the key name.
        :param Name identityName: The name of the identity.
        :param KeyParams params: (optional) The key parameters if a key needs to
          be generated for the identity. If omitted, use DEFAULT_KEY_PARAMS.
        :return: The key name of the auto-generated KSK of the identity.
        :rtype: Name
        """
        return IdentityCertificate.certificateNameToPublicKeyName(
          self.createIdentityAndCertificate(identityName, params))

    def deleteIdentity(self, identityName):
        """
        Delete the identity from the public and private key storage. If the
        identity to be deleted is current default system default, the method
        will not delete the identity and will return immediately.
        :param Name identityName: The name of the identity to delete.
        """
        self._identityManager.deleteIdentity(identityName)

    def getDefaultIdentity(self):
        """
        Get the default identity.

        :return: The name of default identity.
        :rtype: Name
        :raises SecurityException: if the default identity is not set.
        """
        return self._identityManager.getDefaultIdentity()

    def getDefaultCertificateName(self):
        """
        Get the default certificate name of the default identity.

        :return: The requested certificate name.
        :rtype: Name
        :raises SecurityException: if the default identity is not set or the
          default key name for the identity is not set or the default
          certificate name for the key name is not set.
        """
        return self._identityManager.getDefaultCertificateName()

    def generateRSAKeyPair(self, identityName, isKsk = False, keySize = 2048):
        """
        Generate a pair of RSA keys for the specified identity.

        :param Name identityName: The name of the identity.
        :param bool isKsk: (optional) true for generating a Key-Signing-Key
          (KSK), false for a Data-Signing-Key (DSK). If omitted, generate a
          Data-Signing-Key.
        :param int keySize: (optional) The size of the key. If omitted, use a
          default secure key size.
        :return: The generated key name.
        :rtype: Name
        """
        return self._identityManager.generateRSAKeyPair(
          identityName, isKsk, keySize)

    def generateEcdsaKeyPair(self, identityName, isKsk = False, keySize = 2048):
        """
        Generate a pair of ECDSA keys for the specified identity.

        :param Name identityName: The name of the identity.
        :param bool isKsk: (optional) true for generating a Key-Signing-Key
          (KSK), false for a Data-Signing-Key (DSK). If omitted, generate a
          Data-Signing-Key.
        :param int keySize: (optional) The size of the key. If omitted, use a
          default secure key size.
        :return: The generated key name.
        :rtype: Name
        """
        return self._identityManager.generateEcdsaKeyPair(
          identityName, isKsk, keySize)

    def setDefaultKeyForIdentity(self, keyName, identityNameCheck = None):
        """
        Set a key as the default key of an identity. The identity name is
        inferred from keyName.

        :param Name keyName: The name of the key.
        :param Name identityNameCheck: (optional) The identity name to check
          that the keyName contains the same identity name. If an empty name, it
          is ignored.
        """
        if identityNameCheck == None:
            identityNameCheck = Name()
        return self._identityManager.setDefaultKeyForIdentity(
          keyName, identityNameCheck)

    def generateRSAKeyPairAsDefault(
          self, identityName, isKsk = False, keySize = 2048):
        """
        Generate a pair of RSA keys for the specified identity and set it as
        default key for the identity.

        :param NameidentityName: The name of the identity.
        :param bool isKsk: (optional) true for generating a Key-Signing-Key
          (KSK), false for a Data-Signing-Key (DSK). If omitted, generate a
          Data-Signing-Key.
        :param int keySize: (optional) The size of the key. If omitted, use a
          default secure key size.
        :return: The generated key name.
        :rtype: Name
        """
        return  self._identityManager.generateRSAKeyPairAsDefault(
          identityName, isKsk, keySize)

    def generateEcdsaKeyPairAsDefault(
          self, identityName, isKsk = False, keySize = 2048):
        """
        Generate a pair of ECDSA keys for the specified identity and set it as
        default key for the identity.

        :param NameidentityName: The name of the identity.
        :param bool isKsk: (optional) true for generating a Key-Signing-Key
          (KSK), false for a Data-Signing-Key (DSK). If omitted, generate a
          Data-Signing-Key.
        :param int keySize: (optional) The size of the key. If omitted, use a
          default secure key size.
        :return: The generated key name.
        :rtype: Name
        """
        return  self._identityManager.generateEcdsaKeyPairAsDefault(
          identityName, isKsk, keySize)

    def createSigningRequest(self, keyName):
        """
        Create a public key signing request.

        :param Name keyName: The name of the key.
        :return: The signing request data.
        :rtype: Blob
        """
        return self._identityManager.getPublicKey(keyName).getKeyDer()

    def installIdentityCertificate(self, certificate):
        """
        Install an identity certificate into the public key identity storage.

        :param IdentityCertificate certificate: The certificate to to added.
        """
        self._identityManager.addCertificate(certificate)

    def setDefaultCertificateForKey(self, certificate):
        """
        Set the certificate as the default for its corresponding key.

        :param IdentityCertificate certificate: The certificate.
        """
        self._identityManager.setDefaultCertificateForKey(certificate)

    def getCertificate(self, certificateName):
        """
        Get a certificate with the specified name.

        :param Name certificateName: The name of the requested certificate.
        :return: The requested certificate.
        :rtype: IdentityCertificate
        """
        return self._identityManager.getCertificate(certificateName)

    def getIdentityCertificate(self, certificateName):
        """
        :deprecated: Use getCertificate.
        """
        return self._identityManager.getCertificate(certificateName)

    def revokeKey(self, keyName):
        """
        Revoke a key.

        :param Name keyName: The name of the key that will be revoked.
        """
        # TODO: Implement.
        pass

    def revokeCertificate(self, certificateName):
        """
        Revoke a certificate.

        :param Name certificateName: The name of the certificate that will be
          revoked.
        """
        # TODO: Implement.
        pass

    def getIdentityManager(self):
        """
        Get the identity manager given to or created by the constructor.

        :return: The identity manager.
        :rtype: IdentityManager
        """
        return self._identityManager

    #
    # Policy Management
    #

    def getPolicyManager(self):
        """
        Get the policy manager given to or created by the constructor.

        :return: The policy manager.
        :rtype: PolicyManager
        """
        return self._policyManager

    #
    # Sign/Verify
    #

    def sign(self, target, certificateNameOrWireFormat = None, wireFormat = None):
        """
        Sign the target. If it is a Data or Interest object, set its signature.
        If it is an array, return a signature object. There are two forms of sign:
        sign(target, certificateName, wireFormat = None).
        sign(target, wireFormat = None).

        :param target: If this is a Data object, wire encode for signing,
          update its signature and key locator field and wireEncoding. If this
          is an Interest object, wire encode for signing, append a SignatureInfo
          to the Interest name, sign the name components and append a final name
          component with the signature bits. If it is an array, sign it and
          return a Signature object.
        :type target: Data, Interest or an array which implements the
          buffer protocol
        :param Name certificateName: (optional) The certificate name of the key
          to use for signing. If omitted, use the default identity in the
          identity storage.
        :param wireFormat: (optional) A WireFormat object used to encode the
           input. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        :return: The Signature object (only if the target is an array).
        :rtype: An object of a subclass of Signature
        """
        if isinstance(certificateNameOrWireFormat, Name):
            certificateName = certificateNameOrWireFormat
        else:
            certificateName = None

        if isinstance(certificateNameOrWireFormat, WireFormat):
            wireFormat = certificateNameOrWireFormat

        if certificateName == None:
            certificateName = self._prepareDefaultCertificateName()

        if isinstance(target, Interest):
            self._identityManager.signInterestByCertificate(
              target, certificateName, wireFormat)
        elif isinstance(target, Data):
            self._identityManager.signByCertificate(
              target, certificateName, wireFormat)
        else:
            return self._identityManager.signByCertificate(
              target, certificateName)

    def signByIdentity(self, target, identityName = None, wireFormat = None):
        """
        Sign the target. If it is a Data object, set its signature.
        If it is an array, return a signature object.

        :param target: If this is a Data object, wire encode for signing,
          update its signature and key locator field and wireEncoding. If it is
          an array, sign it and return a Signature object.
        :type target: Data or an array which implements the buffer protocol
        :param Name identityName: (optional) The identity name for the key to
          use for signing. If omitted, infer the signing identity from the data
          packet name.
        :param wireFormat: (optional) A WireFormat object used to encode the
           input. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        :return: The Signature object (only if the target is an array).
        :rtype: An object of a subclass of Signature
        """
        if identityName == None:
            identityName = Name()

        if isinstance(target, Data):
            if identityName.size() == 0:
                inferredIdentity = self._policyManager.inferSigningIdentity(
                  target.getName())
                if inferredIdentity.size() == 0:
                    signingCertificateName = self._identityManager.getDefaultCertificateName()
                else:
                    signingCertificateName = \
                      self._identityManager.getDefaultCertificateNameForIdentity(inferredIdentity)
            else:
                signingCertificateName = \
                  self._identityManager.getDefaultCertificateNameForIdentity(identityName)

            if signingCertificateName.size() == 0:
                raise SecurityException("No qualified certificate name found!")

            if not self._policyManager.checkSigningPolicy(
                  target.getName(), signingCertificateName):
                raise SecurityException(
                  "Signing Cert name does not comply with signing policy")

            self._identityManager.signByCertificate(
              target, signingCertificateName, wireFormat)
        else:
            signingCertificateName = \
              self._identityManager.getDefaultCertificateNameForIdentity(identityName)

            if signingCertificateName.size() == 0:
                raise SecurityException("No qualified certificate name found!")

            return self._identityManager.signByCertificate(
              target, signingCertificateName)

    def signWithSha256(self, target, wireFormat = None):
        """
        Sign the target using DigestSha256.

        :param target: If this is a Data object, wire encode for signing,
          digest it and set its SignatureInfo to a DigestSha256, updating its
          signature and wireEncoding. If this is an Interest object, wire encode
          for signing, append a SignatureInfo for DigestSha256 to the Interest
          name, digest the name components and append a final name component
          with the signature bits.
        :type target: Data or Interest
        :param wireFormat: (optional) A WireFormat object used to encode the
           input. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        """
        if isinstance(target, Interest):
            self._identityManager.signInterestWithSha256(target, wireFormat)
        else:
            self._identityManager.signWithSha256(target, wireFormat)

    def verifyData(self, data, onVerified, onVerifyFailed, stepCount = 0):
        """
        Check the signature on the Data object and call either onVerify or
        onVerifyFailed. We use callback functions because verify may fetch
        information to check the signature.

        :param Data data: The Data object with the signature to check.
        :param onVerified: If the signature is verified, this calls
          onVerified(data).
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onVerified: function object
        :param onVerifyFailed: If the signature check fails or can't find the
          public key, this calls onVerifyFailed(data).
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onVerifyFailed: function object
        :param int stepCount: (optional) The number of verification steps that
          have been done. If omitted, use 0.
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
            try:
                onVerified(data)
            except:
                logging.exception("Error in onVerified")
        else:
            try:
                onVerifyFailed(data)
            except:
                logging.exception("Error in onVerifyFailed")

    def verifyInterest(
      self, interest, onVerified, onVerifyFailed, stepCount = 0,
      wireFormat = None):
        """
        Check the signature on the signed interest and call either onVerify or
        onVerifyFailed. We use callback functions because verify may fetch
        information to check the signature.

        :param Interest interest: The interest with the signature to check.
        :param onVerified: If the signature is verified, this calls
          onVerified(interest).
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onVerified: function object
        :param onVerifyFailed: If the signature check fails or can't find the
          public key, this calls onVerifyFailed(interest).
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onVerifyFailed: function object
        :param int stepCount: (optional) The number of verification steps that
          have been done. If omitted, use 0.
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        if self._policyManager.requireVerify(interest):
            nextStep = self._policyManager.checkVerificationPolicy(
              interest, stepCount, onVerified, onVerifyFailed, wireFormat)
            if nextStep != None:
                self._face.expressInterest(
                  nextStep.interest, self._makeOnCertificateData(nextStep),
                  self._makeOnCertificateInterestTimeout(
                    nextStep.retry, onVerifyFailed, interest, nextStep))
        elif self._policyManager.skipVerifyAndTrust(interest):
            try:
                onVerified(interest)
            except:
                logging.exception("Error in onVerified")
        else:
            try:
                onVerifyFailed(interest)
            except:
                logging.exception("Error in onVerifyFailed")

    def setFace(self, face):
        """
        Set the Face which will be used to fetch required certificates.

        :param Face face: The Face object.
        """
        self._face = face

    @staticmethod
    def signWithHmacWithSha256(target, key, wireFormat = None):
        """
        Wire encode the target, compute an HmacWithSha256 and update the
        signature value.
        Note: This method is an experimental feature. The API may change.

        :param target: If this is a Data object, update its signature and wire
          encoding.
        :type target: Data
        :param Blob key: The key for the HmacWithSha256.
        :param wireFormat: (optional) The WireFormat for calling encodeData,
          etc., or WireFormat.getDefaultWireFormat() if omitted.
        :type wireFormat: A subclass of WireFormat
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        if isinstance(target, Data):
            data = target
            # Encode once to get the signed portion.
            encoding = data.wireEncode(wireFormat)

            signer = hmac.HMAC(key.toBytes(), hashes.SHA256(),
              backend = default_backend())
            signer.update(encoding.toSignedBytes())
            data.getSignature().setSignature(
              Blob(bytearray(signer.finalize()), False))
        else:
            raise SecurityException("signWithHmacWithSha256: Unrecognized target type")

    @staticmethod
    def verifyDataWithHmacWithSha256(data, key, wireFormat = None):
        """
        Compute a new HmacWithSha256 for the target and verify it against the
        signature value.
        Note: This method is an experimental feature. The API may change.

        :param target: The Data object to verify.
        :type target: Data
        :param Blob key: The key for the HmacWithSha256.
        :param wireFormat: (optional) The WireFormat for calling encodeData,
          etc., or WireFormat.getDefaultWireFormat() if omitted.
        :type wireFormat: A subclass of WireFormat
        :return: True if the signature verifies, otherwise False.
        :rtype: bool
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        # wireEncode returns the cached encoding if available.
        encoding = data.wireEncode(wireFormat)

        signer = hmac.HMAC(key.toBytes(), hashes.SHA256(),
          backend = default_backend())
        signer.update(encoding.toSignedBytes())
        newSignatureBits = Blob(bytearray(signer.finalize()), False)

        # Use the flexible Blob.equals operator.
        return newSignatureBits == data.getSignature().getSignature()

    DEFAULT_KEY_PARAMS = RsaKeyParams()

    #
    # Private methods
    #

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
                try:
                    onVerifyFailed(data)
                except:
                    logging.exception("Error in onVerifyFailed")
        return onTimeout

    def _prepareDefaultCertificateName(self):
        """
        Get the default certificate from the identity storage and return its name.
        If there is no default identity or default certificate, then create one.

        :return: The default certificate name.
        :rtype: Name
        """
        signingCertificate = self._identityManager.getDefaultCertificate()
        if signingCertificate == None:
          self._setDefaultCertificate()
          signingCertificate = self._identityManager.getDefaultCertificate()

        return signingCertificate.getName()

    def _setDefaultCertificate(self):
        """
        Create the default certificate if it is not initialized. If there is
        no default identity yet, creating a new tmp-identity.
        """
        if self._identityManager.getDefaultCertificate() == None:
            try:
                defaultIdentity = self._identityManager.getDefaultIdentity()
            except:
                # Create a default identity name.
                randomComponent = bytearray(4)
                for i in range(len(randomComponent)):
                    randomComponent[i] = _systemRandom.randint(0, 0xff)
                defaultIdentity = Name().append("tmp-identity").append(
                  Blob(randomComponent, False))

            self.createIdentityAndCertificate(defaultIdentity)
            self._identityManager.setDefaultIdentity(defaultIdentity)

_systemRandom = SystemRandom()

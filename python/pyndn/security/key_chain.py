# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2017 Regents of the University of California.
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

import sys
import inspect
import logging
from random import SystemRandom
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from pyndn.name import Name
from pyndn.interest import Interest
from pyndn.data import Data
from pyndn.meta_info import ContentType
from pyndn.digest_sha256_signature import DigestSha256Signature
from pyndn.sha256_with_ecdsa_signature import Sha256WithEcdsaSignature
from pyndn.sha256_with_rsa_signature import Sha256WithRsaSignature
from pyndn.key_locator import KeyLocator, KeyLocatorType
from pyndn.validity_period import ValidityPeriod
from pyndn.util.blob import Blob
from pyndn.util.common import Common
from pyndn.util.config_file import ConfigFile
from pyndn.security.security_exception import SecurityException
from pyndn.security.key_params import RsaKeyParams
from pyndn.security.security_types import KeyType
from pyndn.security.signing_info import SigningInfo
from pyndn.security.identity.identity_manager import IdentityManager
from pyndn.security.policy.no_verify_policy_manager import NoVerifyPolicyManager
from pyndn.security.certificate.identity_certificate import IdentityCertificate
from pyndn.security.pib.pib_impl import PibImpl
from pyndn.security.pib.pib import Pib
from pyndn.security.pib.pib_sqlite3 import PibSqlite3
from pyndn.security.pib.pib_memory import PibMemory
from pyndn.security.tpm.tpm import Tpm
from pyndn.security.tpm.tpm_back_end_file import TpmBackEndFile
from pyndn.security.tpm.tpm_back_end_memory import TpmBackEndMemory
from pyndn.security.tpm.tpm_back_end_osx import TpmBackEndOsx
from pyndn.security.v2.certificate_v2 import CertificateV2
from pyndn.encoding.wire_format import WireFormat

class KeyChain(object):
    """
    There are three forms to create KeyChain:
    KeyChain(pibLocator, tpmLocator, allowReset = False) - Create a KeyChain to
    use the PIB and TPM defined by the given locators, which creates a security
    v2 KeyChain that uses CertificateV2, Pib, Tpm and Validator (instead of v1
    Certificate, IdentityStorage, PrivateKeyStorage and PolicyManager).
    KeyChain(identityManager = None, policyManager = None) - Create a security
    v1 KeyChain to use the optional identityManager and policyManager.
    KeyChain(pibImpl, tpmBackEnd, policyManager) - Create a KeyChain using this
    temporary constructor for the transition to security v2, which creates a
    security v2 KeyChain but still uses the v1 PolicyManager.

    :param str pibLocator: The PIB locator, e.g., "pib-sqlite3:/example/dir".
    :param str tpmLocator: The TPM locator, e.g., "tpm-memory:".
    :param bool allowReset: (optional) If True, the PIB will be reset when the
      supplied tpmLocator mismatches the one in the PIB. If omitted, don't allow
      reset.
    :param IdentityManager identityManager: (optional) The identity manager as a
      subclass of IdentityManager. If omitted, use the default IdentityManager
      constructor.
    :param PolicyManager policyManager: (optional) The policy manager as a
      subclass of PolicyManager. If omitted, use NoVerifyPolicyManager.
    :param PibImpl pibImpl: The PibImpl when using the constructor form
      KeyChain(pibImpl, tpmBackEnd, policyManager).
    :param TpmBackEnd tpmBackEnd: The TpmBackEnd when using the constructor form
      KeyChain(pibImpl, tpmBackEnd, policyManager).
    """
    def __init__(self, arg1 = None, arg2 = None, arg3 = None):
        self._identityManager_ = None  # for security v1
        self._policyManager = None     # for security v1
        self._face = None              # for security v1

        self._pib = None
        self._tpm = None

        if Common.typeIsString(arg1):
            pibLocator = arg1
            tpmLocator = arg2
            allowReset = arg3
            if allowReset == None:
                allowReset = False

            self._isSecurityV1 = False

            # PIB locator.
            pibScheme = [None]
            pibLocation = [None]
            KeyChain._parseAndCheckPibLocator(pibLocator, pibScheme, pibLocation)
            canonicalPibLocator = pibScheme[0] + ":" + pibLocation[0]

            # Create the PIB.
            self._pib = KeyChain._createPib(canonicalPibLocator)
            oldTpmLocator = ""
            try:
                oldTpmLocator = pib_.getTpmLocator()
            except Pib.Error:
                # The TPM locator is not set in the PIB yet.
                pass

            # TPM locator.
            tpmScheme = [None]
            tpmLocation = [None]
            KeyChain._parseAndCheckTpmLocator(tpmLocator, tpmScheme, tpmLocation)
            canonicalTpmLocator = tpmScheme[0] + ":" + tpmLocation[0]

            config = ConfigFile()
            if canonicalPibLocator == KeyChain._getDefaultPibLocator(config):
                # The default PIB must use the default TPM.
                if (oldTpmLocator != "" and
                      oldTpmLocator != KeyChain._getDefaultTpmLocator(config)):
                    self._pib._reset()
                    canonicalTpmLocator = self._getDefaultTpmLocator(config)
            else:
                # Check the consistency of the non-default PIB.
                if (oldTpmLocator == "" and
                      oldTpmLocator != canonicalTpmLocator):
                    if allowReset:
                        self._pib._reset()
                    else:
                        raise LocatorMismatchError(
                          "The supplied TPM locator does not match the TPM locator in the PIB: " +
                          oldTpmLocator + " != " + canonicalTpmLocator)

            # Note that a key mismatch may still happen if the TPM locator is
            # initially set to a wrong one or if the PIB was shared by more than
            # one TPM before. This is due to the old PIB not having TPM info.
            # The new PIB should not have this problem.
            self._tpm = KeyChain._createTpm(canonicalTpmLocator)
            self._pib.setTpmLocator(canonicalTpmLocator)
        elif isinstance(arg1, PibImpl):
            pibImpl = arg1
            tpmBackEnd = arg2
            policyManager = arg3
            
            self._isSecurityV1 = False
            self._policyManager = policyManager

            self._pib = Pib("", "", pibImpl)
            self._tpm = Tpm("", "", tpmBackEnd)
        else:
            identityManager = arg1
            policyManager = arg2

            self._isSecurityV1 = True
            if identityManager == None:
                identityManager = IdentityManager()
            if policyManager == None:
                policyManager = NoVerifyPolicyManager()

            self._identityManager = identityManager
            self._policyManager = policyManager

    class Error(Exception):
        """
        Create a KeyChain.Error which represents an error in KeyChain processing.

        :param str message: The error message.
        """
        def __init__(self, message):
            super(KeyChain.Error, self).__init__(message)

    def getPib(self):
        """
        :rtype: Pib
        """
        return self._pib

    def getTpm(self):
        """
        :rtype: Tpm
        """
        return self._tpm

    # Identity management

    # TODO: createIdentity

    def deleteIdentity(self, identity):
        """
        Delete the identity. After this operation, the identity is invalid.

        :param PibIdentity identity: The identity to delete.
        """
        identityName = identity.getName()

        keyNames = identity._getKeys().getKeyNames()
        for keyName in keyNames:
            self._tpm._deleteKey(keyName)

        self._pib._removeIdentity(identityName)
        # TODO: Mark identity as invalid.

    def setDefaultIdentity(self, identity):
        """
        Set the identity as the default identity.

        :param PibIdentity identity: The identity to make the default.
        """
        self._pib._setDefaultIdentity(identity.getName())

    # Key management

    # Certificate management

    # Signing

    def sign(self, target, paramsOrCertificateName = None, wireFormat = None):
        """
        Sign the target. If it is a Data or Interest object, set its signature.
        If it is an array, return a signature object.

        :param target: If this is a Data object, wire encode for signing,
          update its signature and key locator field and wireEncoding. If this
          is an Interest object, wire encode for signing, append a SignatureInfo
          to the Interest name, sign the name components and append a final name
          component with the signature bits. If it is an array, sign it and
          return a Signature object.
        :type target: Data, Interest or an array which implements the
          buffer protocol
        :param paramsOrCertificateName: (optional) If a SigningInfo, it is the
          signing parameters. If a Name, it is the certificate name of the key
          to use for signing. If omitted and this is a security v1 KeyChain then
          use the IdentityManager to get the default identity. Otherwise, use
          the PIB to get the default key of the default identity.
        :type paramsOrCertificateName: SigningInfo or Name
        :param wireFormat: (optional) A WireFormat object used to encode the
           input. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        :return: The Signature object (only if the target is an array).
        :rtype: An object of a subclass of Signature
        """
        if isinstance(paramsOrCertificateName, WireFormat):
            # Shift the arguments.
            wireFormat = paramsOrCertificateName
            paramsOrCertificateName = None

        if wireFormat == None:
            wireFormat = WireFormat.getDefaultWireFormat()

        if paramsOrCertificateName == None:
            # Convert sign(target) into sign(target, paramsOrCertificateName)
            if self._isSecurityV1:
                paramsOrCertificateName = self._prepareDefaultCertificateName()
            else:
                paramsOrCertificateName = KeyChain._defaultSigningInfo

        if isinstance(paramsOrCertificateName, Name):
            certificateName = paramsOrCertificateName

            if not self._isSecurityV1:
                # Make and use a SigningInfo for backwards compatibility.
                if not (isinstance(target, Interest) or
                        isinstance(target, Data)):
                    raise SecurityException(
                      "sign(buffer, certificateName) is not supported for security v2. Use sign with SigningInfo.")

                signingInfo = SigningInfo()
                signingInfo.setSigningCertificateName(certificateName)
                try:
                    self.sign(target, signingInfo, wireFormat)
                except Exception as ex:
                    raise SecurityException("Error in sign: " + str(ex))

                return

            if isinstance(target, Interest):
                self._identityManager.signInterestByCertificate(
                  target, certificateName, wireFormat)
            elif isinstance(target, Data):
                self._identityManager.signByCertificate(
                  target, certificateName, wireFormat)
            else:
                return self._identityManager.signByCertificate(
                  target, certificateName)

            return

        params = paramsOrCertificateName

        if isinstance(target, Data):
            data = target

            keyName = [None]
            signatureInfo = self._prepareSignatureInfo(params, keyName)

            data.setSignature(signatureInfo)

            # Encode once to get the signed portion.
            encoding = data.wireEncode(wireFormat)

            signatureBytes = self._signBuffer(
              encoding.toSignedBytes(), keyName[0], params.getDigestAlgorithm())
            data.getSignature().setSignature(signatureBytes)

            # Encode again to include the signature.
            data.wireEncode(wireFormat)
        elif isinstance(target, Interest):
            interest = target

            keyName = [None]
            signatureInfo = self._prepareSignatureInfo(params, keyName)

            # Append the encoded SignatureInfo.
            interest.getName().append(wireFormat.encodeSignatureInfo(signatureInfo))

            # Append an empty signature so that the "signedPortion" is correct.
            interest.getName().append(Name.Component())
            # Encode once to get the signed portion, and sign.
            encoding = interest.wireEncode(wireFormat)
            signatureBytes = self._signBuffer(
              encoding.toSignedBytes(), keyName[0], params.getDigestAlgorithm())
            signatureInfo.setSignature(signatureBytes)

            # Remove the empty signature and append the real one.
            interest.setName(interest.getName().getPrefix(-1).append
              (wireFormat.encodeSignatureValue(signatureInfo)))
        else:
            buffer = target

            keyName = [None]
            signatureInfo = _prepareSignatureInfo(params, keyName)

            return self._signBuffer(
              buffer, keyName[0], params.getDigestAlgorithm())

    def selfSign(self, key):
        """
        Generate a self-signed certificate for the public key and add it to the
        PIB. This creates the certificate name from the key name by appending
        "self" and a version based on the current time. If no default
        certificate for the key has been set, then set the certificate as the
        default for the key.

        :param PibKey key: The PibKey with the key name and public key.
        :return: The new certificate.
        :rtype: CertificateV2
        """
        certificate = CertificateV2()

        # Set the name.
        now = Common.getNowMilliseconds()
        certificateName = Name(key.getName())
        certificateName.append("self").appendVersion(int(now))
        certificate.setName(certificateName)

        # Set the MetaInfo.
        certificate.getMetaInfo().setType(ContentType.KEY)
        # Set a one-hour freshness period.
        certificate.getMetaInfo().setFreshnessPeriod(3600 * 1000.0)

        # Set the content.
        certificate.setContent(key.getPublicKey())

        # Set the signature-info.
        signingInfo = SigningInfo(key)
        dummyKeyName = [None]
        certificate.setSignature(
          self._prepareSignatureInfo(signingInfo, dummyKeyName))
        # Set a 20-year validity period.
        ValidityPeriod.getFromSignature(certificate.getSignature()).setPeriod(
          now, now + 20 * 365 * 24 * 3600 * 1000.0)

        self.sign(certificate, signingInfo)

        try:
            key._addCertificate(certificate)
        except Exception as ex:
            # We don't expect this since we just created the certificate.
            raise KeyChain.Error("Error encoding certificate: " + str(ex))

        return certificate

    # Import and export

    # PIB & TPM backend registry

    # Security v1 methods

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
        if not self._isSecurityV1:
            try:
               self.deleteIdentity(self._pib.getIdentity(identityName))
            except:
                pass

            return

        self._identityManager.deleteIdentity(identityName)

    def getDefaultIdentity(self):
        """
        Get the default identity.

        :return: The name of default identity.
        :rtype: Name
        :raises SecurityException: if the default identity is not set.
        """
        if not self._isSecurityV1:
            try:
               return self._pib.getDefaultIdentity().getName()
            except Exception as ex:
                raise SecurityException("Error in getDefaultIdentity: " + str(ex))

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
        if not self._isSecurityV1:
            try:
                return (self._pib.getDefaultIdentity().getDefaultKey()
                        .getDefaultCertificate().getName())
            except Exception as ex:
                raise SecurityException("Error in getDefaultCertificate: " + str(ex))

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
        if not self._isSecurityV1:
            raise SecurityException(
              "generateRSAKeyPair is not supported for security v2. Use createIdentityV2.")

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
        if not self._isSecurityV1:
            raise SecurityException(
              "generateEcdsaKeyPair is not supported for security v2. Use createIdentityV2.")

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
        if not self._isSecurityV1:
            raise SecurityException(
              "setDefaultKeyForIdentity is not supported for security v2. Use getPib() methods.")

        if identityNameCheck == None:
            identityNameCheck = Name()
        return self._identityManager.setDefaultKeyForIdentity(
          keyName, identityNameCheck)

    def generateRSAKeyPairAsDefault(
          self, identityName, isKsk = False, keySize = 2048):
        """
        Generate a pair of RSA keys for the specified identity and set it as the
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
        if not self._isSecurityV1:
            raise SecurityException(
              "generateRSAKeyPairAsDefault is not supported for security v2. Use createIdentityV2.")

        return  self._identityManager.generateRSAKeyPairAsDefault(
          identityName, isKsk, keySize)

    def generateEcdsaKeyPairAsDefault(
          self, identityName, isKsk = False, keySize = 2048):
        """
        Generate a pair of ECDSA keys for the specified identity and set it as
        the default key for the identity.

        :param NameidentityName: The name of the identity.
        :param bool isKsk: (optional) true for generating a Key-Signing-Key
          (KSK), false for a Data-Signing-Key (DSK). If omitted, generate a
          Data-Signing-Key.
        :param int keySize: (optional) The size of the key. If omitted, use a
          default secure key size.
        :return: The generated key name.
        :rtype: Name
        """
        if not self._isSecurityV1:
            raise SecurityException(
              "generateEcdsaKeyPairAsDefault is not supported for security v2. Use createIdentityV2.")

        return  self._identityManager.generateEcdsaKeyPairAsDefault(
          identityName, isKsk, keySize)

    def createSigningRequest(self, keyName):
        """
        Create a public key signing request.

        :param Name keyName: The name of the key.
        :return: The signing request data.
        :rtype: Blob
        """
        if not self._isSecurityV1:
            try:
                return self._pib.getIdentity(PibKey.extractIdentityFromKeyName(
                         keyName)).getKey(keyName).getPublicKey()
            except Exception as ex:
                raise SecurityException("Error in getKey: " + str(ex))

        return self._identityManager.getPublicKey(keyName).getKeyDer()

    def installIdentityCertificate(self, certificate):
        """
        Install an identity certificate into the public key identity storage.

        :param IdentityCertificate certificate: The certificate to to added.
        """
        if not self._isSecurityV1:
            raise SecurityException(
              "installIdentityCertificate is not supported for security v2. Use getPib() methods.")

        self._identityManager.addCertificate(certificate)

    def setDefaultCertificateForKey(self, certificate):
        """
        Set the certificate as the default for its corresponding key.

        :param IdentityCertificate certificate: The certificate.
        """
        if not self._isSecurityV1:
            raise SecurityException(
              "setDefaultCertificateForKey is not supported for security v2. Use getPib() methods.")

        self._identityManager.setDefaultCertificateForKey(certificate)

    def getCertificate(self, certificateName):
        """
        Get a certificate with the specified name.

        :param Name certificateName: The name of the requested certificate.
        :return: The requested certificate.
        :rtype: IdentityCertificate
        """
        if not self._isSecurityV1:
            raise SecurityException(
              "getCertificate is not supported for security v2. Use getPib() methods.")

        return self._identityManager.getCertificate(certificateName)

    def getIdentityCertificate(self, certificateName):
        """
        :deprecated: Use getCertificate.
        """
        if not self._isSecurityV1:
            raise SecurityException(
              "getIdentityCertificate is not supported for security v2. Use getPib() methods.")

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
        if not self._isSecurityV1:
            raise SecurityException(
              "getIdentityManager is not supported for security v2")

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

        if not self._isSecurityV1:
            if not isinstance(target, Data):
                raise SecurityException(
                  "signByIdentity(buffer, identityName) is not supported for security v2. Use sign with SigningInfo.")

            signingInfo = SigningInfo()
            signingInfo.setSigningIdentity(identityName)
            try:
                self.sign(target, signingInfo, wireFormat)
            except Exception as ex:
                raise SecurityException("Error in sign: " + str(ex))

            return

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
        if not self._isSecurityV1:
            signingInfo = SigningInfo()
            signingInfo.setSha256Signing()
            try:
                self.sign(target, signingInfo, wireFormat)
            except Exception as ex:
                raise SecurityException("Error in sign: " + str(ex))

            return

        if isinstance(target, Interest):
            self._identityManager.signInterestWithSha256(target, wireFormat)
        else:
            self._identityManager.signWithSha256(target, wireFormat)

    def verifyData(self, data, onVerified, onValidationFailed, stepCount = 0):
        """
        Check the signature on the Data object and call either onVerify or
        onValidationFailed. We use callback functions because verify may fetch
        information to check the signature.

        :param Data data: The Data object with the signature to check.
        :param onVerified: If the signature is verified, this calls
          onVerified(data).
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onVerified: function object
        :param onValidationFailed: If the signature check fails or can't find
          the public key, this calls onValidationFailed(data, reason) with the
          Data object and reason string. This also supports the deprecated
          callback onValidationFailed(data) but you should use the callback with
          the reason string.
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onValidationFailed: function object
        :param int stepCount: (optional) The number of verification steps that
          have been done. If omitted, use 0.
        """
        # If onValidationFailed is not a function nor a method assumes it is a
        # calleable object
        if (not inspect.isfunction(onValidationFailed) and
            not inspect.ismethod(onValidationFailed)):
            onValidationFailed = onValidationFailed.__call__
        # Use getcallargs to test if onValidationFailed accepts 2 args.
        try:
            inspect.getcallargs(onValidationFailed, None, None)
        except TypeError:
            # Assume onValidationFailed is old-style with 1 argument. Wrap it
            # with a function that takes and ignores the reason string.
            oldValidationFailed = onValidationFailed
            onValidationFailed = lambda d, reason: oldValidationFailed(d)

        if self._policyManager.requireVerify(data):
            nextStep = self._policyManager.checkVerificationPolicy(
              data, stepCount, onVerified, onValidationFailed)
            if nextStep != None:
                self._face.expressInterest(
                  nextStep.interest, self._makeOnCertificateData(nextStep),
                  self._makeOnCertificateInterestTimeout(
                    nextStep.retry, onValidationFailed, data, nextStep))
        elif self._policyManager.skipVerifyAndTrust(data):
            try:
                onVerified(data)
            except:
                logging.exception("Error in onVerified")
        else:
            try:
                onValidationFailed(
                  data,
                  "The packet has no verify rule but skipVerifyAndTrust is false")
            except:
                logging.exception("Error in onValidationFailed")

    def verifyInterest(
      self, interest, onVerified, onValidationFailed, stepCount = 0,
      wireFormat = None):
        """
        Check the signature on the signed interest and call either onVerify or
        onValidationFailed. We use callback functions because verify may fetch
        information to check the signature.

        :param Interest interest: The interest with the signature to check.
        :param onVerified: If the signature is verified, this calls
          onVerified(interest).
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onVerified: function object
        :param onValidationFailed: If the signature check fails or can't find
          the  public key, this calls onValidationFailed(interest, reason) with
          the Interest object and reason string. This also supports the
          deprecated callback onValidationFailed(interest) but you should use
          the callback with the reason string.
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onValidationFailed: function object
        :param int stepCount: (optional) The number of verification steps that
          have been done. If omitted, use 0.
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        # If onValidationFailed is not a function nor a method assumes it is a
        # calleable object
        if (not inspect.isfunction(onValidationFailed) and
            not inspect.ismethod(onValidationFailed)):
            onValidationFailed = onValidationFailed.__call__
        # Use getcallargs to test if onValidationFailed accepts 2 args.
        try:
            inspect.getcallargs(onValidationFailed, None, None)
        except TypeError:
            # Assume onValidationFailed is old-style with 1 argument. Wrap it
            # with a function that takes and ignores the reason string.
            oldValidationFailed = onValidationFailed
            onValidationFailed = lambda i, reason: oldValidationFailed(i)

        if self._policyManager.requireVerify(interest):
            nextStep = self._policyManager.checkVerificationPolicy(
              interest, stepCount, onVerified, onValidationFailed, wireFormat)
            if nextStep != None:
                self._face.expressInterest(
                  nextStep.interest, self._makeOnCertificateData(nextStep),
                  self._makeOnCertificateInterestTimeout(
                    nextStep.retry, onValidationFailed, interest, nextStep))
        elif self._policyManager.skipVerifyAndTrust(interest):
            try:
                onVerified(interest)
            except:
                logging.exception("Error in onVerified")
        else:
            try:
                onValidationFailed(interest,
                  "The packet has no verify rule but skipVerifyAndTrust is false")
            except:
                logging.exception("Error in onValidationFailed")

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

    # Private security v2 methods

    @staticmethod
    def _getPibFactories():
        """
        Get the PIB factories map. On the first call, this initializes the map
        with factories for standard PibImpl implementations.

        :return: A map where the key is the scheme string and the value is a
          function object makePibImpl(location) which takes a string location
          and returns a new PibImpl object.
        :rtype: dict<str, function object>
        """
        if KeyChain._pibFactories == None:
            KeyChain._pibFactories = {}

            # Add the standard factories.
            KeyChain._pibFactories[
              PibSqlite3.getScheme()] = lambda location: PibSqlite3(location)
            KeyChain._pibFactories[
              PibMemory.getScheme()] = lambda location: PibMemory()

        return KeyChain._pibFactories

    @staticmethod
    def _getTpmFactories():
        """
        Get the TPM factories map. On the first call, this initializes the map
        with factories for standard TpmBackEnd implementations.

        :return: A map where the key is the scheme string and the value is a
          function object makeTpmBackEnd(location) which takes a string location
          and returns a new TpmBackEnd object.
        """
        if KeyChain._tpmFactories == None:
            KeyChain._tpmFactories = {}

            # Add the standard factories.
            if sys.platform == 'darwin':
                KeyChain._tpmFactories[
                  TpmBackEndOsx.getScheme()] = lambda location: TpmBackEndOsx()
            KeyChain._tpmFactories[
              TpmBackEndFile.getScheme()] = lambda location: TpmBackEndFile(location)
            KeyChain._tpmFactories[
              TpmBackEndMemory.getScheme()] = lambda location: TpmBackEndMemory()

        return KeyChain._tpmFactories

    @staticmethod
    def _parseLocatorUri(uri, scheme, location):
        """
        Parse the uri and set the scheme and location.

        :param str uri: The URI to parse.
        :param Array<str> scheme: Set scheme[0] to the scheme.
        :param Array<str> location: Set location[0] to the location.
        """
        iColon = uri.find(':')
        if iColon >= 0:
          scheme[0] = uri[0 : iColon]
          location[0] = uri[iColon + 1 :]
        else:
          scheme[0] = uri
          location[0] = ""

    @staticmethod
    def _parseAndCheckPibLocator(pibLocator, pibScheme, pibLocation):
        """
        Parse the pibLocator and set the pibScheme and pibLocation.

        :param str pibLocator: The PIB locator to parse.
        :param Array<str> pibScheme: Set pibScheme[0] to the PIB scheme.
        :param Array<str> pibLocation: Set pibLocation[0] to the PIB location.
        """
        KeyChain._parseLocatorUri(pibLocator, pibScheme, pibLocation)

        if pibScheme[0] == "":
            pibScheme[0] = KeyChain._getDefaultPibScheme()

        if not (pibScheme[0] in KeyChain._getPibFactories()):
            raise KeyChain.Error("PIB scheme `" + pibScheme[0] +
              "` is not supported")

    @staticmethod
    def _parseAndCheckTpmLocator(tpmLocator, tpmScheme, tpmLocation):
        """
        Parse the tpmLocator and set the tpmScheme and tpmLocation.

        :param str tpmLocator: The TPM locator to parse.
        :param Array<str> tpmScheme: Set tpmScheme[0] to the TPM scheme.
        :param Array<str> tpmLocation: Set tpmLocation[0] to the TPM location.
        """
        KeyChain._parseLocatorUri(tpmLocator, tpmScheme, tpmLocation)

        if tpmScheme[0] == "":
            tpmScheme[0] = KeyChain._getDefaultTpmScheme()

        if not (tpmScheme[0] in KeyChain._getTpmFactories()):
            raise KeyChain.Error("TPM scheme `" + tpmScheme[0] +
              "` is not supported")

    @staticmethod
    def _getDefaultPibScheme():
        """
        :rtype: str
        """
        return PibSqlite3.getScheme()

    @staticmethod
    def _getDefaultTpmScheme():
        """
        :rtype: str
        """
        if sys.platform == 'darwin':
            return TpmBackEndOsx.getScheme()
        else:
            return TpmBackEndFile.getScheme()

    @staticmethod
    def _createPib(pibLocator):
        """
        Create a Pib according to the pibLocator.

        :param str pibLocator: The PIB locator, e.g., "pib-sqlite3:/example/dir".
        :return: A new Pib object.
        :rtype: Pib
        """
        pibScheme = [None]
        pibLocation = [None]
        KeyChain._parseAndCheckPibLocator(pibLocator, pibScheme, pibLocation)
        pibFactory = KeyChain._getPibFactories()[pibScheme[0]]
        return Pib(
          pibScheme[0], pibLocation[0], pibFactory(pibLocation[0]))

    @staticmethod
    def _createTpm(tpmLocator):
        """
        Create a Tpm according to the tpmLocator.

        :param str tpmLocator: The TPM locator, e.g., "tpm-memory:".
        :return: A new Tpm object.
        :rtype: Tpm
        """
        tpmScheme = [None]
        tpmLocation = [None]
        KeyChain._parseAndCheckTpmLocator(tpmLocator, tpmScheme, tpmLocation)
        tpmFactory = KeyChain._getTpmFactories()[tpmScheme[0]]
        return Tpm(
          tpmScheme[0], tpmLocation[0], tpmFactory(tpmLocation[0]))

    @staticmethod
    def _getDefaultPibLocator(config):
        """
        :param str config:
        :rtype: str
        """
        if KeyChain._defaultPibLocator != None:
            return KeyChain._defaultPibLocator

        clientPib = System.getenv("NDN_CLIENT_PIB")
        if clientPib != None and clientPib != "":
            KeyChain._defaultPibLocator = clientPib
        else:
            KeyChain._defaultPibLocator = config.get(
              "pib", KeyChain._getDefaultPibScheme() + ":")

        return KeyChain._defaultPibLocator

    @staticmethod
    def _getDefaultTpmLocator(config):
        """
        :param str config:
        :rtype: str
        """
        if KeyChain._defaultTpmLocator != None:
            return KeyChain._defaultTpmLocator

        clientTpm = System.getenv("NDN_CLIENT_TPM")
        if clientTpm != None and clientTpm != "":
            KeyChain._defaultTpmLocator = clientTpm
        else:
            KeyChain._defaultTpmLocator = config.get(
              "tpm", getDefaultTpmScheme() + ":")

        return KeyChain._defaultTpmLocator

    def _prepareSignatureInfo(self, params, keyName):
        """
        Prepare a Signature object according to signingInfo and get the signing
        key name.

        :param SigningInfo params: The signing parameters.
        :param Array<Name> keyName: Set keyName[0] to the signing key name.
        :return: A new Signature object with the SignatureInfo.
        :rtype: Signature
        :raises InvalidSigningInfoError: when the requested signing method
          cannot be satisfied.
        """
        identity = None
        key = None

        if params.getSignerType() == SigningInfo.SignerType.NULL:
            try:
                identity = self._pib.getDefaultIdentity()
            except Pib.Error:
                # There is no default identity, so use sha256 for signing.
                keyName[0] = SigningInfo.getDigestSha256Identity()
                return DigestSha256Signature()
        elif params.getSignerType() == SigningInfo.SignerType.ID:
            identity = params.getPibIdentity()
            if identity == None:
                try:
                    identity = self._pib.getIdentity(params.getSignerName())
                except Pib.Error:
                    raise InvalidSigningInfoError(
                      "Signing identity `" + params.getSignerName().toUri() +
                      "` does not exist")
        elif params.getSignerType() == SigningInfo.SignerType.KEY:
            key = params.getPibKey()
            if key == None:
                identityName = PibKey.extractIdentityFromKeyName(
                  params.getSignerName())

                try:
                    identity = self._pib.getIdentity(identityName)
                    key = identity.getKey(params.getSignerName())
                    # We will use the PIB key instance, so reset the identity.
                    identity = None
                except Pib.Error:
                    raise InvalidSigningInfoError(
                      "Signing key `" + params.getSignerName().toUri() +
                      "` does not exist")
        elif params.getSignerType() == SigningInfo.SignerType.CERT:
            identityName = CertificateV2.extractIdentityFromCertName(
              params.getSignerName())

            try:
                identity = self._pib.getIdentity(identityName)
                key = identity.getKey(
                  CertificateV2.extractKeyNameFromCertName(params.getSignerName()))
            except Pib.Error:
                raise InvalidSigningInfoError(
                  "Signing certificate `" + params.getSignerName().toUri() +
                  "` does not exist")
        elif params.getSignerType() == SigningInfo.SignerType.SHA256:
            keyName[0] = SigningInfo.getDigestSha256Identity()
            return DigestSha256Signature()
        else:
            # We don't expect this to happen.
            raise InvalidSigningInfoError("Unrecognized signer type")

        if identity == None and key == None:
            raise InvalidSigningInfoError("Cannot determine signing parameters")

        if identity != None and key == None:
            try:
                key = identity.getDefaultKey()
            except Pib.Error:
                raise InvalidSigningInfoError(
                  "Signing identity `" + identity.getName().toUri() +
                  "` does not have default certificate")

        if key.getKeyType() == KeyType.RSA:
            signatureInfo = Sha256WithRsaSignature()
        elif key.getKeyType() == KeyType.ECDSA:
            signatureInfo = Sha256WithEcdsaSignature()
        else:
            raise KeyChain.Error("Unsupported key type")

        keyLocator = KeyLocator.getFromSignature(signatureInfo)
        keyLocator.setType(KeyLocatorType.KEYNAME)
        keyLocator.setKeyName(key.getName())

        keyName[0] = key.getName()
        return signatureInfo

    def _signBuffer(self, buffer, keyName, digestAlgorithm):
        """
        Sign the byte buffer using the key with name keyName.

        :param buffer: The input byte buffer.
        :type buffer: an array which implements the buffer protocol
        :param Name keyName: The name of the key.
        :param digestAlgorithm: The digest algorithm for the signature.
        :type digestAlgorithm: int from DigestAlgorithm
        :return: The signature Blob, or an isNull Blob if the key does not
          exist, or for an unrecognized digestAlgorithm.
        :rtype: Blob
        """
        if keyName.equals(SigningInfo.getDigestSha256Identity()):
            return Blob(Common.digestSha256(buffer))

        return self._tpm.sign(buffer, keyName, digestAlgorithm)

    # Private security v1 methods

    def _makeOnCertificateData(self, nextStep):
        """
        Make and return an onData callback to use in expressInterest.
        """
        def onData(interest, data):
            # Try to verify the certificate (data) according to the parameters
            #   in nextStep.
            self.verifyData(data, nextStep.onVerified, nextStep.onValidationFailed,
                            nextStep.stepCount)
        return onData

    def _makeOnCertificateInterestTimeout(self, retry, onValidationFailed,
          originalDataOrInterest, nextStep):
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
                       retry - 1, onValidationFailed, originalDataOrInterest,
                       nextStep))
            else:
                try:
                    onValidationFailed(
                      originalDataOrInterest,
                      "The retry count is zero after timeout for fetching " +
                        interest.getName().toUri())
                except:
                    logging.exception("Error in onValidationFailed")
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


    _defaultPibLocator = None # str
    _defaultTpmLocator = None # str
    _pibFactories = {} # str => MakePibImpl
    _tpmFactories = {} # str => MakeTpmBackEnd
    _defaultSigningInfo = SigningInfo()

class InvalidSigningInfoError(KeyChain.Error):
    """
    Create an InvalidSigningInfoError which extends KeyChain.Error to indicate
    that the supplied SigningInfo is invalid.

    :param str message: The error message.
    """
    def __init__(self, message):
        super(InvalidSigningInfoError, self).__init__(message)

class LocatorMismatchError(KeyChain.Error):
    """
    Create a LocatorMismatchError which extends KeyChain.Error to indicate that
    the supplied TPM locator does not match the locator stored in the PIB.

    :param str message: The error message.
    """
    def __init__(self, message):
        super(LocatorMismatchError, self).__init__(message)

_systemRandom = SystemRandom()

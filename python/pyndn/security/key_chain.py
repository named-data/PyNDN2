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
This module defines the KeyChain class which provides a set of interfaces to the
security library such as identity management, policy configuration  and packet 
signing and verification.
Note: This class is an experimental feature. See the API docs for more detail at
http://named-data.net/doc/ndn-ccl-api/key-chain.html .
"""

from pyndn.name import Name
from pyndn.interest import Interest
from pyndn.data import Data
from pyndn.sha256_with_rsa_signature import Sha256WithRsaSignature
from pyndn import KeyLocatorType
from pyndn.security.security_types import EncryptMode
from pyndn.security.identity.identity_manager import IdentityManager
from pyndn.security.policy.no_verify_policy_manager import NoVerifyPolicyManager
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
        self._encryptionManager = None
        self._face = None
        self._maxSteps = 100
    
    def createIdentity(self, identityName):
        """
        Create an identity by creating a pair of Key-Signing-Key (KSK) for this 
        identity and a self-signed certificate of the KSK.
        
        :param Name identityName: The name of the identity.
        :return: The key name of the auto-generated KSK of the identity.
        :rtype: Name
        """
        return self._identityManager.createIdentity(identityName)
    
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
    
    def setDefaultKeyForIdentity(self, keyName, identityName = None):
        """
        Set a key as the default key of an identity.

        :param Name keyName: The name of the key.
        :param Name identityName: (optional) the name of the identity. If not 
          specified, the identity name is inferred from the keyName.
        """
        if identityName == None:
            identityName = Name()
        return self._identityManager.setDefaultKeyForIdentity(
          keyName, identityName)
    
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
    
    def createSigningRequest(self, keyName):
        """
        Create a public key signing request.
        
        :param Name keyName: The name of the key.
        :returns: The signing request data.
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
        :return: The requested certificate which is valid.        
        :rtype: Certificate
        """
        return self._identityManager.getCertificate(certificateName)
    
    def getAnyCertificate(self, certificateName):
        """
        Get a certificate even if the certificate is not valid anymore.
        
        :param Name certificateName: The name of the requested certificate.
        :return: The requested certificate.        
        :rtype: Certificate
        """
        return self._identityManager.getAnyCertificate(certificateName)
    
    def getIdentityCertificate(self, certificateName):
        """
        Get an identity certificate with the specified name.
        
        :param Name certificateName: The name of the requested certificate.
        :return: The requested certificate which is valid.
        :rtype: IdentityCertificate
        """
        return self._identityManager.getIdentityCertificate(certificateName)
    
    def getAnyIdentityCertificate(self, certificateName):
        """
        Get an identity certificate even if the certificate is not valid anymore.
        
        :param Name certificateName: The name of the requested certificate.
        :return: The requested certificate.
        :rtype: IdentityCertificate
        """
        return self._identityManager.getAnyIdentityCertificate(certificateName)
    
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
    
    def sign(self, target, certificateName, wireFormat = None):
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
        :param Name certificateName: The certificate name of the key to use for 
          signing.
        :param wireFormat: (optional) A WireFormat object used to encode the 
           input. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        :return: The Signature object (only if the target is an array).
        :rtype: An object of a subclass of Signature
        """
        if isinstance(target, Interest):
            self._signInterest(target, certificateName, wireFormat)
        elif isinstance(target, Data):
            self._identityManager.signByCertificate(
              target, certificateName, wireFormat)
        else:
            return self._identityManager.signByCertificate(
              target, certificateName)
          
    def _signInterest(self, interest, certificateName, wireFormat = None):
        """
        Append a SignatureInfo to the Interest name, sign the name components 
        and append a final name component with the signature bits.
        
        :param Interest interest: The Interest object to be signed. This appends 
          name components of SignatureInfo and the signature bits.
        :param Name certificateName: The certificate name of the key to use for 
          signing.
        :param wireFormat: (optional) A WireFormat object used to encode the 
           input. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        # TODO: Handle signature algorithms other than Sha256WithRsa.
        signature = Sha256WithRsaSignature()
        signature.getKeyLocator().setType(KeyLocatorType.KEYNAME)
        signature.getKeyLocator().setKeyName(certificateName.getPrefix(-1))

        # Append the encoded SignatureInfo.
        interest.getName().append(wireFormat.encodeSignatureInfo(signature))

        # Append an empty signature so that the "signedPortion" is correct.
        interest.getName().append(Name.Component())
        # Encode once to get the signed portion.
        encoding = interest.wireEncode(wireFormat)
        signedSignature = self.sign(encoding.toSignedBuffer(), certificateName)

        # Remove the empty signature and append the real one.
        interest.setName(interest.getName().getPrefix(-1).append(
          wireFormat.encodeSignatureValue(signedSignature)))
          
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
                  data.getName())
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
                  data.getName(), signingCertificateName):
                raise SecurityException(
                  "Signing Cert name does not comply with signing policy")
                  
            self._identityManager.signByCertificate(
              data, signingCertificateName, wireFormat)
        else:
            signingCertificateName = \
              self._identityManager.getDefaultCertificateNameForIdentity(identityName)
    
            if signingCertificateName.size() == 0:
                raise SecurityException("No qualified certificate name found!")

            return self._identityManager.signByCertificate(
              array, signingCertificateName)
          
    def verifyData(self, data, onVerified, onVerifyFailed, stepCount = 0):
        """
        Check the signature on the Data object and call either onVerify or 
        onVerifyFailed. We use callback functions because verify may fetch 
        information to check the signature.
        
        :param Data data: The Data object with the signature to check.
        :param onVerified: If the signature is verified, this calls 
          onVerified(data).
        :type onVerified: function object
        :param onVerifyFailed: If the signature check fails or can't find the 
          public key, this calls onVerifyFailed(data).
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
            onVerified(data)
        else:
            onVerifyFailed(data)

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
        :type onVerified: function object
        :param onVerifyFailed: If the signature check fails or can't find the
          public key, this calls onVerifyFailed(interest).
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
            onVerified(interest)
        else:
            onVerifyFailed(interest)
            
    #
    # Encrypt/Decrypt
    #
    
    def generateSymmetricKey(self, keyName, keyType):
        """
        Generate a symmetric key.
        
        :param Name keyName: The name of the generated key.
        :param keyType: The type of the key, e.g. KeyType.AES
        :type keyType: int from KeyType
        """
        self._encryptionManager.createSymmetricKey(keyName, keyType)
    
    def encrypt(self, keyName, data, useSymmetric = True, 
                encryptMode = EncryptMode.DEFAULT):
        """
        Encrypt a byte array.
        
        :param Name keyName: The name of the encrypting key.
        :param data: The byte array that will be encrypted.
        :type data: an array which implements the buffer protocol
        :param bool useSymmetric: (optional) If true then symmetric encryption 
          is used, otherwise asymmetric encryption is used. If omitted, use
          symmetric encryption.
        :param encryptMode: (optional) The encryption mode. If omitted, use
          EncryptMode.DEFAULT .
        :type encryptMode: int from EncryptMode
        :return: The encrypted data as an immutable Blob.
        :rtype: Blob        
        """
        return self._encryptionManager.encrypt(
          keyName, data, useSymmetric, encryptMode)
    
    def decrypt(self, keyName, data, useSymmetric = True, 
                encryptMode = EncryptMode.DEFAULT):
        """
        Decrypt a byte array.
        
        :param Name keyName: The name of the decrypting key.
        :param data: The byte array that will be decrypted.
        :type data: an array which implements the buffer protocol
        :param bool useSymmetric: (optional) If true then symmetric encryption 
          is used, otherwise asymmetric encryption is used. If omitted, use
          symmetric encryption.
        :param encryptMode: (optional) The encryption mode. If omitted, use
          EncryptMode.DEFAULT .
        :type encryptMode: int from EncryptMode
        :return: The decrypted data as an immutable Blob.
        :rtype: Blob        
        """
        return self._encryptionManager.decrypt(
          keyName, data, useSymmetric, encryptMode)
    
    def setFace(self, face):
        """
        Set the Face which will be used to fetch required certificates.
        
        :param Face face: The Face object.
        """
        self._face = face
    
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
                onVerifyFailed(data)
        return onTimeout
            
            
    def setFace(self, face):
        """
        Set the Face which will be used to fetch required certificates.
        
        :param Face face: The Face object.
        """
        self._face = face
        
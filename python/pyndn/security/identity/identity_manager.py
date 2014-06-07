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
This module defines the IdentityManager class which is the interface of 
operations related to identity, keys, and certificates.
"""

import sys
from pyndn.data import Data
from pyndn.encoding import WireFormat
from pyndn.sha256_with_rsa_signature import Sha256WithRsaSignature
from pyndn import KeyLocatorType
from pyndn.security.identity.basic_identity_storage import BasicIdentityStorage
from pyndn.security.identity.file_private_key_storage import FilePrivateKeyStorage
from pyndn.security.identity.osx_private_key_storage import OSXPrivateKeyStorage

class IdentityManager(object):
    """
    Create a new IdentityManager to use the optional identityStorage and 
    privateKeyStorage.
    
    :param IdentityStorage identityStorage: (optional) An object of a subclass 
      of IdentityStorage. If omitted, use BasicIdentityStorage.
    :param PrivateKeyStorage privateKeyStorage: (optional) An object of a 
      subclass of PrivateKeyStorage. If omitted, use the default 
      PrivateKeyStorage for your system, which is OSXPrivateKeyStorage for OS X, 
      otherwise FilePrivateKeyStorage.
    """
    def __init__(self, identityStorage = None, privateKeyStorage = None):
        if identityStorage == None:
            identityStorage = BasicIdentityStorage()
        if privateKeyStorage == None:
            if sys.platform == 'darwin':
                # Use the OS X Keychain
                privateKeyStorage = OSXPrivateKeyStorage()
            else:
                privateKeyStorage = FilePrivateKeyStorage()
            
        self._identityStorage = identityStorage
        self._privateKeyStorage = privateKeyStorage
    
    def createIdentity(self, identityName):
        """
        Create an identity by creating a pair of Key-Signing-Key (KSK) for this 
        identity and a self-signed certificate of the KSK.
        
        :param Name identityName: The name of the identity.
        :return: The key name of the auto-generated KSK of the identity.
        :rtype: Name
        """
        raise RuntimeError("createIdentity is not implemented")
    
    def getDefaultIdentity(self):
        """
        Get the default identity.
        
        :return: The name of default identity.
        :rtype: Name
        :raises SecurityException: if the default identity is not set.
        """
        return self._identityStorage.getDefaultIdentity()
    
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
        raise RuntimeError("generateRSAKeyPair is not implemented")
    
    def setDefaultKeyForIdentity(self, keyName, identityName = None):
        """
        Set a key as the default key of an identity.

        :param Name keyName: The name of the key.
        :param Name identityName: (optional) the name of the identity. If not 
          specified, the identity name is inferred from the keyName.
        """
        if identityName == None:
            identityName = Name()
        self._identityStorage.setDefaultKeyNameForIdentity(keyName, identityName)
    
    def getDefaultKeyNameForIdentity(self,identityName = None):
        """
        Get the default key for an identity.

        :param Name identityName: The name of the identity.
        :raises SecurityException: if the default key name for the identity is 
          not set.
        """
        return self._identityStorage.getDefaultKeyNameForIdentity(identityName)
    
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
        raise RuntimeError("generateRSAKeyPairAsDefault is not implemented")
    
    def getPublicKey(self, keyName):
        """
        Get the public key with the specified name.
        
        :param Name keyName: The name of the key.
        :return: The public key.
        :rtype: PublicKey
        """
        return PublicKey.fromDer(
          self._identityStorage.getKeyType(keyName),
          self._identityStorage.getKey(keyName))
    
    # TODO: Add two versions of createIdentityCertificate.
    
    def addCertificate(self, certificate):
        """
        Add a certificate into the public key identity storage.
        
        :param IdentityCertificate certificate: The certificate to to added.  
          This makes a copy of the certificate.
        """
        self._identityStorage.addCertificate(certificate)
        
    def setDefaultCertificateForKey(self, certificate):
        """
        Set the certificate as the default for its corresponding key.
        
        :param IdentityCertificate certificate: The certificate.
        """
        keyName = certificate.getPublicKeyName()

        if not self._identityStorage.doesKeyExist(keyName):
            raise SecurityException("No corresponding Key record for certificate!")

        self._identityStorage.setDefaultCertificateNameForKey(
          keyName, certificate.getName())
    
    def addCertificateAsIdentityDefault(self, certificate):
        """
        Add a certificate into the public key identity storage and set the 
        certificate as the default for its corresponding identity.
        
        :param IdentityCertificate certificate: The certificate to to added.  
          This makes a copy of the certificate.
        """
        self._identityStorage.addCertificate(certificate)
        keyName = certificate.getPublicKeyName()
        self.setDefaultKeyForIdentity(keyName)
        self.setDefaultCertificateForKey(certificate)
    
    def addCertificateAsDefault(self, certificate):
        """
        Add a certificate into the public key identity storage and set the 
        certificate as the default of its corresponding key.
                
        :param IdentityCertificate certificate: The certificate to to added.  
          This makes a copy of the certificate.
        """
        self._identityStorage.addCertificate(certificate)
        self.setDefaultCertificateForKey(certificate)

    def getCertificate(self, certificateName):
        """
        Get a certificate with the specified name.
        
        :param Name certificateName: The name of the requested certificate.
        :return: The requested certificate which is valid.        
        :rtype: IdentityCertificate
        """
        return IdentityCertificate(
         self._identityStorage.getCertificate(certificateName, False))

    def getAnyCertificate(self, certificateName):
        """
        Get a certificate even if the certificate is not valid anymore.
        
        :param Name certificateName: The name of the requested certificate.
        :return: The requested certificate.        
        :rtype: IdentityCertificate
        """
        return IdentityCertificate(
         self._identityStorage.getCertificate(certificateName, True))

    def getDefaultCertificateNameForIdentity(self, identityName):
        """
        Get the default certificate name for the specified identity, which will 
        be used when signing is performed based on identity.
        
        :param Name identityName: The name of the specified identity.
        :return: The requested certificate name.
        :rtype: Name
        :raises SecurityException: if the default key name for the identity is 
          not set or the default certificate name for the key name is not set.
        """
        return self._identityStorage.getDefaultCertificateNameForIdentity(
          identityName)
    
    def getDefaultCertificateName(self):
        """
        Get the default certificate name of the default identity.
        
        :return: The requested certificate name.
        :rtype: Name
        :raises SecurityException: if the default identity is not set or the 
          default key name for the identity is not set or the default 
          certificate name for the key name is not set.
        """
        return self._identityStorage.getDefaultCertificateNameForIdentity(
          self.getDefaultIdentity())
        
    def signByCertificate(self, target, certificateName, wireFormat = None):
        """
        Sign the target based on the certificateName. If it is a Data object, 
        set its signature. If it is an array, return a signature object.

        :param target: If this is a Data object, wire encode for signing,
          update its signature and key locator field and wireEncoding. If it is 
          an array, sign it and return a Signature object.
        :param Name certificateName: The Name identifying the certificate which 
          identifies the signing key.
        :param wireFormat: (optional) The WireFormat for calling encodeData, or
          WireFormat.getDefaultWireFormat() if omitted.
        :type wireFormat: A subclass of WireFormat
        :return: The Signature object (only if the target is an array).
        :rtype: An object of a subclass of Signature
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        if isinstance(target, Data):
            data = target
            keyName = self.certificateNameToPublicKeyName(certificateName)

            # For temporary usage, we support RSA + SHA256 only, but will support more.
            data.setSignature(Sha256WithRsaSignature())
            # Get a pointer to the clone which Data made.
            signature = data.getSignature()
            signature.getKeyLocator().setType(KeyLocatorType.KEYNAME)
            signature.getKeyLocator().setKeyName(certificateName.getPrefix(-1))

            # Encode once to get the signed portion.
            encoding = data.wireEncode(wireFormat)

            signature.setSignature(self._privateKeyStorage.sign
              (encoding.toSignedBuffer(), keyName))

            # Encode again to include the signature.
            data.wireEncode(wireFormat)
        else:
            keyName = self.certificateNameToPublicKeyName(certificateName)

            # For temporary usage, we support RSA + SHA256 only, but will support more.
            signature = Sha256WithRsaSignature()

            signature.getKeyLocator().setType(KeyLocatorType.KEYNAME)
            signature.getKeyLocator().setKeyName(certificateName.getPrefix(-1))

            signature.setSignature(
              self._privateKeyStorage.sign(target, keyName))

            return signature

    def selfSign(self, keyName):
        """
        Generate a self-signed certificate for a public key.
        
        :param Name keyName: The name of the public key.
        :return: The generated certificate.
        :rtype: IdentityCertificate
        """
        raise RuntimeError("selfSign is not implemented")
                
                
                
                
    # TODO: Move this to IdentityCertificate
    @staticmethod
    def certificateNameToPublicKeyName(certificateName):
        """
        Get the public key name from the full certificate name.
        
        :param Name certificateName: The full certificate name.
        :return: The related public key name.
        :rtype: Name
        """
        i = certificateName.size() - 1
        idString = "ID-CERT"
        while i >= 0:
            if certificateName[i].toEscapedString() == idString:
                break
            i -= 1

        tmpName = certificateName.getSubName(0, i)
        keyString = "KEY"
        i = 0
        while i < tmpName.size():
            if tmpName[i].toEscapedString() == keyString:
                break
            i += 1

        return tmpName.getSubName(0, i).append(tmpName.getSubName(
                 i + 1, tmpName.size() - i - 1))

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
This module defines the MemoryIdentityStorage class which extends 
IdentityStorage and implements its methods to store identity, public key and 
certificate objects in memory. The application must get the objects through its 
own means and add the objects to the MemoryIdentityStorage object.
To use permanent file-based storage, see BasicIdentityStorage.
"""

from pyndn.util import Blob
from pyndn.security.security_exception import SecurityException
from pyndn.security.identity.identity_storage import IdentityStorage

class MemoryIdentityStorage(IdentityStorage):
    def __init__(self):
        super(MemoryIdentityStorage, self).__init__()
        # A list of name URI.
        self._identityStore = []
        # The default identity in identityStore_, or "" if not defined.
        self._defaultIdentity = ""
        # The key is the keyName.toUri(). The value is the tuple 
        #  (KeyType keyType, Blob keyDer).
        self._keyStore = {}
        # The key is the key is the certificateName.toUri(). The value is the 
        #   encoded certificate.
        self._certificateStore = {}

    def doesIdentityExist(self, identityName):  
        """
        Check if the specified identity already exists.
        
        :param Name identityName: The identity name.
        :return: True if the identity exists, otherwise False.
        :rtype: bool
        """
        return identityName.toUri() in self._identityStore
    
    def addIdentity(self, identityName):
        """
        Add a new identity. An exception will be thrown if the identity already 
        exists.

        :param Name identityName: The identity name.
        """
        identityUri = identityName.toUri()
        if identityUri in self._identityStore:
            raise SecurityException("Identity already exists: " + identityUri)
  
        self._identityStore.append(identityUri)
        
    def revokeIdentity(self):    
        """
        Revoke the identity.
        
        :return: True if the identity was revoked, False if not.
        :rtype: bool
        """
        raise RuntimeError(
          "MemoryIdentityStorage.doesIdentityExist is not implemented")

    def doesKeyExist(self, keyName):    
        """
        Check if the specified key already exists.
        
        :param Name keyName: The name of the key.
        :return: True if the key exists, otherwise False.
        :rtype: bool
        """
        return keyName.toUri() in self._keyStore

    def addKey(self, keyName, keyType, publicKeyDer):    
        """
        Add a public key to the identity storage.
        
        :param Name keyName: The name of the public key to be added.
        :param keyType: Type of the public key to be added.
        :type keyType: int from KeyType
        :param Blob publicKeyDer: A blob of the public key DER to be added.
        """
        identityName = keyName.getSubName(0, keyName.size() - 1)

        if not self.doesIdentityExist(identityName):
            self.addIdentity(identityName)

        if self.doesKeyExist(keyName):
            raise SecurityException("A key with the same name already exists!")
  
        self._keyStore[keyName.toUri()] = (keyType, Blob(publicKeyDer))

    def getKey(self, keyName):    
        """
        Get the public key DER blob from the identity storage.
        
        :param Name keyName: The name of the requested public key.
        :return: The DER Blob. If not found, return a isNull() Blob.
        :rtype: Blob
        """
        keyNameUri = keyName.toUri()
        if not (keyNameUri in self._keyStore):
            # Not found.  Silently return a null Blob.
            return Blob()
        
        (_, publicKeyDer) = self._keyStore[keyNameUri]
        return publicKeyDer

    def getKeyType(self, keyName):    
        """
        Get the KeyType of the public key with the given keyName.
        
        :param Name keyName: The name of the requested public key.
        :return: The KeyType, for example KeyType.RSA.
        :rtype: an int from KeyType
        """
        keyNameUri = keyName.toUri()
        if not (keyNameUri in self._keyStore):
            raise SecurityException(
              "Cannot get public key type because the keyName doesn't exist")
        
        (keyType, _) = self._keyStore[keyNameUri]
        return keyType

    def activateKey(self, keyName):    
        """
        Activate a key. If a key is marked as inactive, its private part will 
        not be used in packet signing.
        
        :param Name keyName: The name of the key.
        """
        raise RuntimeError(
          "MemoryIdentityStorage.activateKey is not implemented")

    def deactivateKey(self, keyName):    
        """
        Deactivate a key. If a key is marked as inactive, its private part will 
        not be used in packet signing.
        
        :param Name keyName: The name of the key.
        """
        raise RuntimeError(
         "MemoryIdentityStorage.deactivateKey is not implemented")

    def doesCertificateExist(self, certificateName):    
        """
        Check if the specified certificate already exists.
        
        :param Name certificateName: The name of the certificate.
        :return: True if the certificate exists, otherwise False.
        :rtype: bool
        """
        return certificateName.toUri() in self._certificateStore

    def addCertificate(self, certificate):    
        """
        Add a certificate to the identity storage.
        
        :param IdentityCertificate certificate: The certificate to be added. 
          This makes a copy of the certificate.
        """
        certificateName = certificate.getName()
        keyName = certificate.getPublicKeyName()

        if not self.doesKeyExist(keyName):
            raise SecurityException(
              "No corresponding Key record for certificate! " + 
              keyName.toUri() + " " + certificateName.toUri())

        # Check if the certificate already exists.
        if self.doesCertificateExist(certificateName):
            raise SecurityException("Certificate has already been installed!")

        # Check if the public key of certificate is the same as the key record.
        keyBlob = getKey(keyName)
        if (keyBlob.isNull() or 
              # Note: In Python, != should do a byte-by-byte comparison.
              keyBlob.toBuffer() != 
              certificate.getPublicKeyInfo().getKeyDer().toBuffer()):
            raise SecurityException(
              "Certificate does not match the public key!")
  
        # Insert the certificate.
        # wireEncode returns the cached encoding if available.
        self._certificateStore[certificateName.toUri()] = (
           certificate.wireEncode())

    def getCertificate(self, certificateName, allowAny = False):    
        """
        Get a certificate from the identity storage.
        
        :param Name certificateName: The name of the requested certificate.
        :param bool allowAny: (optional) If False, only a valid certificate will 
          be returned, otherwise validity is disregarded.  If omitted, 
          allowAny is False.
        :return: The requested certificate. If not found, return None.
        :rtype: Data
        """
        certificateNameUri = certificateName.toUri()
        if not (certificateNameUri in self._certificateStore):
            # Not found.  Silently return None.
            return None
  
        data = Data()
        data.wireDecode(self._certificateStore[certificateNameUri])
        return data

    #
    # Get/Set Default
    #

    def getDefaultIdentity(self):    
        """
        Get the default identity.
        
        :return: The name of default identity.
        :rtype: Name
        :raises SecurityException: if the default identity is not set.
        """
        if len(self._defaultIdentity) == 0:
            raise SecurityException(
          "MemoryIdentityStorage.getDefaultIdentity: The default identity is not defined")
          
        return Name(self._defaultIdentity)

    def getDefaultKeyNameForIdentity(self, identityName):    
        """
        Get the default key name for the specified identity.
        
        :param Name identityName: The identity name.
        :return: The default key name.
        :rtype: Name
        :raises SecurityException: if the default key name for the identity is 
          not set.
        """
        raise RuntimeError(
          "MemoryIdentityStorage.getDefaultKeyNameForIdentity is not implemented")

    def getDefaultCertificateNameForKey(self, keyName):    
        """
        Get the default certificate name for the specified key.
        
        :param Name keyName: The key name.
        :return: The default certificate name.
        :rtype: Name
        :raises SecurityException: if the default certificate name for the key 
          name is not set.
        """
        raise RuntimeError(
          "MemoryIdentityStorage.getDefaultCertificateNameForKey is not implemented")

    def setDefaultIdentity(self, identityName):    
        """
        Set the default identity. If the identityName does not exist, then clear
        the default identity so that getDefaultIdentity() raises an exception.
        
        :param Name identityName: The default identity name.
        """
        identityUri = identityName.toUri()
        if identityUri in self._identityStore:
            self._defaultIdentity = identityUri
        else:
            # The identity doesn't exist, so clear the default.
            self._defaultIdentity = ""

    def setDefaultKeyNameForIdentity(self, keyName, identityNameCheck = None):    
        """
        Set the default key name for the specified identity.
        
        
        :param Name keyName: The key name.
        :param Name identityNameCheck: (optional) The identity name to check the 
          keyName.
        """
        raise RuntimeError(
          "MemoryIdentityStorage.setDefaultKeyNameForIdentity is not implemented")

    def setDefaultCertificateNameForKey(self, keyName, certificateName):        
        """
        Set the default key name for the specified identity.
                
        :param Name keyName: The key name.
        :param Name certificateName: The certificate name.
        """
        raise RuntimeError(
          "MemoryIdentityStorage.setDefaultCertificateNameForKey is not implemented")

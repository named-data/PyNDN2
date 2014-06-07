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
BasicIdentityStorage extends IdentityStorage to implement a basic storage of
identity, public keys and certificates using SQLite.
"""

import os
import sqlite3
from pyndn.name import Name
from pyndn.security.security_exception import SecurityException
from pyndn.security.identity.identity_storage import IdentityStorage

INIT_ID_TABLE = ["""
CREATE TABLE IF NOT EXISTS
  Identity(
      identity_name     BLOB NOT NULL,
      default_identity  INTEGER DEFAULT 0,

      PRIMARY KEY (identity_name)
  );
""",
  "CREATE INDEX identity_index ON Identity(identity_name);"]

INIT_KEY_TABLE = ["""
CREATE TABLE IF NOT EXISTS
  Key(
      identity_name     BLOB NOT NULL,
      key_identifier    BLOB NOT NULL,
      key_type          INTEGER,
      public_key        BLOB,
      default_key       INTEGER DEFAULT 0,
      active            INTEGER DEFAULT 0,

      PRIMARY KEY (identity_name, key_identifier)
  );
""",
  "CREATE INDEX key_index ON Key(identity_name);"]

INIT_CERT_TABLE = ["""
CREATE TABLE IF NOT EXISTS
  Certificate(
      cert_name         BLOB NOT NULL,
      cert_issuer       BLOB NOT NULL,
      identity_name     BLOB NOT NULL,
      key_identifier    BLOB NOT NULL,
      not_before        TIMESTAMP,
      not_after         TIMESTAMP,
      certificate_data  BLOB NOT NULL,
      valid_flag        INTEGER DEFAULT 1,
      default_cert      INTEGER DEFAULT 0,

      PRIMARY KEY (cert_name)
  );
""",
  "CREATE INDEX cert_index ON Certificate(cert_name);",
  "CREATE INDEX subject ON Certificate(identity_name);"]

class BasicIdentityStorage(IdentityStorage):
    def __init__(self):
        super(BasicIdentityStorage, self).__init__()

        if not "HOME" in os.environ:
            # Don't expect this to happen
            home = "."
        else:
            home = os.environ["HOME"]

        identityDirectory = os.path.join(home, ".ndn")
        if not os.path.exists(identityDirectory):
            os.makedirs(identityDirectory)

        self._database = sqlite3.connect(
          os.path.join(identityDirectory, "ndnsec-public-info.db"))

        # Check if the ID table exists.
        cursor = self._database.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' And name='Identity'")
        if cursor.fetchone() == None:
            for command in INIT_ID_TABLE:
                self._database.execute(command)
        cursor.close()

        # Check if the Key table exists.
        cursor = self._database.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' And name='Key'")
        if cursor.fetchone() == None:
            for command in INIT_KEY_TABLE:
                self._database.execute(command)
        cursor.close()

        # Check if the Certificate table exists.
        cursor = self._database.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' And name='Certificate'")
        if cursor.fetchone() == None:
            for command in INIT_CERT_TABLE:
                self._database.execute(command)
        cursor.close()
            
        self._database.commit()

    def doesIdentityExist(self, identityName):  
        """
        Check if the specified identity already exists.
        
        :param Name identityName: The identity name.
        :return: True if the identity exists, otherwise False.
        :rtype: bool
        """
        result = False

        cursor = self._database.cursor()        
        cursor.execute(
          "SELECT count(*) FROM Identity WHERE identity_name=?",
          (identityName.toUri(),))
        (count,) = cursor.fetchone()
        if count > 0:
            result = True
            
        cursor.close()
        return result
        
    def addIdentity(self, identityName):
        """
        Add a new identity. An exception will be thrown if the identity already 
        exists.

        :param Name identityName: The identity name.
        """
        raise RuntimeError("doesIdentityExist is not implemented")

    def revokeIdentity(self):    
        """
        Revoke the identity.
        
        :return: True if the identity was revoked, False if not.
        :rtype: bool
        """
        raise RuntimeError("doesIdentityExist is not implemented")

    def doesKeyExist(self, keyName):    
        """
        Check if the specified key already exists.
        
        :param Name keyName: The name of the key.
        :return: True if the key exists, otherwise False.
        :rtype: bool
        """
        keyId = keyName.get(keyName.size() - 1).toEscapedString()
        identityName = keyName.getSubName(0, keyName.size() - 1)

        cursor = self._database.cursor()        
        cursor.execute(
          "SELECT count(*) FROM Key WHERE identity_name=? AND key_identifier=?",
          (identityName.toUri(), keyId))
        keyIdExists = False
        (count,) = cursor.fetchone()
        if count > 0:
            keyIdExists = True
            
        cursor.close()
        return keyIdExists

    def addKey(self, keyName, keyType, publicKeyDer):    
        """
        Add a public key to the identity storage.
        
        :param Name keyName: The name of the public key to be added.
        :param keyType: Type of the public key to be added.
        :type keyType: int from KeyType
        :param Blob publicKeyDer: A blob of the public key DER to be added.
        """
        raise RuntimeError("addKey is not implemented")

    def getKey(self, keyName):    
        """
        Get the public key DER blob from the identity storage.
        
        :param Name keyName: The name of the requested public key.
        :return: The DER Blob. If not found, return a isNull() Blob.
        :rtype: Blob
        """
        raise RuntimeError("getKey is not implemented")

    def getKeyType(self, keyName):    
        """
        Get the KeyType of the public key with the given keyName.
        
        :param Name keyName: The name of the requested public key.
        :return: The KeyType, for example KeyType.RSA.
        :rtype: an int from KeyType
        """
        keyId = keyName.get(keyName.size() - 1).toEscapedString()
        identityName = keyName.getSubName(0, keyName.size() - 1)

        cursor = self._database.cursor()        
        cursor.execute(
          "SELECT key_type FROM Key WHERE identity_name=? AND key_identifier=?",
          (identityName.toUri(), keyId))
        row = cursor.fetchone()
        
        if row != None:
            (keyType,) = row
            cursor.close()
            return keyType
        else:
            cursor.close()
            raise SecurityException(
              "Cannot get public key type because the keyName doesn't exist")

    def activateKey(self, keyName):    
        """
        Activate a key. If a key is marked as inactive, its private part will 
        not be used in packet signing.
        
        :param Name keyName: The name of the key.
        """
        raise RuntimeError("activateKey is not implemented")

    def deactivateKey(self, keyName):    
        """
        Deactivate a key. If a key is marked as inactive, its private part will 
        not be used in packet signing.
        
        :param Name keyName: The name of the key.
        """
        raise RuntimeError("deactivateKey is not implemented")

    def doesCertificateExist(self, certificateName):    
        """
        Check if the specified certificate already exists.
        
        :param Name certificateName: The name of the certificate.
        :return: True if the certificate exists, otherwise False.
        :rtype: bool
        """
        cursor = self._database.cursor()        
        cursor.execute(
          "SELECT count(*) FROM Certificate WHERE cert_name=?",
          (certificateName.toUri(),))
        certExists = False
        (count,) = cursor.fetchone()
        if count > 0:
            certExists = True
            
        cursor.close()
        return certExists

    def addCertificate(self, certificate):    
        """
        Add a certificate to the identity storage.
        
        :param IdentityCertificate certificate: The certificate to be added. 
          This makes a copy of the certificate.
        """
        raise RuntimeError("addCertificate is not implemented")

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
        raise RuntimeError("getCertificate is not implemented")

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
        cursor = self._database.cursor()        
        cursor.execute(
          "SELECT identity_name FROM Identity WHERE default_identity=1")
        row = cursor.fetchone()
        
        if row != None:
            (identity,) = row
            cursor.close()
            return Name(identity)
        else:
            cursor.close()
            raise SecurityException(
              "BasicIdentityStorage::getDefaultIdentity: The default identity is not defined")

    def getDefaultKeyNameForIdentity(self, identityName):    
        """
        Get the default key name for the specified identity.
        
        :param Name identityName: The identity name.
        :return: The default key name.
        :rtype: Name
        :raises SecurityException: if the default key name for the identity is 
          not set.
        """
        cursor = self._database.cursor()        
        cursor.execute(
          "SELECT key_identifier FROM Key WHERE identity_name=? AND default_key=1",
          (identityName.toUri(),))
        row = cursor.fetchone()
        
        if row != None:
            (keyName,) = row
            cursor.close()
            return Name(identityName).append(keyName)
        else:
            cursor.close()
            raise SecurityException(
              "BasicIdentityStorage::getDefaultKeyNameForIdentity: The default key for the identity is not defined")

    def getDefaultCertificateNameForKey(self, keyName):    
        """
        Get the default certificate name for the specified key.
        
        :param Name keyName: The key name.
        :return: The default certificate name.
        :rtype: Name
        :raises SecurityException: if the default certificate name for the key 
          name is not set.
        """
        keyId = keyName.get(keyName.size() - 1).toEscapedString()
        identityName = keyName.getSubName(0, keyName.size() - 1)

        cursor = self._database.cursor()        
        cursor.execute(
          "SELECT cert_name FROM Certificate WHERE identity_name=? AND key_identifier=? AND default_cert=1",
          (identityName.toUri(), keyId))
        row = cursor.fetchone()
        
        if row != None:
            (certName,) = row
            cursor.close()
            return Name(certName)
        else:
            cursor.close()
            raise SecurityException(
              "BasicIdentityStorage::getDefaultCertificateNameForKey: The default certificate for the key name is not defined")

    def setDefaultIdentity(self, identityName):    
        """
        Set the default identity. If the identityName does not exist, then clear
        the default identity so that getDefaultIdentity() raises an exception.
        
        :param Name identityName: The default identity name.
        """
        raise RuntimeError("setDefaultIdentity is not implemented")

    def setDefaultKeyNameForIdentity(self, keyName, identityNameCheck = None):    
        """
        Set the default key name for the specified identity.
        
        
        :param Name keyName: The key name.
        :param Name identityNameCheck: (optional) The identity name to check the 
          keyName.
        """
        raise RuntimeError("setDefaultKeyNameForIdentity is not implemented")

    def setDefaultCertificateNameForKey(self, keyName, certificateName):        
        """
        Set the default key name for the specified identity.
                
        :param Name keyName: The key name.
        :param Name certificateName: The certificate name.
        """
        raise RuntimeError("setDefaultCertificateNameForKey is not implemented")

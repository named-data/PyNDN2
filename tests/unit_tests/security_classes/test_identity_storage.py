# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Adeola Bannis <thecodemaiden@gmail.com>
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
This module is based on the BasicIdentityStorage class
"""
from pyndn.util import Blob
from pyndn.security.certificate import IdentityCertificate
from pyndn.security.security_exception import SecurityException
from pyndn import Name, Data
from pyndn.security.identity.basic_identity_storage import BasicIdentityStorage
import base64

class TestIdentityStorage(BasicIdentityStorage):
    def addIdentity(self, identityName):
        """
        Add a new identity. An exception will be thrown if the identity already 
        exists.

        :param Name identityName: The identity name.
        """
        identityUri = identityName.toUri()
        if self.doesIdentityExist(identityName):
            raise SecurityException("The identity {} already exists".format(
                identityUri))

        cursor = self._database.cursor() 
        cursor.execute("INSERT INTO Identity(identity_name) VALUES(?)",
            (identityUri,))
        self._database.commit()
        cursor.close()

    def revokeIdentity(self, identityName):
        """
        Delete an identity, and all keys and certificates associated with it.
        :param Name identityName: The identity name
        """
        cursor = self._database.cursor()
        cursor.execute("DELETE FROM Certificate WHERE identity_name=?",
            (identityName.toUri(),))

        cursor.execute("DELETE FROM Key WHERE identity_name=?",
            (identityName.toUri(),))

        cursor.execute("DELETE FROM Identity WHERE identity_name=?",
            (identityName.toUri(),))

        self._database.commit()
        cursor.close()

    def addKey(self, keyName, keyType, publicKeyDer):    
        """
        Add a public key to the identity storage.
        
        :param Name keyName: The name of the public key to be added.
        :param keyType: Type of the public key to be added.
        :type keyType: int from KeyType
        :param Blob publicKeyDer: A blob of the public key DER to be added.
        """
        if self.doesKeyExist(keyName):
            raise SecurityException("A key with the same name already exists!")

        identityName = keyName.getPrefix(-1)
        identityUri = identityName.toUri()
        makeDefault = 0
        if not self.doesIdentityExist(identityName):
            self.addIdentity(identityName)
            makeDefault = 1

        keyId = keyName.get(-1).toEscapedString()
        keyBuffer = buffer(bytearray (publicKeyDer.buf()))

        cursor = self._database.cursor()
        cursor.execute("INSERT INTO Key VALUES(?,?,?,?,?, ?)", 
            (identityUri, keyId, keyType, keyBuffer, makeDefault, 1))
        self._database.commit()
        cursor.close()

    def revokeKey(self, keyName):
        """
        Delete the public key from the store and delete all associated 
        certificates
        :param Name keyName: The name of the key to delete
        """
        keyId = str(keyName[-1].getValue())
        identityName = keyName[:-1]
        cursor = self._database.cursor()
        cursor.execute("DELETE FROM Certificate WHERE identity_name=? AND key_identifier=?",
            (identityName.toUri(), keyId))

        cursor.execute("DELETE FROM Key WHERE identity_name=? and key_identifier=?",
            (identityName.toUri(), keyId))

        self._database.commit()
        cursor.close()

    def getKey(self, keyName):    
        """
        Get the public key DER blob from the identity storage.
        
        :param Name keyName: The name of the requested public key.
        :return: The DER Blob. If not found, return a isNull() Blob.
        :rtype: Blob
        """
        identityUri = keyName.getPrefix(-1).toUri()
        keyId = keyName.get(-1).toEscapedString()

        cursor = self._database.cursor()
        cursor.execute("SELECT public_key FROM Key WHERE identity_name=? AND key_identifier=?",
            (identityUri, keyId))
        (keyData, ) = cursor.fetchone()
        cursor.close()
        return Blob(bytearray(keyData))

    def getAllKeysForIdentity(self, identityName):
        """
        Find all the keys associated with an identity

        :param Name identityName: The identity name to search for
        :return: All the keys associated with this identity
        :rtype: [Name]
        """
        cursor = self._database.cursor()
        cursor.execute("SELECT key_identifier FROM Key WHERE identity_name=?",
            (identityName.toUri(), ))
        keyIds = cursor.fetchall()
        keyNames = [Name(identityName).append(keyId) for keyId in keyIds]
        cursor.close()

        return keyNames

    def doesCertificateExist(self, certificateName):    
        """
        Check if the specified certificate already exists.
        
        :param Name certificateName: The name of the certificate.
        :return: True if the certificate exists, otherwise False.
        :rtype: bool
        """
        cursor = self._database.cursor()        
        # need to use LIKE because key locators cut off timestamps
        escapedUri = certificateName.toUri().replace('%', '\\%')
        cursor.execute(
          "SELECT count(*) FROM Certificate WHERE cert_name LIKE ? ESCAPE '\\'",
          (escapedUri+'%',))
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
        #TODO: actually check validity of certificate timestamp
        certificateName = certificate.getName()
        
        if self.doesCertificateExist(certificateName):
            raise SecurityException("Certificate has already been installed!")

        certCopy = IdentityCertificate(certificate)
        makeDefault = 0
        keyName = certCopy.getPublicKeyName()
        keyInfo = certCopy.getPublicKeyInfo()
        if not self.doesKeyExist(keyName):
            self.addKey(keyName, keyInfo.getKeyType(), keyInfo.getKeyDer())
            makeDefault = 1
        else:
            # see if the key we already have matches this certificate
            keyBlob = self.getKey(keyName)
            if (keyBlob.isNull() or keyBlob.toBuffer() != 
                    keyInfo.getKeyDer().toBuffer()):
                raise SecurityException("Certificate does not match public key")

        keyId = keyName.get(-1).toEscapedString()
        identityUri = keyName.getPrefix(-1).toUri()
        certIssuer = certCopy.getSignature().getKeyLocator().getKeyName().toUri()
        encodedCert = buffer(bytearray(certCopy.wireEncode().buf()))
        notBefore = certCopy.getNotBefore()
        notAfter = certCopy.getNotAfter()
        cursor = self._database.cursor()
        cursor.execute("INSERT INTO Certificate VALUES(?,?,?,?,?,?,?,?,?)",
            (certificateName.toUri(), certIssuer, identityUri, keyId,
                notBefore, notAfter, encodedCert, 1, makeDefault))
        self._database.commit()
        cursor.close()
            

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
        chosenCert = None
        certificateUri = certificateName.toUri()
        cursor = self._database.cursor()

        #if not allowAny:
        #    validityClause = " AND valid_flag=1"
        #else:
        validityClause = ""

        # use LIKE because key locators chop off timestamps
        # need to escape any percent signs in the certificate uri for sql's
        # sake, but still append % for LIKE
        escapedUri = certificateUri.replace('%', '\\%')
        full_statement = "SELECT certificate_data FROM Certificate WHERE cert_name LIKE ?"+validityClause+" ESCAPE '\\' ORDER BY cert_name DESC"
        #full_statement = "SELECT certificate_data FROM Certificate WHERE cert_name=?"+validityClause
        cursor.execute(full_statement, (escapedUri+'%', ))
        try:
            (certData, ) = cursor.fetchone()
        except TypeError:
            pass
        else:
            chosenCert = IdentityCertificate()
            chosenCert.wireDecode(bytearray(certData))
        return chosenCert 
        
    def setDefaultIdentity(self, identityName):    
        """
        Set the default identity. If the identityName does not exist,  
        raises a SecurityException.
        
        :param Name identityName: The default identity name.
        """
        if not self.doesIdentityExist(identityName):
            raise SecurityException("Identity does not exist")
        
        try:
            cursor = None
            currentDefault = self.getDefaultIdentity().toUri()
        except SecurityException:
            # no default, no need to remove default flag
            pass
        else:
            cursor = self._database.cursor()
            cursor.execute("UPDATE Identity SET default_identity=0 WHERE identity_name=?", (currentDefault,))

        if cursor is None:
            cursor = self._database.cursor()

        # now set this identity as default
        cursor.execute("UPDATE Identity SET default_identity=1 WHERE identity_name=?", (identityName.toUri(), ))

        self._database.commit()
        cursor.close()
            
    def setDefaultKeyNameForIdentity(self, keyName, identityNameCheck = None):    
        """
        Set the default key name for the corresponding identity.
        :param Name keyName: The key name.
        :param Name identityNameCheck: Not used
        """

        if not self.doesKeyExist(keyName):
            raise SecurityException("Key does not exist")
        
        keyId = keyName.get(-1).toEscapedString()
        if identityNameCheck is None:
            identityName = keyName.getPrefix(-1)
        else:
            identityName = identityNameCheck

        identityUri = identityName.toUri()
        try:
            cursor = None
            currentDefault = self.getDefaultKeyNameForIdentity(identityName)
        except SecurityException:
            # no current default, it's okay
            pass
        else:
            cursor = self._database.cursor()
            currentKeyId = currentDefault.get(-1).toEscapedString()
            cursor.execute("UPDATE Key SET default_key=0 WHERE identity_name=? AND key_identifier=?",
                (identityUri, currentKeyId))

        if cursor is None:
            cursor = self._database.cursor()
        
        cursor.execute("UPDATE Key SET default_key=1 WHERE identity_name=? AND key_identifier=?", (identityUri, keyId))

        self._database.commit()
        cursor.close()

    def setDefaultCertificateNameForKey(self, keyName, certificateName):        
        """
        Set the default certificate name for the corresponding key
                
        :param Name keyName: not used
        :param Name certificateName: The certificate name.
        """
        
        if not self.doesCertificateExist(certificateName):
            raise SecurityException("Certificate does not exist")

        keyName = IdentityCertificate.certificateNameToPublicKeyName(certificateName)
        identityUri = keyName.getPrefix(-1).toUri()
        keyId = keyName.get(-1).toEscapedString()

        try:
            cursor = None
            currentDefault = self.getDefaultCertificateNameForKey(keyName)
        except SecurityException:
            pass
        else:
            cursor = self._database.cursor()
            cursor.execute("UPDATE Certificate SET default_cert=0 WHERE cert_name=? AND identity_name=? AND key_identifier=?",
                (currentDefault.toUri(), identityUri, keyId))

        if cursor is None:
            cursor = self._database.cursor()
        
        cursor.execute("UPDATE Certificate SET default_cert=1 WHERE cert_name=? AND identity_name=? AND key_identifier=?",
                (certificateName.toUri(), identityUri, keyId))

        self._database.commit()
        cursor.close()

    def revokeCertificate(self, certificateName):
        """
        Delete a certificate and dissociate it from all keys.
        :param Name certificateName: The full name of the certificate
        """

        cursor = self._database.cursor()
        cursor.execute("DELETE FROM Certificate WHERE cert_name=?",
            (certificateName.toUri(),))

        self._database.commit()
        cursor.close()


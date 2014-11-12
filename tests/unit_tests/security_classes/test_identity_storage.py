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
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU Lesser General Public License is in the file COPYING.

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
        :rtype: IdentityCertificate
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

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

from pyndn.security.identity import IdentityManager
from pyndn.util.common import Common
from pyndn.util import Blob
from pyndn.name import Name
from test_private_key_storage import TestPrivateKeyStorage
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from pyndn.security.security_types import KeyType
from pyndn.security.certificate import IdentityCertificate, PublicKey, CertificateSubjectDescription
from pyndn.security.security_exception import SecurityException
import struct

class TestIdentityManager(IdentityManager):

    def createIdentity(self, identityName):
        """
        Create an identity by creating a pair of Key-Signing-Key (KSK) for this
        identity and a self-signed certificate of the KSK.

        :param Name identityName: The name of the identity.
        :return: The key name of the auto-generated KSK of the identity.
        :rtype: Name
        """
        self._identityStorage.addIdentity(identityName)
        newKeyName = self.generateRSAKeyPairAsDefault(identityName, True)
        return newKeyName

    def deleteIdentity(self, identityName):
        """
        Delete the identity from the public and private key storage
        :param Name identityName: The name of the identity to delete.
        """
        if (Name(self._identityStorage.getDefaultIdentity()) ==
                identityName):
            return # don't delete the default identity!
        self._identityStorage.deleteIdentityInfo(identityName)
        keysToDelete = self._identityStorage.getAllKeysForIdentity(identityName)
        for keyName in keysToDelete:
            self._privateKeyStorage.deleteKeyPair(keyName)

    def getPrivateKey(self, keyName):
        return self._privateKeyStorage.getPrivateKey(keyName)

    def addPrivateKey(self, keyName, keyDer):
        self._privateKeyStorage.addPrivateKey(keyName, keyDer)

    def generateRSAKeyPair(self, identityName, isKsk=False, keySize=2048):
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
        keyName = self._identityStorage.getNewKeyName(identityName, isKsk)
        self._privateKeyStorage.generateKeyPair(keyName, keySize)
        publicKeyBits = self._privateKeyStorage.getPublicKey(keyName)
        self._identityStorage.addKey(keyName, KeyType.RSA, publicKeyBits)
        newCert = self.selfSign(keyName)
        self.addCertificateAsDefault(newCert)


        return keyName

    def generateRSAKeyPairAsDefault(self, identityName, isKsk=False, keySize=2048):
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
        newKeyName = self.generateRSAKeyPair(identityName, isKsk, keySize)
        self._identityStorage.setDefaultKeyNameForIdentity(newKeyName)
        return newKeyName

    def selfSign(self, keyName):
        """
        Generate a self-signed certificate for a public key.

        :param Name keyName: The name of the public key.
        :return: The generated certificate.
        :rtype: IdentityCertificate
        """
        certificate = self.generateCertificateForKey(keyName)
        self.signByCertificate(certificate, certificate.getName())

        return certificate

    def generateCertificateForKey(self, keyName):
        # let any raised SecurityExceptions bubble up
        publicKeyBits = self._identityStorage.getKey(keyName)
        publicKeyType = self._identityStorage.getKeyType(keyName)

        publicKey = PublicKey(publicKeyType, publicKeyBits)

        timestamp = Common.getNowMilliseconds()

        # TODO: specify where the 'KEY' component is inserted
        # to delegate responsibility for cert delivery
        # cf: http://redmine.named-data.net/issues/1659
        certificateName = keyName.getPrefix(-1).append('KEY').append(keyName.get(-1))
        certificateName.append("ID-CERT").append(Name.Component(struct.pack(">Q", timestamp)))

        certificate = IdentityCertificate(certificateName)

        certificate.setNotBefore(timestamp)
        certificate.setNotAfter((timestamp + 30*86400*1000)) # about a month

        certificate.setPublicKeyInfo(publicKey)

        # ndnsec likes to put the key name in a subject description
        sd = CertificateSubjectDescription("2.5.4.41", keyName.toUri())
        certificate.addSubjectDescription(sd)

        certificate.encode()

        return certificate

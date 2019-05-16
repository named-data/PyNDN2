# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From the NAC library https://github.com/named-data/name-based-access-control/blob/new/src/decryptor.cpp
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
This module defines the DecryptorV2 class which decrypts the supplied
EncryptedContent element, using asynchronous operations, contingent on the
retrieval of the CK Data packet, the KDK, and the successful decryption of both
of these. For the meaning of "KDK", etc. see:
https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst
"""

import logging
from pyndn.name import Name
from pyndn.interest import Interest
from pyndn.key_locator import KeyLocatorType
from pyndn.security.key_chain import KeyChain
from pyndn.security.safe_bag import SafeBag
from pyndn.security.pib.pib import Pib
from pyndn.encrypt.encryptor_v2 import EncryptorV2
from pyndn.encrypt.encrypt_error import EncryptError
from pyndn.encrypt.encrypted_content import EncryptedContent
from pyndn.encrypt.algo.encrypt_params import EncryptParams, EncryptAlgorithmType
from pyndn.encrypt.algo.aes_algorithm import AesAlgorithm

class DecryptorV2(object):
    """
    Create a DecryptorV2 with the given parameters.

    :param PibKey credentialsKey: The credentials key to be used to retrieve and
      decrypt the KDK.
    :param Validator validator: The validation policy to ensure the validity of
      the KDK and CK.
    :param KeyChain keyChain: The KeyChain that will be used to decrypt the KDK.
    :param Face face: The Face that will be used to fetch the CK and KDK.
    """
    def __init__(self, credentialsKey, validator, keyChain, face):
        # The dictionary key is the CK Name. The value is a DecryptorV2.ContentKey.
        # TODO: add some expiration, so they are not stored forever.
        self._contentKeys = {}

        self._credentialsKey = credentialsKey
        # self._validator = validator
        self._face = face
        # The external keychain with access credentials.
        self._keyChain = keyChain

        # The internal in-memory keychain for temporarily storing KDKs.
        self._internalKeyChain = KeyChain("pib-memory:", "tpm-memory:")

    def shutdown(self):
        for name, contentKey in self._contentKeys.items():
            if contentKey.pendingInterest > 0:
                self._face.removePendingInterest(contentKey.pendingInterest)
                contentKey.pendingInterest = 0

                for pendingDecrypt in contentKey.pendingDecrypts:
                    pendingDecrypt.onError(
                      EncryptError.ErrorCode.CkRetrievalFailure,
                      "Canceling pending decrypt as ContentKey is being destroyed")

                # Clear is not really necessary, but just in case.
                contentKey.pendingDecrypts = []

    def decrypt(self, encryptedContent, onSuccess, onError):
        """
        Asynchronously decrypt the encryptedContent.

        :param EncryptedContent encryptedContent: The EncryptedContent to
          decrypt, which must have a KeyLocator with a KEYNAME and and initial
          vector. This does not copy the EncryptedContent object. If you may
          change it later, then pass in a copy of the object.
        :param onSuccess: On successful decryption, this calls
          onSuccess(plainData) where plainData is the decrypted Blob.
          NOTE: The library will log any exceptions thrown by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onSuccess: function object
        :param onError: On failure, this calls onError(errorCode, message) where
          errorCode is from EncryptError.ErrorCode and message is a str.
          NOTE: The library will log any exceptions thrown by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onError: function object
        """
        if encryptedContent.getKeyLocator().getType() != KeyLocatorType.KEYNAME:
            logging.getLogger(__name__).info(
              "Missing required KeyLocator in the supplied EncryptedContent block")
            onError(EncryptError.ErrorCode.MissingRequiredKeyLocator,
              "Missing required KeyLocator in the supplied EncryptedContent block")
            return

        if not encryptedContent.hasInitialVector():
            logging.getLogger(__name__).info(
              "Missing required initial vector in the supplied EncryptedContent block")
            onError(EncryptError.ErrorCode.MissingRequiredInitialVector,
              "Missing required initial vector in the supplied EncryptedContent block")
            return

        ckName = encryptedContent.getKeyLocatorName()
        isNew = True
        if ckName in self._contentKeys:
            contentKey = self._contentKeys[ckName]
            isNew = False
        if isNew:
            contentKey = DecryptorV2.ContentKey()
            self._contentKeys[ckName] = contentKey

        if contentKey.isRetrieved:
            DecryptorV2._doDecrypt(
              encryptedContent, contentKey.bits, onSuccess, onError)
        else:
            logging.getLogger(__name__).info("CK " +ckName.toUri() +
              " not yet available, so adding to the pending decrypt queue")
            contentKey.pendingDecrypts.append(DecryptorV2.ContentKey.PendingDecrypt
              (encryptedContent, onSuccess, onError))

        if isNew:
            self._fetchCk(ckName, contentKey, onError, EncryptorV2.N_RETRIES)

    class ContentKey(object):
        def __init__(self):
            self.isRetrieved = False
            # Blob
            self.bits = None
            self.pendingInterest = 0
            # Array of DecryptorV2.ContentKey.PendingDecrypt
            self.pendingDecrypts = []

        class PendingDecrypt(object):
            def __init__(self, encryptedContent, onSuccess, onError):
                # EncryptedContent
                self.encryptedContent = encryptedContent
                # This calls onSuccess(plainData) where plainData is a Blob.
                self.onSuccess = onSuccess
                # This calls onError(errorCode, message)
                self.onError = onError

    def _fetchCk(self, ckName, contentKey, onError, nTriesLeft):
        """
        :param Name ckName:
        :param DecryptorV2.ContentKey contentKey:
        :param onError: On error, this calls onError(errorCode, message)
        :type onError: function object
        :param int nTriesLeft:
        """
        # The full name of the CK is
        #
        # <whatever-prefix>/CK/<ck-id>  /ENCRYPTED-BY /<kek-prefix>/KEK/<key-id>
        # \                          /                \                        /
        #  -----------  -------------                  -----------  -----------
        #             \/                                          \/
        #   from the encrypted data          unknown (name in retrieved CK is used to determine KDK)

        logging.getLogger(__name__).info("Fetching CK " + ckName.toUri())

        def onData(ckInterest, ckData):
            try:
                contentKey.pendingInterest = 0
                # TODO: Verify that the key is legitimate.
                kdkPrefix = [None]
                kdkIdentityName = [None]
                kdkKeyName = [None]
                if not DecryptorV2._extractKdkInfoFromCkName(
                     ckData.getName(), ckInterest.getName(), onError, kdkPrefix,
                     kdkIdentityName, kdkKeyName):
                    # The error has already been reported.
                    return

                # Check if the KDK already exists.
                kdkIdentity = None
                try:
                    kdkIdentity = self._internalKeyChain.getPib().getIdentity(
                      kdkIdentityName[0])
                except Pib.Error:
                    pass

                if kdkIdentity != None:
                    kdkKey = None
                    try:
                        kdkKey = kdkIdentity.getKey(kdkKeyName[0])
                    except Pib.Error:
                        pass

                    if kdkKey != None:
                        # The KDK was already fetched and imported.
                        logging.getLogger(__name__).info("KDK " + kdkKeyName[0].toUri() +
                          " already exists, so directly using it to decrypt the CK")
                        self._decryptCkAndProcessPendingDecrypts(
                          contentKey, ckData, kdkKeyName[0], onError)
                        return

                self._fetchKdk(
                  contentKey, kdkPrefix[0], ckData, onError, EncryptorV2.N_RETRIES)
            except Exception as ex:
                onError(EncryptError.ErrorCode.General,
                  "Error in fetchCk onData: " + repr(ex))

        def onTimeout(interest):
            contentKey.pendingInterest = 0
            if nTriesLeft > 1:
                self._fetchCk(ckName, contentKey, onError, nTriesLeft - 1)
            else:
                onError(EncryptError.ErrorCode.CkRetrievalTimeout,
                  "Retrieval of CK [" + interest.getName().toUri() + "] timed out")
 
        def onNetworkNack(interest, networkNack):
            contentKey.pendingInterest = 0
            onError(EncryptError.ErrorCode.CkRetrievalFailure,
              "Retrieval of CK [" + interest.getName().toUri() +
              "] failed. Got NACK (" + str(networkNack.getReason()) + ")")

        try:
            contentKey.pendingInterest = self._face.expressInterest(
              Interest(ckName).setMustBeFresh(False).setCanBePrefix(True),
              onData, onTimeout, onNetworkNack)
        except Exception as ex:
            onError(EncryptError.ErrorCode.General,
              "expressInterest error: " + repr(ex))

    def _fetchKdk(self, contentKey, kdkPrefix, ckData, onError, nTriesLeft):
        """
        :param DecryptorV2.ContentKey contentKey:
        :param Name kdkPrefix:
        :param Data ckData:
        :param onError: On error, this calls onError(errorCode, message)
        :type onError: function object
        :param int nTriesLeft:
        """
        # <kdk-prefix>/KDK/<kdk-id>    /ENCRYPTED-BY  /<credential-identity>/KEY/<key-id>
        # \                          /                \                                /
        #  -----------  -------------                  ---------------  ---------------
        #             \/                                              \/
        #     from the CK data                                from configuration

        kdkName = Name(kdkPrefix)
        kdkName.append(EncryptorV2.NAME_COMPONENT_ENCRYPTED_BY).append(
          self._credentialsKey.getName())

        logging.getLogger(__name__).info("Fetching KDK " + kdkName.toUri())

        def onData(kdkInterest, kdkData):
            try:
                contentKey.pendingInterest = 0
                # TODO: Verify that the key is legitimate.

                isOk = self._decryptAndImportKdk(kdkData, onError)
                if not isOk:
                    return
                # This way of getting the kdkKeyName is a bit hacky.
                kdkKeyName = kdkPrefix.getPrefix(-2).append("KEY").append(
                  kdkPrefix.get(-1))
                self._decryptCkAndProcessPendingDecrypts(
                  contentKey, ckData, kdkKeyName, onError)
            except Exception as ex:
                onError(EncryptError.ErrorCode.General,
                  "Error in fetchCk onData: " + repr(ex))

        def onTimeout(interest):
            contentKey.pendingInterest = 0
            if nTriesLeft > 1:
                self._fetchKdk(
                  contentKey, kdkPrefix, ckData, onError, nTriesLeft - 1)
            else:
                onError(EncryptError.ErrorCode.KdkRetrievalTimeout,
                  "Retrieval of KDK [" + interest.getName().toUri() +
                  "] timed out")

        def onNetworkNack(interest, networkNack):
            contentKey.pendingInterest = 0
            onError(EncryptError.ErrorCode.KdkRetrievalFailure,
              "Retrieval of KDK [" + interest.getName().toUri() +
              "] failed. Got NACK (" + str(networkNack.getReason()) + ")")

        try:
            contentKey.pendingInterest = self._face.expressInterest(
              Interest(kdkName).setMustBeFresh(True).setCanBePrefix(False),
              onData, onTimeout, onNetworkNack)
        except Exception as ex:
            onError(EncryptError.ErrorCode.General,
              "expressInterest error: " + repr(ex))

    def _decryptAndImportKdk(self, kdkData, onError):
        """
        :param Data kdkData:
        :param onError: On error, this calls onError(errorCode, message)
        :type onError: function object
        :return: True for success, false for error (where this has called onError).
        :rtype: bool
        """
        try:
            logging.getLogger(__name__).info("Decrypting and importing KDK " +
              kdkData.getName().toUri())
            encryptedContent = EncryptedContent()
            encryptedContent.wireDecodeV2(kdkData.getContent())

            safeBag = SafeBag(encryptedContent.getPayload())
            secret = self._keyChain.getTpm().decrypt(
              encryptedContent.getPayloadKey().toBytes(),
              self._credentialsKey.getName())
            if secret.isNull():
                onError(EncryptError.ErrorCode.TpmKeyNotFound,
                  "Could not decrypt secret, " + self._credentialsKey.getName().toUri() +
                  " not found in TPM")
                return False

            self._internalKeyChain.importSafeBag(safeBag, secret.toBytes())
            return True
        except Exception as ex:
            onError(EncryptError.ErrorCode.DecryptionFailure,
              "Failed to decrypt KDK [" + kdkData.getName().toUri() + "]: " +
              repr(ex))
            return False

    def _decryptCkAndProcessPendingDecrypts(
      self, contentKey, ckData, kdkKeyName, onError):
        logging.getLogger(__name__).info("Decrypting CK data " +
          ckData.getName().toUri())

        content = EncryptedContent()
        try:
          content.wireDecodeV2(ckData.getContent())
        except Exception as ex:
            onError(EncryptError.ErrorCode.InvalidEncryptedFormat,
              "Error decrypting EncryptedContent: " + repr(ex))
            return

        try:
            ckBits = self._internalKeyChain.getTpm().decrypt(
              content.getPayload().toBytes(), kdkKeyName)
        except Exception as ex:
            # We don't expect this from the in-memory KeyChain.
            onError(EncryptError.ErrorCode.DecryptionFailure,
              "Error decrypting the CK EncryptedContent " + repr(ex))
            return

        if ckBits.isNull():
            onError(EncryptError.ErrorCode.TpmKeyNotFound,
              "Could not decrypt secret, " + kdkKeyName.toUri() +
              " not found in TPM")
            return

        contentKey.bits = ckBits
        contentKey.isRetrieved = True

        for pendingDecrypt in contentKey.pendingDecrypts:
            # TODO: If this calls onError, should we quit?
            DecryptorV2._doDecrypt(
              pendingDecrypt.encryptedContent, contentKey.bits,
              pendingDecrypt.onSuccess, pendingDecrypt.onError)

        contentKey.pendingDecrypts = []

    @staticmethod
    def _doDecrypt(content, ckBits, onSuccess, onError):
        """
        :param EncryptedContent content:
        :param Blob ckBits:
        :param onSuccess: On success, this calls onSuccess(plainData) where
          plainData is a Blob.
        :param onError: On error, this calls onError(errorCode, message)
        :type onError: function object
        """
        if not content.hasInitialVector():
            onError(EncryptError.ErrorCode.MissingRequiredInitialVector,
              "Expecting Initial Vector in the encrypted content, but it is not present")
            return

        try:
            params = EncryptParams(EncryptAlgorithmType.AesCbc)
            params.setInitialVector(content.getInitialVector())
            plainData = AesAlgorithm.decrypt(
              ckBits, content.getPayload(), params)
        except Exception as ex:
            onError(EncryptError.ErrorCode.DecryptionFailure,
              "Decryption error in doDecrypt: " + repr(ex))
            return

        try:
            onSuccess(plainData)
        except:
            logging.exception("Error in onSuccess")

    @staticmethod
    def _convertKekNameToKdkPrefix(kekName, onError):
        """
        Convert the KEK name to the KDK prefix:
        <access-namespace>/KEK/<key-id> ==> <access-namespace>/KDK/<key-id>.

        :param Name kekName: The KEK name.
        :param onError: On error, this calls onError(errorCode, message)
        :type onError: function object
        :return: The KDK prefix, or None if an error was reported to onError.
        :rtype: Name
        """
        if (kekName.size() < 2 or
             not kekName.get(-2).equals(EncryptorV2.NAME_COMPONENT_KEK)):
            onError(EncryptError.ErrorCode.KekInvalidName,
              "Invalid KEK name [" + kekName.toUri() + "]")
            return None

        return kekName.getPrefix(-2).append(
          EncryptorV2.NAME_COMPONENT_KDK).append(kekName.get(-1))

    @staticmethod
    def _extractKdkInfoFromCkName(
      ckDataName, ckName, onError, kdkPrefix, kdkIdentityName, kdkKeyId):
        """
        Extract the KDK information from the CK Data packet name. The KDK
        identity name plus the KDK key ID together identify the KDK private key
        in the KeyChain.

        :param Name ckDataName: The name of the CK Data packet.
        :param Name ckName: The CK name from the Interest used to fetch the CK
          Data packet.
        :param onError: On error, this calls onError(errorCode, message)
        :type onError: function object
        :param kdkPrefix: This sets kdkPrefix[0] to the KDK prefix.
        :type kdkPrefix: Array<Name>
        :param kdkIdentityName: This sets kdkIdentityName[0] to the KDK identity
          name.
        :type kdkIdentityName: Array<Name>
        :param kdkKeyId: This sets kdkKeyId[0] to the KDK key ID.
        :type kdkKeyId: Array<Name>
        :return: True for success or false if an error was reported to onError.
        :rtype: bool
        """
        # <full-ck-name-with-id> | /ENCRYPTED-BY/<kek-prefix>/NAC/KEK/<key-id>

        if (ckDataName.size() < ckName.size() + 1 or
            not ckDataName.getPrefix(ckName.size()).equals(ckName) or
            not ckDataName.get(ckName.size()).equals
              (EncryptorV2.NAME_COMPONENT_ENCRYPTED_BY)):
            onError(EncryptError.ErrorCode.CkInvalidName,
              "Invalid CK name [" + ckDataName.toUri() + "]")
            return False

        kekName = ckDataName.getSubName(ckName.size() + 1)
        kdkPrefix[0] = DecryptorV2._convertKekNameToKdkPrefix(kekName, onError)
        if kdkPrefix[0] == None:
            # The error has already been reported.
            return False

        kdkIdentityName[0] = kekName.getPrefix(-2)
        kdkKeyId[0] = kekName.getPrefix(-2).append("KEY").append(kekName.get(-1))
        return True

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From the NAC library https://github.com/named-data/name-based-access-control/blob/new/src/encryptor.cpp
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
This module defines the EncryptorV2 class which encrypts the requested content
for name-based access control (NAC) using security v2. For the meaning of "KEK",
etc. see:
https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst
"""

import logging
from random import SystemRandom
from pyndn.name import Name
from pyndn.interest import Interest
from pyndn.data import Data
from pyndn.util.common import Common
from pyndn.util.blob import Blob
from pyndn.in_memory_storage.in_memory_storage_retaining import InMemoryStorageRetaining
from pyndn.security.certificate.public_key import PublicKey
from pyndn.encrypt.algo.encrypt_params import EncryptParams, EncryptAlgorithmType
from pyndn.encrypt.algo.aes_algorithm import AesAlgorithm
from pyndn.encrypt.encrypt_error import EncryptError
from pyndn.encrypt.encrypted_content import EncryptedContent

# The Python documentation says "Use SystemRandom if you require a
#   cryptographically secure pseudo-random number generator."
# http://docs.python.org/2/library/random.html
_systemRandom = SystemRandom()

class EncryptorV2(object):
    """
    Create an EncryptorV2 with the given parameters. This uses the face to
    register to receive Interests for the prefix {ckPrefix}/CK.

    :param Name accessPrefix: The NAC prefix to fetch the Key Encryption Key
      (KEK) (e.g., /access/prefix/NAC/data/subset). This copies the Name.
    :param Name ckPrefix: The prefix under which Content Keys (CK) will be
      generated. (Each will have a unique version appended.) This copies the Name.
    :param SigningInfo ckDataSigningInfo: The SigningInfo parameters to sign the
      Content Key (CK) Data packet. This copies the SigningInfo.
    :param onError: On failure to create the CK data (failed to fetch the KEK,
      failed to encrypt with the KEK, etc.), this calls
      onError(errorCode, message) where errorCode is from EncryptError.ErrorCode
      and message is a str. The encrypt method will continue trying to retrieve
      the KEK until success (with each attempt separated by
      RETRY_DELAY_KEK_RETRIEVAL_MS) and onError may be called multiple times.
      NOTE: The library will log any exceptions thrown by this callback, but for
      better error handling the callback should catch and properly handle any
      exceptions.
    :type onError: function object
    :param Validator validator: The validation policy to ensure correctness of
      the KEK.
    :param KeyChain keyChain: The KeyChain used to sign Data packets.
    :param Face face: The Face that will be used to fetch the KEK and publish CK
      data.
    """
    def __init__(self, accessPrefix, ckPrefix, ckDataSigningInfo,
      onError, validator, keyChain, face):
        # Copy the Name.
        self._accessPrefix = Name(accessPrefix)
        self._ckPrefix = Name(ckPrefix)
        self._ckBits = bytearray(EncryptorV2.AES_KEY_SIZE)
        self._ckDataSigningInfo = SigningInfo(ckDataSigningInfo)
        self._isKekRetrievalInProgress = False
        self._onError = onError
        self._keyChain = keyChain
        self._face = face

        self._kekData = None
        # Storage for encrypted CKs.
        self._storage = InMemoryStorageRetaining()
        self._kekPendingInterestId = 0

        self.regenerateCk()

        def onInterest(prefix, interest, face, interestFilterId, filter):
            data = self._storage.find(interest)
            if data != None:
                logging.getLogger(__name__).info("Serving " +
                  data.getName().toUri() + " from InMemoryStorage")
                try:
                    face.putData(data)
                except:
                    logging.exception("Error in Face.putData")
            else:
                logging.getLogger(__name__).info(
                  "Didn't find CK data for " + interest.getName().toUri())
                # TODO: Send NACK?

        def onRegisterFailed(prefix):
            logging.getLogger(__name__).error(
              "Failed to register prefix " + prefix.toUri())

        self._ckRegisteredPrefixId = self._face.registerPrefix(
          Name(ckPrefix).append(EncryptorV2.NAME_COMPONENT_CK),
          onInterest, onRegisterFailed)

    def shutdown(self):
        self._face.unsetInterestFilter(self._ckRegisteredPrefixId)
        if self._kekPendingInterestId > 0:
            self._face.removePendingInterest(self._kekPendingInterestId)

    def encrypt(self, plainData):
        """
        Encrypt the plainData using the existing Content Key (CK) and return a
        new EncryptedContent.

        :param plainData: The data to encrypt.
        :type plainData: Blob or an array which implements the buffer protocol
        :return: The new EncryptedContent.
        :rtype: EncryptedContent
        """
        # Generate the initial vector.
        initialVector = bytearray(EncryptorV2.AES_IV_SIZE)
        for i in range(len(initialVector)):
            initialVector[i] = _systemRandom.randint(0, 0xff)

        params = EncryptParams(EncryptAlgorithmType.AesCbc)
        params.setInitialVector(Blob(initialVector, False))
        encryptedData = AesAlgorithm.encrypt(
          Blob(self._ckBits, False), Blob(plainData, False), params)

        content = EncryptedContent()
        content.setInitialVector(params.getInitialVector())
        content.setPayload(encryptedData)
        content.setKeyLocatorName(self._ckName)

        return content

    def regenerateCk(self):
        """
        Create a new Content Key (CK) and publish the corresponding CK Data
        packet. This uses the onError given to the constructor to report errors.
        """
        # TODO: Ensure that the CK Data packet for the old CK is published when
        # the CK is updated before the KEK is fetched.

        self._ckName = Name(self._ckPrefix)
        self._ckName.append(EncryptorV2.NAME_COMPONENT_CK)
        # The version is the ID of the CK.
        self._ckName.appendVersion(int(Common.getNowMilliseconds()))

        logging.getLogger(__name__).info("Generating new CK: " +
          self._ckName.toUri())
        for i in range(len(self._ckBits)):
            self._ckBits[i] = _systemRandom.randint(0, 0xff)

        # One implication: If the CK is updated before the KEK is fetched, then
        # the KDK for the old CK will not be published.
        if self._kekData == None:
            self._retryFetchingKek()
        else:
            self._makeAndPublishCkData(self._onError)

    def size(self):
        """
        Get the number of packets stored in in-memory storage.
        
        :return: The number of packets.
        :rtype: int
        """
        return self._storage.size()

    def _retryFetchingKek(self):
        if self._isKekRetrievalInProgress:
            return

        logging.getLogger(__name__).info("Retrying fetching of the KEK")
        self._isKekRetrievalInProgress = True

        def onReady():
            logging.getLogger(__name__).info("The KEK was retrieved and published")
            self._isKekRetrievalInProgress = False

        def onError(errorCode, message):
            logging.getLogger(__name__).info("Failed to retrieve KEK: " + message)
            self._isKekRetrievalInProgress = False
            self._onError(errorCode, message)

        self._fetchKekAndPublishCkData(onReady, onError, EncryptorV2.N_RETRIES)

    def _fetchKekAndPublishCkData(self, onReady, onError, nTriesLeft):
        """
        Create an Interest for <access-prefix>/KEK to retrieve the
        <access-prefix>/KEK/<key-id> KEK Data packet, and set _kekData.

        :param onReady: When the KEK is retrieved and published, this calls
          onReady().
        :type onError: function object
        :param onError: On failure, this calls onError(errorCode, message)
          where errorCode is from EncryptError.ErrorCode, and message is an
          error string.
        :type onError: function object
        :param int nTriesLeft: The number of retries for expressInterest timeouts.
        """
        logging.getLogger(__name__).info("Fetching KEK: " +
          Name(self._accessPrefix).append(EncryptorV2.NAME_COMPONENT_KEK).toUri())

        if self._kekPendingInterestId > 0:
            onError(EncryptError.ErrorCode.General,
              "fetchKekAndPublishCkData: There is already a _kekPendingInterestId")
            return

        def onData(interest, kekData):
            self._kekPendingInterestId = 0
            # TODO: Verify if the key is legitimate.
            self._kekData = kekData
            if self._makeAndPublishCkData(onError):
                onReady()
            # Otherwise, failure has already been reported.

        def onTimeout(interest):
            self._kekPendingInterestId = 0
            if nTriesLeft > 1:
                self._fetchKekAndPublishCkData(onReady, onError, nTriesLeft - 1)
            else:
                onError(EncryptError.ErrorCode.KekRetrievalTimeout,
                  "Retrieval of KEK [" + interest.getName().toUri() + "] timed out")
                logging.getLogger(__name__).info(
                  "Scheduling retry after all timeouts")
                self._face.callLater(
                  EncryptorV2.RETRY_DELAY_KEK_RETRIEVAL_MS, self._retryFetchingKek)

        def onNetworkNack(interest, networkNack):
            self._kekPendingInterestId = 0
            if nTriesLeft > 1:
                def callback():
                    self._fetchKekAndPublishCkData(onReady, onError, nTriesLeft - 1)
                self._face.callLater(EncryptorV2.RETRY_DELAY_AFTER_NACK_MS, callback)
            else:
                onError(EncryptError.ErrorCode.KekRetrievalFailure,
                  "Retrieval of KEK [" + interest.getName().toUri() +
                  "] failed. Got NACK (" + str(networkNack.getReason()) + ")")
                logging.getLogger(__name__).info("Scheduling retry from NACK")
                self._face.callLater(
                  EncryptorV2.RETRY_DELAY_KEK_RETRIEVAL_MS, self._retryFetchingKek)

        try:
            self._kekPendingInterestId = self._face.expressInterest(
              Interest(Name(self._accessPrefix).append(EncryptorV2.NAME_COMPONENT_KEK))
                .setMustBeFresh(True)
                .setCanBePrefix(True),
              onData, onTimeout, onNetworkNack)
        except Exception as ex:
            onError(EncryptError.ErrorCode.General,
              "expressInterest error: " + repr(ex))

    def _makeAndPublishCkData(self, onError):
        """
        Make a CK Data packet for _ckName encrypted by the KEK in _kekData and
        insert it in the _storage.

        :param onError: On failure, this calls onError(errorCode, message) where
          errorCode is from EncryptError.ErrorCode, and message is an error
          string.
        :type onError: function object
        :return: True on success, else False.
        :rtype: bool
        """
        try:
            kek = PublicKey(self._kekData.getContent())

            content = EncryptedContent()
            content.setPayload(kek.encrypt
              (Blob(self._ckBits, False), EncryptAlgorithmType.RsaOaep))

            ckData = Data(
              Name(self._ckName).append(EncryptorV2.NAME_COMPONENT_ENCRYPTED_BY)
               .append(self._kekData.getName()))
            ckData.setContent(content.wireEncodeV2())
            # FreshnessPeriod can serve as a soft access control for revoking access.
            ckData.getMetaInfo().setFreshnessPeriod(
              EncryptorV2.DEFAULT_CK_FRESHNESS_PERIOD_MS)
            self._keyChain.sign(ckData, self._ckDataSigningInfo)
            self._storage.insert(ckData)

            logging.getLogger(__name__).info("Publishing CK data: " +
              ckData.getName().toUri())
            return True
        except Exception as ex:
            onError(EncryptError.ErrorCode.EncryptionFailure,
              "Failed to encrypt generated CK with KEK " +
              self._kekData.getName().toUri())
            return False

    NAME_COMPONENT_ENCRYPTED_BY = Name.Component("ENCRYPTED-BY")
    NAME_COMPONENT_NAC = Name.Component("NAC")
    NAME_COMPONENT_KEK = Name.Component("KEK")
    NAME_COMPONENT_KDK = Name.Component("KDK")
    NAME_COMPONENT_CK  = Name.Component("CK")

    RETRY_DELAY_AFTER_NACK_MS    = 1000.0
    RETRY_DELAY_KEK_RETRIEVAL_MS = 60 * 1000.0

    AES_KEY_SIZE = 32
    AES_IV_SIZE  = 16
    N_RETRIES    = 3

    DEFAULT_CK_FRESHNESS_PERIOD_MS = 3600 * 1000.0

# Import this at the end of the file to avoid circular references.
from pyndn.security.signing_info import SigningInfo

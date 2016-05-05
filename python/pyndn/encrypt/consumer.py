# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt src/consumer https://github.com/named-data/ndn-group-encrypt
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
This module defines the Consumer class which manages fetched group keys used to
decrypt a data packet in the group-based encryption protocol.
Note: This class is an experimental feature. The API may change.
"""

import logging
from pyndn.name import Name
from pyndn.interest import Interest
from pyndn.util.blob import Blob
from pyndn.encrypt.encrypted_content import EncryptedContent
from pyndn.encrypt.encrypt_error import EncryptError
from pyndn.encrypt.algo.aes_algorithm import AesAlgorithm
from pyndn.encrypt.algo.rsa_algorithm import RsaAlgorithm
from pyndn.encrypt.algo.encrypt_params import EncryptParams, EncryptAlgorithmType
from pyndn.encrypt.algo.encryptor import Encryptor

class Consumer(object):
    """
    Create a Consumer to use the given ConsumerDb, Face and other values.

    :param Face face: The face used for data packet and key fetching.
    :param KeyChain keyChain: The keyChain used to verify data packets.
    :param Name groupName: The reading group name that the consumer belongs to.
      This makes a copy of the Name.
    :param Name consumerName: The identity of the consumer. This makes a copy of
      the Name.
    :param ConsumerDb database: The ConsumerDb database for storing decryption
      keys.
    """
    def __init__(self, face, keyChain, groupName, consumerName, database):
        self._database = database
        self._keyChain = keyChain
        self._face = face
        self._groupName = Name(groupName)
        self._consumerName = Name(consumerName)

        # The dictionary key is the C-KEY name. The value is the encoded key Blob.
        self._cKeyMap = {}
        # The dictionary key is the D-KEY name. The value is the encoded key Blob.
        self._dKeyMap = {}

    def consume(self, contentName, onConsumeComplete, onError):
        """
        Express an Interest to fetch the content packet with contentName, and
        decrypt it, fetching keys as needed.

        :param Name contentName: The name of the content packet.
        :param onConsumeComplete: When the content packet is fetched and
          decrypted, this calls onConsumeComplete(contentData, result) where
          contentData is the fetched Data packet and result is the decrypted
          plain text Blob.
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onPlainText: function object
        :param onError: This calls onError(errorCode, message) for an error,
          where errorCode is from EncryptError.ErrorCode and message is a str.
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onError: function object
        """
        interest = Interest(contentName)

        # Prepare the callback functions.
        def onData(contentInterest, contentData):
            # The Interest has no selectors, so assume the library correctly
            # matched with the Data name before calling onData.

            try:
                def onVerified(validData):
                    # Decrypt the content.
                    def onPlainText(plainText):
                        try:
                            onConsumeComplete(contentData, plainText)
                        except:
                            logging.exception("Error in onConsumeComplete")
                    self._decryptContent(validData, onPlainText, onError)
                self._keyChain.verifyData(
                    contentData, onVerified,
                    lambda d: Consumer._callOnError(onError, EncryptError.ErrorCode.Validation,
                                      "verifyData failed"))
            except Exception as ex:
                try:
                    onError(EncryptError.ErrorCode.General, "verifyData error: " + repr(ex))
                except:
                    logging.exception("Error in onError")

        def onTimeout(contentInterest):
            # We should re-try at least once.
            try:
                self._face.expressInterest(
                  interest, onData,
                  lambda contentInterest:
                    Consumer._callOnError(onError,
                      EncryptError.ErrorCode.Timeout, interest.getName().toUri()))
            except Exception as ex:
                try:
                    onError(EncryptError.ErrorCode.General,
                            "expressInterest error: " + repr(ex))
                except:
                    logging.exception("Error in onError")

        # Express the Interest.
        try:
            self._face.expressInterest(interest, onData, onTimeout)
        except Exception as ex:
            try:
                onError(EncryptError.ErrorCode.General,
                        "expressInterest error: " + repr(ex))
            except:
                logging.exception("Error in onError")

    def setGroup(self, groupName):
        """
        Set the group name.

        :param Name groupName: The reading group name that the consumer belongs
          to. This makes a copy of the Name.
        """
        self._groupName = Name(groupName)

    def addDecryptionKey(self, keyName, keyBlob):
        """
        Add a new decryption key with keyName and keyBlob to the database.

        :param Name keyName: The key name.
        :param Blob keyBlob: The encoded key.
        :raises ConsumerDb.Error: If a key with the same keyName already exists
          in the database, or other database error.
        :raises RuntimeError: if the consumer name is not a prefix of the key name.
        """
        if not self._consumerName.match(keyName):
            raise RuntimeError(
              "addDecryptionKey: The consumer name must be a prefix of the key name")

        self._database.addKey(keyName, keyBlob)

    @staticmethod
    def _decrypt(encryptedContent, keyBits, onPlainText, onError):
        """
        Decrypt encryptedContent using keyBits.

        :param encryptedContent: The EncryptedContent to decrypt, or a Blob
          which is first decoded as an EncryptedContent.
        :type encryptedContent: Blob or EncryptedContent
        :param {Blob} keyBits The key value.
        :param onPlainText: When encryptedBlob is decrypted, this calls
          onPlainText(decryptedBlob) with the decrypted Blob.
        :type onPlainText: function object
        :param onError: This calls onError(errorCode, message) for an error,
          where errorCode is from EncryptError.ErrorCode and message is a str.
        :type onError: function object
        """
        if isinstance(encryptedContent, Blob):
            # Decode as EncryptedContent.
            encryptedBlob = encryptedContent
            encryptedContent = EncryptedContent()
            encryptedContent.wireDecode(encryptedBlob)

        payload = encryptedContent.getPayload()

        if encryptedContent.getAlgorithmType() == EncryptAlgorithmType.AesCbc:
            # Prepare the parameters.
            decryptParams = EncryptParams(EncryptAlgorithmType.AesCbc)
            decryptParams.setInitialVector(encryptedContent.getInitialVector())

            # Decrypt the content.
            try:
                content = AesAlgorithm.decrypt(keyBits, payload, decryptParams)
            except Exception as ex:
                try:
                    onError(EncryptError.ErrorCode.InvalidEncryptedFormat, repr(ex))
                except:
                    logging.exception("Error in onError")
                return
            onPlainText(content)
        elif encryptedContent.getAlgorithmType() == EncryptAlgorithmType.RsaOaep:
            # Prepare the parameters.
            decryptParams = EncryptParams(EncryptAlgorithmType.RsaOaep)

            # Decrypt the content.
            try:
                content = RsaAlgorithm.decrypt(keyBits, payload, decryptParams)
            except Exception as ex:
                Consumer._callOnError(onError,
                  EncryptError.ErrorCode.InvalidEncryptedFormat, repr(ex))
                return
            onPlainText(content)
        else:
            Consumer._callOnError(onError,
              EncryptError.ErrorCode.UnsupportedEncryptionScheme,
              repr(encryptedContent.getAlgorithmType()))

    def _decryptContent(self, data, onPlainText, onError):
        """
        Decrypt the data packet.

        :param Data data: The data packet.
        :param onPlainText: When the data packet is decrypted, this calls
          onPlainText(decryptedBlob) with the decrypted blob.
        :type onPlainText: function object
        :param onError: This calls onError(errorCode, message) for an error,
          where errorCode is from EncryptError.ErrorCode and message is a str.
        :type onError: function object
        """
        # Get the encrypted content.
        dataEncryptedContent = EncryptedContent()
        try:
            dataEncryptedContent.wireDecode(data.getContent())
        except Exception as ex:
            Consumer._callOnError(onError,
              EncryptError.ErrorCode.InvalidEncryptedFormat, repr(ex))
            return
        cKeyName = dataEncryptedContent.getKeyLocator().getKeyName()

        # Check if the content key is already in the store.
        if cKeyName in self._cKeyMap:
            cKey = self._cKeyMap[cKeyName]
            self._decrypt(dataEncryptedContent, cKey, onPlainText, onError)
        else:
            # Retrieve the C-KEY Data from the network.
            interestName = Name(cKeyName)
            interestName.append(Encryptor.NAME_COMPONENT_FOR).append(self._groupName)
            interest = Interest(interestName)

            # Prepare the callback functions.
            def onData(cKeyInterest, cKeyData):
                # The Interest has no selectors, so assume the library correctly
                # matched with the Data name before calling onData.

                try:
                    def onVerified(validCKeyData):
                        def localOnPlainText(cKeyBits):
                           # cKeyName is already a copy inside the local
                           #   dataEncryptedContent.
                           self._cKeyMap[cKeyName] = cKeyBits
                           Consumer._decrypt(
                             dataEncryptedContent, cKeyBits, onPlainText, onError)
                        self._decryptCKey(validCKeyData, localOnPlainText, onError)
                    self._keyChain.verifyData(
                        cKeyData, onVerified,
                        lambda d: Consumer._callOnError(onError, EncryptError.ErrorCode.Validation,
                                          "verifyData failed"))
                except Exception as ex:
                    try:
                        onError(EncryptError.ErrorCode.General,
                                "verifyData error: " + repr(ex))
                    except:
                        logging.exception("Error in onError")

            def onTimeout(dKeyInterest):
                # We should re-try at least once.
                try:
                    self._face.expressInterest(
                      interest, onData,
                      lambda contentInterest:
                        Consumer._callOnError(onError,
                          EncryptError.ErrorCode.Timeout, interest.getName().toUri()))
                except Exception as ex:
                    try:
                        onError(EncryptError.ErrorCode.General,
                                "expressInterest error: " + repr(ex))
                    except:
                        logging.exception("Error in onError")

            # Express the Interest.
            try:
                self._face.expressInterest(interest, onData, onTimeout)
            except Exception as ex:
                try:
                    onError(EncryptError.ErrorCode.General,
                            "expressInterest error: " + repr(ex))
                except:
                    logging.exception("Error in onError")

    def _decryptCKey(self, cKeyData, onPlainText, onError):
        """
        Decrypt cKeyData.

        :param Data cKeyData: The C-KEY data packet.
        :param onPlainText: When the data packet is decrypted, this calls
          onPlainText(decryptedBlob) with the decrypted blob.
        :type onPlainText: function object
        :param onError: This calls onError(errorCode, message) for an error,
          where errorCode is from EncryptError.ErrorCode and message is a str.
        :type onError: function object
        """
        # Get the encrypted content.
        cKeyContent = cKeyData.getContent()
        cKeyEncryptedContent = EncryptedContent()
        try:
            cKeyEncryptedContent.wireDecode(cKeyContent)
        except Exception as ex:
            try:
                onError(EncryptError.ErrorCode.InvalidEncryptedFormat, repr(ex))
            except:
                logging.exception("Error in onError")
            return
        eKeyName = cKeyEncryptedContent.getKeyLocator().getKeyName()
        dKeyName = eKeyName.getPrefix(-3)
        dKeyName.append(Encryptor.NAME_COMPONENT_D_KEY).append(
          eKeyName.getSubName(-2))

        # Check if the decryption key is already in the store.
        if dKeyName in self._dKeyMap:
            dKey = self._dKeyMap[dKeyName]
            Consumer._decrypt(cKeyEncryptedContent, dKey, onPlainText, onError)
        else:
            # Get the D-Key Data.
            interestName = Name(dKeyName)
            interestName.append(Encryptor.NAME_COMPONENT_FOR).append(
              self._consumerName)
            interest = Interest(interestName)

            # Prepare the callback functions.
            def onData(dKeyInterest, dKeyData):
                # The Interest has no selectors, so assume the library correctly
                # matched with the Data name before calling onData.

                try:
                    def onVerified(validDKeyData):
                        def localOnPlainText(dKeyBits):
                            # dKeyName is already a local copy.
                            self._dKeyMap[dKeyName] = dKeyBits
                            Consumer._decrypt(
                              cKeyEncryptedContent, dKeyBits, onPlainText, onError)
                        self._decryptDKey(validDKeyData, localOnPlainText, onError)
                    self._keyChain.verifyData(
                        dKeyData, onVerified,
                        lambda d: Consumer._callOnError(onError, EncryptError.ErrorCode.Validation,
                                          "verifyData failed"))
                except Exception as ex:
                    try:
                        onError(EncryptError.ErrorCode.General,
                                "verifyData error: " + repr(ex))
                    except:
                        logging.exception("Error in onError")

            def onTimeout(dKeyInterest):
                # We should re-try at least once.
                try:
                    self._face.expressInterest(
                      interest, onData,
                      lambda contentInterest:
                        Consumer._callOnError(onError,
                          EncryptError.ErrorCode.Timeout, interest.getName().toUri()))
                except Exception as ex:
                    try:
                        onError(EncryptError.ErrorCode.General,
                                "expressInterest error: " + repr(ex))
                    except:
                        logging.exception("Error in onError")

            # Express the Interest.
            try:
                self._face.expressInterest(interest, onData, onTimeout)
            except Exception as ex:
                try:
                    onError(EncryptError.ErrorCode.General,
                            "expressInterest error: " + repr(ex))
                except:
                    logging.exception("Error in onError")

    def _decryptDKey(self, dKeyData, onPlainText, onError):
        """
        Decrypt dKeyData.

        :param Data dKeyData: The D-KEY data packet.
        :param onPlainText: When the data packet is decrypted, this calls
          onPlainText(decryptedBlob) with the decrypted blob.
        :type onPlainText: function object
        :param onError: This calls onError(errorCode, message) for an error,
          where errorCode is from EncryptError.ErrorCode and message is a str.
        :type onError: function object
        """
        # Get encrypted content.
        dataContent = dKeyData.getContent()

        # Process the nonce.
        # dataContent is a sequence of the two EncryptedContent.
        encryptedNonce = EncryptedContent()
        try:
          encryptedNonce.wireDecode(dataContent)
        except Exception as ex:
            try:
                onError(EncryptError.ErrorCode.InvalidEncryptedFormat, repr(ex))
            except:
                logging.exception("Error in onError")
            return
        consumerKeyName = encryptedNonce.getKeyLocator().getKeyName()

        # Get consumer decryption key.
        try:
          consumerKeyBlob = self._getDecryptionKey(consumerKeyName)
        except Exception as ex:
            Consumer._callOnError(onError,
              EncryptError.ErrorCode.NoDecryptKey, "Database error: " + repr(ex))
            return
        if consumerKeyBlob.size() == 0:
            try:
                onError(EncryptError.ErrorCode.NoDecryptKey,
                  "The desired consumer decryption key in not in the database")
            except:
                logging.exception("Error in onError")
            return

        # Process the D-KEY.
        # Use the size of encryptedNonce to find the start of encryptedPayload.
        encryptedPayloadBlob = Blob(
          dataContent.buf()[encryptedNonce.wireEncode().size():], False)
        if encryptedPayloadBlob.size() == 0:
            try:
                onError(EncryptError.ErrorCode.InvalidEncryptedFormat,
                  "The data packet does not satisfy the D-KEY packet format")
            except:
                logging.exception("Error in onError")

        # Decrypt the D-KEY.
        Consumer._decrypt(
          encryptedNonce, consumerKeyBlob,
          lambda nonceKeyBits: Consumer._decrypt(
            encryptedPayloadBlob, nonceKeyBits, onPlainText, onError),
          onError)

    def _getDecryptionKey(self, decryptionKeyName):
        """
        Get the encoded blob of the decryption key with decryptionKeyName from
        the database.

        :param Name decryptionKeyName: The key name.
        :return: A Blob with the encoded key, or an isNull Blob if cannot find
          the key with keyName.
        :rtype: Blob
        :raises ConsumerDb.Error: For a database error.
        """
        return self._database.getKey(decryptionKeyName)

    @staticmethod
    def _callOnError(onError, errorCode, message):
        """
        Call onError(errorCode, message) within a try block to log exceptions
        that it throws. We name this separate helper function to use inside
        lambda expressions.
        """
        try:
            onError(errorCode, message)
        except:
            logging.exception("Error in onError")

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
# Author: From ndn-group-encrypt src/encryptor https://github.com/named-data/ndn-group-encrypt
#
# Copyright (C) 2015-2016 Regents of the University of California.
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
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU Lesser General Public License is in the file COPYING.

"""
This module defines the Encryptor class which has static constants and utility
methods for encryption, such as encryptData.
Note: This class is an experimental feature. The API may change.
"""

from random import SystemRandom
from pyndn.name import Name
from pyndn.util.blob import Blob
from pyndn.key_locator import KeyLocator, KeyLocatorType
from pyndn.encoding.tlv_wire_format import TlvWireFormat
from pyndn.encrypt.encrypted_content import EncryptedContent
from pyndn.encrypt.algo.encrypt_params import EncryptParams, EncryptAlgorithmType

# The Python documentation says "Use SystemRandom if you require a
#   cryptographically secure pseudo-random number generator."
# http://docs.python.org/2/library/random.html
_systemRandom = SystemRandom()

class Encryptor(object):
    NAME_COMPONENT_FOR = Name.Component("FOR")
    NAME_COMPONENT_READ = Name.Component("READ")
    NAME_COMPONENT_SAMPLE = Name.Component("SAMPLE")
    NAME_COMPONENT_ACCESS = Name.Component("ACCESS")
    NAME_COMPONENT_E_KEY = Name.Component("E-KEY")
    NAME_COMPONENT_D_KEY = Name.Component("D-KEY")
    NAME_COMPONENT_C_KEY = Name.Component("C-KEY")

    @staticmethod
    def encryptData(data, payload, keyName, key, params):
        """
        Prepare an encrypted data packet by encrypting the payload using the key
        according to the params. In addition, this prepares the encoded
        EncryptedContent with the encryption result using keyName and params.
        The encoding is set as the content of the data packet. If params defines
        an asymmetric encryption algorithm and the payload is larger than the
        maximum plaintext size, this encrypts the payload with a symmetric key
        that is asymmetrically encrypted and provided as a nonce in the content
        of the data packet. The packet's <dataName>/ is updated to be
        <dataName>/FOR/<keyName>

        :param Data data: The data packet which is updated.
        :param Blob payload: The payload to encrypt.
        :param Name keyName: The key name for the EncryptedContent.
        :param Blob key: The encryption key value.
        :param EncryptParams params: The parameters for encryption.
        """
        dataName = data.getName()
        dataName.append(Encryptor.NAME_COMPONENT_FOR).append(keyName)
        data.setName(dataName)

        algorithmType = params.getAlgorithmType()

        if (algorithmType == EncryptAlgorithmType.AesCbc or
            algorithmType == EncryptAlgorithmType.AesEcb):
            content = Encryptor._encryptSymmetric(payload, key, keyName, params)
            data.setContent(content.wireEncode(TlvWireFormat.get()))
        elif (algorithmType == EncryptAlgorithmType.RsaPkcs or
              algorithmType == EncryptAlgorithmType.RsaOaep):
            # Cryptography doesn't have a direct way to get the maximum plain text
            # size, so try to encrypt the payload first and catch the error if
            # it is too big.
            try:
                content = Encryptor._encryptAsymmetric(payload, key, keyName, params)
                data.setContent(content.wireEncode(TlvWireFormat.get()))
                return
            except ValueError as ex:
                message = ex.args[0]
                if not ("Data too long for key size" in message):
                    raise ex
                # Else the payload is larger than the maximum plaintext size. Continue.

            # 128-bit nonce.
            nonceKeyBuffer = bytearray(16)
            for i in range(16):
                nonceKeyBuffer[i] = _systemRandom.randint(0, 0xff)
            nonceKey = Blob(nonceKeyBuffer, False)

            nonceKeyName = Name(keyName)
            nonceKeyName.append("nonce")

            symmetricParams =  EncryptParams(
              EncryptAlgorithmType.AesCbc, AesAlgorithm.BLOCK_SIZE)

            nonceContent = Encryptor._encryptSymmetric(
              payload, nonceKey, nonceKeyName, symmetricParams)

            payloadContent = Encryptor._encryptAsymmetric(
              nonceKey, key, keyName, params)

            nonceContentEncoding = nonceContent.wireEncode()
            payloadContentEncoding = payloadContent.wireEncode()
            content = bytearray(
              nonceContentEncoding.size() + payloadContentEncoding.size())
            content[0:payloadContentEncoding.size()] = payloadContentEncoding.buf()
            content[payloadContentEncoding.size():] = nonceContentEncoding.buf()

            data.setContent(Blob(content, False))
        else:
            raise RuntimeError("Unsupported encryption method")

    @staticmethod
    def _encryptSymmetric(payload, key, keyName, params):
        """
        Encrypt the payload using the symmetric key according to params, and
        return an EncryptedContent.

        :param Blob payload: The data to encrypt.
        :param Blob key: The key value.
        :param Name keyName: The key name for the EncryptedContent key locator.
        :param EncryptParams params: The parameters for encryption.
        :return: A new EncryptedContent.
        :rtype: EncryptedContent
        """
        algorithmType = params.getAlgorithmType()
        initialVector = params.getInitialVector()
        keyLocator = KeyLocator()
        keyLocator.setType(KeyLocatorType.KEYNAME)
        keyLocator.setKeyName(keyName)

        if (algorithmType == EncryptAlgorithmType.AesCbc or
            algorithmType == EncryptAlgorithmType.AesEcb):
            if (algorithmType == EncryptAlgorithmType.AesCbc):
                if initialVector.size() != AesAlgorithm.BLOCK_SIZE:
                    raise RuntimeError("incorrect initial vector size")

            encryptedPayload = AesAlgorithm.encrypt(key, payload, params)

            result = EncryptedContent()
            result.setAlgorithmType(algorithmType)
            result.setKeyLocator(keyLocator)
            result.setPayload(encryptedPayload)
            result.setInitialVector(initialVector)
            return result
        else:
            raise RuntimeError("Unsupported encryption method")

    @staticmethod
    def _encryptAsymmetric(payload, key, keyName, params):
        """
        Encrypt the payload using the asymmetric key according to params, and
        return an EncryptedContent.

        :param Blob payload: The data to encrypt. The size should be within
          range of the key.
        :param Blob key: The key value.
        :param Name keyName: The key name for the EncryptedContent key locator.
        :param EncryptParams params: The parameters for encryption.
        :return: A new EncryptedContent.
        :rtype: EncryptedContent
        """
        algorithmType = params.getAlgorithmType()
        keyLocator = KeyLocator()
        keyLocator.setType(KeyLocatorType.KEYNAME)
        keyLocator.setKeyName(keyName)

        if (algorithmType == EncryptAlgorithmType.RsaPkcs or
            algorithmType == EncryptAlgorithmType.RsaOaep):
            encryptedPayload = RsaAlgorithm.encrypt(key, payload, params)

            result = EncryptedContent()
            result.setAlgorithmType(algorithmType)
            result.setKeyLocator(keyLocator)
            result.setPayload(encryptedPayload)
            return result
        else:
            raise RuntimeError("Unsupported encryption method")

# Import these at the end of the file to avoid circular references.
from pyndn.encrypt.algo.aes_algorithm import AesAlgorithm
from pyndn.encrypt.algo.rsa_algorithm import RsaAlgorithm

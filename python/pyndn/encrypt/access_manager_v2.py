# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From the NAC library https://github.com/named-data/name-based-access-control/blob/new/src/access-manager.cpp
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
This module defines the AccessManagerV2 class which controls the decryption
policy by publishing granular per-namespace access policies in the form of key
encryption (KEK, plaintext public) and key decryption (KDK, encrypted private
key) key pairs. This works with EncryptorV2 and DecryptorV2 using security v2.
For the meaning of "KDK", etc. see:
https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst
"""

import logging
from random import SystemRandom
from pyndn.name import Name
from pyndn.data import Data
from pyndn.util.blob import Blob
from pyndn.security.key_params import RsaKeyParams
from pyndn.security.security_types import KeyType
from pyndn.security.certificate.public_key import PublicKey
from pyndn.in_memory_storage.in_memory_storage_retaining import InMemoryStorageRetaining
from pyndn.encrypt.algo.encrypt_params import EncryptAlgorithmType
from pyndn.encrypt.encryptor_v2 import EncryptorV2
from pyndn.encrypt.encrypted_content import EncryptedContent

# The Python documentation says "Use SystemRandom if you require a
#   cryptographically secure pseudo-random number generator."
# http://docs.python.org/2/library/random.html
_systemRandom = SystemRandom()

class AccessManagerV2(object):
    """
    Create an AccessManagerV2 to serve the NAC public key for other data
    producers to fetch, and to serve encrypted versions of the private keys
    (as safe bags) for authorized consumers to fetch.

    KEK and KDK naming:

    [identity]/NAC/[dataset]/KEK            /[key-id]                           (== KEK, public key)

    [identity]/NAC/[dataset]/KDK/[key-id]   /ENCRYPTED-BY/[user]/KEY/[key-id]   (== KDK, encrypted private key)

    |_____________  ______________/
                  |/
         registered with NFD

    :param PibIdentity identity: The data owner's namespace identity. (This will
      be used to sign the KEK and KDK.)
    :param Name dataset: The name of dataset that this manager is controlling.
    :param KeyChain keyChain: The KeyChain used to sign Data packets.
    :param Face face: The Face for calling registerPrefix that will be used to
      publish the KEK and KDK Data packets.
    """
    def __init__(self, identity, dataset, keyChain, face):
        self._identity = identity
        self._keyChain = keyChain
        self._face = face

        # storage_ is for the KEK and KDKs.
        self._storage = InMemoryStorageRetaining()

        # The NAC identity is: <identity>/NAC/<dataset>
        # Generate the NAC key.
        nacIdentity = self._keyChain.createIdentityV2(
          Name(identity.getName())
          .append(EncryptorV2.NAME_COMPONENT_NAC).append(dataset),
          RsaKeyParams())
        self._nacKey = nacIdentity.getDefaultKey()
        if self._nacKey.getKeyType() != KeyType.RSA:
            logging.getLogger(__name__).info(
              "Cannot re-use existing KEK/KDK pair, as it is not an RSA key, regenerating")
            self._nacKey = self._keyChain.createKey(nacIdentity, RsaKeyParams())

        nacKeyId = self._nacKey.getName().get(-1)

        kekPrefix = Name(self._nacKey.getIdentityName()).append(
          EncryptorV2.NAME_COMPONENT_KEK)

        kekData = Data(self._nacKey.getDefaultCertificate())
        kekData.setName(Name(kekPrefix).append(nacKeyId))
        kekData.getMetaInfo().setFreshnessPeriod(
          AccessManagerV2.DEFAULT_KEK_FRESHNESS_PERIOD_MS)
        self._keyChain.sign(kekData, SigningInfo(self._identity))
        # kek looks like a cert, but doesn't have ValidityPeriod
        self._storage.insert(kekData)

        def serveFromStorage(prefix, interest, face, interestFilterId, filter):
            data = self._storage.find(interest)
            if data != None:
                logging.getLogger(__name__).info("Serving " +
                  data.getName().toUri() + " from in-memory-storage")
                try:
                    face.putData(data)
                except:
                    logging.exception("AccessManagerV2: Error in Face.putData")
            else:
                logging.getLogger(__name__).info("Didn't find data for " +
                  interest.getName().toUri())
                # TODO: Send NACK?

        def onRegisterFailed(prefix):
            logging.getLogger(__name__).error(
              "AccessManagerV2: Failed to register prefix " + prefix.toUri())

        self._kekRegisteredPrefixId = self._face.registerPrefix(
          kekPrefix, serveFromStorage, onRegisterFailed)

        kdkPrefix = Name(self._nacKey.getIdentityName()).append(
          EncryptorV2.NAME_COMPONENT_KDK).append(nacKeyId)
        self._kdkRegisteredPrefixId = self._face.registerPrefix(
          kdkPrefix, serveFromStorage, onRegisterFailed)

    def shutdown(self):
        self._face.unsetInterestFilter(self._kekRegisteredPrefixId)
        self._face.unsetInterestFilter(self._kdkRegisteredPrefixId)

    def addMember(self, memberCertificate):
        """
        Authorize a member identified by memberCertificate to decrypt data under
        the policy.

        :param CertificateV2 memberCertificate: The certificate that identifies
          the member to authorize.
        :return: The published KDK Data packet.
        :rtype: Data
        """
        kdkName = Name(self._nacKey.getIdentityName())
        kdkName.append(
          EncryptorV2.NAME_COMPONENT_KDK).append(
          # key-id
          self._nacKey.getName().get(-1)).append(
          EncryptorV2.NAME_COMPONENT_ENCRYPTED_BY).append(
          memberCertificate.getKeyName())

        secretLength = 32
        secret = bytearray(secretLength)
        for i in range(secretLength):
            secret[i] = _systemRandom.randint(0, 0xff)
        # To be compatible with OpenSSL which uses a null-terminated string,
        # replace each 0 with 1. And to be compatible with the Java security
        # library which interprets the secret as a char array converted to UTF8,
        # limit each byte to the ASCII range 1 to 127.
        for i in range(secretLength):
            if secret[i] == 0:
                secret[i] = 1

            secret[i] &= 0x7f

        kdkSafeBag = self._keyChain.exportSafeBag(
          self._nacKey.getDefaultCertificate(), Blob(secret, False).toBytes())

        memberKey = PublicKey(memberCertificate.getPublicKey())

        encryptedContent = EncryptedContent()
        encryptedContent.setPayload(kdkSafeBag.wireEncode())
        encryptedContent.setPayloadKey(memberKey.encrypt
          (Blob(secret, False).toBytes(), EncryptAlgorithmType.RsaOaep))

        kdkData = Data(kdkName)
        kdkData.setContent(encryptedContent.wireEncodeV2())
        # FreshnessPeriod can serve as a soft access control for revoking access.
        kdkData.getMetaInfo().setFreshnessPeriod(
          AccessManagerV2.DEFAULT_KDK_FRESHNESS_PERIOD_MS)
        self._keyChain.sign(kdkData, SigningInfo(self._identity))

        self._storage.insert(kdkData)

        return kdkData

    def size(self):
        """
        Get the number of packets stored in in-memory storage.

        :return: The number of packets.
        :rtype: int
        """
        return self._storage.size()

    DEFAULT_KEK_FRESHNESS_PERIOD_MS = 3600 * 1000.0
    DEFAULT_KDK_FRESHNESS_PERIOD_MS = 3600 * 1000.0

# Import this at the end of the file to avoid circular references.
from pyndn.security.signing_info import SigningInfo

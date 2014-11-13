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
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU Lesser General Public License is in the file COPYING.

"""
This module defines the PublicKey class which holds an encoded public key
for use by the security library.
"""

from Crypto.PublicKey import RSA
from pyndn.util import Blob
from pyndn.security.security_types import DigestAlgorithm
from pyndn.security.security_types import KeyType
from pyndn.security.security_exception import SecurityException

from pyndn.encoding.der import DerNode

from Crypto.Hash import SHA256

class PublicKey(object):
    """
    Create a new PublicKey with the given values.

    :param keyType: The KeyType, such as KeyType.RSA.
    :type keyType: an int from KeyType
    :param Blob keyDer: The blob of the PublicKeyInfo in terms of DER.
    """
    def __init__(self, keyType, keyDer):
        self._keyType = keyType
        self._keyDer = keyDer

        # TODO: Implementation of managed properties?

    def toDer(self):
        """
        Encode the public key into DER.

        :return: The encoded DER syntax tree.
        :rtype: DerNode
        """
        return DerNode.parse(self._keyDer)

    @staticmethod
    def fromDer(keyType, keyDer):
        """
        Decode the public key from DER blob.

        :param keyType: The KeyType, such as KeyType.RSA.
        :type keyType: an int from KeyType
        :param Blob keyDer: The DER blob.
        :return: The decoded public key.
        :rtype: PublicKey
        """
        if keyType == KeyType.RSA:
            RSA.importKey(keyDer.toRawStr())
        else:
            raise SecurityException("PublicKey::fromDer: Unrecognized keyType")

        return PublicKey(keyType, keyDer)

    def getDigest(self, digestAlgorithm = DigestAlgorithm.SHA256):
        """
        Get the digest of the public key.

        :param digestAlgorithm: (optional) The digest algorithm.  If omitted,
          use DigestAlgorithm.SHA256 .
        :type digestAlgorithm: int from DigestAlgorithm
        :return: The digest value
        :rtype: Blob
        """
        if digestAlgorithm == DigestAlgorithm.SHA256:
            hashFunc  = SHA256.new()
            hashFunc.update(self._keyDer.buf())

            return Blob(hashFunc.digest())
        else:
            raise RuntimeError("Unimplemented digest algorithm")


    def getKeyType(self):
        """
        Get the key type.

        :return: The key type
        :rtype: an int from KeyType
        """
        return self._keyType

    def getKeyDer(self):
        """
        Get the raw bytes of the public key in DER format.

        :return: The public key DER
        :rtype: Blob
        """
        return self._keyDer


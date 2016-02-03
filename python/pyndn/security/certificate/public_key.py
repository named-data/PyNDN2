# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
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

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from pyndn.util.blob import Blob
from pyndn.encoding.der.der_node import DerNode
from pyndn.encoding.der.der_exceptions import DerDecodingException
from pyndn.security.security_types import DigestAlgorithm
from pyndn.security.security_types import KeyType
from pyndn.security.security_exception import UnrecognizedKeyFormatException

from pyndn.encoding.der import DerNode

class PublicKey(object):
    """
    Create a new PublicKey by decoding the keyDer. Set the key type from the
    decoding.

    :param Blob keyDer: The blob of the PublicKeyInfo in terms of DER.
    :raises: UnrecognizedKeyFormatException if can't decode the key DER.
    """
    def __init__(self, keyDer = None):
        # TODO: Implementation of managed properties?

        if keyDer == None:
            self._keyDer = Blob()
            self._keyType = None
            return

        self._keyDer = keyDer

        # Get the public key OID.
        oidString = ""
        try:
            parsedNode = DerNode.parse(keyDer.buf(), 0)
            rootChildren = parsedNode.getChildren()
            algorithmIdChildren = DerNode.getSequence(
              rootChildren, 0).getChildren()
            oidString = algorithmIdChildren[0].toVal()
        except DerDecodingException as ex:
          raise UnrecognizedKeyFormatException(
            "PublicKey.decodeKeyType: Error decoding the public key: " + str(ex))

        # Verify that the we can decode.
        if oidString == self.RSA_ENCRYPTION_OID:
            self._keyType = KeyType.RSA
            serialization.load_der_public_key(
              keyDer.toBytes(), backend = default_backend())
        elif oidString == self.EC_ENCRYPTION_OID:
            self._keyType = KeyType.ECDSA
            # TODO: Check EC decoding.
        else:
            raise UnrecognizedKeyFormatException(
              "PublicKey.decodeKeyType: Unrecognized OID " + oidString)

    def toDer(self):
        """
        Encode the public key into DER.

        :return: The encoded DER syntax tree.
        :rtype: DerNode
        """
        return DerNode.parse(self._keyDer)

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
            sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
            sha256.update(self._keyDer.toBytes())
            digest = sha256.finalize()

            return Blob(bytearray(digest), False)
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

    RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1"
    EC_ENCRYPTION_OID = "1.2.840.10045.2.1"

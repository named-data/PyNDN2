# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/tpm/key-handle.cpp
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
This module defines the TpmKeyHandle class which is an abstract base class for a
TPM key handle, which provides an interface to perform cryptographic operations
with a key in the TPM.
"""

from pyndn.name import Name

class TpmKeyHandle(object):
    def __init__(self):
        self._keyName = Name()

    def sign(self, digestAlgorithm, data):
        """
        Compute a digital signature from the byte buffer using this key with
        digestAlgorithm.

        :param digestAlgorithm: The digest algorithm.
        :type digestAlgorithm: int from DigestAlgorithm
        :param data: The input byte buffer.
        :type data: an array which implements the buffer protocol
        :return: The signature Blob, or an isNull Blob for an unrecognized
          digestAlgorithm.
        :rtype: Blob
        """
        return self._doSign(digestAlgorithm, data)

    def decrypt(self, cipherText):
        """
        Return the plain text which is decrypted from cipherText using this key.

        :param cipherText: The cipher text byte buffer.
        :type cipherText: an array which implements the buffer protocol
        :return: The decrypted data.
        :rtype: Blob
        """
        return self._doDecrypt(cipherText)

    def derivePublicKey(self):
        """
        Get the encoded public key derived from this key.

        :return: The public key encoding Blob.
        :rtype: Blob
        """
        return self._doDerivePublicKey()

    def setKeyName(self, keyName):
        """
        Set the key name.

        :param Name keyName: The key name which is copied.
        """
        self._keyName = Name(keyName)

    def getKeyName(self):
        """
        Get the key name.

        :return: The key name.
        :rtype: Name
        """
        return self._keyName

    def _doSign(self, digestAlgorithm, data):
        """
        A protected method to do the work of sign().
        Your subclass must implement it.

        :param digestAlgorithm: The digest algorithm.
        :type digestAlgorithm: int from DigestAlgorithm
        :param data: The input byte buffer.
        :type data: an array which implements the buffer protocol
        :return: The signature Blob, or an isNull Blob for an unrecognized
          digestAlgorithm.
        :rtype: Blob
        """
        raise RuntimeError("TpmKeyHandle._doSign is not implemented")

    def _doDecrypt(self, cipherText):
        """
        A protected method to do the work of decrypt().
        Your subclass must implement it.

        :param cipherText: The cipher text byte buffer.
        :type cipherText: an array which implements the buffer protocol
        :return: The decrypted data.
        :rtype: Blob
        """
        raise RuntimeError("TpmKeyHandle._doDecrypt is not implemented")

    def _doDerivePublicKey(self):
        """
        A protected method to do the work of derivePublicKey().
        Your subclass must implement it.

        :return: The public key encoding Blob.
        :rtype: Blob
        """
        raise RuntimeError("TpmKeyHandle._doDerivePublicKey is not implemented")

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/tpm/key-handle-mem.cpp
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
This module defines the TpmKeyHandleMemory class which extends TpmKeyHandle to
implement a TPM key handle that keeps the private key in memory.
"""

from pyndn.util import Blob
from pyndn.security.security_types import DigestAlgorithm
from pyndn.security.tpm.tpm_back_end import TpmBackEnd
from pyndn.security.tpm.tpm_private_key import TpmPrivateKey
from pyndn.security.tpm.tpm_key_handle import TpmKeyHandle

class TpmKeyHandleMemory(TpmKeyHandle):
    """
    Create a TpmKeyHandleMemory to use the given in-memory key.

    :param TpmPrivateKey key: The in-memory key.
    """
    def __init__(self, key):
        super(TpmKeyHandleMemory, self).__init__()

        if key == None:
            raise ValueError("The key is None")

        self._key = key

    def _doSign(self, digestAlgorithm, data):
        """
        A protected method to do the work of sign().

        :param digestAlgorithm: The digest algorithm.
        :type digestAlgorithm: int from DigestAlgorithm
        :param data: The input byte buffer.
        :type data: an array which implements the buffer protocol
        :return: The signature Blob, or an isNull Blob for an unrecognized
          digestAlgorithm.
        :rtype: Blob
        """
        if digestAlgorithm == DigestAlgorithm.SHA256:
            try:
                return self._key.sign(data, digestAlgorithm)
            except TpmPrivateKey.Error as ex:
                raise TpmBackEnd.Error("Error in TpmPrivateKey.sign: " + str(ex))
        else:
            return Blob()

    def _doDecrypt(self, cipherText):
        """
        A protected method to do the work of decrypt().

        :param cipherText: The cipher text byte buffer.
        :type cipherText: an array which implements the buffer protocol
        :return: The decrypted data.
        :rtype: Blob
        """
        try:
            return self._key.decrypt(cipherText)
        except TpmPrivateKey.Error as ex:
            raise TpmBackEnd.Error("Error in TpmPrivateKey.decrypt: " + str(ex))

    def _doDerivePublicKey(self):
        """
        A protected method to do the work of derivePublicKey().

        :return: The public key encoding Blob.
        :rtype: Blob
        """
        try:
            return self._key.derivePublicKey()
        except TpmPrivateKey.Error as ex:
            raise TpmBackEnd.Error(
              "Error in TpmPrivateKey.derivePublicKey: " + str(ex))

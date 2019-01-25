# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/tpm/key-handle-osx.cpp
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
This module defines the TpmKeyHandleOsx class which extends TpmKeyHandle to
implement a TPM key handle that uses the macOS Keychain services.
"""

from pyndn.security.tpm.tpm_key_handle import TpmKeyHandle

class TpmKeyHandleOsx(TpmKeyHandle):
    """
    Create a TpmKeyHandleOsx to use the given macOS Keychain key.

    :param c_void_p key: The macOS Keychain key.
    """
    def __init__(self, key):
        super(TpmKeyHandleOsx, self).__init__()

        if key == None:
            raise ValueError("TpmKeyHandleOsx: The key is not set")

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
        return TpmBackEndOsx.sign(self._key, digestAlgorithm, data)

    def _doDecrypt(self, cipherText):
        """
        A protected method to do the work of decrypt().

        :param cipherText: The cipher text byte buffer.
        :type cipherText: an array which implements the buffer protocol
        :return: The decrypted data.
        :rtype: Blob
        """
        return TpmBackEndOsx.decrypt(self._key, cipherText)

    def _doDerivePublicKey(self):
        """
        A protected method to do the work of derivePublicKey().

        :return: The public key encoding Blob.
        :rtype: Blob
        """
        return TpmBackEndOsx.derivePublicKey(self._key)

# Put this last to avoid an import loop.
from pyndn.security.tpm.tpm_back_end_osx import TpmBackEndOsx

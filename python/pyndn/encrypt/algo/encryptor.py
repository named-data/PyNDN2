# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
# Author: From ndn-group-encrypt src/encryptor https://github.com/named-data/ndn-group-encrypt
#
# Copyright (C) 2015 Regents of the University of California.
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

from Crypto.Hash import SHA256

"""
This module defines the Encryptor class which static constants and utility
methods for encryption, such as encryptData.
"""

class Encryptor(object):
    @staticmethod
    def toPyCrypto(blob):
        """
        Convert the blob to an input buffer for PyCrypto.

        :param Blob blob: The blob to convert.
        :return: The input buffer for PyCrypto
        :rtype: raw string or bytearray
        """
        if Encryptor.PyCryptoUsesStr:
            return blob.toRawStr()
        else:
            return bytes(blob.toBuffer())

    # Depending on the Python version, PyCrypto uses str or bytes.
    PyCryptoUsesStr = type(SHA256.new().digest()) is str

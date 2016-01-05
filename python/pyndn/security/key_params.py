# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2016 Regents of the University of California.
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
This module defines KeyParams which is a base class for key parameters. This
also defines the subclasses which are used to store parameters for key
generation.
"""

from pyndn.security.security_types import KeyType

class KeyParams(object):
    """
    The constructor is protected and used by subclasses.
    """
    def __init__(self, keyType):
        self._keyType = keyType

    def getKeyType(self):
        return self._keyType

class RsaKeyParams(KeyParams):
    def __init__(self, size = None):
        super(RsaKeyParams, self).__init__(RsaKeyParams._getType())

        if size == None:
            size = RsaKeyParams._getDefaultSize()
        self._size = size

    def getKeySize(self):
        return self._size

    @staticmethod
    def _getDefaultSize():
        return 2048

    @staticmethod
    def _getType():
        return KeyType.RSA

class EcdsaKeyParams(KeyParams):
    def __init__(self, size = None):
        super(EcdsaKeyParams, self).__init__(EcdsaKeyParams._getType())

        if size == None:
            size = EcdsaKeyParams._getDefaultSize()
        self._size = size

    def getKeySize(self):
        return self._size

    @staticmethod
    def _getDefaultSize():
        return 256

    @staticmethod
    def _getType():
        return KeyType.ECDSA

class AesKeyParams(KeyParams):
    def __init__(self, size = None):
        super(AesKeyParams, self).__init__(AesKeyParams._getType())

        if size == None:
            size = AesKeyParams._getDefaultSize()
        self._size = size

    def getKeySize(self):
        return self._size

    @staticmethod
    def _getDefaultSize():
        return 64

    @staticmethod
    def _getType():
        return KeyType.AES

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# @author: From ndn-group-encrypt src/encrypt-params https://github.com/named-data/ndn-group-encrypt
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
This module defines the EncryptParams class which holds an algorithm type and
other parameters used to encrypt and decrypt.
Note: This class is an experimental feature. The API may change.
"""

from random import SystemRandom
from pyndn.util.blob import Blob

# The Python documentation says "Use SystemRandom if you require a
#   cryptographically secure pseudo-random number generator."
# http://docs.python.org/2/library/random.html
_systemRandom = SystemRandom()

class EncryptAlgorithmType(object):
    # These correspond to the TLV codes.
    AesEcb = 0
    AesCbc = 1
    RsaPkcs = 2
    RsaOaep = 3

class EncryptParams(object):
    """
    Create an EncryptParams with the given parameters.

    :param int algorithmType: The algorithm type from EncryptAlgorithmType, or
      None if not specified.
    :param int initialVectorLength: (optional) The initial vector length, or 0
      if the initial vector is not specified. If ommitted, the initial vector is
      not specified.
    """
    def __init__(self, algorithmType, initialVectorLength = None):
        self._algorithmType = algorithmType

        if initialVectorLength != None and initialVectorLength > 0:
            initialVector = bytearray(initialVectorLength)
            for i in range(initialVectorLength):
                initialVector[i] = _systemRandom.randint(0, 0xff)
            self._initialVector = Blob(initialVector, False)
        else:
            self._initialVector = Blob()

    def getAlgorithmType(self):
        """
        Get the algorithmType.

        :return: The algorithm type from EncryptAlgorithmType, or None if not
          specified.
        :rtype: int
        """
        return self._algorithmType

    def getInitialVector(self):
        """
        Get the initial vector.

        :return: The initial vector. If not specified, isNull() is true.
        :rtype: Blob
        """
        return self._initialVector

    def setAlgorithmType(self, algorithmType):
        """
        Set the algorithm type.

        :param int algorithmType: The algorithm type from EncryptAlgorithmType.
          If not specified, set to None.
        :return: This EncryptParams so that you can chain calls to update values.
        :rtype: EncryptParams
        """
        self._algorithmType = algorithmType
        return self

    def setInitialVector(self, initialVector):
        """
        Set the initial vector.

        :param Blob initialVector: The initial vector. If not specified, set to
          the default Blob() where isNull() is True.
        :return: This EncryptParams so that you can chain calls to update values.
        :rtype: EncryptParams
        """
        self._initialVector = (initialVector if isinstance(initialVector, Blob)
                               else Blob(initialVector))
        return self

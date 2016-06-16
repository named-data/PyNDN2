# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
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
This module defines the DigestSha256Signature class which extends Signature and
holds the signature bits (which are only the SHA256 digest) and an empty
SignatureInfo for a data packet or signed interest.
"""

from pyndn.util.blob import Blob
from pyndn.signature import Signature

class DigestSha256Signature(Signature):
    """
    Create a new DigestSha256Signature object, possibly copying values from
    another object.

    :param value: (optional) If value is a DigestSha256Signature, copy its
      values.  If value is omitted, the signature is unspecified.
    :type value: DigestSha256Signature
    """
    def __init__(self, value = None):
        if value == None:
            self._signature = Blob()
        elif type(value) is DigestSha256Signature:
            # Copy its values.
            self._signature = value._signature
        else:
            raise RuntimeError(
              "Unrecognized type for DigestSha256Signature constructor: " +
              str(type(value)))

        self._changeCount = 0

    def clone(self):
        """
        Create a new DigestSha256Signature which is a copy of this object.

        :return: A new object which is a copy of this object.
        :rtype: DigestSha256Signature
        """
        return DigestSha256Signature(self)

    def getSignature(self):
        """
        Get the data packet's signature bytes (which is the digest).

        :return: The signature bytes as a Blob, which maybe isNull().
        :rtype: Blob
        """
        return self._signature

    def setSignature(self, signature):
        """
        Set the signature bytes (which is the digest) to the given value.

        :param signature: The array with the signature bytes. If signature is
          not a Blob, then create a new Blob to copy the bytes (otherwise
          take another pointer to the same Blob).
        :type signature: A Blob or an array type with int elements
        """
        self._signature = (signature if isinstance(signature, Blob)
                           else Blob(signature))
        self._changeCount += 1

    def clear(self):
        self._signature = Blob()
        self._changeCount += 1

    def getChangeCount(self):
        """
        Get the change count, which is incremented each time this object is
        changed.

        :return: The change count.
        :rtype: int
        """
        return self._changeCount

    # Create managed properties for read/write properties of the class for more
    # pythonic syntax.
    signature = property(getSignature, setSignature)

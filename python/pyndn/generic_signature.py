# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2016 Regents of the University of California.
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
This module defines the GenericSignature class which extends Signature and holds
the encoding bytes of the SignatureInfo so that the application can process
experimental signature types. When decoding a packet, if the type of
SignatureInfo is not recognized, the library creates a GenericSignature.
"""

from pyndn.util.blob import Blob
from pyndn.signature import Signature

class GenericSignature(Signature):
    """
    Create a new GenericSignature object, possibly copying values from another
    object.

    :param value: (optional) If value is a GenericSignature, copy its
      values.
    :type value: GenericSignature
    """
    def __init__(self, value = None):
        if value == None:
            self._signature = Blob()
            self._signatureInfoEncoding = Blob()
            self._typeCode = None
        elif type(value) is GenericSignature:
            # Copy its values.
            self._signature = value._signature
            self._signatureInfoEncoding = value._signatureInfoEncoding
            self._typeCode = value._typeCode
        else:
            raise RuntimeError(
              "Unrecognized type for GenericSignature constructor: " +
              str(type(value)))

        self._changeCount = 0

    def clone(self):
        """
        Create a new GenericSignature which is a copy of this object.

        :return: A new object which is a copy of this object.
        :rtype: GenericSignature
        """
        return GenericSignature(self)

    def getSignature(self):
        """
        Get the data packet's signature bytes.

        :return: The signature bytes as a Blob, which maybe isNull().
        :rtype: Blob
        """
        return self._signature

    def getSignatureInfoEncoding(self):
        """
        Get the bytes of the entire signature info encoding (including the type
        code).

        :return: The encoding bytes. If not specified, the value isNull().
        :rtype: Blob
        """
        return self._signatureInfoEncoding

    def getTypeCode(self):
        """
        Get the type code of the signature type. When wire decode calls
        setSignatureInfoEncoding, it sets the type code. Note that the type code
        is ignored during wire encode, which simply uses
        getSignatureInfoEncoding() where the encoding already has the type code.

        :return:The type code, or None if not known.
        :rtype: int
        """
        return self._typeCode

    def setSignature(self, signature):
        """
        Set the signature bytes to the given value.

        :param signature: The array with the signature bytes. If signature is
          not a Blob, then create a new Blob to copy the bytes (otherwise
          take another pointer to the same Blob).
        :type signature: A Blob or an array type with int elements
        """
        self._signature = (signature if isinstance(signature, Blob)
                           else Blob(signature))
        self._changeCount += 1

    def setSignatureInfoEncoding(self, signatureInfoEncoding, typeCode = None):
        """
        Set the bytes of the entire signature info encoding (including the type
        code).

        :param signatureInfoEncoding: The array with the encoding bytes. If
          signatureInfoEncoding is not a Blob, then create a new Blob to copy
          the bytes (otherwise take another pointer to the same Blob).
        :type signatureInfoEncoding: A Blob or an array type with int elements
        :param int typeCode: (optional) The type code of the signature type, or
          None if not known. (When a GenericSignature is created by wire
          decoding, it sets the typeCode.)
        """
        self._signatureInfoEncoding = (
          signatureInfoEncoding if isinstance(signatureInfoEncoding, Blob)
            else Blob(signatureInfoEncoding))
        self._typeCode = typeCode
        self._changeCount += 1

    def clear(self):
        self._signature = Blob()
        self._signatureInfoEncoding = Blob()
        self._typeCode = None
        self._changeCount += 1

    def getChangeCount(self):
        """
        Get the change count, which is incremented each time this object
        (or a child object) is changed.

        :return: The change count.
        :rtype: int
        """
        return self._changeCount

    # Create managed properties for read/write properties of the class for more pythonic syntax.
    signature = property(getSignature, setSignature)
    signatureInfoEncoding = property(getSignatureInfoEncoding, setSignatureInfoEncoding)
    signature = property(getTypeCode)

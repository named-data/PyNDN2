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
This module defines the Common class which has static utility functions.
"""

import time
from io import BytesIO

# _BytesIOValueIsStr is True if BytesIO.getvalue would return a str.
_BytesIOValueIsStr = type(BytesIO().getvalue()) is str

# _bytesElementIsInt if an element of a bytes is an int.
_bytesElementIsInt = type(bytes([0])[0]) is int

def _chr_ord(x):
    """
    This is a private utility function for getBytesIOString to return
    chr(ord(x))
    """
    return chr(ord(x))

# If an element of a bytes is an int, then we can convert simply with chr.
# Otherwise, converting with chr(ord(x)) seems to work on other versions of
#   Python 3.
_bytesElementToChr = chr if _bytesElementIsInt else _chr_ord

# This should only be true in Python 2.
_haveTypeUnicode = False
try:
    x = unicode
    _haveTypeUnicode = True
except:
    pass

class Common(object):
    @staticmethod
    def getNowMilliseconds():
        """
        Get the current time in milliseconds.

        :return: The current time in milliseconds since 1/1/1970, including
          fractions of a millisecond.
        :rtype: float
        """
        return time.time() * 1000.0

    @staticmethod
    def getBytesIOString(bytesIO):
        """
        Return bytesIO.getvalue(), making sure the result is a str.  This is
        necessary because getvalue() returns a bytes object in Python 3.
        """
        if _BytesIOValueIsStr:
            # We don't need to convert.
            return bytesIO.getvalue()
        else:
            # Assume value is a Python 3 bytes object. Convert to str.
            return "".join(map(_bytesElementToChr, bytesIO.getvalue()))

    @staticmethod
    def typeIsString(obj):
        """
        Check if obj has type str or (in Python 2) unicode. This is necessary
        because Python 2 has two string types, str and unicode, but Python 3
        doesn't have type unicode so we have to be carefor to check for
        type(obj) is unicode.

        :param any obj: The object to check if it is str or unicode.
        :return: True if obj is str or unicode, otherwise false
        :rtype: bool
        """
        return type(obj) is str or _haveTypeUnicode and type(obj) is unicode

    @staticmethod
    def stringToUtf8Array(input):
        """
        If the input has type str (in Python 3) or unicode (in Python 2), then
        encode it as UTF8 and return an array of integers. If the input is
        str (in Python 2) then treat it as a "raw" string and just convert each
        element to int.  Otherwise, if the input is not str or unicode, just
        return the input.  This is necessary because in Python 3 doesn't have
        the unicode type and the elements in a string a Unicode characters.
        But in Python 2 only the unicode type has Unicode characters, and str
        elements are bytes with value 0 to 255 (and often used to carry binary
        data).
        """
        if _haveTypeUnicode:
            # Assume this is Python 2.
            if type(input) is str:
                # Convert the raw string to an int array.
                return map(ord, input)
            elif type(input) is unicode:
                # In Python 2, the result of encode is a str, so convert to int array.
                return map(ord, input.encode('utf-8'))
            else:
                return input
        else:
            if type(input) is str:
                return input.encode('utf-8')
            else:
                return input

    """
    The practical limit of the size of a network-layer packet. If a packet is
    larger than this, the library or application MAY drop it. This constant is
    defined in this low-level header file so that internal code can use it, but
    applications should use the static API method
    Face.getMaxNdnPacketSize() which is equivalent.
    """
    MAX_NDN_PACKET_SIZE = 8800

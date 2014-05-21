# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
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
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU General Public License is in the file COPYING.

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
    def unicodeToString(input):
        """
        If the input is type unicode, return a str. Otherwise, just return the
        input. This is necessary because Python 3 doesn't have the unicode
        type, but Python 2 does, and we just want to check arguments for str.
        """
        if _haveTypeUnicode and type(input) == unicode:
            # In Python 2, we can't use str(input) since this fails for non-ascii.
            return "".join(map(_chr_ord, input))
        else:
            return input

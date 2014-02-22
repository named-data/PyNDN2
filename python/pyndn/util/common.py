# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

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
        
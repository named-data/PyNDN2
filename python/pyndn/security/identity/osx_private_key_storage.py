# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Some code is from the examples at https://github.com/acdha/pymacadmin .
# See COPYING for copyright and distribution information.
#

import ctypes
from pyndn.security.security_types import KeyClass
from pyndn.security.identity.private_key_storage import PrivateKeyStorage

def load_carbon_framework(f_path):
    """
    Load a Carbon framework using ctypes.CDLL and add an errcheck wrapper to
    replace traditional errno-style error checks with exception handling.

    Example:
    >>> load_carbon_framework('/System/Library/Frameworks/Security.framework/Versions/Current/Security') # doctest: +ELLIPSIS
    <CDLL '/System/Library/Frameworks/Security.framework/Versions/Current/Security', handle ... at ...>
    """
    framework = ctypes.cdll.LoadLibrary(f_path)

    # TODO: Do we ever need to wrap framework.__getattr__ too?
    old_getitem = framework.__getitem__
    # @wraps(old_getitem)
    def new_getitem(k):
        v = old_getitem(k)
        if hasattr(v, "errcheck") and not v.errcheck:
            v.errcheck = checked_carbon_call
        return v
    framework.__getitem__ = new_getitem

    return framework

class OSXPrivateKeyStorage(PrivateKeyStorage):
    def __init__(self):
        super(OSXPrivateKeyStorage, self).__init__()
        
        self._lib = load_carbon_framework(
          "/System/Library/Frameworks/Security.framework/Versions/Current/Security")

    def _toInternalKeyName(keyName, keyClass):
        """
        Convert an NDN name of a key to an internal name of the key base on
        the keyClass.
        
        :param Name keyName: The NDN name of the key.
        :param keyClass: The class of the key, e.g. KeyClass.PUBLIC, 
           KeyClass.PRIVATE, or KeyClass.SYMMETRIC.
        :type keyClass: int from KeyClass
        :return: The internal key name.
        :rtype: str
        """
        keyUri = keyName.toUri()

        if KeyClass.SYMMETRIC == keyClass:
            return keyUri + "/symmetric"
        else:
            return keyUri

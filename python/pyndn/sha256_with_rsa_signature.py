# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the Sha256WithRsaSignature class which extends Signature and 
holds the signature bits and other info representing a SHA256-with-RSA signature
in a data packet.
"""

from pyndn.util.change_counter import ChangeCounter
from pyndn.util import Blob
from pyndn.signature import Signature
from pyndn.key_locator import KeyLocator

class Sha256WithRsaSignature(Signature):
    """
    Create a new Sha256WithRsaSignature object, possibly copying values from 
    another object.
    
    :param value: (optional) If value is a Sha256WithRsaSignature, copy its 
      values.  If value is omitted, the keyLocator is the default with
      unspecified values and the signature is unspecified.
    :param value: Sha256WithRsaSignature
    """
    def __init__(self, value = None):
        if value == None:
            self._keyLocator = ChangeCounter(KeyLocator())
            self._signature = Blob()
        elif type(value) is Sha256WithRsaSignature:
            # Copy its values.
            self._keyLocator = ChangeCounter(KeyLocator(value.getKeyLocator()))
            self._signature = value._signature
        else:
            raise RuntimeError(
              "Unrecognized type for Sha256WithRsaSignature constructor: " +
              repr(type(value)))
            
        self._changeCount = 0
            
    def clone(self):
        """
        Create a new Sha256WithRsaSignature which is a copy of this object.

        :return: A new object which is a copy of this object.
        :rtype: Sha256WithRsaSignature
        """
        return Sha256WithRsaSignature(self)

    def getKeyLocator(self):
        """
        Get the key locator.
        
        :return: The key locator.
        :rtype: KeyLocator
        """
        return self._keyLocator.get()

    def getSignature(self):
        """
        Get the data packet's signature bytes.
        
        :return: The signature bytes as a Blob, which maybe isNull().
        :rtype: Blob
        """
        return self._signature
    
    def setKeyLocator(self, keyLocator):
        """
        Set the key locator to a copy of the given keyLocator.
        
        :param keyLocator: The KeyLocator to copy.
        :type keyLocator: KeyLocator
        """
        self._keyLocator.set(KeyLocator(keyLocator)) 
        self._changeCount += 1

    def setSignature(self, signature):
        """
        Set the signature bytes to the given value.
        
        :param signature: The array with the signature bytes. If signature is 
          not a Blob, then create a new Blob to copy the bytes (otherwise 
          take another pointer to the same Blob).
        :type signature: A Blob or an array type with int elements 
        """
        self._signature = (signature if type(signature) == Blob 
                           else Blob(signature))
        self._changeCount += 1

    def clear(self):
        self._keyLocator.get().clear()
        self._signature = Blob()
        self._changeCount += 1        

    def getChangeCount(self):
        """
        Get the change count, which is incremented each time this object 
        (or a child object) is changed.

        :return: The change count.
        :rtype: int
        """
        # Make sure each of the checkChanged is called.
        changed = self._keyLocator.checkChanged()
        if changed:
            # A child object has changed, so update the change count.
            self._changeCount += 1

        return self._changeCount

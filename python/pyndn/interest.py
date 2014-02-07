#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

from encoding import WireFormat
from pyndn.util import Blob
from pyndn.util import ChangeCounter
from name import Name

"""
This module defines the NDN Interest class.
"""

class Interest(object):
    def __init__(self, name = None):
        self._name = ChangeCounter(name if type(name) == Name else Name(name))
        self._nonce = Blob()
        
        self._getNonceChangeCount = 0
        self._changeCount = 0

    def getName(self):
        return self._name.get()
    
    def getNonce(self):
        """
        Return the nonce value from the incoming interest.  If you change any of
        the fields in this Interest object, then the nonce value is cleared.
        
        :return: The nonce.  If isNull() then there nonce is omitted.
        :rtype: Blob
        """
        if self._getNonceChangeCount != self.getChangeCount():
            # The values have changed, so the existing nonce is invalidated.
            self._nonce = Blob()
            self._getNonceChangeCount = self.getChangeCount()

        return self._nonce
    
    def setName(self, name):
        self._name = ChangeCounter(name if type(name) == Name else Name(name))
        self._changeCount += 1
    
    def setNonce(self, nonce):
        self._nonce = nonce if type(nonce) == Blob else Blob(nonce)
        # Set _getNonceChangeCount so that the next call to getNonce() won't 
        #   clear _nonce.
        self._changeCount += 1
        self._getNonceChangeCount = self.getChangeCount();
    
    def wireEncode(self, wireFormat = WireFormat.getDefaultWireFormat()):
        """
        Encode this Interest for a particular wire format.
        
        :param wireFormat: (optional) A WireFormat object used to encode this 
           Interest. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat.
        """
        return wireFormat.encodeInterest(self)
    
    def wireDecode(self, input, wireFormat = WireFormat.getDefaultWireFormat()):
        """
        Decode the input using a particular wire format and update this Interest.
        
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements.
        :param wireFormat: (optional) A WireFormat object used to decode this 
           Interest. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat.
        """
        wireFormat.decodeInterest(self, input)
        
    def getChangeCount(self):
        """
        Get the change count, which is incremented each time this object 
        (or a child object) is changed.
        
        :return: The change count.
        :rtype: int
        """
        # Make sure each of the checkChanged is called.
        changed = self._name.checkChanged()
        if changed:
            # A child object has changed, so update the change count.
            self._changeCount += 1

        return self._changeCount
        
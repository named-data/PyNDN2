#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the NDN Interest class.
"""

from pyndn.encoding import WireFormat
from pyndn.util import Blob
from pyndn.util.change_counter import ChangeCounter
from pyndn.name import Name
from pyndn.key_locator import KeyLocator

class Interest(object):
    def __init__(self, name = None):
        self._name = ChangeCounter(name if type(name) == Name else Name(name))
        self._minSuffixComponents = None
        self._maxSuffixComponents = None
        self._keyLocator = ChangeCounter(KeyLocator())
        # TODO: Use the following for Exclude.
        #self._exclude = ChangeCounter(Exclude())
        self._childSelector = None
        self._mustBeFresh = False

        self._nonce = Blob()
        self._scope = None
        self._interestLifetimeMilliseconds = None
        
        self._getNonceChangeCount = 0
        self._changeCount = 0

    def getName(self):
        """
        Return the interest Name.
        
        :return: The name.  The name size() may be 0 if not specified.
        :rtype: Name
        """
        return self._name.get()
    
    def getMinSuffixComponents(self):
        """
        Get the min suffix components.
        
        :return: The min suffix components, or None if not specified.
        :rtype: int
        """
        return self._minSuffixComponents
    
    def getMaxSuffixComponents(self):
        """
        Get the max suffix components.
        
        :return: The max suffix components, or None if not specified.
        :rtype: int
        """
        return self._maxSuffixComponents
    
    def getKeyLocator(self):
        """
        Return the interest key locator.
        
        :return: The key locator. If getType() is None, then the key locator
          is not specified.
        :rtype: KeyLocator
        """
        return self._keyLocator.get()
    
    # TODO: Implement getExclude.
    
    def getChildSelector(self):
        """
        Get the child selector.
        
        :return: The child selector, or None if not specified.
        :rtype: int
        """
        return self._childSelector
    
    def getMustBeFresh(self):
        """
        Get the must be fresh flag.
        
        :return: The must be fresh flag.  If not specified, the default is 
          False.
        :rtype: bool
        """
        return self._mustBeFresh
    
    def getNonce(self):
        """
        Return the nonce value from the incoming interest.  If you change any of
        the fields in this Interest object, then the nonce value is cleared.
        
        :return: The nonce.  If isNull() then the nonce is omitted.
        :rtype: Blob
        """
        if self._getNonceChangeCount != self.getChangeCount():
            # The values have changed, so the existing nonce is invalidated.
            self._nonce = Blob()
            self._getNonceChangeCount = self.getChangeCount()

        return self._nonce
    
    def getScope(self):
        """
        Get the interest scope.
        
        :return: The scope, or None for none.
        :rtype: int
        """
        return self._scope

    def getInterestLifetimeMilliseconds(self):
        """
        Get the interest lifetime.
        
        :return: The interest lifetime in milliseconds, or None for none.
        :rtype: float
        """
        return self._interestLifetimeMilliseconds
    
    def setName(self, name):
        self._name.set(name if type(name) == Name else Name(name))
        self._changeCount += 1
    
    def setMinSuffixComponents(self, minSuffixComponents):
        self._minSuffixComponents = minSuffixComponents
        self._changeCount += 1
    
    def setMaxSuffixComponents(self, maxSuffixComponents):
        self._maxSuffixComponents = maxSuffixComponents
        self._changeCount += 1
    
    def setKeyLocator(self, keyLocator):
        self._keyLocator.set(keyLocator if type(keyLocator) == KeyLocator 
                             else KeyLocator())
        self._changeCount += 1
    
    # TODO: Implement setExclude.
    
    def setChildSelector(self, childSelector):
        self._childSelector = childSelector
        self._changeCount += 1
    
    def setMustBeFresh(self, mustBeFresh):
        self._mustBeFresh = True if mustBeFresh else False
        self._changeCount += 1
    
    def setNonce(self, nonce):
        self._nonce = nonce if type(nonce) == Blob else Blob(nonce)
        # Set _getNonceChangeCount so that the next call to getNonce() won't 
        #   clear _nonce.
        self._changeCount += 1
        self._getNonceChangeCount = self.getChangeCount();
    
    def setScope(self, scope):
        self._scope = scope
        self._changeCount += 1
    
    def setInterestLifetimeMilliseconds(self, interestLifetimeMilliseconds):
        self._interestLifetimeMilliseconds = (None
           if interestLifetimeMilliseconds == None
           else float(interestLifetimeMilliseconds)) 
        self._changeCount += 1
    
    def wireEncode(self, wireFormat = WireFormat.getDefaultWireFormat()):
        """
        Encode this Interest for a particular wire format.
        
        :param wireFormat: (optional) A WireFormat object used to encode this 
           Interest. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat.
        :return: The encoded buffer.
        :rtype: Blob
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
        # If input is a blob, get its buf().
        decodeBuffer = input.buf() if isinstance(input, Blob) else input
        wireFormat.decodeInterest(self, decodeBuffer)
        
    def getChangeCount(self):
        """
        Get the change count, which is incremented each time this object 
        (or a child object) is changed.
        
        :return: The change count.
        :rtype: int
        """
        # Make sure each of the checkChanged is called.
        changed = self._name.checkChanged()
        changed = self._keyLocator.checkChanged() or changed
        # TODO: Use the following for _exclude.
        # changed = self._exclude.checkChanged() or changed
        if changed:
            # A child object has changed, so update the change count.
            self._changeCount += 1

        return self._changeCount
        
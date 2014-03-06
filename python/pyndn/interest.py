# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
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
from pyndn.exclude import Exclude

class Interest(object):
    def __init__(self, value = None):
        if type(value) is Interest:
            # Copy the values.
            self._name = ChangeCounter(Name(value.getName()))
            self._minSuffixComponents = value._minSuffixComponents
            self._maxSuffixComponents = value._maxSuffixComponents
            self._keyLocator = ChangeCounter(KeyLocator(value.getKeyLocator()))
            self._exclude = ChangeCounter(Exclude(value.getExclude()))
            self._childSelector = value._childSelector
            self._mustBeFresh = value._mustBeFresh

            self._nonce = value.getNonce()
            self._scope = value._scope
            self._interestLifetimeMilliseconds = value._interestLifetimeMilliseconds
        else:
            self._name = ChangeCounter(Name(value) if type(value) is Name 
                                                   else Name())
            self._minSuffixComponents = None
            self._maxSuffixComponents = None
            self._keyLocator = ChangeCounter(KeyLocator())
            self._exclude = ChangeCounter(Exclude())
            self._childSelector = None
            self._mustBeFresh = True

            self._nonce = Blob()
            self._scope = None
            self._interestLifetimeMilliseconds = None            
        
        self._getNonceChangeCount = 0
        self._changeCount = 0

    def getName(self):
        """
        Get the interest Name.
        
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
        Get the interest key locator.
        
        :return: The key locator. If getType() is None, then the key locator
          is not specified.
        :rtype: KeyLocator
        """
        return self._keyLocator.get()
    
    def getExclude(self):
        """
        Get the exclude object.
        
        :return: The exclude object. If the exclude size() is zero, then
          the exclude is not specified.
        :rtype: Exclude
        """
        return self._exclude.get()
    
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
        
        :return: The scope, or None if not specified.
        :rtype: int
        """
        return self._scope

    def getInterestLifetimeMilliseconds(self):
        """
        Get the interest lifetime.
        
        :return: The interest lifetime in milliseconds, or None if not specified.
        :rtype: float
        """
        return self._interestLifetimeMilliseconds
    
    def setName(self, name):
        self._name.set(name if type(name) is Name else Name(name))
        self._changeCount += 1
    
    def setMinSuffixComponents(self, minSuffixComponents):
        self._minSuffixComponents = minSuffixComponents
        self._changeCount += 1
    
    def setMaxSuffixComponents(self, maxSuffixComponents):
        self._maxSuffixComponents = maxSuffixComponents
        self._changeCount += 1
    
    def setKeyLocator(self, keyLocator):
        """
        Set this interest to use a copy of the given keyLocator.
        Note: You can also change this interest's key locator modifying
        the object from getKeyLocator().
        
        :param keyLocator: The KeyLocator that is copied.
        :type keyLocator: KeyLocator
        """
        self._keyLocator.set(
          keyLocator if type(keyLocator) is KeyLocator(keyLocator) 
                     else KeyLocator())
        self._changeCount += 1
    
    def setExclude(self, exclude):
        """
        Set this interest to use a copy of the given exclude object.
        Note: You can also change this interest's exclude object modifying
        the object from getExclude().
        
        :param exclude: The exlcude object that is copied.
        :type exclude: Exclude
        """
        self._exclude.set(
          Exclude(exclude) if type(exclude) is Exclude else Exclude())
        self._changeCount += 1
    
    def setChildSelector(self, childSelector):
        self._childSelector = childSelector
        self._changeCount += 1
    
    def setMustBeFresh(self, mustBeFresh):
        self._mustBeFresh = True if mustBeFresh else False
        self._changeCount += 1
    
    def setNonce(self, nonce):
        self._nonce = nonce if type(nonce) is Blob else Blob(nonce)
        # Set _getNonceChangeCount so that the next call to getNonce() won't 
        #   clear _nonce.
        self._changeCount += 1
        self._getNonceChangeCount = self.getChangeCount()
    
    def setScope(self, scope):
        self._scope = scope
        self._changeCount += 1
    
    def setInterestLifetimeMilliseconds(self, interestLifetimeMilliseconds):
        self._interestLifetimeMilliseconds = (None
           if interestLifetimeMilliseconds == None
           else float(interestLifetimeMilliseconds)) 
        self._changeCount += 1
    
    def wireEncode(self, wireFormat = None):
        """
        Encode this Interest for a particular wire format.
        
        :param wireFormat: (optional) A WireFormat object used to encode this 
           Interest. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat.
        :return: The encoded buffer.
        :rtype: Blob
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        return wireFormat.encodeInterest(self)
    
    def wireDecode(self, input, wireFormat = None):
        """
        Decode the input using a particular wire format and update this Interest.
        
        :param input: The array with the bytes to decode.
        :type input: An array type with int elements
        :param wireFormat: (optional) A WireFormat object used to decode this 
           Interest. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat.
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        # If input is a blob, get its buf().
        decodeBuffer = input.buf() if isinstance(input, Blob) else input
        wireFormat.decodeInterest(self, decodeBuffer)
        
    def toUri(self):
        """
        Encode the name according to the "NDN URI Scheme".  If there are 
        interest selectors, append "?" and add the selectors as a query string.  
        For example "/test/name?ndn.ChildSelector=1".
        :note: This is an experimental feature.  See the API docs for more 
        detail at http://named-data.net/doc/ndn-ccl-api .
        
        :return: The URI string.
        :rtype: string
        """
        selectors = ""
        if self._minSuffixComponents != None:
            selectors += "&ndn.MinSuffixComponents=" + repr(
              self._minSuffixComponents)
        if self._maxSuffixComponents != None:
            selectors += "&ndn.MaxSuffixComponents=" + repr(
              self._maxSuffixComponents)
        if self._childSelector != None:
            selectors += "&ndn.ChildSelector=" + repr(self._childSelector)
        if self._mustBeFresh:
            selectors += "&ndn.MustBeFresh=true"
        if self._scope != None:
            selectors += "&ndn.Scope=" + repr(self._scope)
        if self._interestLifetimeMilliseconds != None:
            selectors += "&ndn.InterestLifetime=" + repr(
              self._interestLifetimeMilliseconds)
        if self.getNonce().size() > 0:
            selectors += ("&ndn.Nonce=" +
              Name.toEscapedString(self.getNonce().buf()))
        if self.getExclude().size() > 0:
            selectors += "&ndn.Exclude=" + self.getExclude().toUri()
            
        result = self.getName().toUri()
        if selectors != "":
            # Replace the first & with ?.
            result += "?" + selectors[1:]
            
        return result
        
    def matchesName(self, name):
        """
        Check if this interest's name matches the given name (using Name.match) 
        and the given name also conforms to the interest selectors.
        
        :param name: The name to check.
        :type name: Name
        :return: True if the name and interest selectors match, False otherwise.
        :rtype: bool
        """
        if not self.getName().match(name):
            return False
  
        if (self._minSuffixComponents != None and
              # Add 1 for the implicit digest.
              not (name.size() + 1 - self.getName().size() >= 
                   self._minSuffixComponents)):
            return False
        if (self._maxSuffixComponents != None and
              # Add 1 for the implicit digest.
              not (name.size() + 1 - self.getName().size() <= 
                   self._maxSuffixComponents)):
            return False
        if (self.getExclude().size() > 0 and 
              name.size() > self.getName().size() and
              self.getExclude().matches(name[self.getName().size()])):
            return False

        return True
        
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
        changed = self._exclude.checkChanged() or changed
        if changed:
            # A child object has changed, so update the change count.
            self._changeCount += 1

        return self._changeCount
        
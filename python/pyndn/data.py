#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the NDN Interest class.
"""

from encoding import WireFormat
from pyndn.util import Blob
from pyndn.util import SignedBlob
from pyndn.util import ChangeCounter
from name import Name

class Data(object):
    def __init__(self, name = None):
        self._name = ChangeCounter(name if type(name) == Name else Name(name))
        self._defaultWireEncoding = SignedBlob()

        self._getDefaultWireEncodingChangeCount = 0
        self._changeCount = 0
    
    def wireEncode(self, wireFormat = WireFormat.getDefaultWireFormat()):
        """
        Encode this Data for a particular wire format. If wireFormat is the 
        default wire format, also set the defaultWireEncoding field to the 
        encoded result.
        
        :param wireFormat: (optional) A WireFormat object used to encode this 
           Interest. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat.
        :return: The encoded buffer.
        :rtype: Blob
        """
        (encoding, signedPortionBeginOffset, signedPortionEndOffset) = \
          wireFormat.encodeData(self)
        wireEncoding = SignedBlob(
          encoding, signedPortionBeginOffset, signedPortionEndOffset)
          
        if wireFormat == WireFormat.getDefaultWireFormat():
            # This is the default wire encoding.
            self._setDefaultWireEncoding(wireEncoding)
        return wireEncoding
    
    def wireDecode(self, input, wireFormat = WireFormat.getDefaultWireFormat()):
        """
        Decode the input using a particular wire format and update this Data. 
        If wireFormat is the default wire format, also set the 
        defaultWireEncoding to another pointer to the input.
        
        :param input: The array with the bytes to decode. If input is not a 
          Blob, then copy the bytes to save the defaultWireEncoding (otherwise 
          take another pointer to the same Blob).
        :type input: An array type with int elements. 
        :param wireFormat: (optional) A WireFormat object used to decode this 
           Interest. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat.
        """
        # If input is a blob, get its buf().
        decodeBuffer = input.buf() if isinstance(input, Blob) else input
        (signedPortionBeginOffset, signedPortionEndOffset) = \
          wireFormat.decodeData(self, decodeBuffer)
  
        if wireFormat == WireFormat.getDefaultWireFormat():
            # This is the default wire encoding.  In the Blob constructor, set
            #   copy true, but if input is already a Blob, it won't copy.
            self._setDefaultWireEncoding(SignedBlob(
              Blob(input, True), 
              signedPortionBeginOffset, signedPortionEndOffset))
        else:
            self._setDefaultWireEncoding(SignedBlob())

    def getName(self):
        return self._name.get()
    
    def getDefaultWireEncoding(self):
        """
        Return the default wire encoding.
        
        :return: The default wire encoding, whose isNull() may be true if there
          is none.
        :rtype: SignedBlob
        """
        if self._getDefaultWireEncodingChangeCount != self.getChangeCount():
            # The values have changed, so the default wire encoding is 
            # invalidated.
            self._defaultWireEncoding = SignedBlob()
            self._getDefaultWireEncodingChangeCount = self.getChangeCount()
            
        return self._defaultWireEncoding
        
    def setName(self, name):
        self._name.set(name if type(name) == Name else Name(name))
        self._changeCount += 1
    
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

    def _setDefaultWireEncoding(self, defaultWireEncoding):
        self._defaultWireEncoding = defaultWireEncoding
        # Set _getDefaultWireEncodingChangeCount so that the next call to 
        # getDefaultWireEncoding() won't clear _defaultWireEncoding.
        self._getDefaultWireEncodingChangeCount = self.getChangeCount()
        
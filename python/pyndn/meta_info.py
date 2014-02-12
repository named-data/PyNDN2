#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the MetaInfo class which is used by Data and represents
the fields of an NDN MetaInfo.
"""

class MetaInfo(object):
    """
    Create a new MetaInfo object, possibly copying values from another object.
    
    :param value: (optional) If value is a MetaInfo, copy its values.  If
      value is omitted, the type is the default ContentType.BLOB and the 
      freshness period is not specified.
    :param value: MetaInfo
    """
    def __init__(self, value = None):
        if value == None:
            self._type = ContentType.BLOB
            self._freshnessPeriod = None
        elif type(value) is MetaInfo:
            # Copy its values.
            self._type = value._type
            self._freshnessPeriod = value._freshnessPeriod
        else:
            raise RuntimeError(
              "Unrecognized type for MetaInfo constructor: " +
              repr(type(value)))
                    
        self._changeCount = 0
        
    def getType(self):
        """
        Get the content type.
        
        :return: The content type.
        :rtype: an int from ContentType
        """
        return self._type
    
    def getFreshnessPeriod(self):
        """
        Get the freshness period.
        
        :return: The freshness period in milliseconds, or None if not specified.
        :rtype: float
        """
        return self._freshnessPeriod
    
    def setType(self, type):
        """
        Set the content type.
        
        :param type: The content type.  If None, this uses ContentType.BLOB.
        :type type: an int from ContentType
        """
        self._type = ContentType.BLOB if type == None or type < 0 else type
        self._changeCount += 1
        
    def setFreshnessPeriod(self, freshnessPeriod):
        """
        Set the freshness period.
        
        :param freshnessPeriod: The freshness period in milliseconds, or None 
          for not specified.
        :type freshnessPeriod: float
        """
        self._freshnessPeriod = freshnessPeriod
        self._changeCount += 1

    def getChangeCount(self):
        """
        Get the change count, which is incremented each time this object is 
        changed.
        
        :return: The change count.
        :rtype: int
        """
        return self._changeCount

class ContentType(object):
    """
    A ContentType specifies the content type in a MetaInfo object.
    """
    BLOB = 0
    LINK = 1
    KEY =  2
    
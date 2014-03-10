# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the Signature class which is an abstract base class 
providing methods to work with the signature information in an NDN Data packet.
You must use an object of a subclass, for example Sha256WithRsaSignature.
"""

class Signature(object):
    def clone(self):
        """
        Create a new Signature which is a copy of this signature.
        Your derived class should override.

        :return: A new object which is a copy of this object.
        :rtype: A subclass of Signature
        :raises RuntimeError: for unimplemented if the derived class does not 
          override.
        """
        raise RuntimeError("Signature.clone is not implemented")

    def getChangeCount(self):
        """
        Get the change count, which is incremented each time this object 
        (or a child object) is changed.
        Your derived class should override.

        :return: The change count.
        :rtype: int
        :raises RuntimeError: for unimplemented if the derived class does not 
          override.
        """
        raise RuntimeError("Signature.getChangeCount is not implemented")

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the SignedBlob class which extends Blob to keep the offsets
of a signed portion (e.g., the bytes of Data packet). 
"""

from blob import Blob

class SignedBlob(Blob):
    """
    Create a new SignedBlob using the given Blob and offsets.
    
    :param blob: (optional) The Blob with a signed portion.  If omitted,
    then isNull() is True.
    :type blob: Blob or SignedBlob
    :param signedPortionBeginOffset: (optional) The offset in the buffer of the
    beginning of the signed portion.
    :type signedPortionBeginOffset: int
    :param signedPortionEndOffset: (optional) The offset in the buffer of the
    end of the signed portion.
    :type signedPortionEndOffset: int
    """
    def __init__(
          self, blob = None, signedPortionBeginOffset = None, 
          signedPortionEndOffset = None):
        super(SignedBlob, self).__init__(blob)
        if self.isNull():
            self._signedPortionBeginOffset = 0
            self._signedPortionEndOffset = 0
        elif type(blob) is SignedBlob:
            # Copy the SignedBlob, allowing override for offsets.
            self._signedPortionBeginOffset = (
              blob._signedPortionBeginOffset if signedPortionBeginOffset == None
              else signedPortionBeginOffset)
            self._signedPortionEndOffset = (
              blob._signedPortionEndOffset if signedPortionEndOffset == None
              else signedPortionEndOffset)
        else:
            self._signedPortionBeginOffset = signedPortionBeginOffset
            self._signedPortionEndOffset = signedPortionEndOffset
        
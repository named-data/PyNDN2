# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the PublicKey class which holds an encoded public key
for use by the security library.
"""

from pyndn.security.security_types import DigestAlgorithm

class PublicKey(object):
    """
    Create a new PublicKey with the given values.
    
    :param OID algorithm: The algorithm of the public key.
    :param Blob keyDer: The blob of the PublicKeyInfo in terms of DER.
    """
    def __init__(self, algorithm, keyDer):
        self._algorithm = algorithm
        self._keyDer = keyDer
        
    def toDer(self):
        """
        Encode the public key into DER.
        
        :return: The encoded DER syntax tree.
        :rtype: DerNode
        """
        raise RuntimeError("PublicKey.toDer is not implemented")
    
    @staticmethod
    def fromDer(keyDer):
        """
        Decode the public key from DER blob.
        
        :param Blob keyDer: The DER blob.
        :return: The decoded public key.
        :rtype: PublicKey
        """
        raise RuntimeError("PublicKey.fromDer is not implemented")
    
    def getDigest(self, digestAlgorithm = DigestAlgorithm.SHA256):
        """
        Get the digest of the public key.
        
        :param digestAlgorithm: (optional) The digest algorithm.  If omitted,
          use DigestAlgorithm.SHA256 .
        :type digestAlgorithm: int from DigestAlgorithm
        :return: The digest value
        :rtype: Blob
        """
        raise RuntimeError("PublicKey.getDigest is not implemented")
    
    def getKeyDer(self):
        """
        Get the raw bytes of the public key in DER format.
        
        :return: The public key DER
        :rtype: Blob
        """
        return self._keyDer
    
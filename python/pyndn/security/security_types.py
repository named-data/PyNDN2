# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines constants used by the security library.
"""

class KeyType(object):
    RSA = 1
    AES = 2
    # DSA
    # DES
    # RC4
    # RC2

class KeyClass(object):
    PUBLIC = 1
    PRIVATE = 2
    SYMMETRIC = 3
    
class DigestAlgorithm(object):
    SHA256 = 1
    # MD2
    # MD5
    # SHA1

class EncryptMode(object):
    DEFAULT = 1
    CFB_AES = 2
    # CBC_AES

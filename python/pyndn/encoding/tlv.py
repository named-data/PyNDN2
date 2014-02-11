# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the Tlv class with type codes for the NDN-TLV wire format.  
"""

class Tlv(object):
    Interest      = 1
    Data          = 2
    Name          = 3
    NameComponent = 4
    Selectors     = 5
    Nonce         = 6
    Scope         = 7
    InterestLifetime          = 8
    MinSuffixComponents       = 9
    MaxSuffixComponents       = 10
    PublisherPublicKeyLocator = 11
    Exclude       =   12
    ChildSelector =   13
    MustBeFresh   =   14
    Any           =   15
    MetaInfo      =   16
    Content       =   17
    SignatureInfo =   18
    SignatureValue =  19
    ContentType   =   20
    FreshnessPeriod = 21
    SignatureType =   22
    KeyLocator    =   23
    KeyLocatorDigest = 24

    AppPrivateBlock1 = 128
    AppPrivateBlock2 = 32767

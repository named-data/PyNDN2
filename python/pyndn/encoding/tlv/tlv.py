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
    Interest =         5
    Data =             6
    Name =             7
    NameComponent =    8
    Selectors =        9
    Nonce =            10
    Scope =            11
    InterestLifetime = 12
    MinSuffixComponents = 13
    MaxSuffixComponents = 14
    PublisherPublicKeyLocator = 15
    Exclude =          16
    ChildSelector =    17
    MustBeFresh =      18
    Any =              19
    MetaInfo =         20
    Content =          21
    SignatureInfo =    22
    SignatureValue =   23
    ContentType =      24
    FreshnessPeriod =  25
    FinalBlockId =     26
    SignatureType =    27
    KeyLocator =       28
    KeyLocatorDigest = 29
    FaceInstance =     128
    ForwardingEntry =  129
    StatusResponse =   130
    Action =           131
    FaceID =           132
    IPProto =          133
    Host =             134
    Port =             135
    MulticastInterface = 136
    MulticastTTL =     137
    ForwardingFlags =  138
    StatusCode =       139
    StatusText =       140

    SignatureType_DigestSha256 = 0
    SignatureType_SignatureSha256WithRsa = 1

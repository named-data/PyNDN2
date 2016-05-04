# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU Lesser General Public License is in the file COPYING.

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
    # <Unassigned> =   11
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
    SelectedDelegation = 32
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
    SignatureType_SignatureSha256WithEcdsa = 3
    SignatureType_SignatureHmacWithSha256 = 4

    ContentType_Default = 0
    ContentType_Link = 1
    ContentType_Key = 2

    NfdCommand_ControlResponse = 101
    NfdCommand_StatusCode =      102
    NfdCommand_StatusText =      103

    ControlParameters_ControlParameters =   104
    ControlParameters_FaceId =              105
    ControlParameters_Uri =                 114
    ControlParameters_LocalControlFeature = 110
    ControlParameters_Origin =              111
    ControlParameters_Cost =                106
    ControlParameters_Flags =               108
    ControlParameters_Strategy =            107
    ControlParameters_ExpirationPeriod =    109

    LpPacket_LpPacket =        100
    LpPacket_Fragment =         80
    LpPacket_Sequence =         81
    LpPacket_FragIndex =        82
    LpPacket_FragCount =        83
    LpPacket_Nack =            800
    LpPacket_NackReason =      801
    LpPacket_NextHopFaceId =   816
    LpPacket_IncomingFaceId =  817
    LpPacket_CachePolicy =     820
    LpPacket_CachePolicyType = 821
    LpPacket_IGNORE_MIN =      800
    LpPacket_IGNORE_MAX =      959

    Link_Preference = 30
    Link_Delegation = 31

    Encrypt_EncryptedContent = 130
    Encrypt_EncryptionAlgorithm = 131
    Encrypt_EncryptedPayload = 132
    Encrypt_InitialVector = 133

    # For RepetitiveInterval.
    Encrypt_StartDate = 134
    Encrypt_EndDate = 135
    Encrypt_IntervalStartHour = 136
    Encrypt_IntervalEndHour = 137
    Encrypt_NRepeats = 138
    Encrypt_RepeatUnit = 139
    Encrypt_RepetitiveInterval = 140

    # For Schedule.
    Encrypt_WhiteIntervalList = 141
    Encrypt_BlackIntervalList = 142
    Encrypt_Schedule = 143

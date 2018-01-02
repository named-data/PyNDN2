# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2018 Regents of the University of California.
# Author: Jeff Burke <jburke@remap.ucla.edu>
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

import sys, traceback

def testPropertyRW( obj, p, vals, onlyCheckPresence=False ):

    if not hasattr(obj, p): return (False, type(obj).__name__, "No attribute", p)

    capitalP = p[0].upper() + p[1:]

    try:
        getter = getattr(obj, "get" + capitalP)   # Let these throw an exception if not available.
    except:
        return (False,  type(obj).__name__, "No getter .get"+capitalP)
    try:
        setter = getattr(obj, "set" + capitalP)
    except:
        return (False, type(obj).__name__, "No setter .set"+capitalP)

    if not onlyCheckPresence:
        if len(vals) < 2: raise RuntimeError("Need two values for vals in testPropertyRW, got fewer")
        try:
            # actually test getter and setter
            v = vals[0]
            setter(v)
            v1 = getter()
            v2 = getattr(obj, p)
            if hasattr(v1, "equals"):
                if not v1.equals(v): return (False, type(obj).__name__, "Setter then getter failed using equals", p, v, v1)
                if not v2.equals(v): return (False, type(obj).__name__, "Setter then property get failed using equals", p, v, v2)
            else:
                if v1 != v: return (False, type(obj).__name__, "Setter then getter failed", p, v, v1)
                if v2 != v: return (False, type(obj).__name__, "Setter then property get failed", p, v, v2)

            v = vals[1]
            setattr(obj, p, v)
            v1 = getter()
            v2 = getattr(obj, p)
            if hasattr(v1, "equals"):
                if not v1.equals(v): return (False, type(obj).__name__, "Property set then getter failed using equals()", p, v, v1)
                if not v2.equals(v): return (False, type(obj).__name__, "Property set then property get failed using equals()", p, v, v2)
            else:
                if v1 != v: return (False, type(obj).__name__, "Property set then getter failed", p, v, v1)
                if v2 != v: return (False, type(obj).__name__, "Property set then property get failed", p, v, v2)
        except Exception as e:
                #exc_type, exc_value, exc_traceback = sys.exc_info()
                #traceback.print_tb(exc_traceback, limit=1, file=sys.stdout)
                return (False, type(obj).__name__, "Exception raised", e)

    return (True, type(obj).__name__, vals)

## To Do: Add value checks

# ControlParameters
#
from pyndn.name import Name
from pyndn.control_parameters import ControlParameters
from pyndn.forwarding_flags import ForwardingFlags
for p in [("name",Name("yes"),Name("another")), ("faceId", 32, None), ("localControlFeature", 1, None), ("origin", 2, 9), ("cost", 1, None), ("forwardingFlags", ForwardingFlags(), ForwardingFlags()), ("expirationPeriod", 1000.1, None)]:
    res = testPropertyRW( ControlParameters(), p[0], [p[1],p[2]])
    if not res[0]: print(res)

# Data
#
from pyndn.data import Data
from pyndn.name import Name
from pyndn.meta_info import MetaInfo
from pyndn.signature import Signature
from pyndn.util.blob import Blob
# We do not test the signature property because clone is not yet implemented for it.
#
for p in [("name",Name("yes"),Name("another")), ("metaInfo", MetaInfo(), MetaInfo()), ("content", Blob("foo"), Blob("bar"))]:
    res = testPropertyRW( Data(), p[0], [p[1],p[2]])
    if not res[0]: print(res)

# ForwardingFlags
# All boolean, so use shortcut below
#
from pyndn.forwarding_flags import ForwardingFlags
for p in ["active", "childInherit", "advertise", "last", "capture", "local", "tap", "captureOk"]:
    res = testPropertyRW( ForwardingFlags(), p, [True, False] )
    if not res[0]: print(res)

# Interest
# TODO: We do not check exclude because there is no equals() for it yet.
# TODO: When passing None as the KeyLocator, it generates a blank KeyLocator object, so equivalence checks fail.  Don't check None.
#
from pyndn.name import Name
from pyndn.key_locator import KeyLocator
from pyndn.exclude import Exclude
from pyndn.interest import Interest
for p in [("name", Name("yes"), Name("another")), ("minSuffixComponents", 4, None), ("maxSuffixComponents", 1, None), ("keyLocator", KeyLocator(), KeyLocator()),("childSelector", 1, 0), ("mustBeFresh", 0, 1), ("nonce", Blob(), Blob()), ("interestLifetimeMilliseconds", 49, None)]:
    res = testPropertyRW( Interest(), p[0], [p[1],p[2]])
    if not res[0]: print(res)

# KeyLocator
#
from pyndn.name import Name
from pyndn.util.blob import Blob
from pyndn.key_locator import KeyLocator, KeyLocatorType
for p in [("type", KeyLocatorType.KEYNAME, KeyLocatorType.KEY_LOCATOR_DIGEST), ("keyName", Name("yes"), Name("another")),  ("keyData", Blob(), Blob())]:
    res = testPropertyRW( KeyLocator(), p[0], [p[1],p[2]])
    if not res[0]: print(res)

# MetaInfo
# TODO:  Support FinalBlockId of None.
#
from pyndn.name import Name
from pyndn.meta_info import MetaInfo, ContentType
for p in [("type", ContentType.BLOB, ContentType.LINK), ("freshnessPeriod", 47, None), ("finalBlockId", Name.Component("12"), Name.Component())]:
    res = testPropertyRW( MetaInfo(), p[0], [p[1],p[2]])
    if not res[0]: print(res)

# Sha256WithRsaSignature
# TODO: When passing None as the KeyLocator, it generates a blank KeyLocator object, so equivalence checks fail.  Don't check None.
# TODO: Should the signature value be a blob? (Or allow Signature?)
#
from pyndn.key_locator import KeyLocator
from pyndn.signature import Signature
from pyndn.sha256_with_rsa_signature import Sha256WithRsaSignature
for p in [("keyLocator", KeyLocator(), KeyLocator()), ("signature", Blob(), Blob())]:
    res = testPropertyRW( Sha256WithRsaSignature(), p[0], [p[1],p[2]])
    if not res[0]: print(res)




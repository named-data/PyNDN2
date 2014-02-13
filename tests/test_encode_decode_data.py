# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

from pyndn import Data
from pyndn import ContentType
from pyndn import Sha256WithRsaSignature
from pyndn import KeyLocatorType

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str else repr(element)) + " "
    print(result)

def dumpData(data):
    dump("name:", data.getName().toUri())
    if data.getContent().size() > 0:
        dump("content (raw):", bytearray(data.getContent().buf()).decode('latin-1'))
        dump("content (hex):", data.getContent().toHex())
    else:
        dump("content: <empty>")
    if not data.getMetaInfo().getType() == ContentType.BLOB:
        dump("metaInfo.type:",
             "LINK" if data.getMetaInfo().getType() == ContentType.LINK
             else "KEY" if data.getMetaInfo().getType() == ContentType.KEY
             else "uknown")
    dump("metaInfo.freshnessPeriod (milliseconds):",
         data.getMetaInfo().getFreshnessPeriod()
         if data.getMetaInfo().getFreshnessPeriod() >= 0 else "<none>")
    signature = data.getSignature()
    if type(signature) is Sha256WithRsaSignature:
        dump("signature.signature:", 
             "<none>" if signature.getSignature().size() == 0
                      else signature.getSignature().toHex())
        if signature.getKeyLocator().getType() != None:
            if (signature.getKeyLocator().getType() == 
                KeyLocatorType.KEY_LOCATOR_DIGEST):
                dump("signature.keyLocator: KeyLocatorDigest:",
                     signature.getKeyLocator().getKeyData().toHex())
            elif signature.getKeyLocator().getType() == KeyLocatorType.KEYNAME:
                dump("signature.keyLocator: KeyName:",
                     signature.getKeyLocator().getKeyName().toUri())
            else:
                dump("signature.keyLocator: <unrecognized KeyLocatorType")
        else:
            dump("signature.keyLocator: <none>")

data = Data()
data.getName().set("/ndn/abc")
data.getMetaInfo().setFreshnessPeriod(5000.0)
data.setContent("SUCCESS!")
data.getSignature().getKeyLocator().setType(1)
data.getSignature().getKeyLocator().setName("/key/name")
data.getSignature().setSignature([1, 2, 3])
data.getSignature().setKeyLocator(data.getSignature().getKeyLocator())
data.setSignature(data.getSignature())
dumpData(data)
encoding = data.wireEncode()
decodedData = Data()
decodedData.wireDecode(encoding.buf())
dumpData(decodedData)

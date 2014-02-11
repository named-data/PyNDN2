# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

from pyndn import Data
from pyndn import ContentType

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

data = Data()
data.getName().set("/ndn/abc")
data.getMetaInfo().setType(ContentType.LINK)
data.getMetaInfo().setFreshnessPeriod(1234.5)
data.setContent("SUCCESS!")
dumpData(data)
encoding = data.wireEncode()
decodedData = Data()
decodedData.wireDecode(encoding.buf())
dumpData(decodedData)

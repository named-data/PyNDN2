# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

from pyndn import Data

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str or type(element) is unicode
                   else repr(element)) + " "
    print(result)

def dumpData(data):
    dump("name:", data.getName().toUri())
    if data.getContent().size() > 0:
        dump("content (raw):", bytearray(data.getContent().buf()).decode('latin-1'))
        dump("content (hex):", data.getContent().toHex())
    else:
        dump("content: <empty>")

data = Data()
data.getName().append("ndn").append("abc")
data.setContent("SUCCESS!")
dumpData(data)
encoding = data.wireEncode()
decodedData = Data()
decodedData.wireDecode(encoding.buf())
dumpData(decodedData)

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2016-2018 Regents of the University of California.
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
This decodes and verifies a hard-coded data packet with an HMAC signature. Then
this creates a fresh data packet with an HMAC signature, signs and verifies it.
For testing, this uses a hard-coded shared secret.
"""

from pyndn import Name, Data, HmacWithSha256Signature, KeyLocatorType
from pyndn.security import KeyChain
from pyndn.util import Blob

TlvData = Blob(bytearray([
0x06, 0x49, # NDN Data
  0x07, 0x0a, # Name
    0x08, 0x03, 0x6e, 0x64, 0x6e, # "ndn"
    0x08, 0x03, 0x61, 0x62, 0x63, # "abc"
  0x14, 0x00, # MetaInfo
  0x15, 0x08, 0x53, 0x55, 0x43, 0x43, 0x45, 0x53, 0x53, 0x21, # Content = "SUCCESS!"
  0x16, 0x0d, # SignatureInfo
    0x1b, 0x01, 0x04, # SignatureType = SignatureHmacWithSha256
    0x1c, 0x08, # KeyLocator
      0x07, 0x06, # Name
        0x08, 0x04, 0x6b, 0x65, 0x79, 0x31, # "key1"
  0x17, 0x20, # SignatureValue
    0x19, 0x86, 0x8e, 0x71, 0x83, 0x99, 0x8d, 0xf3, 0x73, 0x33,
    0x2f, 0x3d, 0xd1, 0xc9, 0xc9, 0x50, 0xfc, 0x29, 0xd7, 0x34,
    0xc0, 0x79, 0x77, 0x79, 0x1d, 0x83, 0x96, 0xfa, 0x3b, 0x91,
    0xfd, 0x36
  ]))

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str else repr(element)) + " "
    print(result)

def main():
    data = Data()
    data.wireDecode(TlvData)

    # Use a hard-wired secret for testing. In a real application the signer
    # ensures that the verifier knows the shared key and its keyName.
    key = Blob(bytearray([
       0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
      16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
    ]))

    if KeyChain.verifyDataWithHmacWithSha256(data, key):
      dump("Hard-coded data signature verification: VERIFIED")
    else:
      dump("Hard-coded data signature verification: FAILED")

    freshData = Data(Name("/ndn/abc"))
    signature = HmacWithSha256Signature()
    signature.getKeyLocator().setType(KeyLocatorType.KEYNAME)
    signature.getKeyLocator().setKeyName(Name("key1"))
    freshData.setSignature(signature)
    freshData.setContent("SUCCESS!")
    dump("Signing fresh data packet", freshData.getName().toUri())
    KeyChain.signWithHmacWithSha256(freshData, key)

    if KeyChain.verifyDataWithHmacWithSha256(freshData, key):
      dump("Freshly-signed data signature verification: VERIFIED")
    else:
      dump("Freshly-signed data signature verification: FAILED")

main()

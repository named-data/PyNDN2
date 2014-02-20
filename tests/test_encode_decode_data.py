# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

from pyndn import Name
from pyndn import Data
from pyndn import ContentType
from pyndn import KeyLocatorType
from pyndn import Sha256WithRsaSignature
from pyndn.util import Blob

TlvData = Blob(bytearray([
0x06, 0xCC, # NDN Data
  0x07, 0x0A, 0x08, 0x03, 0x6E, 0x64, 0x6E, 0x08, 0x03, 0x61, 0x62, 0x63, # Name
  0x14, 0x08, # MetaInfo
    0x19, 0x02, 0x13, 0x88, # FreshnessPeriod
    0x1A, 0x02, 0x00, 0x09, # FinalBlockId
  0x15, 0x08, 0x53, 0x55, 0x43, 0x43, 0x45, 0x53, 0x53, 0x21, # Content
  0x16, 0x28, # SignatureInfo
    0x1B, 0x01, 0x01, # SignatureType
    0x1C, 0x23, # KeyLocator
      0x07, 0x21, # Name
        0x08, 0x08, 0x74, 0x65, 0x73, 0x74, 0x6E, 0x61, 0x6D, 0x65,
        0x08, 0x03, 0x4B, 0x45, 0x59,
        0x08, 0x07, 0x44, 0x53, 0x4B, 0x2D, 0x31, 0x32, 0x33,
        0x08, 0x07, 0x49, 0x44, 0x2D, 0x43, 0x45, 0x52, 0x54,
  0x17, 0x80, # SignatureValue
    0x31, 0xC9, 0x45, 0x1E, 0x6A, 0x93, 0x8D, 0x09, 0x9B, 0x9D, 0x62, 0xC6, 0x10, 0x10, 0x12, 0x71,
    0x98, 0xD5, 0x36, 0x4A, 0x25, 0xA6, 0x97, 0x06, 0x65, 0xAC, 0x5C, 0x89, 0x2B, 0xD1, 0x41, 0x83,
    0xCF, 0x56, 0x12, 0x1C, 0xAD, 0x15, 0xD9, 0x75, 0x24, 0xAB, 0x21, 0x82, 0x54, 0x4A, 0xDC, 0x40,
    0xAA, 0xB5, 0x79, 0xE8, 0xD9, 0x6F, 0x05, 0x1C, 0x72, 0x0A, 0x93, 0xBA, 0xA6, 0x7A, 0xD2, 0x22,
    0x13, 0x33, 0xB8, 0x7A, 0xC6, 0x88, 0x4E, 0x6F, 0x4A, 0x06, 0x02, 0x99, 0xA3, 0xAF, 0x9C, 0x50,
    0xB4, 0xAE, 0x40, 0x96, 0xF0, 0x4E, 0xD5, 0x01, 0x67, 0x50, 0x52, 0xB2, 0x1A, 0xAF, 0xCC, 0x66,
    0xAA, 0x72, 0x6E, 0xA5, 0x5B, 0xBD, 0x2E, 0x78, 0xAF, 0xA0, 0xE9, 0x15, 0x7C, 0x89, 0x66, 0x32,
    0x6F, 0x9E, 0xC4, 0x84, 0x86, 0x93, 0x95, 0xE6, 0x4B, 0x76, 0xFB, 0x6E, 0x59, 0xCA, 0x0E, 0xD4,
1
  ]))

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str else repr(element)) + " "
    print(result)

def dumpData(data):
    dump("name:", data.getName().toUri())
    if data.getContent().size() > 0:
        # Use join to convert each byte to chr.
        dump("content (raw):", "".join(map(chr, data.getContent().buf())))
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
    dump("metaInfo.finalBlockID:",
         data.getMetaInfo().getFinalBlockID().toEscapedString()
         if data.getMetaInfo().getFinalBlockID().getValue().size() >= 0 
         else "<none>")
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

def main():
    data = Data()
    data.wireDecode(TlvData)
    dump("Decoded Data:")
    dumpData(data)
    
    # Set the content again to clear the cached encoding so we encode again.
    data.setContent(data.getContent())
    encoding = data.wireEncode()
    
    reDecodedData = Data()
    reDecodedData.wireDecode(encoding)
    dump("")
    dump("Re-decoded Data:")
    dumpData(reDecodedData)

    freshData = Data(Name("/ndn/abc"))
    freshData.setContent("SUCCESS!")
    freshData.getMetaInfo().setFreshnessPeriod(5000)
    freshData.getMetaInfo().setFinalBlockID(Name("/%00%09")[0])
    
    #identityStorage = MemoryIdentityStorage()
    #privateKeyStorage = MemoryPrivateKeyStorage()
    #keyChain = KeyChain(IdentityManager(identityStorage, privateKeyStorage), 
    #                    SelfVerifyPolicyManager(identityStorage))
    
    # Initialize the storage.
    keyName = Name("/testname/DSK-123")
    certificateName = keyName.getSubName(0, keyName.size() - 1).append(
      "KEY").append(keyName[-1]).append("ID-CERT").append("0")
    #identityStorage.addKey(keyName, KEY_TYPE_RSA, DEFAULT_PUBLIC_KEY_DER)
    #privateKeyStorage.setKeyPairForKeyName(
    #  (keyName, DEFAULT_PUBLIC_KEY_DER, DEFAULT_PRIVATE_KEY_DER))
    
    #keyChain.sign(freshData, certificateName)
    dump("")
    dump("Freshly-signed Data:")
    dumpData(freshData);
    
    #keyChain.verifyData(freshData, bind(&onVerified, "Freshly-signed Data", _1), bind(&onVerifyFailed, "Freshly-signed Data", _1));
    
main()

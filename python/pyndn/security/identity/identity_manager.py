# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the IdentityManager class which is the interface of 
operations related to identity, keys, and certificates.
"""

from pyndn.encoding import WireFormat
from pyndn.sha256_with_rsa_signature import Sha256WithRsaSignature
from pyndn import KeyLocatorType

class IdentityManager(object):
    """
    Create a new IdentityManager to use the identityStorage and 
    privateKeyStorage.
    
    :param identityStorage: An object of a subclass of IdentityStorage.
    :type identityStorage: IdentityStorage
    :param privateKeyStorage: An object of a subclass of PrivateKeyStorage.
    :type privateKeyStorage: PrivateKeyStorage
    """
    def __init__(self, identityStorage, privateKeyStorage):
        self._identityStorage = identityStorage
        self._privateKeyStorage = privateKeyStorage
        
    def signByCertificate(self, data, certificateName, wireFormat = None):
        """
        Sign data packet based on the certificate name.

        :param data: The Data object to sign and update its signature.
        :type data: Data
        :param certificateName: The Name identifying the certificate which 
          identifies the signing key.
        :type certificateName: Name
        :param wireFormat: (optional) The WireFormat for calling encodeData, or
          WireFormat.getDefaultWireFormat() if omitted.
        :type wireFormat: A subclass of WireFormat.
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        keyName = self.certificateNameToPublicKeyName(certificateName)
        publicKey = self._privateKeyStorage.getPublicKey(keyName)

        # For temporary usage, we support RSA + SHA256 only, but will support more.
        data.setSignature(Sha256WithRsaSignature())
        # Get a pointer to the clone which Data made.
        signature = data.getSignature()
        signature.getKeyLocator().setType(KeyLocatorType.KEYNAME)
        signature.getKeyLocator().setKeyName(certificateName.getPrefix(-1))

        # Encode once to get the signed portion.
        encoding = data.wireEncode(wireFormat)
  
        signature.setSignature(self._privateKeyStorage.sign
          (encoding.toSignedBuffer(), keyName))

        # Encode again to include the signature.
        data.wireEncode(wireFormat)
        
    # TODO: Move this to IdentityCertificate
    @staticmethod
    def certificateNameToPublicKeyName(certificateName):
        """
        Get the public key name from the full certificate name.
        
        :param certificateName: The full certificate name.
        :type certificateName: Name
        :return: The related public key name.
        :rtype: Name
        """
        i = certificateName.size() - 1
        idString = "ID-CERT"
        while i >= 0:
            if certificateName[i].toEscapedString() == idString:
                break
            i -= 1

        tmpName = certificateName.getSubName(0, i)
        keyString = "KEY"
        i = 0
        while i < tmpName.size():
            if tmpName[i].toEscapedString() == keyString:
                break
            i += 1

        return tmpName.getSubName(0, i).append(tmpName.getSubName(
                 i + 1, tmpName.size() - i - 1))

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/safe-bag.cpp
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
This module defines the SafeBag class which represents a container for sensitive
related information such as a certificate and private key.
"""

from pyndn.name import Name
from pyndn.data import Data
from pyndn.meta_info import ContentType
from pyndn.key_locator import KeyLocatorType
from pyndn.sha256_with_ecdsa_signature import Sha256WithEcdsaSignature
from pyndn.sha256_with_rsa_signature import Sha256WithRsaSignature
from pyndn.key_locator import KeyLocator
from pyndn.validity_period import ValidityPeriod
from pyndn.security.security_types import KeyType
from pyndn.security.v2.certificate_v2 import CertificateV2
from pyndn.security.certificate.public_key import PublicKey
from pyndn.security.security_types import DigestAlgorithm
from pyndn.util.common import Common
from pyndn.security.tpm.tpm import Tpm
from pyndn.security.tpm.tpm_back_end_memory import TpmBackEndMemory
from pyndn.encoding.wire_format import WireFormat

class SafeBag(object):
    """
    There are two forms of the SafeBag constructor:
    SafeBag(certificate, privateKeyBag) - Create a SafeBag with the given
    certificate and private key.
    SafeBag(keyName, privateKeyBag, publicKeyEncoding [, password,
    digestAlgorithm, wireFormat]) - Create a SafeBag with given private key
    and a new self-signed certificate for the given public key.

    :param Data certificate: The certificate data packet (used only for
      SafeBag(certificate, privateKeyBag)). This copies the object.
    :param Blob privateKeyBag: The encoded private key. If encrypted, this is a
      PKCS #8 EncryptedPrivateKeyInfo. If not encrypted, this is an unencrypted
      PKCS #8 PrivateKeyInfo.
    :param password: (optional) The password for decrypting the private key in
      order to sign the self-signed certificate. If the password is supplied,
      use it to decrypt the PKCS #8 EncryptedPrivateKeyInfo. If the password is
      omitted or None, privateKeyBag is an unencrypted PKCS #8 PrivateKeyInfo.
    :type password: an array which implements the buffer protocol
    :param int digestAlgorithm: (optional) The digest algorithm for signing the
      self-signed certificate. If omitted, use DigestAlgorithm.SHA256 .
    :type digestAlgorithm: int from the DigestAlgorithm enum
    :param WireFormat wireFormat: (optional) A WireFormat object used to encode
      the self-signed certificate in order to sign it. If omitted, use
      WireFormat.getDefaultWireFormat().
    """
    def __init__(self, keyNameOrCertificate, privateKeyBag,
      publicKeyEncoding = None, password = None,
      digestAlgorithm = DigestAlgorithm.SHA256, wireFormat = None):
        if isinstance(keyNameOrCertificate, Name):
            keyName = keyNameOrCertificate
            if wireFormat == None:
                # Don't use a default argument since getDefaultWireFormat can change.
                wireFormat = WireFormat.getDefaultWireFormat()

            self._certificate = SafeBag._makeSelfSignedCertificate(
              keyName, privateKeyBag, publicKeyEncoding, password,
              digestAlgorithm, wireFormat)
            self._privateKeyBag = privateKeyBag
        else:
            # The certificate is supplied.
            self._certificate = Data(keyNameOrCertificate)
            self._privateKeyBag = privateKeyBag

    def getCertificate(self):
        """
        Get the certificate data packet.

        :return: The certificate as a Data packet. If you need to process it as
          a certificate object then you must create a new CertificateV2(data).
        :rtype: Data
        """
        return self._certificate

    def getPrivateKeyBag(self):
        """
        Get the encoded private key.

        :return: The encoded private key. If encrypted, this is a PKCS #8
          EncryptedPrivateKeyInfo. If not encrypted, this is an unencrypted PKCS
          #8 PrivateKeyInfo.
        :rtype: Blob
        """
        return self._privateKeyBag

    @staticmethod
    def _makeSelfSignedCertificate(
      keyName, privateKeyBag, publicKeyEncoding, password, digestAlgorithm,
      wireFormat):
        certificate = CertificateV2()

        # Set the name.
        now = Common.getNowMilliseconds()
        certificateName = Name(keyName)
        certificateName.append("self").appendVersion(int(now))
        certificate.setName(certificateName)

        # Set the MetaInfo.
        certificate.getMetaInfo().setType(ContentType.KEY)
        # Set a one-hour freshness period.
        certificate.getMetaInfo().setFreshnessPeriod(3600 * 1000.0)

        # Set the content.
        publicKey = PublicKey(publicKeyEncoding)
        certificate.setContent(publicKey.getKeyDer())

        # Create a temporary in-memory Tpm and import the private key.
        tpm = Tpm("", "", TpmBackEndMemory())
        tpm._importPrivateKey(keyName, privateKeyBag.toBytes(), password)

        # Set the signature info.
        if publicKey.getKeyType() == KeyType.RSA:
            certificate.setSignature(Sha256WithRsaSignature())
        elif publicKey.getKeyType() == KeyType.ECDSA:
            certificate.setSignature(Sha256WithEcdsaSignature())
        else:
            raise ValueError("Unsupported key type")
        signatureInfo = certificate.getSignature()
        KeyLocator.getFromSignature(signatureInfo).setType(KeyLocatorType.KEYNAME)
        KeyLocator.getFromSignature(signatureInfo).setKeyName(keyName)

        # Set a 20-year validity period.
        ValidityPeriod.getFromSignature(signatureInfo).setPeriod(
          now, now + 20 * 365 * 24 * 3600 * 1000.0)

        # Encode once to get the signed portion.
        encoding = certificate.wireEncode(wireFormat)
        signatureBytes = tpm.sign(encoding.toSignedBytes(), keyName,
          digestAlgorithm)
        signatureInfo.setSignature(signatureBytes)

        # Encode again to include the signature.
        certificate.wireEncode(wireFormat)

        return certificate

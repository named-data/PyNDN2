# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/certificate.hpp
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
This module defines the CertificateV2 class which represents a certificate
following the certificate format naming convention.

Overview of the NDN certificate format:

    CertificateV2 ::= DATA-TLV TLV-LENGTH
                        Name      (= /<NameSpace>/KEY/[KeyId]/[IssuerId]/[Version])
                        MetaInfo  (.ContentType = KEY)
                        Content   (= X509PublicKeyContent)
                        SignatureInfo (= CertificateV2SignatureInfo)
                        SignatureValue

    X509PublicKeyContent ::= CONTENT-TLV TLV-LENGTH
                               BYTE+ (= public key bits in PKCS#8 format)

    CertificateV2SignatureInfo ::= SIGNATURE-INFO-TYPE TLV-LENGTH
                                     SignatureType
                                     KeyLocator
                                     ValidityPeriod
                                     ... optional critical or non-critical extension blocks ...

An example of NDN certificate name:

    /edu/ucla/cs/yingdi/KEY/%03%CD...%F1/%9F%D3...%B7/%FD%d2...%8E
    \_________________/    \___________/ \___________/\___________/
   Certificate Namespace      Key Id       Issuer Id     Version
        (Identity)
    \__________________________________/
                  Key Name

Notes:

- `Key Id` is an opaque name component to identify the instance of the public
  key for the certificate namespace. The value of `Key ID` is controlled by
  the namespace owner. The library includes helpers for generating key IDs
  using an 8-byte random number, SHA-256 digest of the public key, timestamp,
  and the specified numerical identifiers.

- `Issuer Id` is sn opaque name component to identify the issuer of the
  certificate. The value is controlled by the issuer. The library includes
  helpers to set issuer the ID to an 8-byte random number, SHA-256 digest of
  the issuer's public key, and the specified numerical identifiers.

- `Key Name` is a logical name of the key used for management purposes. the
   Key Name includes the certificate namespace, keyword `KEY`, and `KeyId`
   components.

See https://github.com/named-data/ndn-cxx/blob/master/docs/specs/certificate-format.rst
"""

from pyndn.name import Name
from pyndn.data import Data
from pyndn.meta_info import ContentType
from pyndn.validity_period import ValidityPeriod
from pyndn.key_locator import KeyLocator, KeyLocatorType
from pyndn.sha256_with_ecdsa_signature import Sha256WithEcdsaSignature
from pyndn.sha256_with_rsa_signature import Sha256WithRsaSignature
from pyndn.encrypt.schedule import Schedule
from pyndn.util.common import Common

class CertificateV2(Data):
    """
    Create a CertificateV2 from the content in the Data packet (if not omitted).

    :param Data data: (optional) The data packet with the content to copy.
      If omitted, create a CertificateV2 with content type KEY and default
      or unspecified values.
    """
    def __init__(self, data = None):
        super(CertificateV2, self).__init__(data)
        if isinstance(data, Data):
            self._checkFormat()
        else:
            self.getMetaInfo().setType(ContentType.KEY)

    class Error(Exception):
        """
        Create a CertificateV2.Error to report an error for not complying
        with the certificate format.

        :param str message: The error message.
        """
        def __init__(self, message):
            super(CertificateV2.Error, self).__init__(message)

    def _checkFormat(self):
        if not CertificateV2.isValidName(self.getName()):
            raise CertificateV2.Error(
              "The Data Name does not follow the certificate naming convention")

        if self.getMetaInfo().getType() != ContentType.KEY:
            raise CertificateV2.Error("The Data ContentType is not KEY")

        if self.getMetaInfo().getFreshnessPeriod() < 0.0:
            raise CertificateV2.Error(
              "The Data FreshnessPeriod is not set")

        if self.getContent().size() == 0:
            raise CertificateV2.Error("The Data Content is empty")

    def getKeyName(self):
        """
        Get key name from the certificate name.

        :return: The key name as a new Name.
        :rtype: Name
        """
        return self.getName().getPrefix(CertificateV2.KEY_ID_OFFSET + 1)

    def getIdentity(self):
        """
        Get the identity name from the certificate name.

        :return: The identity name as a new Name.
        :rtype: Name
        """
        return self.getName().getPrefix(CertificateV2.KEY_COMPONENT_OFFSET)

    def getKeyId(self):
        """
        Get the key ID component from the certificate name.

        :return: The key ID name component.
        :rtype: Name.Component
        """
        return self.getName().get(CertificateV2.KEY_ID_OFFSET)

    def getIssuerId(self):
        """
        Get the issuer ID component from the certificate name.

        :return: The issuer ID component.
        :rtype: Name.Component
        """
        return self.getName().get(CertificateV2.ISSUER_ID_OFFSET)

    def getPublicKey(self):
        """
        Get the public key DER encoding.

        :return: The DER encoding Blob.
        :rtype: Blob
        :raises CertificateV2.Error: If the public key is not set.
        """
        if self.getContent().size() == 0:
            raise CertificateV2.Error(
              "The public key is not set (the Data content is empty)")

        return self.getContent()

    def getValidityPeriod(self):
        """
        Get the certificate validity period from the SignatureInfo.

        :return: The ValidityPeriod object.
        :rtype: ValidityPeriod
        :raises ValueError: If the SignatureInfo doesn't have a
          ValidityPeriod.
        """
        if not ValidityPeriod.canGetFromSignature(self.getSignature()):
            raise ValueError(
              "The SignatureInfo does not have a ValidityPeriod")

        return ValidityPeriod.getFromSignature(self.getSignature())

    def isValid(self, time = None):
        """
        Check if the time falls within the validity period.

        :param float time: (optional) The time to check as milliseconds since
          Jan 1, 1970 UTC. If omitted, use the current time.
        :return: True if the beginning of the validity period is less than or
          equal to time and time is less than or equal to the end of the
          validity period.
        :rtype: bool
        :raises ValueError: If the SignatureInfo doesn't have a
          ValidityPeriod.
        """
        return self.getValidityPeriod().isValid(time)

    def wireDecode(self, buf, wireFormat = None):
        """
        Override to call the base class wireDecode then check the certificate
        format.

        :param input: The array with the bytes to decode. If input is not a
          Blob, then copy the bytes to save the defaultWireEncoding (otherwise
          take another pointer to the same Blob).
        :type input: A Blob or an array type with int elements
        :param wireFormat: (optional) A WireFormat object used to decode this
           Data object. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        """
        Data.wireDecode(self, buf, wireFormat)
        self._checkFormat()

    def __str__(self):
        """
        Get a string representation of this certificate.

        :return: The string representation.
        :rtype: str
        """
        result = ""
        result += "Certificate name:\n"
        result += "  " + self.getName().toUri() + "\n"
        result += "Validity:\n"
        result += "  NotBefore: " + Schedule.toIsoString(
          self.getValidityPeriod().getNotBefore()) + "\n"
        result += "  NotAfter: " + Schedule.toIsoString(
          self.getValidityPeriod().getNotAfter()) + "\n"

        # TODO: Print the extension.

        result += "Public key bits:\n"
        try:
            result += Common.base64Encode(self.getPublicKey().toBytes(), True)
        except:
            # No public key.
            pass

        result += "Signature Information:\n"
        result += "  Signature Type: "
        if isinstance(self.getSignature(), Sha256WithEcdsaSignature):
            result += "SignatureSha256WithEcdsa\n"
        elif isinstance(self.getSignature(), Sha256WithRsaSignature):
            result += "SignatureSha256WithRsa\n"
        else:
            result += "<unknown>\n"

        if KeyLocator.canGetFromSignature(self.getSignature()):
            result += "  Key Locator: "
            keyLocator = KeyLocator.getFromSignature(self.getSignature())
            if keyLocator.getType() == KeyLocatorType.KEYNAME:
                if keyLocator.getKeyName().equals(self.getKeyName()):
                    result += "Self-Signed "

                result += "Name=" + keyLocator.getKeyName().toUri() + "\n"
            else:
                result += "<no KeyLocator key name>\n"

        return result

    @staticmethod
    def isValidName(certificateName):
        """
        Check if certificateName follows the naming convention for a certificate.

        :param Name certificateName: The name of the certificate.
        :return: True if certificateName follows the naming convention.
        :rtype: bool
        """
        # /<NameSpace>/KEY/[KeyId]/[IssuerId]/[Version]
        return (certificateName.size() >= CertificateV2.MIN_CERT_NAME_LENGTH and
                certificateName.get(CertificateV2.KEY_COMPONENT_OFFSET).equals
                  (CertificateV2.KEY_COMPONENT))

    @staticmethod
    def extractIdentityFromCertName(certificateName):
        """
        Extract the identity namespace from certificateName.

        :param Name certificateName: The name of the certificate.
        :return: The identity namespace as a new Name.
        :rtype: Name
        """
        if not CertificateV2.isValidName(certificateName):
            raise ValueError(
              "Certificate name `" + certificateName.toUri() +
              "` does not follow the naming conventions")

        return certificateName.getPrefix(CertificateV2.KEY_COMPONENT_OFFSET)

    @staticmethod
    def extractKeyNameFromCertName(certificateName):
        """
        Extract key name from certificateName.

        :param Name certificateName: The name of the certificate.
        :return: The key name as a new Name.
        :rtype: Name
        """
        if not CertificateV2.isValidName(certificateName):
            raise ValueError(
              "Certificate name `" + certificateName.toUri() +
              "` does not follow the naming conventions")

        # Trim everything after the key ID.
        return certificateName.getPrefix(CertificateV2.KEY_ID_OFFSET + 1)

    VERSION_OFFSET = -1
    ISSUER_ID_OFFSET = -2
    KEY_ID_OFFSET = -3
    KEY_COMPONENT_OFFSET = -4
    MIN_CERT_NAME_LENGTH = 4
    MIN_KEY_NAME_LENGTH = 2
    KEY_COMPONENT = Name.Component("KEY")

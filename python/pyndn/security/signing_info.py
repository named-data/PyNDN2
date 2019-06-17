# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/signing-info.cpp
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
This module defines the SigningInfo class which holds the signing parameters
passed to the KeyChain. A SigningInfo is invalid if the specified
identity/key/certificate does not exist, or the PibIdentity or PibKey instance
is not valid.
"""

from pyndn.name import Name
from pyndn.security.security_types import DigestAlgorithm
from pyndn.validity_period import ValidityPeriod
from pyndn.security.pib.pib_identity import PibIdentity
from pyndn.security.pib.pib_key import PibKey

class SigningInfo(object):
    """
    The SigningInfo constructor has multiple forms:
    SigningInfo() - Create a default SigningInfo with
    SigningInfo.SignerType.NULL (which will cause  KeyChain.sign to use the
      default identity) and an empty Name.
    SigningInfo(signingInfo) - Create a SigningInfo as a copy of the given
      signingInfo (taking a pointer to the given signingInfo PibIdentity and
      PibKey without copying).
    SigningInfo(signerType, signerName) - Create a SigningInfo with the
    signerType and optional signer Name.
    Signinginfo(identity) - Create a SigningInfo of type
    SigningInfo.SignerType.ID according to the given PibIdentity, where the
    digest algorithm is set to DigestAlgorithm.SHA256.
    SigningInfo(key) - Create a SigningInfo of type SigningInfo.SignerType.KEY
    according to the given PibKey, where the digest algorithm is set to
    DigestAlgorithm.SHA256.
    SigningInfo(signingString) - Create a SigningInfo from its string
    representation, where the digest algorithm is set to DigestAlgorithm.SHA256.

    :param SigningInfo signingInfo: The SigningInfo to copy.
    :param signerType: The type of signer.
    :type signerType: An int from the SigningInfo.SignerType enum.
    :param Name signerName: The name of signer. The interpretation of the
      signerName differs based on the signerType. This copies the Name.
    :param PibIdentity identity: An existing PibIdentity which is not copied.
    :param PibKey key: An existing PibKey which is not copied.
    :param str signingString: The representative signing string for the signing
      method, as follows:
      Default signing: "" (the empty string).
      Signing with the default certificate of the default key for the identity
      with the specified name:
      `id:/my-identity`.
      Signing with the default certificate of the key with the specified name:
      `key:/my-identity/ksk-1`.
      Signing with the certificate with the specified name:
      `cert:/my-identity/KEY/ksk-1/ID-CERT/%FD%01`.
      Signing with sha256 digest: `id:/localhost/identity/digest-sha256` (the
      value returned by getDigestSha256Identity()).
    :raises ValueError: If the signingString format is invalid.
    """
    def __init__(self, arg1 = None, arg2 = None):
        self._validityPeriod = ValidityPeriod()
        if arg1 is None:
            self.reset(SigningInfo.SignerType.NULL)
            self._digestAlgorithm = DigestAlgorithm.SHA256
        elif isinstance(arg1, SigningInfo):
            # The copy constructor.
            signingInfo = arg1

            self._type = signingInfo._type
            self._name = Name(signingInfo._name)
            self._identity = signingInfo._identity
            self._key = signingInfo._key
            self._digestAlgorithm = signingInfo._digestAlgorithm
            self._validityPeriod = ValidityPeriod(signingInfo._validityPeriod)
        elif type(arg1) is int:
            signerType = arg1

            self.reset(signerType)
            if not (arg2 is None):
                self._name = Name(arg2)
            self._digestAlgorithm = DigestAlgorithm.SHA256
        elif isinstance(arg1, PibIdentity):
            self._digestAlgorithm = DigestAlgorithm.SHA256
            self.setPibIdentity(arg1)
        elif isinstance(arg1, PibKey):
            self._digestAlgorithm = DigestAlgorithm.SHA256
            self.setPibKey(arg1)
        elif type(arg1) is str:
            signingString = arg1

            self.reset(SigningInfo.SignerType.NULL)
            self._digestAlgorithm = DigestAlgorithm.SHA256

            if signingString == "":
                return

            try:
                iColon = signingString.index(':')
            except:
                raise ValueError(
                  "Invalid signing string cannot represent SigningInfo")

            scheme = signingString[0 : iColon]
            nameArg = signingString[iColon + 1:]

            if scheme == "id":
                if nameArg == SigningInfo.getDigestSha256Identity().toUri():
                    self.setSha256Signing()
                else:
                    self.setSigningIdentity(Name(nameArg))
            elif scheme == "key":
                self.setSigningKeyName(Name(nameArg))
            elif scheme == "cert":
                self.setSigningCertificateName(Name(nameArg))
            else:
                raise ValueError("Invalid signing string scheme")
        else:
            raise ValueError("SigningInfo: Unrecognized type")

    class SignerType(object):
        # No signer is specified. Use default settings or follow the trust schema.
        NULL = 0
        # The signer is an identity. Use its default key and default certificate.
        ID = 1
        # The signer is a key. Use its default certificate.
        KEY = 2
        # The signer is a certificate. Use it directly.
        CERT = 3
        # Use a SHA-256 digest. No signer needs to be specified.
        SHA256 = 4

    def setSigningIdentity(self, identityName):
        """
        Set this to type SignerType.ID and an identity with name identityName.
        This does not change the digest algorithm.

        :param Name identityName: The name of the identity. This copies the Name.
        :return: This SigningInfo.
        :rtype: SigningInfo
        """
        self.reset(SigningInfo.SignerType.ID)
        self._name = Name(identityName)
        return self

    def setSigningKeyName(self, keyName):
        """
        Set this to type SignerType.KEY and a key with name keyName. This does
        not change the digest algorithm.

        :param Name keyName: The name of the key. This copies the Name.
        :return: This SigningInfo.
        :rtype: SigningInfo
        """
        self.reset(SigningInfo.SignerType.KEY)
        self._name = Name(keyName)
        return self

    def setSigningCertificateName(self, certificateName):
        """
        Set this to type SignerType.CERT and a certificate with name
        certificateName. This does not change the digest algorithm.

        :param Name certificateName: The name of the certificate. This copies
          the Name.
        :return: This SigningInfo.
        :rtype: SigningInfo
        """
        self.reset(SigningInfo.SignerType.CERT)
        self._name = Name(certificateName)
        return self

    def setSha256Signing(self):
        """
        Set this to type SignerType.SHA256, and set the digest algorithm to
        DigestAlgorithm.SHA256.

        :return: This SigningInfo.
        :rtype: SigningInfo
        """
        self.reset(SigningInfo.SignerType.SHA256)
        self._digestAlgorithm = DigestAlgorithm.SHA256
        return self

    def setPibIdentity(self, identity):
        """
        Set this to type SignerType.ID according to the given PibIdentity. This
        does not change the digest algorithm.

        :param PibIdentity identity: An existing PibIdentity which is not
          copied, or None. If this is None then use the default identity,
          otherwise use identity.getName().
        :return: This SigningInfo.
        :rtype: SigningInfo
        """
        self.reset(SigningInfo.SignerType.ID)
        if identity != None:
            self._name = identity.getName()
        self._identity = identity
        return self

    def setPibKey(self, key):
        """
        Set this to type SignerType.KEY according to the given PibKey. This does
        not change the digest algorithm.

        :param PibKey key: An existing PibKey which is not copied, or None. If
          this is None then use the default key for the identity, otherwise use
          key.getName().
        :return: This SigningInfo.
        :rtype: SigningInfo
        """
        self.reset(SigningInfo.SignerType.KEY)
        if key != None:
            self._name = key.getName()
        self._key = key
        return self

    def getSignerType(self):
        """
        Get the type of the signer.

        :return:The type of the signer
        :rtype: int from the SigningInfo.SignerType enum
        """
        return self._type

    def getSignerName(self):
        """
        Get the name of signer.

        :return: The name of signer. The interpretation differs based on the
          signerType.
        :rtype: Name
        """
        return self._name

    def getPibIdentity(self):
        """
        Get the PibIdentity of the signer.

        :return: The PibIdentity handler of the signer, or None if
          getSignerName() should be used to find the identity.
        :rtype: PibIdentity
        :raises ValueError: If the signer type is not SignerType.ID.
        """
        if self._type != SigningInfo.SignerType.ID:
            raise ValueError(
              "getPibIdentity: The signer type is not SignerType.ID")
        return self._identity

    def getPibKey(self):
        """
        Get the PibKey of the signer.

        :return: The PibKey handler of the signer, or None if getSignerName()
          should be used to find the key.
        :rtype: PibKey
        :raise ValueError: If the signer type is not SignerType.KEY.
        """
        if self._type != SigningInfo.SignerType.KEY:
            raise ValueError(
              "getPibKey: The signer type is not SignerType.KEY")
        return self._key

    def setDigestAlgorithm(self, digestAlgorithm):
        """
        Set the digest algorithm for public key operations.

        :param digestAlgorithm: The digest algorithm.
        :type digestAlgorithm: int from the DigestAlgorithm enum
        :return: This SigningInfo.
        :rtype: SigningInfo
        """
        self._digestAlgorithm = digestAlgorithm
        return self

    def getDigestAlgorithm(self):
        """
        Get the digest algorithm for public key operations.

        :return: The digest algorithm.
        :rtype: int from the DigestAlgorithm enum
        """
        return self._digestAlgorithm

    def setValidityPeriod(self, validityPeriod):
        """
        Set the validity period for the signature info.
        Note that the equivalent ndn-cxx method uses a semi-prepared
        SignatureInfo, but this method only uses the ValidityPeriod from the
        SignatureInfo.

        :param ValidityPeriod validityPeriod: The validity period, which is
          copied.
        :return: This SigningInfo.
        :rtype: SigningInfo
        """
        self._validityPeriod = ValidityPeriod(validityPeriod)
        return self

    def getValidityPeriod(self):
        """
        Get the validity period for the signature info.
        Note that the equivalent ndn-cxx method uses a semi-prepared
        SignatureInfo, but this method only uses the ValidityPeriod from the
        SignatureInfo.

        :return: The validity period.
        :rtype: ValidityPeriod
        """
        return self._validityPeriod

    def __str__(self):
        """
        Get the string representation of this SigningInfo.

        :return: The string representation.
        :rtype: str
        """
        if self._type == SigningInfo.SignerType.NULL:
            return ""
        elif self._type == SigningInfo.SignerType.ID:
            return "id:" + self.getSignerName().toUri()
        elif self._type == SigningInfo.SignerType.KEY:
            return "key:" + self.getSignerName().toUri()
        elif self._type == SigningInfo.SignerType.CERT:
            return "cert:" + self.getSignerName().toUri()
        elif self._type == SigningInfo.SignerType.SHA256:
            return "id:" + SigningInfo.getDigestSha256Identity().toUri()
        else:
            # We don't expect this to happen.
            raise ValueError("Unknown signer type")

    @staticmethod
    def getDigestSha256Identity():
        """
        Get the localhost identity which indicates that the signature is
        generated using SHA-256.

        :return: A new Name of the SHA-256 identity.
        :rtype: Name
        """
        return Name("/localhost/identity/digest-sha256")

    def reset(self, signerType):
        """
        Check and set the signerType, and set others to default values. This
        does NOT reset the digest algorithm.

        :param signerType: The type of signer.
        :type signerType: int from the SigningInfo.SignerType enum
        """
        if (not (signerType == SigningInfo.SignerType.NULL or
                 signerType == SigningInfo.SignerType.ID or
                 signerType == SigningInfo.SignerType.KEY or
                 signerType == SigningInfo.SignerType.CERT or
                 signerType == SigningInfo.SignerType.SHA256)):
            raise ValueError("SigningInfo: The signerType is not valid")

        self._type = signerType
        self._name = Name()
        self._identity = None
        self._key = None
        self._validityPeriod = ValidityPeriod()



# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2019 Regents of the University of California.
# Author: Adeola Bannis <thecodemaiden@gmail.com>
# From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
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

import os
import re
import logging
from base64 import b64decode

from pyndn.name import Name
from pyndn.data import Data
from pyndn.interest import Interest
from pyndn.key_locator import KeyLocator
from pyndn.security.policy.policy_manager import PolicyManager
from pyndn.security.policy.certificate_cache import CertificateCache
from pyndn.security.v2.certificate_v2 import CertificateV2
from pyndn.security.v2.certificate_cache_v2 import CertificateCacheV2
from pyndn.security.policy.validation_request import ValidationRequest
from pyndn.security.certificate.identity_certificate import IdentityCertificate
from pyndn.security.security_exception import SecurityException
from pyndn.util.blob import Blob
from pyndn.util.common import Common
from pyndn.encoding.wire_format import WireFormat
from pyndn.key_locator import KeyLocatorType

from pyndn.util.boost_info_parser import BoostInfoParser
from pyndn.util.regex.ndn_regex_top_matcher import NdnRegexTopMatcher

"""
This module manages trust according to a configuration file in the
Validator Configuration File Format
(http://redmine.named-data.net/projects/ndn-cxx/wiki/CommandValidatorConf)

Once a rule is matched, the ConfigPolicyManager looks in the
certificate cache for the certificate matching the name in the KeyLocator
and uses its public key to verify the data packet or signed interest. If the
certificate can't be found, it is downloaded, verified and installed. A chain
of certificates will be followed to a maximum depth.
If the new certificate is accepted, it is used to complete the verification.

The KeyLocators of data packets and signed interests MUST contain a name for
verification to succeed.
"""

class ConfigPolicyManager(PolicyManager):
    """
    Create a new ConfigPolicyManager which will act on the rules specified
    in the configuration and download unknown certificates when necessary.
    If certificateCache is a CertificateCache (or omitted) this creates a
    security v1 PolicyManager to verify certificates in format v1. To verify
    certificates in format v2, use a CertificateCacheV2 for the certificateCache.

    :param str configFileName: (optional) If not None or empty, the path to the
      configuration file containing verification rules. Otherwise, you should
      separately call load().
    :param certificateCache: (optional) A CertificateCache to hold known
      certificates. If certificateCache is a CertificateCache (or omitted
      or None) this creates a security v1 PolicyManager to verify certificates
      in format v1. If this is a CertificateCacheV2, verify certificates in
      format v2. If omitted or None, create an internal v1 CertificateCache.
    :type certificateCache: CertificateCache or CertificateCacheV2
    :param int searchDepth: (optional) The maximum number of links to follow
      when verifying a certificate chain.
    :param int graceInterval: (optional) The window of time difference (in
        milliseconds) allowed between the timestamp of the first interest signed
        with a new public key and the validation time. If omitted, use a default
        value.
    :param int keyTimestampTtl: (optional) How long a public key's last-used
        timestamp is kept in the store (milliseconds). If omitted, use a default
        value.
    :param int maxTrackedKeys: (optional) The maximum number of public key use
        timestamps to track.
    """
    def __init__(self, configFileName = None, certificateCache = None,
            searchDepth=5, graceInterval=3000, keyTimestampTtl=3600000,
            maxTrackedKeys=1000):
        super(ConfigPolicyManager, self).__init__()

        if certificateCache is None:
            certificateCache = CertificateCache()

        # _certificateCacheV2 will be replaced below, but set it here to make pylint happy.
        self._certificateCacheV2 = CertificateCacheV2()
        if isinstance(certificateCache, CertificateCache):
            self._isSecurityV1 = True
            self._certificateCache = certificateCache
            self._certificateCacheV2 = None
        else:
            self._isSecurityV1 = False
            self._certificateCache = None
            self._certificateCacheV2 = certificateCache

        self._maxDepth = searchDepth
        self._keyGraceInterval = graceInterval
        self._keyTimestampTtl = keyTimestampTtl
        self._maxTrackedKeys = maxTrackedKeys

        self.reset()

        if configFileName != None and configFileName != "":
            self.load(configFileName)

    def reset(self):
        """
        Reset the certificate cache and other fields to the constructor state.
        """
        if self._isSecurityV1:
            self._certificateCache.reset()
        else:
            self._certificateCacheV2.clear()

        # stores the fixed-signer certificate name associated with validation rules
        # so we don't keep loading from files
        self._fixedCertificateCache = {}

        # stores the timestamps for each public key used in command interests to avoid
        # replay attacks
        # key is public key name, value is last timestamp
        self._keyTimestamps = {}

        self.requiresVerification = True

        self.config = BoostInfoParser()
        self._refreshManager = TrustAnchorRefreshManager(self._isSecurityV1)

    def load(self, configFileNameOrInput, inputName = None):
        """
        Call reset() and load the configuration rules from the file name or the
        input string. There are two forms:
        load(configFileName) reads configFileName from the file system.
        load(input, inputName) reads from the input, in which case inputName is
        used only for log messages, etc.

        :param str configFileName: The path to the file containing configuration
          rules.
        :param str input: The contents of the configuration rules, with lines
          separated by NL or CR/NL.
        :param str inputName: Use with input for log messages, etc.
        """
        self.reset()
        self.config.read(configFileNameOrInput, inputName)
        self._loadTrustAnchorCertificates()

    def requireVerify(self, dataOrInterest):
        """
        If the configuration file contains the trust anchor 'any',
        nothing is verified.
        """
        return self.requiresVerification

    def checkSigningPolicy(self, dataName, certificateName):
        """
        Override to always indicate that the signing certificate name and data
        name satisfy the signing policy.

        :param Name dataName: The name of data to be signed.
        :param Name certificateName: The name of signing certificate.
        :return: True to indicate that the signing certificate can be used to
          sign the data.
        :rtype: boolean
        """
        return True

    def skipVerifyAndTrust(self, dataOrInterest):
        """
        If the configuration file contains the trust anchor 'any',
        nothing is verified.
        """
        return not self.requiresVerification

    def _loadTrustAnchorCertificates(self):
        """
        The configuration file allows 'trust anchor' certificates to be preloaded.
        The certificates may also be loaded from a directory, and if the 'refresh'
        option is set to an interval, the certificates are reloaded at the
        specified interval
        """

        try:
            anchors = self.config["validator/trust-anchor"]
        except KeyError:
            return

        for anchor in anchors:
            typeName = anchor["type"][0].getValue()
            if typeName == 'file':
                certID = anchor["file-name"][0].getValue()
                isPath = True
            elif typeName == 'base64':
                certID = anchor["base64-string"][0].getValue()
                isPath = False
            elif typeName == "dir":
                dirName = anchor["dir"][0].getValue()
                try:
                    refreshPeriodStr = anchor["refresh"][0].getValue()
                except KeyError:
                    refreshPeriod = 0
                else:
                    refreshMatch = re.match('(\\d+)([hms])', refreshPeriodStr)
                    if not refreshMatch:
                        refreshPeriod = 0
                    else:
                        refreshPeriod = int(refreshMatch.group(1))
                        if refreshMatch.group(2) != 's':
                            refreshPeriod *= 60
                            if refreshMatch.group(2) != 'm':
                                refreshPeriod *= 60

                # Convert refreshPeriod from seconds to milliseconds.
                self._refreshManager.addDirectory(dirName, refreshPeriod * 1000)
                continue
            elif typeName == "any":
                # this disables all security!
                self.requiresVerification = False
                break

            if self._isSecurityV1:
                self._lookupCertificate(certID, isPath)
            else:
                self._lookupCertificateV2(certID, isPath)

    def _checkSignatureMatch(self, signatureName, objectName, rule, failureReason):
        """
        Once a rule is found to match data or a signed interest, the name in the
        KeyLocator must satisfy the condition in the 'checker' section of the rule,
        else the data or interest is rejected.

        :param Name signatureName: The certificate name from the KeyLocator .
        :param Name objectName: The name of the data packet or interest. In the
          case of signed interests, this excludes the timestamp, nonce and signature
          components.
        :param BoostInfoTree rule: The rule from the configuration file that matches
          the data or interest.
        :param Array<str> failureReason: If verification fails, set
          failureReason[0] to the failure reason string.
        :return: True if matches.
        :rtype: bool

        """
        checker = rule['checker'][0]
        checkerType = checker['type'][0].getValue()
        if checkerType == 'fixed-signer':
            signerInfo = checker['signer'][0]
            signerType = signerInfo['type'][0].getValue()
            if signerType == 'file':
                if self._isSecurityV1:
                    cert = self._lookupCertificate(
                      signerInfo['file-name'][0].getValue(), True)
                    if cert is None:
                        failureReason[0] = (
                          "Can't find fixed-signer certificate file: " +
                          signerInfo['file-name'][0].getValue())
                        return False
                else:
                    cert = self._lookupCertificateV2(
                      signerInfo['file-name'][0].getValue(), True)
                    if cert is None:
                        failureReason[0] = (
                          "Can't find fixed-signer certificate file: " +
                          signerInfo['file-name'][0].getValue())
                        return False
            elif signerType == 'base64':
                if self._isSecurityV1:
                    cert = self._lookupCertificate(
                      signerInfo['base64-string'][0].getValue(), False)
                    if cert is None:
                        failureReason[0] = (
                          "Can't find fixed-signer certificate base64: " +
                          signerInfo['base64-string'][0].getValue())
                        return False
                else:
                    cert = self._lookupCertificateV2(
                      signerInfo['base64-string'][0].getValue(), False)
                    if cert is None:
                        failureReason[0] = (
                          "Can't find fixed-signer certificate base64: " +
                          signerInfo['base64-string'][0].getValue())
                        return False
            else:
                failureReason[0] = ("Unrecognized fixed-signer signerType: " +
                  signerType)
                return False

            if cert.getName().equals(signatureName):
                return True
            else:
                failureReason[0] = ("fixed-signer cert name \"" +
                  cert.getName().toUri() + "\" does not equal signatureName \"" +
                  signatureName.toUri() + "\"")
                return False
        elif checkerType == 'hierarchical':
            # this just means the data/interest name has the signing identity as a prefix
            # that means everything before 'ksk-?' in the key name
            identityRegex = '^([^<KEY>]*)<KEY>(<>*)<ksk-.+><ID-CERT>'
            identityMatch = NdnRegexTopMatcher(identityRegex)
            if identityMatch.match(signatureName):
                identityPrefix = identityMatch.expand("\\1").append(
                  identityMatch.expand("\\2"))
                if self._matchesRelation(objectName, identityPrefix, 'is-prefix-of'):
                    return True
                else:
                    failureReason[0] = ("The hierarchical objectName \"" +
                      objectName.toUri() + "\" is not a prefix of \"" +
                      identityPrefix.toUri() + "\"")
                    return False

            if not self._isSecurityV1:
                # Check for a security v2 key name.
                identityRegex2 = "^(<>*)<KEY><>$"
                identityMatch2 = NdnRegexTopMatcher(identityRegex2)
                if identityMatch2.match(signatureName):
                    identityPrefix = identityMatch2.expand("\\1")
                    if self._matchesRelation(objectName, identityPrefix, 'is-prefix-of'):
                        return True
                    else:
                        failureReason[0] = ("The hierarchical objectName \"" +
                          objectName.toUri() + "\" is not a prefix of \"" +
                          identityPrefix.toUri() + "\"")
                        return False

            failureReason[0] = ("The hierarchical identityRegex \"" +
              identityRegex + "\" does not match signatureName \"" +
              signatureName.toUri() + "\"")
            return False
        elif checkerType == 'customized':
            keyLocatorInfo = checker['key-locator'][0]
            # not checking type - only name is supported

            # is this a simple relation?
            relationType = keyLocatorInfo.getFirstValue("relation")
            if relationType != None:
                matchName = Name(keyLocatorInfo['name'][0].getValue())
                if self._matchesRelation(signatureName, matchName, relationType):
                    return True
                else:
                    failureReason[0] = ("The custom signatureName \"" +
                      signatureName.toUri() + "\" does not match matchName \"" +
                      matchName.toUri() + "\" using relation " + relationType)
                    return False

            # Is this a simple regex?
            simpleKeyRegex = keyLocatorInfo.getFirstValue("regex")
            if simpleKeyRegex != None:
                if NdnRegexTopMatcher(simpleKeyRegex).match(signatureName):
                    return True
                else:
                    failureReason[0] = ("The custom signatureName \"" +
                      signatureName.toUri() +
                      "\" does not regex match simpleKeyRegex \"" +
                      simpleKeyRegex + "\"")
                    return False

            # is this a hyper-relation?
            hyperRelationList = keyLocatorInfo["hyper-relation"]
            if len(hyperRelationList) >= 1:
                hyperRelation = hyperRelationList[0]

                keyRegex = hyperRelation.getFirstValue('k-regex')
                keyExpansion = hyperRelation.getFirstValue('k-expand')
                nameRegex = hyperRelation.getFirstValue('p-regex')
                nameExpansion = hyperRelation.getFirstValue('p-expand')
                relationType = hyperRelation.getFirstValue('h-relation')
                if (keyRegex != None and keyExpansion != None and
                      nameRegex != None and nameExpansion != None and
                      relationType != None):
                    keyMatch = NdnRegexTopMatcher(keyRegex)
                    if not keyMatch.match(signatureName):
                        failureReason[0] = (
                          "The custom hyper-relation signatureName \"" +
                          signatureName.toUri() +
                          "\" does not match the keyRegex \"" + keyRegex + "\"")
                        return False
                    keyMatchPrefix = keyMatch.expand(keyExpansion)

                    nameMatch = NdnRegexTopMatcher(nameRegex)
                    if not nameMatch.match(objectName):
                        failureReason[0] = (
                          "The custom hyper-relation objectName \"" +
                          objectName.toUri() +
                          "\" does not match the nameRegex \"" + nameRegex + "\"")
                        return False
                    nameMatchExpansion = nameMatch.expand(nameExpansion)

                    if self._matchesRelation(
                          nameMatchExpansion, keyMatchPrefix, relationType):
                        return True
                    else:
                        failureReason[0] = (
                          "The custom hyper-relation nameMatch \"" +
                          nameMatchExpansion.toUri() +
                          "\" does not match the keyMatchPrefix \"" +
                          keyMatchPrefix.toUri() + "\" using relation " +
                          relationType)
                        return False

        failureReason[0] = "Unrecognized checkerType: " + checkerType
        return False

    def _lookupCertificate(self, certID, isPath):
        """
        This looks up certificates specified as base64-encoded data or file names.
        These are cached by filename or encoding to avoid repeated reading of files
        or decoding.

        :return: The certificate object, or None if not found.
        :rtype: IdentityCertificate
        """
        if not self._isSecurityV1:
            raise SecurityException(
              "lookupCertificate: For security v2, use lookupCertificateV2()")

        try:
            certUri = self._fixedCertificateCache[certID]
        except KeyError:
            if isPath:
                # load the certificate data (base64 encoded IdentityCertificate)
                cert = TrustAnchorRefreshManager.loadIdentityCertificateFromFile(
                        certID)
            else:
                certData = b64decode(certID)
                cert = IdentityCertificate()
                cert.wireDecode(Blob(certData, False))

            certUri = cert.getName()[:-1].toUri()
            self._fixedCertificateCache[certID] = certUri
            self._certificateCache.insertCertificate(cert)
        else:
            cert = self._certificateCache.getCertificate(Name(certUri))

        return cert

    def _lookupCertificateV2(self, certID, isPath):
        """
        This looks up certificates specified as base64-encoded data or file
        names. These are cached by filename or encoding to avoid repeated
        reading of files or decoding.

        :return: The CertificateV2, or None if not found.
        :rtype: CertificateV2
        """
        if self._isSecurityV1:
            raise SecurityException(
              "lookupCertificateV2: For security v1, use lookupCertificate()")

        try:
            certUri = self._fixedCertificateCache[certID]
        except KeyError:
            if isPath:
                # load the certificate data (base64 encoded IdentityCertificate)
                cert = TrustAnchorRefreshManager.loadCertificateV2FromFile(
                        certID)
            else:
                certData = b64decode(certID)
                cert = CertificateV2()
                cert.wireDecode(Blob(certData, False))

            certUri = cert.getName()[:-1].toUri()
            self._fixedCertificateCache[certID] = certUri
            self._certificateCacheV2.insert(cert)
        else:
            cert = self._certificateCacheV2.find(Name(certUri))

        return cert

    def _findMatchingRule(self, objName, matchType):
        """
        Search the configuration file for the first rule that matches the data
        or signed interest name. In the case of interests, the name to match
        should exclude the timestamp, nonce, and signature components.
        :param Name objName: The name to be matched.
        :param string matchType: The rule type to match, "data" or "interest".
        """
        rules = self.config["validator/rule"]
        for r in rules:
            if r['for'][0].getValue() == matchType:
                passed = True
                try:
                    filters = r['filter']
                except KeyError:
                    # no filters means we pass!
                    return r
                else:
                    for f in filters:
                        # don't check the type - it can only be name for now
                        # we need to see if this is a regex or a relation
                        regexPattern = f.getFirstValue("regex")
                        if regexPattern == None:
                            matchRelation =f.getFirstValue("relation")
                            matchUri = f.getFirstValue("name")
                            matchName = Name(matchUri)
                            passed = self._matchesRelation(objName, matchName, matchRelation)
                        else:
                            passed =  NdnRegexTopMatcher(regexPattern).match(objName)

                        if not passed:
                            break
                    if passed:
                        return r

        return None

    @staticmethod
    def _matchesRelation(name, matchName, matchRelation):
        """
        Determines if a name satisfies the relation to another name, which can
        be one of:
            'is-prefix-of' - passes if the name is equal to or has the other
               name as a prefix
            'is-strict-prefix-of' - passes if the name has the other name as a
               prefix, and is not equal
            'equal' - passes if the two names are equal
        """
        passed = False
        if matchRelation == 'is-strict-prefix-of':
            if matchName.size() == name.size():
                passed = False
            elif matchName.match(name):
                passed = True
        elif matchRelation == 'is-prefix-of':
            if matchName.match(name):
                passed = True
        elif matchRelation == 'equal':
            if matchName.equals(name):
                passed = True
        return passed

    @staticmethod
    def _extractSignature(dataOrInterest, wireFormat=None):
        """
        Extract the signature information from the interest name or from the
        data packet.
        :param dataOrInterest: The object whose signature is needed.
        :type dataOrInterest: Data or Interest
        :param WireFormat wireFormat: (optional) The wire format used to decode
          signature information from the interest name.
        """
        if isinstance(dataOrInterest, Data):
            return dataOrInterest.getSignature()
        elif isinstance(dataOrInterest, Interest):
            if wireFormat is None:
                # Don't use a default argument since getDefaultWireFormat can change.
                wireFormat = WireFormat.getDefaultWireFormat()
            try:
                signature = wireFormat.decodeSignatureInfoAndValue(
                   dataOrInterest.getName().get(-2).getValue().buf(),
                   dataOrInterest.getName().get(-1).getValue().buf(), False)
            except (IndexError, ValueError):
                return None
            return signature
        return None

    def _interestTimestampIsFresh(self, keyName, timestamp, failureReason):
        """
        Determine whether the timestamp from the interest is newer than the last use
        of this key, or within the grace interval on first use.

        :param Name keyName: The name of the public key used to sign the interest.
        :paramt int timestamp: The timestamp extracted from the interest name.
        :param Array<str> failureReason: If verification fails, set
          failureReason[0] to the failure reason string.
        """
        try:
            lastTimestamp = self._keyTimestamps[keyName.toUri()]
        except KeyError:
            now = Common.getNowMilliseconds()
            notBefore = now - self._keyGraceInterval
            notAfter = now + self._keyGraceInterval
            if not (timestamp > notBefore and timestamp < notAfter):
                return False
                failureReason[0] = (
                  "The command interest timestamp is not within the first use grace period of " +
                  str(self._keyGraceInterval) + " milliseconds.")
            else:
                return True
        else:
            if timestamp <= lastTimestamp:
                failureReason[0] = (
                  "The command interest timestamp is not newer than the previous timestamp")
                return False
            else:
                return True

    def _updateTimestampForKey(self, keyName, timestamp):
        """
        Trim the table size down if necessary, and insert/update the latest
        interest signing timestamp for the key.

        Any key which has not been used within the TTL period is purged. If the
        table is still too large, the oldest key is purged.

        :param Name keyName: The name of the public key used to sign the interest.
        :paramt int timestamp: The timestamp extracted from the interest name.

        """
        self._keyTimestamps[keyName.toUri()] = timestamp

        if len(self._keyTimestamps) >= self._maxTrackedKeys:
            now = Common.getNowMilliseconds()
            oldestTimestamp = now
            oldestKey = None
            trackedKeys = self._keyTimestamps.keys()
            for keyUri in trackedKeys:
                ts = self._keyTimestamps[keyUri]
                if now - ts > self._keyTimestampTtl:
                    del self._keyTimestamps[keyUri]
                elif ts < oldestTimestamp:
                    oldestTimestamp = ts
                    oldestKey = keyUri

            if len(self._keyTimestamps) > self._maxTrackedKeys:
                # have not removed enough
                del self._keyTimestamps[oldestKey]

    def checkVerificationPolicy(self, dataOrInterest, stepCount, onVerified,
                                onValidationFailed, wireFormat = None):
        """
        If there is a rule matching the data or interest, and the matching
        certificate is missing, download it. If there is no matching rule,
        verification fails. Otherwise, verify the signature using the public key
        in the IdentityStorage.

        :param dataOrInterest: The Data object or interest with the signature to
          check.
        :type dataOrInterest: Data or Interest
        :param int stepCount: The number of verification steps that have been
          done, used to track the verification progress.
        :param onVerified: If the signature is verified, this calls
          onVerified(dataOrInterest).
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onVerified: function object
        :param onValidationFailed: If the signature check fails, this calls
          onValidationFailed(dataOrInterest, reason).
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onValidationFailed: function object
        :return: None for no further step for looking up a certificate chain.
        :rtype: ValidationRequest
        """
        objectName = dataOrInterest.getName()
        matchType = "data"

        # For command interests, we need to ignore the last 4 components when
        #   matching the name.
        if isinstance(dataOrInterest, Interest):
            objectName = objectName.getPrefix(-4)
            matchType = "interest"

        signature = self._extractSignature(dataOrInterest, wireFormat)
        # no signature -> fail
        if signature is None:
            try:
                onValidationFailed(
                  dataOrInterest, "Cannot extract the signature from " +
                  dataOrInterest.getName().toUri())
            except:
                logging.exception("Error in onValidationFailed")
            return None

        failureReason = ["unknown"]
        certificateInterest = self._getCertificateInterest(
          stepCount, matchType, objectName, signature, failureReason)
        if certificateInterest is None:
            try:
                onValidationFailed(dataOrInterest, failureReason[0])
            except:
                logging.exception("Error in onValidationFailed")
            return None

        if certificateInterest.getName().size() > 0:
            def onCertificateDownloadComplete(data):
                if self._isSecurityV1:
                    try:
                        certificate = IdentityCertificate(data)
                    except:
                        try:
                            onValidationFailed(
                              dataOrInterest, "Cannot decode certificate " +
                              data.getName().toUri())
                        except:
                            logging.exception("Error in onValidationFailed")
                        return None
                    self._certificateCache.insertCertificate(certificate)
                else:
                    try:
                        certificate = CertificateV2(data)
                    except:
                        try:
                            onValidationFailed(
                              dataOrInterest, "Cannot decode certificate " +
                              data.getName().toUri())
                        except:
                            logging.exception("Error in onValidationFailed")
                        return None
                    self._certificateCacheV2.insert(certificate)

                self.checkVerificationPolicy(dataOrInterest, stepCount+1,
                        onVerified, onValidationFailed)

            return ValidationRequest(certificateInterest,
                    onCertificateDownloadComplete, onValidationFailed,
                    2, stepCount+1)

        # For interests, we must check that the timestamp is fresh enough.
        # This is done after (possibly) downloading the certificate to avoid
        # filling the cache with bad keys.
        if isinstance(dataOrInterest, Interest):
            signatureName = KeyLocator.getFromSignature(signature).getKeyName()
            if self._isSecurityV1:
                keyName = IdentityCertificate.certificateNameToPublicKeyName(
                  signatureName)
            else:
                keyName = signatureName
            timestamp = dataOrInterest.getName().get(-4).toNumber()

            if not self._interestTimestampIsFresh(
                  keyName, timestamp, failureReason):
                try:
                    onValidationFailed(dataOrInterest, failureReason[0])
                except:
                    logging.exception("Error in onValidationFailed")
                return None

        # Certificate is known. Verify the signature.
        # wireEncode returns the cached encoding if available.
        if self._verify(signature, dataOrInterest.wireEncode(), failureReason):
            try:
                onVerified(dataOrInterest)
            except:
                logging.exception("Error in onVerified")
            if isinstance(dataOrInterest, Interest):
                self._updateTimestampForKey(keyName, timestamp)
        else:
            try:
                onValidationFailed(dataOrInterest, failureReason[0])
            except:
                logging.exception("Error in onValidationFailed")

    def _getCertificateInterest(self, stepCount, matchType, objectName,
           signature, failureReason):
        """
        This is a helper for checkVerificationPolicy to verify the rule and
        return a certificate interest to fetch the next certificate in the
        hierarchy if needed.

        :param int stepCount: The number of verification steps that have been
          done, used to track the verification progress.
        :param str matchType: Either "data" or "interest".
        :param Name objectName: The name of the data or interest packet.
        :param Signature signature: The Signature object for the data or
          interest packet.
        :param Array<str> failureReason: If can't determine the interest, set
          failureReason[0] to the failure reason.
        :return: None if can't determine the interest, otherwise the interest
          for the ValidationRequest to fetch the next certificate. However, if
          the interest has an empty name, the validation succeeded and no need
          to fetch a certificate.
        :rtype: Interest
        """
        if stepCount > self._maxDepth:
            failureReason[0] = ("The verification stepCount " + stepCount +
                  " exceeded the maxDepth " + self._maxDepth)
            return None

        # First see if we can find a rule to match this packet.
        try:
            matchedRule = self._findMatchingRule(objectName, matchType)
        except:
            matchedRule = None

        # No matching rule -> fail.
        if matchedRule is None:
            failureReason[0] = "No matching rule found for " + objectName.toUri()
            return None

        if not KeyLocator.canGetFromSignature(signature):
            # We only support signature types with key locators.
            failureReason[0] = "The signature type does not support a KeyLocator"
            return None

        keyLocator = KeyLocator.getFromSignature(signature)

        signatureName = keyLocator.getKeyName()
        # No key name in KeyLocator -> fail.
        if signatureName.size() == 0:
            failureReason[0] = "The signature KeyLocator doesn't have a key name"
            return None

        signatureMatches = self._checkSignatureMatch(
          signatureName, objectName, matchedRule, failureReason)
        if not signatureMatches:
            return None

        # Before we look up keys, refresh any certificate directories.
        self._refreshManager.refreshAnchors()

        # If we don't actually have the certificate yet, return a
        #   certificateInterest for it.
        if self._isSecurityV1:
            foundCert = self._refreshManager.getCertificate(signatureName)
            if foundCert is None:
                foundCert = self._certificateCache.getCertificate(signatureName)
            if foundCert is None:
                return Interest(signatureName)
        else:
            foundCert = self._refreshManager.getCertificateV2(signatureName)
            if foundCert is None:
                foundCert = self._certificateCacheV2.find(signatureName)
            if foundCert is None:
                return Interest(signatureName)

        return Interest()

    def _verify(self, signatureInfo, signedBlob, failureReason):
        """
        Check the type of signatureInfo to get the KeyLocator. Look in the
        IdentityStorage for the public key with the name in the KeyLocator and
        use it to verify the signedBlob. If the public key can't be found,
        return false. (This is a generalized method which can verify both a Data
        packet and an interest.)

        :param Signature signatureInfo: An object of a subclass of Signature,
          e.g. Sha256WithRsaSignature.
        :param SignedBlob signedBlob: the SignedBlob with the signed portion to
          verify.
        :param Array<str> failureReason: If verification fails, set
          failureReason[0] to the failure reason string.
        :return: True if the signature verifies, False if not.
        :rtype: boolean
        """
        # We have already checked once that there is a key locator.
        keyLocator = KeyLocator.getFromSignature(signatureInfo)

        if (keyLocator.getType() == KeyLocatorType.KEYNAME):
            # Assume the key name is a certificate name.
            signatureName = keyLocator.getKeyName()

            if self._isSecurityV1:
                certificate = self._refreshManager.getCertificate(signatureName)
                if certificate is None:
                    certificate = self._certificateCache.getCertificate(
                      signatureName)
                if certificate is None:
                    failureReason[0] = ("Cannot find a certificate with name " +
                      signatureName.toUri())
                    return False

                publicKeyDer = certificate.getPublicKeyInfo().getKeyDer()
                if publicKeyDer.isNull():
                    # We don't expect this to happen.
                    failureReason[0] = (
                      "There is no public key in the certificate with name " +
                      certificate.getName().toUri())
                    return False
            else:
                certificate = self._refreshManager.getCertificateV2(signatureName)
                if certificate is None:
                    certificate = self._certificateCacheV2.find(
                      signatureName)
                if certificate is None:
                    failureReason[0] = ("Cannot find a certificate with name " +
                      signatureName.toUri())
                    return False

                try:
                    publicKeyDer = certificate.getPublicKey()
                except:
                    # We don't expect this to happen.
                    failureReason[0] = (
                      "There is no public key in the certificate with name " +
                      certificate.getName().toUri())
                    return False

            if self.verifySignature(signatureInfo, signedBlob, publicKeyDer):
                return True
            else:
                failureReason[0] = (
                  "The signature did not verify with the given public key")
                return False
        else:
            failureReason[0] = "The KeyLocator does not have a key name"
            return False

class TrustAnchorRefreshManager(object):
    """
    Manages the trust-anchor certificates, including refresh.
    """
    def __init__(self, isSecurityV1):
        self._isSecurityV1 = isSecurityV1

        self._certificateCache = CertificateCache()
        self._certificateCacheV2 = CertificateCacheV2()
        # maps the directory name to certificate names so they can be
        # deleted when necessary
        self._refreshDirectories = {}

    @staticmethod
    def loadIdentityCertificateFromFile(filename):
        """
        :param str filename:
        :rtype: IdentityCertificate
        """
        with open(filename, 'r') as certFile:
            encodedData = certFile.read()
            decodedData = b64decode(encodedData)
            cert = IdentityCertificate()
            cert.wireDecode(Blob(decodedData, False))
            return cert

    @staticmethod
    def loadCertificateV2FromFile(filename):
        """
        :param str filename:
        :rtype: CertificateV2
        """
        with open(filename, 'r') as certFile:
            encodedData = certFile.read()
            decodedData = b64decode(encodedData)
            cert = CertificateV2()
            cert.wireDecode(Blob(decodedData, False))
            return cert

    def getCertificate(self, certificateName):
        """
        :param Name certificateName:
        :rtype: IdentityCertificate
        """
        if not self._isSecurityV1:
            raise SecurityException(
              "getCertificate: For security v2, use getCertificateV2()")

        # assumes timestamp is already removed
        return self._certificateCache.getCertificate(certificateName)

    def getCertificateV2(self, certificateName):
        """
        :param Name certificateName:
        :rtype: CertificateV2
        """
        if self._isSecurityV1:
            raise SecurityException(
              "getCertificateV2: For security v1, use getCertificate()")

        # assumes timestamp is already removed
        return self._certificateCacheV2.find(certificateName)

    # refershPeriod in milliseconds.
    def addDirectory(self, directoryName, refreshPeriod):
        allFiles = [f for f in os.listdir(directoryName)
                if os.path.isfile(os.path.join(directoryName, f))]
        certificateNames = []
        for f in allFiles:
            if self._isSecurityV1:
                try:
                    fullPath = os.path.join(directoryName, f)
                    cert = self.loadIdentityCertificateFromFile(fullPath)
                except Exception:
                    pass # allow files that are not certificates
                else:
                    # Cut off the timestamp so it matches KeyLocator Name format.
                    certUri = cert.getName()[:-1].toUri()
                    self._certificateCache.insertCertificate(cert)
                    certificateNames.append(certUri)
            else:
                try:
                    fullPath = os.path.join(directoryName, f)
                    cert = self.loadCertificateV2FromFile(fullPath)
                except Exception:
                    pass # allow files that are not certificates
                else:
                    # Get the key name since this is in the KeyLocator.
                    certUri = CertificateV2.extractKeyNameFromCertName(
                      cert.getName()).toUri()
                    self._certificateCacheV2.insert(cert)
                    certificateNames.append(certUri)

        self._refreshDirectories[directoryName] = {
          'certificates': certificateNames,
          'nextRefresh': Common.getNowMilliseconds() + refreshPeriod,
          'refreshPeriod':refreshPeriod }

    def refreshAnchors(self):
        refreshTime =  Common.getNowMilliseconds()
        for directory, info in self._refreshDirectories.items():
            nextRefreshTime = info['nextRefresh']
            if nextRefreshTime <= refreshTime:
                certificateList = info['certificates'][:]
                # delete the certificates associated with this directory if possible
                # then re-import
                # IdentityStorage subclasses may not support deletion
                # should we be deleting
                for c in certificateList:
                    try:
                        if self._isSecurityV1:
                            self._certificateCache.deleteCertificate(Name(c))
                        else:
                            # The name in the CertificateCacheV2 contains the
                            # but the name in the certificateList does not, so
                            # find the certificate based on the prefix first.
                            foundCertificate = self._certificateCacheV2.find(Name(c))
                            if foundCertificate != None:
                                self._certificateCacheV2.deleteCertificate(
                                  foundCertificate.getName())
                    except KeyError:
                        # was already removed? not supported?
                        pass
                self.addDirectory(directory, info['refreshPeriod'])



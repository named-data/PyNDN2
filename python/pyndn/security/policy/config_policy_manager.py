# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
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

from pyndn import Name, Data, Interest, KeyLocator
from pyndn.security.policy.policy_manager import PolicyManager
from pyndn.security.policy.certificate_cache import CertificateCache
from pyndn.security.policy.validation_request import ValidationRequest
from pyndn.security.certificate.identity_certificate import IdentityCertificate
from pyndn.util.blob import Blob
from pyndn.util.common import Common
from pyndn.encoding.wire_format import WireFormat
from pyndn.key_locator import KeyLocatorType
from pyndn.security.security_exception import SecurityException

from pyndn.util.boost_info_parser import BoostInfoParser
from pyndn.util.ndn_regex import NdnRegexMatcher

"""
This module manages trust according to a configuration file in the
Validator Configuration File Format
(http://redmine.named-data.net/projects/ndn-cxx/wiki/CommandValidatorConf)

Once a rule is matched, the ConfigPolicyManager looks in the
CertificateCache for the IdentityCertificate matching the name in the KeyLocator
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

    :param str configFileName: (optional) If not null or empty, the path to the
      configuration file containing verification rules. Otherwise, you should
      separately call load().
    :param CertificateCache certificateCache: (optional) A CertificateCache to
        hold known certificates.
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
            self._certificateCache = CertificateCache()
        else:
            self._certificateCache = certificateCache
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
        self._certificateCache.reset()

        # stores the fixed-signer certificate name associated with validation rules
        # so we don't keep loading from files
        self._fixedCertificateCache = {}

        # stores the timestamps for each public key used in command interests to avoid
        # replay attacks
        # key is public key name, value is last timestamp
        self._keyTimestamps = {}

        self.requiresVerification = True

        self.config = BoostInfoParser()
        self._refreshManager = TrustAnchorRefreshManager()

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
                    refreshMatch = re.match('(\d+)([hms])', refreshPeriodStr)
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

            self._lookupCertificate(certID, isPath)

    def _checkSignatureMatch(self, signatureName, objectName, rule):
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

        """
        checker = rule['checker'][0]
        checkerType = checker['type'][0].getValue()
        if checkerType == 'fixed-signer':
            signerInfo = checker['signer'][0]
            signerType = signerInfo['type'][0].getValue()
            if signerType == 'file':
                cert = self._lookupCertificate(signerInfo['file-name'][0].getValue(), True)
            elif signerType == 'base64':
                cert = self._lookupCertificate(signerInfo['base64-string'][0].getValue(), False)
            else:
                return False
            if cert is None:
                return False
            else:
                return cert.getName().equals(signatureName)
        elif checkerType == 'hierarchical':
            # this just means the data/interest name has the signing identity as a prefix
            # that means everything before 'ksk-?' in the key name
            identityRegex = '^([^<KEY>]*)<KEY>(<>*)<ksk-.+><ID-CERT>'
            identityMatch = NdnRegexMatcher.match(identityRegex, signatureName)
            if identityMatch is not None:
                identityPrefix = Name(identityMatch.group(1)).append(Name(identityMatch.group(2)))
                return self._matchesRelation(objectName, identityPrefix, 'is-prefix-of')
            else:
                return False
        elif checkerType == 'customized':
            keyLocatorInfo = checker['key-locator'][0]
            # not checking type - only name is supported

            # is this a simple relation?
            try:
                relationType = keyLocatorInfo['relation'][0].getValue()
            except KeyError:
                pass
            else:
                matchName = Name(keyLocatorInfo['name'][0].getValue())
                return self._matchesRelation(signatureName, matchName, relationType)

            # is this a simple regex?
            try:
                keyRegex = keyLocatorInfo['regex'][0].getValue()
            except KeyError:
                pass
            else:
                return NdnRegexMatcher.match(keyRegex, signatureName) is not None

            # is this a hyper-relation?
            try:
                hyperRelation = keyLocatorInfo['hyper-relation'][0]
            except KeyError:
                pass
            else:
                try:
                    keyRegex = hyperRelation['k-regex'][0].getValue()
                    keyMatch = NdnRegexMatcher.match(keyRegex, signatureName)
                    keyExpansion = hyperRelation['k-expand'][0].getValue()
                    keyMatchPrefix = keyMatch.expand(keyExpansion)

                    nameRegex = hyperRelation['p-regex'][0].getValue()
                    nameMatch = NdnRegexMatcher.match(nameRegex, objectName)
                    nameExpansion = hyperRelation['p-expand'][0].getValue()
                    nameMatchStr = nameMatch.expand(nameExpansion)

                    relationType = hyperRelation['h-relation'][0].getValue()

                    return self._matchesRelation(Name(nameMatchStr), Name(keyMatchPrefix), relationType)
                except:
                    pass

        # unknown type
        return False

    def _lookupCertificate(self, certID, isPath):
        """
        This looks up certificates specified as base64-encoded data or file names.
        These are cached by filename or encoding to avoid repeated reading of files
        or decoding.
        """
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
                cert.wireDecode(certData)

            certUri = cert.getName()[:-1].toUri()
            self._fixedCertificateCache[certID] = certUri
            self._certificateCache.insertCertificate(cert)
        else:
            cert = self._certificateCache.getCertificate(Name(certUri))

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
                        try:
                            regex = f['regex'][0].getValue()
                        except KeyError:
                            matchRelation = f['relation'][0].getValue()
                            matchUri = f['name'][0].getValue()
                            matchName = Name(matchUri)
                            passed = self._matchesRelation(objName, matchName, matchRelation)
                        else:
                            passed =  NdnRegexMatcher.match(regex, objName) is not None
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
                   dataOrInterest.getName().get(-1).getValue().buf())
            except (IndexError, ValueError):
                return None
            return signature
        return None

    def _interestTimestampIsFresh(self, keyName, timestamp):
        """
        Determine whether the timestamp from the interest is newer than the last use
        of this key, or within the grace interval on first use.

        :param Name keyName: The name of the public key used to sign the interest.
        :paramt int timestamp: The timestamp extracted from the interest name.
        """
        try:
            lastTimestamp = self._keyTimestamps[keyName.toUri()]
        except KeyError:
            now = Common.getNowMilliseconds()
            notBefore = now - self._keyGraceInterval
            notAfter = now + self._keyGraceInterval
            return timestamp > notBefore and timestamp < notAfter
        else:
            return timestamp > lastTimestamp

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
                                onVerifyFailed, wireFormat = None):
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
        :param onVerifyFailed: If the signature check fails, this calls
          onVerifyFailed(dataOrInterest).
          NOTE: The library will log any exceptions raised by this callback, but
          for better error handling the callback should catch and properly
          handle any exceptions.
        :type onVerifyFailed: function object
        :return: None for no further step for looking up a certificate chain.
        :rtype: ValidationRequest
        """
        if stepCount > self._maxDepth:
            try:
                onVerifyFailed(dataOrInterest)
            except:
                logging.exception("Error in onVerifyFailed")
            return None

        signature = self._extractSignature(dataOrInterest, wireFormat)
        # no signature -> fail
        if signature is None:
            try:
                onVerifyFailed(dataOrInterest)
            except:
                logging.exception("Error in onVerifyFailed")
            return None

        if not KeyLocator.canGetFromSignature(signature):
            # We only support signature types with key locators.
            try:
                onVerifyFailed(dataOrInterest)
            except:
                logging.exception("Error in onVerifyFailed")
            return None

        keyLocator = None
        try:
            keyLocator = KeyLocator.getFromSignature(signature)
        except:
            # No key locator -> fail.
            try:
                onVerifyFailed(dataOrInterest)
            except:
                logging.exception("Error in onVerifyFailed")
            return None

        signatureName = keyLocator.getKeyName()
        # no key name in KeyLocator -> fail
        if signatureName.size() == 0:
            try:
                onVerifyFailed(dataOrInterest)
            except:
                logging.exception("Error in onVerifyFailed")
            return None

        objectName = dataOrInterest.getName()
        matchType = "data"

        #for command interests, we need to ignore the last 4 components when matching the name
        if isinstance(dataOrInterest, Interest):
            objectName = objectName.getPrefix(-4)
            matchType = "interest"

        # first see if we can find a rule to match this packet
        try:
            matchedRule = self._findMatchingRule(objectName, matchType)
        except:
            matchedRule = None

        # no matching rule -> fail
        if matchedRule is None:
            try:
                onVerifyFailed(dataOrInterest)
            except:
                logging.exception("Error in onVerifyFailed")
            return None

        signatureMatches = self._checkSignatureMatch(signatureName, objectName,
                matchedRule)
        if not signatureMatches:
            try:
                onVerifyFailed(dataOrInterest)
            except:
                logging.exception("Error in onVerifyFailed")
            return None

        # before we look up keys, refresh any certificate directories
        self._refreshManager.refreshAnchors()

        # now finally check that the data or interest was signed correctly
        # if we don't actually have the certificate yet, create a
        # ValidationRequest for it
        foundCert = self._refreshManager.getCertificate(signatureName)
        if foundCert is None:
            foundCert = self._certificateCache.getCertificate(signatureName)
        if foundCert is None:
            certificateInterest = Interest(signatureName)
            def onCertificateDownloadComplete(certificate):
                certificate = IdentityCertificate(certificate)
                self._certificateCache.insertCertificate(certificate)
                self.checkVerificationPolicy(dataOrInterest, stepCount+1,
                        onVerified, onVerifyFailed)

            nextStep = ValidationRequest(certificateInterest,
                    onCertificateDownloadComplete, onVerifyFailed,
                    2, stepCount+1)

            return nextStep

        # for interests, we must check that the timestamp is fresh enough
        # I do this after (possibly) downloading the certificate to avoid
        # filling the cache with bad keys
        if isinstance(dataOrInterest, Interest):
            keyName = foundCert.getPublicKeyName()
            timestamp = dataOrInterest.getName().get(-4).toNumber()

            if not self._interestTimestampIsFresh(keyName, timestamp):
                try:
                    onVerifyFailed(dataOrInterest)
                except:
                    logging.exception("Error in onVerifyFailed")
                return None

        # certificate is known, verify the signature
        if self._verify(signature, dataOrInterest.wireEncode()):
            try:
                onVerified(dataOrInterest)
            except:
                logging.exception("Error in onVerified")
            if isinstance(dataOrInterest, Interest):
                self._updateTimestampForKey(keyName, timestamp)
        else:
            try:
                onVerifyFailed(dataOrInterest)
            except:
                logging.exception("Error in onVerifyFailed")

    def _verify(self, signatureInfo, signedBlob):
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
        :return: True if the signature verifies, False if not.
        :rtype: boolean
        """
        # We have already checked once that there is a key locator.
        keyLocator = KeyLocator.getFromSignature(signatureInfo)

        if (keyLocator.getType() == KeyLocatorType.KEYNAME):
            # Assume the key name is a certificate name.
            signatureName = keyLocator.getKeyName()
            certificate = self._refreshManager.getCertificate(signatureName)
            if certificate is None:
                certificate = self._certificateCache.getCertificate(signatureName)
            if certificate is None:
                return False

            publicKeyDer = certificate.getPublicKeyInfo().getKeyDer()
            if publicKeyDer.isNull():
                # Can't find the public key with the name.
                return False

            return self.verifySignature(signatureInfo, signedBlob, publicKeyDer)
        else:
            # Can't find a key to verify.
            return False

class TrustAnchorRefreshManager(object):
    """
    Manages the trust-anchor certificates, including refresh.
    """
    def __init__(self):
        super(TrustAnchorRefreshManager, self).__init__()

        self._certificateCache = CertificateCache()
        # maps the directory name to certificate names so they can be
        # deleted when necessary
        self._refreshDirectories = {}

    @staticmethod
    def loadIdentityCertificateFromFile(filename):
        with open(filename, 'r') as certFile:
            encodedData = certFile.read()
            decodedData = b64decode(encodedData)
            cert = IdentityCertificate()
            cert.wireDecode(Blob(decodedData, False))
            return cert

    def getCertificate(self, certificateName):
        # assumes timestamp is already removed
        return self._certificateCache.getCertificate(certificateName)

    # refershPeriod in milliseconds.
    def addDirectory(self, directoryName, refreshPeriod):
        allFiles = [f for f in os.listdir(directoryName)
                if os.path.isfile(os.path.join(directoryName, f))]
        certificateNames = []
        for f in allFiles:
            try:
                fullPath = os.path.join(directoryName, f)
                cert = self.loadIdentityCertificateFromFile(fullPath)
            except SecurityException:
                pass # allow files that are not certificates
            else:
                # cut off timestamp so it matches KeyLocator Name format
                certUri = cert.getName()[:-1].toUri()
                self._certificateCache.insertCertificate(cert)
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
                        self._certificateCache.deleteCertificate(Name(c))
                    except KeyError:
                        # was already removed? not supported?
                        pass
                self.addDirectory(directory, info['refreshPeriod'])



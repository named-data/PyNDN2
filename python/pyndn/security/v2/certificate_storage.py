# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/certificate-storage.hpp
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
This module defines the CertificateStorage class which stores trusted anchors
and has a verified certificate cache, and an unverified certificate cache.
"""

from pyndn.security.v2.trust_anchor_container import TrustAnchorContainer
from pyndn.security.v2.certificate_cache_v2 import CertificateCacheV2

class CertificateStorage(object):
    def __init__(self):
        self._trustAnchors = TrustAnchorContainer()
        self._verifiedCertificateCache = CertificateCacheV2(3600 * 1000.0)
        self._unverifiedCertificateCache = CertificateCacheV2(300 * 1000.0)

    def findTrustedCertificate(self, interestForCertificate):
        """
        Find a trusted certificate in the trust anchor container or in the
        verified cache.

        :param Interest interestForCertificate: The Interest for the certificate.
        :return: The found certificate, or None if not found.
        :rtype: CertificateV2
        """
        certificate = self._trustAnchors.find(interestForCertificate);
        if certificate != None:
          return certificate

        certificate = self._verifiedCertificateCache.find(interestForCertificate)
        return certificate

    def isCertificateKnown(self, certificatePrefix):
        """
        Check if the certificate with the given name prefix exists in the
        verified cache, the unverified cache, or in the set of trust anchors.

        :param Name certificatePrefix: The certificate name prefix.
        :return: True if the certificate is known.
        :rtype: bool
        """
        return (self._trustAnchors.find(certificatePrefix) != None or
                self._verifiedCertificateCache.find(certificatePrefix) != None or
                self._unverifiedCertificateCache.find(certificatePrefix) != None)

    def cacheUnverifiedCertificate(self, certificate):
        """
        Cache the unverified certificate for a period of time (5 minutes).

        :param CertificateV2 certificate: The certificate packet, which is copied.
        """
        self._unverifiedCertificateCache.insert(certificate)

    def getTrustAnchors(self):
        """
        Get the trust anchor container.

        :return: The trust anchor container.
        :rtype: TrustAnchorContainer
        """
        return self._trustAnchors

    def getVerifiedCertificateCache(self):
        """
        Get the verified certificate cache.

        :return: The verified certificate cache.
        :rtype: CertificateCacheV2
        """
        return self._verifiedCertificateCache

    def getUnverifiedCertificateCache(self):
        """
        Get the unverified certificate cache.

        :return: The unverified certificate cache.
        :rtype: CertificateCacheV2
        """
        return self._unverifiedCertificateCache

    def loadAnchor(self, groupId, certificateOrPath, refreshPeriod = None,
          isDirectory = False):
        """
        There are two forms of loadAnchor:
        loadAnchor(groupId, certificate) - Load a static trust anchor. Static
        trust anchors are permanently associated with the validator and never
        expire.
        loadAnchor(groupId, path, refreshPeriod, isDirectory) - Load dynamic
        trust anchors. Dynamic trust anchors are associated with the validator
        for as long as the underlying trust anchor file (or set of files) exists.

        :param str groupId: The certificate group id.
        :param CertificateV2 certificate: The certificate to load as a trust
          anchor, which is copied.
        :param str path: The path to load the trust anchors.
        :param float refreshPeriod: The refresh time in milliseconds for the
          anchors under path. This must be positive. The relevant trust anchors
          will only be updated when find is called.
        :param bool isDirectory: (optional) If True, then path is a directory.
          If False or omitted, it is a single file.
        """
        self._trustAnchors.insert(
          groupId, certificateOrPath, refreshPeriod, isDirectory)

    def resetAnchors(self):
        """
        Remove any previously loaded static or dynamic trust anchors.
        """
        self._trustAnchors.clear()

    def cacheVerifiedCertificate(self, certificate):
        """
        Cache the verified certificate a period of time (1 hour).

        :param CertificateV2 certificate: The certificate object, which is
          copied.
        """
        self._verifiedCertificateCache.insert(certificate)

    def resetVerifiedCertificates(self):
        """
        Remove any cached verified certificates.
        """
        self._verifiedCertificateCache.clear()

    def _setCacheNowOffsetMilliseconds(self, nowOffsetMilliseconds):
        """
        Set the offset when the cache insert() and refresh() get the current
          time, which should only be used for testing.

        :param float nowOffsetMilliseconds: The offset in milliseconds.
        """
        self._verifiedCertificateCache._setNowOffsetMilliseconds(nowOffsetMilliseconds)
        self._unverifiedCertificateCache._setNowOffsetMilliseconds(nowOffsetMilliseconds)

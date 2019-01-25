# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/certificate-cache.cpp
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
This module defines the CertificateCacheV2 class which holds other user's
verified certificates in security v2 format CertificateV2. A certificate is
removed no later than its NotAfter time, or maxLifetime after it has been added
to the cache.
"""

import sys
import logging
import bisect
from pyndn.name import Name
from pyndn.security.v2.certificate_v2 import CertificateV2
from pyndn.encrypt.schedule import Schedule
from pyndn.util.common import Common

class CertificateCacheV2(object):
    """
    Create a CertificateCacheV2.

    :param float maxLifetimeMilliseconds: (optional) The maximum time that
      certificates can live inside the cache, in milliseconds. If omitted use
      getDefaultLifetime()
    """
    def __init__(self, maxLifetimeMilliseconds = None):
        if maxLifetimeMilliseconds == None:
            maxLifetimeMilliseconds = CertificateCacheV2.getDefaultLifetime()

        # Name => CertificateCacheV2._Entry.
        self._certificatesByName = {}
        # The keys of _certificatesByName in sorted order, kept in sync with it.
        # (We don't use OrderedDict because it doesn't sort keys on insert.)
        self._certificatesByNameKeys = []

        self._nextRefreshTime = sys.float_info.max
        self._maxLifetimeMilliseconds = maxLifetimeMilliseconds
        self._nowOffsetMilliseconds = 0

    def insert(self, certificate):
        """
        Insert the certificate into the cache. The inserted certificate will be
        removed no later than its NotAfter time, or maxLifetimeMilliseconds
        given to the constructor.

        :param CertificateV2 certificate: The certificate object, which is
          copied.
        """
        notAfterTime = certificate.getValidityPeriod().getNotAfter()
        # _nowOffsetMilliseconds is only used for testing.
        now = Common.getNowMilliseconds() + self._nowOffsetMilliseconds
        if notAfterTime < now:
            logging.getLogger(__name__).info("Not adding " +
              certificate.getName().toUri() + ": already expired at " +
              Schedule.toIsoString(notAfterTime))
            return

        removalTime = min(notAfterTime, now + self._maxLifetimeMilliseconds)
        if removalTime < self._nextRefreshTime:
            # We need to run refresh() sooner.
            self._nextRefreshTime = removalTime

        logging.getLogger(__name__).info("Adding " + certificate.getName().toUri() +
          ", will remove in " + str((removalTime - now) / (3600 * 1000.0)) +
          " hours")

        certificateCopy = CertificateV2(certificate)
        certificateName = certificateCopy.getName()

        if certificateName in self._certificatesByName:
            # A duplicate name. Simply replace.
            self._certificatesByName[certificateName]._certificate = certificateCopy
            self._certificatesByName[certificateName]._removalTime = removalTime
        else:
            # Insert into _certificatesByNameKeys sorted.
            # Keep it sync with _certificatesByName.
            self._certificatesByName[certificateName] = CertificateCacheV2._Entry(
              certificateCopy, removalTime)
            bisect.insort(self._certificatesByNameKeys, certificateName)

    def find(self, certificatePrefixOrInterest):
        """
        Find the certificate by the given key name or interest.

        :param certificatePrefixOrInterest: If a Name, it is the  certificate
          prefix for searching for the certificate. If an Interest, it is the
          input interest object.
        :type certificatePrefixOrInterest: Name or Interest
        :return: The found certificate which matches the interest, or None if
          not found. You must not modify the returned object. If you need to
          modify it, then make a copy.
        :note: If searching by Interest, the ChildSelector is not supported.
        """
        if isinstance(certificatePrefixOrInterest, Name):
            certificatePrefix = certificatePrefixOrInterest

            if (certificatePrefix.size() > 0 and
                certificatePrefix.get(-1).isImplicitSha256Digest()):
                logging.getLogger(__name__).error(
                  "Certificate search using a name with an implicit digest is not yet supported")

            self._refresh()

            # Find the first that is greater than or equal to certificatePrefix.
            i = bisect.bisect_left(self._certificatesByNameKeys, certificatePrefix)
            if (i >= len(self._certificatesByNameKeys) or
                not certificatePrefix.isPrefixOf(self._certificatesByNameKeys[i])):
                return None
            return self._certificatesByName[self._certificatesByNameKeys[i]]._certificate
        else:
            interest = certificatePrefixOrInterest

            if interest.getChildSelector() != None:
                logging.getLogger(__name__).error(
                  "Certificate search using a ChildSelector is not supported. Searching as if this selector not specified")

            if (interest.getName().size() > 0 and
                interest.getName().get(-1).isImplicitSha256Digest()):
                logging.getLogger(__name__).error(
                  "Certificate search using a name with an implicit digest is not yet supported")

            self._refresh()

            # Find the first that is greater than or equal to interest.getName().
            i = bisect.bisect_left(self._certificatesByNameKeys, interest.getName())
            if i >= len(self._certificatesByNameKeys):
                return None

            while i < len(self._certificatesByNameKeys):
                key = self._certificatesByNameKeys[i]
                certificate = self._certificatesByName[key]._certificate
                if not interest.getName().isPrefixOf(certificate.getName()):
                    break

                if interest.matchesData(certificate):
                    return certificate

                i += 1

            return None

    def deleteCertificate(self, certificateName):
        """
        Remove the certificate whose name equals the given name. If no such
        certificate is in the cache, do nothing.

        :param Name certificateName: The name of the certificate.
        """
        try:
            del self._certificatesByName[certificateName]
        except KeyError:
            # Do nothing if it doesn't exist.
            pass
        try:
            self._certificatesByNameKeys.remove(certificateName)
        except ValueError:
            # Do nothing if it doesn't exist.
            pass

        # This may be the certificate to be removed at _nextRefreshTime by
        # _refresh(), but just allow _refresh() to run instead of updating
        # _nextRefreshTime now.

    def clear(self):
        """
        Clear all certificates from the cache.
        """
        self._certificatesByName = {}
        self._certificatesByNameKeys = []
        self._nextRefreshTime = sys.float_info.max

    @staticmethod
    def getDefaultLifetime():
        """
        Get the default maximum lifetime (1 hour).

        :return: The lifetime in milliseconds.
        :rtype: float
        """
        return 3600.0 * 1000

    def _setNowOffsetMilliseconds(self, nowOffsetMilliseconds):
        """
        Set the offset when insert() and _refresh() get the current time, which
        should only be used for testing.

        :param float nowOffsetMilliseconds: The offset in milliseconds.
        """
        self._nowOffsetMilliseconds = nowOffsetMilliseconds

    class _Entry(object):
        """
        CertificateCacheV2._Entry is the value of the _certificatesByName map.
        Create a new CertificateCacheV2.Entry with the given values.

        :param CertificateV2 certificate: The certificate.
        :param float removalTime: The removal time for this entry as
          milliseconds since Jan 1, 1970 UTC.
        """
        def __init__(self, certificate, removalTime):
            self._certificate = certificate
            self._removalTime = removalTime

    def _refresh(self):
        """
        Remove all outdated certificate entries.
        """
        # _nowOffsetMilliseconds is only used for testing.
        now = Common.getNowMilliseconds() + self._nowOffsetMilliseconds
        if now < self._nextRefreshTime:
            return

        # We recompute _nextRefreshTime.
        nextRefreshTime = sys.float_info.max
        # Go backwards through the list so we can erase entries.
        i = len(self._certificatesByNameKeys) - 1
        while i >= 0:
            entry = self._certificatesByName[self._certificatesByNameKeys[i]]

            if entry._removalTime <= now:
                del self._certificatesByName[self._certificatesByNameKeys[i]]
                self._certificatesByNameKeys.pop(i)
            else:
                nextRefreshTime = min(nextRefreshTime, entry._removalTime)

            i -= 1

        self._nextRefreshTime = nextRefreshTime

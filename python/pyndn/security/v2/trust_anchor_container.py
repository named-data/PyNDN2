# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/trust-anchor-container.cpp
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
This module defines the TrustAnchorContainer class which represents a container
for trust anchors.

There are two kinds of anchors:
static anchors that are permanent for the lifetime of the container, and
dynamic anchors that are periodically updated.

Trust anchors are organized in groups. Each group has a unique group id.
The same anchor certificate (same name without considering the implicit
digest) can be inserted into multiple groups, but no more than once into each.

Dynamic groups are created using the appropriate TrustAnchorContainer.insert
method. Once created, the dynamic anchor group cannot be updated.

The returned pointer to Certificate from `find` methods is only guaranteed to
be valid until the next invocation of `find` and may be invalidated
afterwards.
"""

import bisect
from pyndn.name import Name
from pyndn.security.v2.certificate_v2 import CertificateV2
from pyndn.security.v2.dynamic_trust_anchor_group import DynamicTrustAnchorGroup
from pyndn.security.v2.static_trust_anchor_group import StaticTrustAnchorGroup
from pyndn.security.v2.certificate_container_interface import CertificateContainerInterface

class TrustAnchorContainer(object):
    """
    Create an empty TrustAnchorContainer.
    """
    def __init__(self):
        # The key is the group ID string. The value is the TrustAnchorGroup.
        self._groups = {}
        self._anchors = TrustAnchorContainer._AnchorContainer()

    class Error(Exception):
        """
        Create a TrustAnchorContainer.Error.

        :param str message: The error message.
        """
        def __init__(self, message):
            super(TrustAnchorContainer.Error, self).__init__(message)

    def insert(self, groupId, certificateOrPath, refreshPeriod = None,
               isDirectory = False):
        """
        There are two forms of insert:
        insert(groupId, certificate) - Insert a static trust anchor. If the
        certificate (having the same name without considering implicit digest)
        already exists in the group with groupId, then do nothing.
        insert(groupId, path, refreshPeriod, isDirectory) - Insert dynamic trust
        anchors from the path.

        :param str groupId: The certificate group id.
        :param CertificateV2 certificate: The certificate to insert, which is
          copied.
        :param str path: The path to load the trust anchors.
        :param float refreshPeriod: The refresh time in milliseconds for the
          anchors under path. This must be positive. The relevant trust anchors
          will only be updated when find is called.
        :param bool isDirectory: (optional) If True, then path is a directory.
          If False or omitted, it is a single file.
        :raises: TrustAnchorContainer.Error If inserting a static trust anchor
          and groupId is for a dynamic anchor group , or if inserting a dynamic
          trust anchor and a group with groupId already exists.
        :raises: ValueError If refreshPeriod is not positive.
        """
        if isinstance(certificateOrPath, CertificateV2):
            certificate = certificateOrPath

            try:
                group = self._groups[groupId]
            except KeyError:
                group = StaticTrustAnchorGroup(self._anchors, groupId)
                self._groups[groupId] = group

            if not isinstance(group, StaticTrustAnchorGroup):
                raise TrustAnchorContainer.Error(
                  "Cannot add a static anchor to the non-static anchor group " +
                   str(groupId))

            group.add(certificate)
        else:
            path = certificateOrPath

            if groupId in self._groups:
                raise TrustAnchorContainer.Error(
                  "Cannot create the dynamic group, because group " +
                  str(groupId) + " already exists")

            self._groups[groupId] = DynamicTrustAnchorGroup(
              self._anchors, groupId, path, refreshPeriod, isDirectory)

    def clear(self):
        """
        Remove all static and dynamic anchors.
        """
        self._groups = {}
        self._anchors.clear()

    def find(self, keyNameOrInterest):
        """
        There are two forms of find:
        find(keyName) - Search for a certificate across all groups (longest
        prefix match).
        find(interest) - Find a certificate for the given interest. Note:
        Interests with implicit digest are not supported.

        :param Name keyName: The key name prefix for searching for the
          certificate.
        :param Interest} interest: The input interest packet.
        :return: The found certificate, or None if not found.
        :rtype: CertificateV2
        """
        if isinstance(keyNameOrInterest, Name):
            keyName = keyNameOrInterest

            self._refresh()

            # Find the first that is greater than or equal to keyName.
            i = bisect.bisect_left(self._anchors._anchorsByNameKeys, keyName)
            if i >= len(self._anchors._anchorsByNameKeys):
                return None
            certificate = self._anchors._anchorsByName[
                self._anchors._anchorsByNameKeys[i]]
            if not keyName.isPrefixOf(certificate.getName()):
                return None
            return certificate
        else:
            interest = keyNameOrInterest

            self._refresh()

            i = bisect.bisect_left(
              self._anchors._anchorsByNameKeys, interest.getName())
            if i >= len(self._anchors._anchorsByNameKeys):
                return None

            while i < len(self._anchors._anchorsByNameKeys):
                key = self._anchors._anchorsByNameKeys[i]
                certificate = self._anchors._anchorsByName[key]
                if not interest.getName().isPrefixOf(certificate.getName()):
                    break

                if interest.matchesData(certificate):
                    return certificate

                i += 1

            return None

    def getGroup(self, groupId):
        """
        Get the trust anchor group for the groupId.

        :param str groupId: The group ID.
        :return: The trust anchor group.
        :rtype: TrustAnchorGroup
        :raises: TrustAnchorContainer.Error if the groupId does not exist.
        """
        try:
           group = self._groups[groupId]
        except KeyError:
            raise TrustAnchorContainer.Error(
              "Trust anchor group " + str(groupId) + " does not exist")

        return group

    def size(self):
        """
        Get the number of trust anchors across all groups.

        :return: The number of trust anchors.
        :rtype: int
        """
        return self._anchors.size()

    class _AnchorContainer(CertificateContainerInterface):
        def __init__(self):
            # Name => CertificateV2.
            self._anchorsByName = {}
            # The keys of _anchorsByName in sorted order, kept in sync with it.
            # (We don't use OrderedDict because it doesn't sort keys on insert.)
            self._anchorsByNameKeys = []

        def add(self, certificate):
            """
            Add the certificate to the container.

            :param CertificateV2 certificate: The certificate to add, which is
              copied.
            """
            certificateCopy = CertificateV2(certificate)

            name = certificateCopy.getName()
            if name in self._anchorsByNameKeys:
                # Just replace the existing entry value.
                self._anchorsByName[name] = certificateCopy
                return

            # Insert into _anchorsByNameKeys sorted.
            # Keep it sync with _anchorsByName.
            self._anchorsByName[name] = certificateCopy
            bisect.insort(self._anchorsByNameKeys, name)

        def remove(self, certificateName):
            """
            Remove the certificate with the given name. If the name does not
            exist, do nothing.

            :param Name certificateName: The name of the certificate.
            """
            try:
                del self._anchorsByName[certificateName]
            except KeyError:
                pass
            try:
                self._anchorsByNameKeys.remove(certificateName)
            except ValueError:
                pass

        def clear(self):
            """
            Clear all certificates.
            """
            self._anchorsByName = {}
            self._anchorsByNameKeys = []

        def size(self):
            return len(self._anchorsByName)

    def _refresh(self):
        for groupId in self._groups:
            self._groups[groupId].refresh()

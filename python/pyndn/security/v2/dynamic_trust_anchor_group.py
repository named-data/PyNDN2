# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/trust-anchor-group.cpp
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
This module defines the DynamicTrustAnchorGroup class which extends
TrustAnchorGroup to implement a dynamic trust anchor group.
"""

import os
import logging
from pyndn.util.common import Common
from pyndn.security.v2.trust_anchor_group import TrustAnchorGroup

class DynamicTrustAnchorGroup(TrustAnchorGroup):
    """
    Create a DynamicTrustAnchorGroup to use an existing container.

    :param CertificateContainer certificateContainer: The existing certificate
      container which implements the CertificateContainer interface.
    :param str id: The group ID.
    :param str path: The file path for trust anchor(s), which could be a
      directory or a file. If it is a directory, all the certificates in the
      directory will be loaded.
    :param float refreshPeriod: The refresh time in milliseconds for the
      anchors under path. This must be positive.
    :param bool isDirectory: If True, then path is a directory. If False, it
      is a single file.
    :raises: ValueError If refreshPeriod is not positive.
    """
    def __init__(self, certificateContainer, id, path, refreshPeriod, isDirectory):
        super(DynamicTrustAnchorGroup, self).__init__(certificateContainer, id)

        self._isDirectory = isDirectory
        self._path = path
        self._refreshPeriod = refreshPeriod
        self._expireTime = 0.0
        if refreshPeriod <= 0.0:
            raise ValueError(
              "Refresh period for the dynamic group must be positive")

        logging.getLogger(__name__).info(
          "Create a dynamic trust anchor group " + str(id) + " for file/dir " +
          path + " with refresh time " + str(refreshPeriod))
        self.refresh()

    def refresh(self):
        """
        Request a certificate refresh.
        """
        now = Common.getNowMilliseconds()
        if self._expireTime > now:
            return

        self._expireTime = now + self._refreshPeriod
        logging.getLogger(__name__).info(
          "Reloading the dynamic trust anchor group")

        # Save a copy of _anchorNames .
        oldAnchorNames = set(self._anchorNames)

        if not self._isDirectory:
            self._loadCertificate(self._path, oldAnchorNames)
        else:
            try:
                allFiles = [f for f in os.listdir(self._path)
                  if os.path.isfile(os.path.join(self._path, f))]
            except:
                raise RuntimeError("Cannot list files in directory " + self._path)

            for f in allFiles:
                self._loadCertificate(os.path.join(self._path, f), oldAnchorNames)

        # Remove old certificates.
        for name in oldAnchorNames:
            self._anchorNames.remove(name)
            self._certificates.remove(name)

    def _loadCertificate(self, file, oldAnchorNames):
        """
        :param str file:
        :type oldAnchorNames: set of Name
        """
        certificate = TrustAnchorGroup.readCertificate(file)
        if certificate != None:
            if not (certificate.getName() in self._anchorNames):
                self._anchorNames.add(certificate.getName())
                self._certificates.add(certificate)
            else:
                oldAnchorNames.remove(certificate.getName())

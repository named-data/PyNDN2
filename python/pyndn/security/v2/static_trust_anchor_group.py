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
This module defines the StaticTrustAnchorGroup class which extends
TrustAnchorGroup to implement a static trust anchor group.
"""
from pyndn.name import Name
from pyndn.security.v2.trust_anchor_group import TrustAnchorGroup

class StaticTrustAnchorGroup(TrustAnchorGroup):
    """
    Create a StaticTrustAnchorGroup to use an existing container.

    :param CertificateContainer certificateContainer: The existing certificate
      container which implements the CertificateContainer interface.
    :param str id: The group ID.
    """
    def __init__(self, certificateContainer, id):
        super(StaticTrustAnchorGroup, self).__init__(certificateContainer, id)

    def add(self, certificate):
        """
        Load the static anchor certificate. If a certificate with the name is
        already added, do nothing.

        :param CertificateV2 certificate: The certificate to add, which is
          copied.
        """
        if certificate.getName() in self._anchorNames:
            return

        # Copy the certificate name.
        self._anchorNames.add(Name(certificate.getName()))
        # This copies the certificate.
        self._certificates.add(certificate)

    def remove(self, certificateName):
        """
        Remove the static anchor with the certificate name.

        :param Name certificateName: The certificate name.
        """
        try:
            self._anchorNames.remove(certificateName)
        except:
            pass

        self._certificates.remove(certificateName)

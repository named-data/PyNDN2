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
This module defines the TrustAnchorGroup class which represents a group of trust
anchors which implement the CertificateContainer interface.
"""

from base64 import b64decode
from pyndn.util.blob import Blob
from pyndn.security.v2.certificate_v2 import CertificateV2

class TrustAnchorGroup(object):
    """
    Create a TrustAnchorGroup to use an existing container.

    :param CertificateContainer certificateContainer: The existing certificate
      container which implements the CertificateContainer interface.
    :param str id: The group ID.
    """
    def __init__(self, certificateContainer, id):
        self._certificates = certificateContainer
        self._id = id

        self._anchorNames = set()  # of Name

    def getId(self):
        """
        Get the group id given to the constructor.

        :return: The group id.
        :rtype: str
        """
        return self._id

    def size(self):
        """
        Get the number of certificates in the group.

        :return: The number of certificates.
        :rtype: int
        """
        return len(self._anchorNames)

    def refresh(self):
        """
        Request a certificate refresh. The base method does nothing.
        """
        pass

    @staticmethod
    def readCertificate(filePath):
        """
        Read a base-64-encoded certificate from a file.

        :param str filePath: The certificate file path.
        :return: The decoded certificate, or None if there is an error.
        :rtype: CertificateV2
        """
        try:
            with open(filePath, 'r') as certificateFile:
                encodedData = certificateFile.read()
                decodedData = b64decode(encodedData)
                result = CertificateV2()
                result.wireDecode(Blob(decodedData, False))
                return result
        except:
            return None


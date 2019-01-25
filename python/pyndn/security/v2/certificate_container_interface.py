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
This module defines the CertificateContainerInterface class.
"""

class CertificateContainerInterface(object):
    def add(self, certificate):
        """
        Add the certificate to the container.

        :param CertificateV2 certificate: The certificate to add, which is
          copied.
        """
        raise RuntimeError("CertificateContainerInterface.add is unimplemented")

    def remove(self, certificateName):
        """
        Remove the certificate with the given name. If the name does not exist,
        do nothing.

        :param Name certificateName: The name of the certificate.
        """
        raise RuntimeError("CertificateContainerInterface.remove is unimplemented")

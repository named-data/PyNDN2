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
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU General Public License is in the file COPYING.

from pyndn.security.certificate.identity_certificate import IdentityCertificate
class CertificateCache(object):
    def __init__(self):
        super(CertificateCache, self).__init__()
        self._cache = {}

    def insertCertificate(self, certificate):
        """
        Insert the certificate into the cache. Assumes the timestamp is not yet
        removed.
        :param IdentityCertificate certificate: The certificate to insert.
        """
        certificate = IdentityCertificate(certificate)
        certName = certificate.getName()[:-1]
        self._cache[certName.toUri()] = certificate.wireEncode()

    def deleteCertificate(self, certificateName):
        """
        Remove a certificate from the cache. Does nothing if it is not present.

        :param Name certificateName: The name of the certificate to remove.
            Assumes there is no timestamp in the name.
        """
        try:
            self._cache.pop(certificateName.toUri())
        except KeyError:
            pass

    def getCertificate(self, certificateName):
        """
        Fetch a certificate from the cache.

        :param Name certificateName: The name of the certificate to remove.
            Assumes there is no timestamp in the name.
        """
        try:
            cert = IdentityCertificate()
            certData = self._cache[certificateName.toUri()]
            cert.wireDecode(certData)
            return cert
        except KeyError:
            return None

    def reset(self):
        """
        Clear all certificates from the store.
        """
        self._cache={}

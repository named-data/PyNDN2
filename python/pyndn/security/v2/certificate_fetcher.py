# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/certificate-fetcher.hpp
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
This module defines the CertificateFetcher class which is an abstract base class
which provides an interface used by the validator to fetch missing certificates.
"""

import logging

class CertificateFetcher(object):
    def __init__(self):
        self._certificateStorage = None

    def setCertificateStorage(self, certificateStorage):
        """
        Assign the certificate storage used to check for known certificates and
        to cache unverified ones.

        :param CertificateStorage certificateStorage: The certificate storage
          object which must be valid for the lifetime of this CertificateFetcher.
        """
        self._certificateStorage = certificateStorage

    def fetch(self, certificateRequest, state, continueValidation):
        """
        Asynchronously fetch a certificate. setCertificateStorage must have been
        called first. If the requested certificate exists in the
        storage, then this method will immediately call continueValidation with
        the certificate. If certificate is not available, then the
        implementation-specific doFetch will be called to asynchronously fetch
        the certificate. The successfully-retrieved certificate will be
        automatically added to the unverified cache of the certificate storage.
        When the requested certificate is retrieved, continueValidation is
        called. Otherwise, the fetcher implementation calls state.failed() with
        the appropriate error code and diagnostic message.

        :param CertificateRequest certificateRequest: The the request with the
          Interest for fetching the certificate.
        :param ValidationState state: The validation state.
        :param continueValidation: After fetching, this calls
          continueValidation(certificate, state) where certificate is the
          fetched certificate and state is the ValidationState.
        :type continueValidation: function object
        """
        if self._certificateStorage == None:
            raise RuntimeError(
              "CertificateFetcher.fetch: You must first call setCertificateStorage")

        certificate = self._certificateStorage.getUnverifiedCertificateCache().find(
            certificateRequest._interest)
        if certificate != None:
            logging.getLogger(__name__).info(
              "Found certificate in **un**verified key cache " +
              certificate.getName().toUri())
            continueValidation(certificate, state)
            return

        # Fetch asynchronously.
        def continueFetch(certificate, state):
            self._certificateStorage.cacheUnverifiedCertificate(certificate)
            continueValidation(certificate, state)
        self._doFetch(certificateRequest, state, continueFetch)

    def _doFetch(self, certificateRequest, state, continueValidation):
        """
        An implementation to fetch a certificate asynchronously. The subclass
        must implement this method.

        :param CertificateRequest certificateRequest: The the request with the
          Interest for fetching the certificate.
        :param ValidationState state: The validation state.
        :param continueValidation: After fetching, this calls
          continueValidation(certificate, state) where certificate is the
          fetched certificate and state is the ValidationState.
        :type continueValidation: function object
        """
        raise RuntimeError("CertificateFetcher._doFetch is not implemented")

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/certificate-fetcher-from-network.cpp
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
This module defines the CertificateFetcherFromNetwork class which extends
CertificateFetcher to fetch missing certificates from the network.
"""

import logging
from pyndn.security.v2.certificate_v2 import CertificateV2
from pyndn.security.v2.validation_error import ValidationError
from pyndn.security.v2.certificate_fetcher import CertificateFetcher

class CertificateFetcherFromNetwork(CertificateFetcher):
    def __init__(self, face):
        super(CertificateFetcherFromNetwork, self).__init__()

        self._face = face

    def _doFetch(self, certificateRequest, state, continueValidation):
        """
        Implement doFetch to use _face.expressInterest to fetch a certificate.

        :param CertificateRequest certificateRequest: The the request with the
          Interest for fetching the certificate.
        :param ValidationState state: The validation state.
        :param continueValidation: After fetching, this calls
          continueValidation(certificate, state) where certificate is the
          fetched certificate and state is the ValidationState.
        :type continueValidation: function object
        """
        def onData(interest, data):
            logging.getLogger(__name__).info("Fetched certificate from network " +
              data.getName().toUri())

            try:
                certificate = CertificateV2(data)
            except Exception as ex:
                state.fail(ValidationError
                  (ValidationError.MALFORMED_CERTIFICATE,
                   "Fetched a malformed certificate `" + data.getName().toUri() +
                   "` (" + repr(ex) + ")"))
                return

            try:
                continueValidation(certificate, state)
            except Exception as ex:
                state.fail(ValidationError
                  (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
                   "Error in continueValidation: " + repr(ex)))

        def onTimeout(interest):
            logging.getLogger(__name__).info("Timeout while fetching certificate " +
              certificateRequest._interest.getName().toUri() + ", retrying")

            certificateRequest._nRetriesLeft -= 1
            if certificateRequest._nRetriesLeft >= 0:
                try:
                    self.fetch(certificateRequest, state, continueValidation)
                except Exception as ex:
                   state.fail(ValidationError
                     (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
                      "Error in fetch: " + repr(ex)))
            else:
                state.fail(ValidationError
                  (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
                   "Cannot fetch certificate after all retries `" +
                   certificateRequest._interest.getName().toUri() + "`"))

        def onNetworkNack(interest, networkNack):
            logging.getLogger(__name__).info("NACK (" +
              str(networkNack.getReason()) + ") while fetching certificate " +
              certificateRequest._interest.getName().toUri())

            certificateRequest._nRetriesLeft -= 1
            if certificateRequest._nRetriesLeft >= 0:
                try:
                    self.fetch(certificateRequest, state, continueValidation)
                except Exception as ex:
                   state.fail(ValidationError
                     (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
                      "Error in fetch: " + repr(ex)))
            else:
                state.fail(ValidationError
                  (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
                   "Cannot fetch certificate after all retries `" +
                   certificateRequest._interest.getName().toUri() + "`"))

        try:
            self._face.expressInterest(
              certificateRequest._interest, onData, onTimeout, onNetworkNack)
        except Exception as ex:
            state.fail(ValidationError(ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
              "Error in expressInterest: " + repr(ex)))

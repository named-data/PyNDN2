# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/validator.hpp
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
This module defines the Validator class which provides an interface for
validating data and interest packets.

Every time a validation process is initiated, it creates a ValidationState that
exists until the validation finishes with either success or failure. This state
serves several purposes:
to record the Interest or Data packet being validated,
to record the failure callback,
to record certificates in the certification chain for the Interest or Data
packet being validated,
to record the names of the requested certificates in order to detect loops in
the certificate chain,
and to keep track of the validation chain size (also known as the validation
"depth").

During validation, the policy and/or key fetcher can augment the validation
state with policy- and fetcher-specific information using tags.

A Validator has a trust anchor cache to save static and dynamic trust anchors, a
verified certificate cache for saving certificates that are already verified,
and an unverified certificate cache for saving pre-fetched but not yet verified
certificates.
"""

import logging
from pyndn.data import Data
from pyndn.security.v2.validation_error import ValidationError
from pyndn.security.v2.data_validation_state import DataValidationState
from pyndn.security.v2.interest_validation_state import InterestValidationState
from pyndn.security.v2.certificate_fetcher_offline import CertificateFetcherOffline
from pyndn.security.v2.certificate_storage import CertificateStorage

class Validator(CertificateStorage):
    """
    Create a Validator with the policy and fetcher.

    :param ValidationPolicy policy: The validation policy to be associated with
      this validator.
    :param CertificateFetcher certificateFetcher: (optional) The certificate
      fetcher implementation. If omitted, use a CertificateFetcherOffline
      (assuming that the validation policy doesn't need to fetch certificates).
    """
    def __init__(self, policy, certificateFetcher = None):
        super(Validator, self).__init__()

        if certificateFetcher == None:
            certificateFetcher = CertificateFetcherOffline()

        self._policy = policy
        self._certificateFetcher = certificateFetcher
        self._maxDepth = 25

        if self._policy == None:
            raise RuntimeError("The policy is None")
        if self._certificateFetcher == None:
            raise RuntimeError("The certificateFetcher is None")

        self._policy.setValidator(self)
        self._certificateFetcher.setCertificateStorage(self)

    def getPolicy(self):
        """
        Get the ValidationPolicy given to the constructor.

        :return: The ValidationPolicy.
        :rtype: ValidationPolicy
        """
        return self._policy

    def getFetcher(self):
        """
        Get the CertificateFetcher given to (or created in) the constructor.

        :return: The CertificateFetcher.
        :rtype: CertificateFetcher
        """
        return self._certificateFetcher

    def setMaxDepth(self, maxDepth):
        """
        Set the maximum depth of the certificate chain.

        :param int maxDepth: The maximum depth.
        """
        self._maxDepth = maxDepth

    def getMaxDepth(self):
        """
        Get the maximum depth of the certificate chain.

        :return:  The maximum depth.
        :rtype: int
        """
        return self._maxDepth

    def validate(self, dataOrInterest, successCallback, failureCallback):
        """
        Asynchronously validate the Data or Interest packet.

        :param dataOrInterest: The Data or Interest packet to validate, which is
          copied.
        :type dataOrInterest: Data or Interest
        :param successCallback: On validation success, this calls
          successCallback(dataOrInterest).
        :type successCallback: function object
        :param failureCallback: On validation failure, this calls
          failureCallback(dataOrInterest, error) where error is a
          ValidationError.
        :type failureCallback: function object
        """
        if isinstance(dataOrInterest, Data):
            state = DataValidationState(
              dataOrInterest, successCallback, failureCallback)
            logging.getLogger(__name__).info("Start validating data " +
              dataOrInterest.getName().toUri())
        else:
            state = InterestValidationState(
              dataOrInterest, successCallback, failureCallback)
            logging.getLogger(__name__).info("Start validating interest " +
              dataOrInterest.getName().toUri())

        def continueValidate(certificateRequest, state):
            if certificateRequest == None:
                state._bypassValidation()
            else:
                # We need to fetch the key and validate it.
                self._requestCertificate(certificateRequest, state)
        self._policy.checkPolicy(dataOrInterest, state, continueValidate)

    def _validateCertificate(self, certificate, state):
        """
        Recursively validate the certificates in the certification chain.

        :param CertificateV2 certificate: The certificate to check.
        :param ValidationState state: The current validation state.
        """
        logging.getLogger(__name__).info("Start validating certificate " +
          certificate.getName().toUri())

        if not certificate.isValid():
            state.fail(ValidationError(ValidationError.EXPIRED_CERTIFICATE,
               "Retrieved certificate is not yet valid or expired `" +
               certificate.getName().toUri() + "`"))
            return

        def continueValidateCertificate(certificateRequest, state):
            if certificateRequest == None:
                state.fail(ValidationError(ValidationError.POLICY_ERROR,
                   "Validation policy is not allowed to designate `" +
                   certificate.getName().toUri() + "` as a trust anchor"))
            else:
              # We need to fetch the key and validate it.
              state.addCertificate(certificate)
              self._requestCertificate(certificateRequest, state)
        self._policy.checkCertificatePolicy(
          certificate, state, continueValidateCertificate)

    def _requestCertificate(self, certificateRequest, state):
        """
        Request a certificate for further validation.

        :param CertificateRequest certificateRequest: The certificate request.
        :param ValidationState state: The current validation state.
        """
        if state.getDepth() >= self._maxDepth:
            state.fail(ValidationError(ValidationError.EXCEEDED_DEPTH_LIMIT,
              "Exceeded validation depth limit"))
            return

        if state.hasSeenCertificateName(certificateRequest._interest.getName()):
            state.fail(ValidationError(ValidationError.LOOP_DETECTED,
               "Validation loop detected for certificate `" +
                 certificateRequest._interest.getName().toUri() + "`"))
            return

        logging.getLogger(__name__).info("Retrieving " +
          certificateRequest._interest.getName().toUri())

        certificate = self.findTrustedCertificate(certificateRequest._interest)
        if certificate != None:
            logging.getLogger(__name__).info("Found trusted certificate " +
              certificate.getName().toUri())

            certificate = state._verifyCertificateChain(certificate)
            if certificate != None:
                state._verifyOriginalPacket(certificate)

            for i in range(len(state._certificateChain)):
                self.cacheVerifiedCertificate(state._certificateChain[i])

            return

        self._certificateFetcher.fetch(
          certificateRequest, state, self._validateCertificate)

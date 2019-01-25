# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/validation-state.hpp
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
This module defines the ValidationState class which is an abstract base class
for DataValidationState and InterestValidationState.

One instance of the validation state is kept for the validation of the whole
certificate chain.

The state collects the certificate chain that adheres to the selected validation
policy to validate data or interest packets. Certificate, data, and interest
packet signatures are verified only after the validator determines that the
chain terminates with a trusted certificate (a trusted anchor or a previously
validated certificate). This model allows filtering out invalid certificate
chains without incurring (costly) cryptographic signature verification overhead
and mitigates some forms of denial-of-service attacks.

A validation policy and/or key fetcher may add custom information associated
with the validation state using tags.
"""

import logging
from pyndn.security.verification_helpers import VerificationHelpers
from pyndn.security.v2.certificate_v2 import CertificateV2
from pyndn.security.v2.validation_error import ValidationError

class ValidationState(object):
    def __init__(self):
        # Each certificate in the chain signs the next certificate. The last
        # certificate signs the original packet.
        self._certificateChain = []  # of CertificateV2
        self._seenCertificateNames = set()  # of Name
        self._hasOutcome = False
        self._outcome = False

    def hasOutcome(self):
        """
        Check if validation failed or success has been called.

        :return: True if validation failed or success has been called.
        :rtype: bool
        """
        return self._hasOutcome

    def isOutcomeFailed(self):
        """
        Check if validation failed has been called.

        :return: True if validation failed has been called, False if no
          validation callbacks have been called or validation success was called.
        :rtype: bool
        """
        return self._hasOutcome and self._outcome == False

    def isOutcomeSuccess(self):
        """
        Check if validation success has been called.

        :return: True if validation success has been called, False if no
          validation callbacks have been called or validation failed was called.
        :rtype: bool
        """
        return self._hasOutcome and self._outcome == True

    def fail(self, error):
        """
        Call the failure callback.

        :param ValidationError error:
        """
        raise RuntimeError("ValidationState.fail is not implemented")

    def getDepth(self):
        """
        Get the depth of the certificate chain.

        :return: The depth of the certificate chain.
        :rtype: int
        """
        return len(self._certificateChain)

    def hasSeenCertificateName(self, certificateName):
        """
        Check if certificateName has been previously seen, and record the
        supplied name.

        :param Name certificateName: The certificate name, which is copied.
        :return: True if certificateName has been previously seen.
        :rtype: bool
        """
        if certificateName in self._seenCertificateNames:
            return True
        else:
            self._seenCertificateNames.add(certificateName)
            return False

    def addCertificate(self, certificate):
        """
        Add the certificate to the top of the certificate chain. If the
        certificate chain is empty, then the certificate should be the signer of
        the original packet. If the certificate chain is not empty, then the
        certificate should be the signer of the front of the certificate chain.
        Note: This function does not verify the signature bits.

        :param CertificateV2 certificate: The certificate to add, which is
          copied.
        """
        self._certificateChain.insert(0, CertificateV2(certificate))

    def setOutcome(self, outcome):
        """
        Set the outcome to the given value, and set _hasOutcome True.

        :param bool outcome: The outcome.
        :raises: RuntimeError If this ValidationState already has an outcome.
        """
        if self._hasOutcome:
            raise RuntimeError("The ValidationState already has an outcome")

        self._hasOutcome = True
        self._outcome = outcome

    def _verifyOriginalPacket(self, trustedCertificate):
        """
        Verify the signature of the original packet. This is only called by the
        Validator class.

        :param CertificateV2 trustedCertificate: The certificate that signs the
          original packet.
        """
        raise RuntimeError(
          "ValidationState._verifyOriginalPacket is not implemented")

    def _bypassValidation(self):
        """
        Call the success callback of the original packet without signature
        validation. This is only called by the Validator class.
        """
        raise RuntimeError(
          "ValidationState._bypassValidation is not implemented")

    def _verifyCertificateChain(self, trustedCertificate):
        """
        Verify signatures of certificates in the certificate chain. On return,
        the certificate chain contains a list of certificates successfully
        verified by trustedCertificate.
        When the certificate chain cannot be verified, this method will call
        fail() with the INVALID_SIGNATURE error code and the appropriate message.
        This is only called by the Validator class.

        :return: The certificate to validate the original data packet, either
          the last entry in the certificate chain or trustedCertificate if the
          certificate chain is empty. However, return None if the signature of
          at least one certificate in the chain is invalid, in which case all
          unverified certificates have been removed from the certificate chain.
        :rtype: CertificateV2
        """
        validatedCertificate = trustedCertificate
        for i in range(len(self._certificateChain)):
            certificateToValidate = self._certificateChain[i]

            if not VerificationHelpers.verifyDataSignature(
                  certificateToValidate, validatedCertificate):
                self.fail(ValidationError(ValidationError.INVALID_SIGNATURE,
                  "Invalid signature of certificate `" +
                  certificateToValidate.getName().toUri() + "`"))
                # Remove this and remaining certificates in the chain.
                while len(self._certificateChain) > i:
                    self._certificateChain.pop(i)

                return None
            else:
                logging.getLogger(__name__).info(
                  "OK signature for certificate `" +
                  certificateToValidate.getName().toUri() + "`")
                validatedCertificate = certificateToValidate

        return validatedCertificate

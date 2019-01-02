# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
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
This module defines the ValidationPolicyFromPib class which extends
ValidationPolicy to implement a validator policy that validates a packet using
the default certificate of the key in the PIB that is named by the packet's
KeyLocator.
"""

from pyndn.interest import Interest
from pyndn.security.pib.pib_key import PibKey
from pyndn.security.v2.certificate_request import CertificateRequest
from pyndn.security.v2.validation_error import ValidationError
from pyndn.security.v2.validation_policy import ValidationPolicy

class ValidationPolicyFromPib(ValidationPolicy):
    """
    Create a ValidationPolicyFromPib to use the given PIB.

    :param Pib pib: The PIB with certificates.
    """
    def __init__(self, pib):
        super(ValidationPolicyFromPib, self).__init__()

        self._pib = pib

    def checkPolicy(self, dataOrInterest, state, continueValidation):
        """
        :param dataOrInterest:
        :type dataOrInterest: Data or Interest
        :param ValidationState state:
        :param continueValidation:
        :type continueValidation: function object
        """
        keyName = ValidationPolicy.getKeyLocatorName(dataOrInterest, state)
        if state.isOutcomeFailed():
            # Already called state.fail() .
            return

        self._checkPolicyHelper(keyName, state, continueValidation)

    def _checkPolicyHelper(self, keyName, state, continueValidation):
        """
        :param Name keyName:
        :param ValidationState state:
        :param continueValidation:
        :type continueValidation: function object
        """
        try:
            identity = self._pib.getIdentity(
              PibKey.extractIdentityFromKeyName(keyName))
        except Exception as ex:
            state.fail(ValidationError
              (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
               "Cannot get the PIB identity for key " + keyName.toUri() + ": " +
               repr(ex)))
            return

        try:
            key = identity.getKey(keyName)
        except Exception as ex:
            state.fail(ValidationError
              (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
               "Cannot get the PIB key " + keyName.toUri() + ": " + repr(ex)))
            return

        try:
            certificate = key.getDefaultCertificate()
        except Exception as ex:
            state.fail(ValidationError
              (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
               "Cannot get the default certificate for key " + keyName.toUri() +
               ": " + repr(ex)))
            return

        # Add the certificate as the temporary trust anchor.
        self._validator.resetAnchors()
        self._validator.loadAnchor("", certificate)
        continueValidation(CertificateRequest(Interest(keyName)), state)
        # Clear the temporary trust anchor.
        self._validator.resetAnchors()

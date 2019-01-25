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
This modules defines the DataValidationState class which extends ValidationState
to hold the validation state for a Data packet.
"""

import logging
from pyndn.interest import Interest
from pyndn.security.verification_helpers import VerificationHelpers
from pyndn.security.v2.validation_error import ValidationError
from pyndn.security.v2.validation_state import ValidationState

class InterestValidationState(ValidationState):
    """
    Create a InterestValidationState for the Interest packet. The caller must
    ensure that the state instance is valid until the validation finishes (i.e.,
    until validateCertificateChain() and validateOriginalPacket() have been
    called).

    :param Interest interest: The Date packet being validated, which is copied.
    :param successCallback: This calls successCallback(interest) to report a
      successful Interest validation.
    :type successCallback: function object
    :param failureCallback: This calls failureCallback(interest, error) to
      report a failed Interest validation, where error is a ValidationError.
    :type failureCallback: function object
    """
    def __init__(self, interest, successCallback, failureCallback):
        super(InterestValidationState, self).__init__()

        # Make a copy.
        self._interest = Interest(interest)
        self._successCallbacks = [successCallback] # of SuccessCallback function object
        self._failureCallback = failureCallback

        if successCallback == None:
            raise ValueError("The successCallback is None")
        if self._failureCallback == None:
            raise ValueError("The failureCallback is None")

    def fail(self, error):
        """
        Call the failure callback.

        :param ValidationError error:
        """
        logging.getLogger(__name__).info("" + str(error))
        try:
            self._failureCallback(self._interest, error)
        except:
            logging.exception("Error in failureCallback")

        self.setOutcome(False)

    def getOriginalInterest(self):
        """
        Get the original Interest packet being validated which was given to the
        constructor.

        :return: The original Interest packet.
        :rtype: Interest
        """
        return self._interest

    def addSuccessCallback(self, successCallback):
        """
        :param successCallback: This calls successCallback(interest).
        :type successCallback: function object
        """
        self._successCallbacks.append(successCallback)

    def _verifyOriginalPacket(self, trustedCertificate):
        """
        Verify the signature of the original packet. This is only called by the
        Validator class.

        :param CertificateV2 trustedCertificate: The certificate that signs the
          original packet.
        """
        if VerificationHelpers.verifyInterestSignature(
              self._interest, trustedCertificate):
            logging.getLogger(__name__).info("OK signature for interest `" +
              self._interest.getName().toUri() + "`")
            for i in range(len(self._successCallbacks)):
                try:
                    self._successCallbacks[i](self._interest)
                except:
                    logging.exception("Error in successCallback")

            self.setOutcome(True)
        else:
          self.fail(ValidationError(ValidationError.INVALID_SIGNATURE,
            "Invalid signature of interest `" + self._interest.getName().toUri() +
            "`"))

    def _bypassValidation(self):
        """
        Call the success callback of the original packet without signature
        validation. This is only called by the Validator class.
        """
        logging.getLogger(__name__).info(
          "Signature verification bypassed for interest `" +
          self._interest.getName().toUri() + "`")
        for i in range(len(self._successCallbacks)):
            try:
                self._successCallbacks[i](self._interest)
            except:
                logging.exception("Error in successCallback")

        self.setOutcome(True)


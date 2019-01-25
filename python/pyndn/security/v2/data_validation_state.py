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
from pyndn.data import Data
from pyndn.security.verification_helpers import VerificationHelpers
from pyndn.security.v2.validation_error import ValidationError
from pyndn.security.v2.validation_state import ValidationState

class DataValidationState(ValidationState):
    """
    Create a DataValidationState for the Data packet. The caller must ensure
    that the state instance is valid until the validation finishes (i.e., until
    validateCertificateChain() and validateOriginalPacket() have been called).

    :param Data data: The Date packet being validated, which is copied.
    :param successCallback: This calls successCallback(data) to report a
      successful Data validation.
    :type successCallback: function object
    :param failureCallback: This calls failureCallback(data, error) to report a
      failed Data validation, where error is a ValidationError.
    :type failureCallback: function object
    """
    def __init__(self, data, successCallback, failureCallback):
        super(DataValidationState, self).__init__()

        # Make a copy.
        self._data = Data(data)
        self._successCallback = successCallback
        self._failureCallback = failureCallback

        if self._successCallback == None:
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
            self._failureCallback(self._data, error)
        except:
            logging.exception("Error in failureCallback")

        self.setOutcome(False)

    def getOriginalData(self):
        """
        Get the original Data packet being validated which was given to the
        constructor.

        :return: The original Data packet.
        :rtype: Data
        """
        return self._data

    def _verifyOriginalPacket(self, trustedCertificate):
        """
        Verify the signature of the original packet. This is only called by the
        Validator class.

        :param CertificateV2 trustedCertificate: The certificate that signs the
          original packet.
        """
        if VerificationHelpers.verifyDataSignature(self._data, trustedCertificate):
            logging.getLogger(__name__).info("OK signature for data `" +
              self._data.getName().toUri() + "`")
            try:
                self._successCallback(self._data)
            except:
                logging.exception("Error in successCallback")

            self.setOutcome(True)
        else:
          self.fail(ValidationError(ValidationError.INVALID_SIGNATURE,
            "Invalid signature of data `" + self._data.getName().toUri() + "`"))

    def _bypassValidation(self):
        """
        Call the success callback of the original packet without signature
        validation. This is only called by the Validator class.
        """
        logging.getLogger(__name__).info("Signature verification bypassed for data `" +
          self._data.getName().toUri() + "`")
        try:
            self._successCallback(self._data)
        except:
            logging.exception("Error in successCallback")

        self.setOutcome(True)

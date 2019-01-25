# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/validation-policy.hpp
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
This module defines the ValidationPolicy class which is an abstract base class
that implements a validation policy for Data and Interest packets.
"""

from pyndn.name import Name
from pyndn.data import Data
from pyndn.key_locator import KeyLocator, KeyLocatorType
from pyndn.security.v2.validation_error import ValidationError
from pyndn.encoding.wire_format import WireFormat

class ValidationPolicy(object):
    def __init__(self):
        self._validator = None
        self._innerPolicy = None

    def setInnerPolicy(self, innerPolicy):
        """
        Set the inner policy.
        Multiple assignments of the inner policy will create a "chain" of linked
        policies. The inner policy from the latest invocation of setInnerPolicy
        will be at the bottom of the policy list.
        For example, the sequence `self.setInnerPolicy(policy1)` and
        `self.setInnerPolicy(policy2)`, will result in
        `self._innerPolicy == policy1`,
        `self._innerPolicy_._innerPolicy == policy2', and
        `self._innerPolicy._innerPolicy._innerPolicy == None`.

        :param ValidationPolicy innerPolicy:
        :raises: ValueError if the innerPolicy is None.
        """
        if innerPolicy == None:
            raise ValueError("The innerPolicy argument cannot be None")

        if self._validator != None:
            innerPolicy.setValidator(self._validator)

        if self._innerPolicy == None:
            self._innerPolicy = innerPolicy
        else:
            self._innerPolicy.setInnerPolicy(innerPolicy)

    def hasInnerPolicy(self):
        """
        Check if the inner policy is set.

        :return: True if the inner policy is set.
        :rtype: bool
        """
        return self._innerPolicy != None

    def getInnerPolicy(self):
        """
        Get the inner policy. If the inner policy was not set, the behavior is
        undefined.

        :return: The inner policy.
        :rtype: ValidationPolicy
        """
        return self._innerPolicy

    def setValidator(self, validator):
        """
        Set the validator to which this policy is associated. This replaces any
        previous validator.

        :param Validator validator: The validator.
        """
        self._validator = validator
        if self._innerPolicy != None:
            self._innerPolicy.setValidator(validator)

    def checkPolicy(self, dataOrInterest, state, continueValidation):
        """
        Check the Data or Interest packet against the policy. Your derived class
        must implement this. Depending on the implementation of the policy, this
        check can be done synchronously or asynchronously. The semantics of
        checkPolicy are as follows:
        If the packet violates the policy, then the policy should call
        state.fail() with an appropriate error code and error description.
        If the packet conforms to the policy and no further key retrievals are
        necessary, then the policy should call continueValidation(None, state).
        If the packet conforms to the policy and a key needs to be fetched, then
        the policy should call
        continueValidation({appropriate-key-request-instance}, state).

        :param dataOrInterest: The Data or Interest packet to check.
        :type dataOrInterest: Data or Interest
        :param ValidationState state: The ValidationState of this validation.
        :param continueValidation: The policy should call
          continueValidation() as described above.
        :type continueValidation: function object
        """
        raise RuntimeError("ValidationPolicy.checkPolicy is not implemented")

    def checkCertificatePolicy(self, certificate, state, continueValidation):
        """
        Check the certificate against the policy. This base class implementation
        just calls checkPolicy(certificate, ...). Your derived class may
        override. Depending on implementation of the policy, this check can be
        done synchronously or asynchronously. See the checkPolicy(Data)
        documentation for the semantics.

        :param CertificateV2 certificate: The certificate to check.
        :param ValidationState state: The ValidationState of this validation.
        :param continueValidation: The policy should call
          continueValidation() as described above.
        :type continueValidation: function object
        """
        self.checkPolicy(certificate, state, continueValidation)

    @staticmethod
    def getKeyLocatorName(dataOrInterest, state):
        """
        Extract the KeyLocator Name from a Data or signed Interest packet. The
        SignatureInfo in the packet must contain a KeyLocator of type KEYNAME.
        Otherwise, state.fail is invoked with INVALID_KEY_LOCATOR.

        :param dataOrInterest: The Data or Interest packet with the KeyLocator.
        :type dataOrInterest: Data or Interest
        :param ValidationState state: On error, this calls state.fail and
          returns an empty Name.
        :return: The KeyLocator name, or an empty Name for failure.
        :rtype: Name
        """
        if isinstance(dataOrInterest, Data):
            data = dataOrInterest
            return ValidationPolicy._getKeyLocatorNameFromSignature(
              data.getSignature(), state)
        else:
          interest = dataOrInterest

          name = interest.getName()
          if name.size() < 2:
              state.fail(ValidationError(ValidationError.INVALID_KEY_LOCATOR,
                "Invalid signed Interest: name too short"))
              return Name()

          try:
            # TODO: Generalize the WireFormat.
            signatureInfo = WireFormat.getDefaultWireFormat().decodeSignatureInfoAndValue(
              interest.getName().get(-2).getValue().buf(),
              interest.getName().get(-1).getValue().buf())
          except Exception as ex:
              state.fail(ValidationError(ValidationError.INVALID_KEY_LOCATOR,
                "Invalid signed Interest: " + repr(ex)))
              return Name()

          return ValidationPolicy._getKeyLocatorNameFromSignature(
            signatureInfo, state)

    @staticmethod
    def _getKeyLocatorNameFromSignature(signatureInfo, state):
        """
        A helper method for getKeyLocatorName.

        :param Signature signatureInfo:
        :param ValidationState state:
        :rtype: Name
        """
        if not KeyLocator.canGetFromSignature(signatureInfo):
            state.fail(ValidationError
              (ValidationError.INVALID_KEY_LOCATOR, "KeyLocator is missing"))
            return Name()

        keyLocator = KeyLocator.getFromSignature(signatureInfo)
        if keyLocator.getType() != KeyLocatorType.KEYNAME:
            state.fail(ValidationError
              (ValidationError.INVALID_KEY_LOCATOR, "KeyLocator type is not Name"))
            return Name()

        return keyLocator.getKeyName()

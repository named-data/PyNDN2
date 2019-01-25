# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/validation-error.cpp
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
This module defines the ValidationError class which holds an error code and an
optional detailed error message.
"""

class ValidationError(object):
    """
    Create a new ValidationError for the given code.

    :param int code: The code which is one of the standard error codes such as
      ValidationError.INVALID_SIGNATURE, or a custom code if greater than or
      equal to ValidationError.USER_MIN .
    :param str info: {optinal) The error message. If omitted, use an empty
      string.
    """
    def __init__(self, code, info = ""):
        self._code = code
        self._info = info

    NO_ERROR =                    0
    INVALID_SIGNATURE =           1
    NO_SIGNATURE =                2
    CANNOT_RETRIEVE_CERTIFICATE = 3
    EXPIRED_CERTIFICATE =         4
    LOOP_DETECTED =               5
    MALFORMED_CERTIFICATE =       6
    EXCEEDED_DEPTH_LIMIT =        7
    INVALID_KEY_LOCATOR =         8
    POLICY_ERROR =                9
    IMPLEMENTATION_ERROR =        255
    # Custom error codes should use >= USER_MIN.
    USER_MIN =                    256

    def getCode(self):
        """
        Get the error code given to the constructor.

        :return: The error code which is one of the standard error codes such as
          ValidationError.INVALID_SIGNATURE, or a custom code if greater than or
          equal to ValidationError.USER_MIN.
        :rtype: int
        """
        return self._code

    def getInfo(self):
        """
        Get the error message given to the constructor.

        :return: The error message, or "" if none.
        :rtype: str
        """
        return self._info

    def toString(self):
        """
        Get a string representation of this ValidationError.

        :return: The string representation.
        :rtype: str
        """
        if self._code == ValidationError.NO_ERROR:
            result = "No error"
        elif self._code == ValidationError.INVALID_SIGNATURE:
            result = "Invalid signature"
        elif self._code == ValidationError.NO_SIGNATURE:
            result = "Missing signature"
        elif self._code == ValidationError.CANNOT_RETRIEVE_CERTIFICATE:
            result = "Cannot retrieve certificate"
        elif self._code == ValidationError.EXPIRED_CERTIFICATE:
            result = "Certificate expired"
        elif self._code == ValidationError.LOOP_DETECTED:
            result = "Loop detected in certification chain"
        elif self._code == ValidationError.MALFORMED_CERTIFICATE:
            result = "Malformed certificate"
        elif self._code == ValidationError.EXCEEDED_DEPTH_LIMIT:
            result = "Exceeded validation depth limit"
        elif self._code == ValidationError.INVALID_KEY_LOCATOR:
            result = "Key locator violates validation policy"
        elif self._code == ValidationError.POLICY_ERROR:
            result = "Validation policy error"
        elif self._code == ValidationError.IMPLEMENTATION_ERROR:
            result = "Internal implementation error"
        elif self._code >= ValidationError.USER_MIN:
            result = "Custom error code " + str(self._code)
        else:
            result = "Unrecognized error code " + str(self._code)

        if len(self._info) > 0:
            result += " (" + self._info + ")"

        return result

    def __str__(self):
        return self.toString()

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/validation-policy-accept-all.hpp
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
This module defines the ValidationPolicyAcceptAll class which extends
ValidationPolicy to implement a validator policy that accepts any signature of a
Data or Interest packet.
"""

from pyndn.security.v2.validation_policy import ValidationPolicy

class ValidationPolicyAcceptAll(ValidationPolicy):
    def __init__(self):
        super(ValidationPolicyAcceptAll, self).__init__()

    def checkPolicy(self, dataOrInterest, state, continueValidation):
        """
        :param dataOrInterest:
        :type dataOrInterest: Data or Interest
        :param ValidationState state:
        :param continueValidation:
        :type continueValidation: function object
        """
        continueValidation(None, state)

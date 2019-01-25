# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/validator-null.hpp
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
This module defines the ValidatorNull class which extends Validator with an
"accept-all" policy and an offline certificate fetcher.
"""

from pyndn.security.v2.validator import Validator
from pyndn.security.v2.validation_policy_accept_all import ValidationPolicyAcceptAll
from pyndn.security.v2.certificate_fetcher_offline import CertificateFetcherOffline

class ValidatorNull(Validator):
    def __init__(self):
        super(ValidatorNull, self).__init__(
          ValidationPolicyAcceptAll(), CertificateFetcherOffline())


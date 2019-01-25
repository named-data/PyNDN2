# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/certificate-request.hpp
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
This module defines the CertificateRequest class which represents a request for
a certificate, associated with the number of retries left. The _interest and
_nRetriesLeft fields are public so that you can modify them. _interest is the
Interest for the requested Data packet or Certificate, and _nRetriesLeft is the
number of remaining retries after a timeout or NACK.
"""

from pyndn.interest import Interest

class CertificateRequest(object):
    """
    Create a CertificateRequest with an optional Interest.

    :param Interest interest: (optional) If supplied, create a
      CertificateRequest with a copy of the interest and 3 retries left. Of
      omitted, create a CertificateRequest with a default Interest object and 0
      retries left.
    """
    def __init__(self, interest):
        if interest != None:
            self._interest = Interest(interest)
            self._nRetriesLeft = 3
        else:
            self._interest = Interest()
            self._nRetriesLeft = 0

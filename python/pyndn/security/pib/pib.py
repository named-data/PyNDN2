# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/pib.cpp
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
This module defines the Pib class.
In general, a PIB (Public Information Base) stores the public portion of a
user's cryptography keys. The format and location of stored information is
indicated by the PIB locator. A PIB is designed to work with a TPM (Trusted
Platform Module) which stores private keys. There is a one-to-one association
between a PIB and a TPM, and therefore the TPM locator is recorded by the PIB
to enforce this association and prevent one from operating on mismatched PIB
and TPM.

Information in the PIB is organized in a hierarchy of
Identity-Key-Certificate. At the top level, this Pib class provides access to
identities, and allows setting a default identity. Properties of an identity
(such as PibKey objects) can be accessed after obtaining a PibIdentity object.
(Likewise, CertificateV2 objects can be obtained from a PibKey object.)

Note: A Pib instance is created and managed only by the KeyChain, and is
returned by the KeyChain getPib() method.
"""

class Pib(object):
    class Error(Exception):
        """
        Create a Pib.Error which represents a semantic error in PIB processing.

        :param str message: The error message.
        """
        def __init__(self, message):
            super(Pib.Error, self).__init__(message)

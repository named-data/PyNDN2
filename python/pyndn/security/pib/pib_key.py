# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017 Regents of the University of California.
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
This module defines the PibKey class which provides access to a key at the s
econd level in the PIB's Identity-Key-Certificate hierarchy. A PibKey object has
a Name (identity + "KEY" + keyId), and contains one or more CertificateV2
objects, one of which is set as the default certificate of this key. A
certificate can be directly accessed by getting a CertificateV2 object.
"""

from pyndn.security.v2.certificate_v2 import CertificateV2

class PibKey(object):

    @staticmethod
    def isValidKeyName(keyName):
        """
        Check if keyName follows the naming conventions for a key name.

        :param Name keyName: The name of the key.
        :return: True if keyName follows the naming conventions, otherwise False.
        :rtype bool:
        """
        return (keyName.size() > CertificateV2.MIN_KEY_NAME_LENGTH and
                keyName.get(-CertificateV2.MIN_KEY_NAME_LENGTH).equals
                  (CertificateV2.KEY_COMPONENT))

    @staticmethod
    def extractIdentityFromKeyName(keyName):
        """
        Extract the identity namespace from keyName.

        :param Name keyName: The name of the key.
        :return: The identity name as a new Name.
        :rtype: Name
        """
        if not PibKey.isValidKeyName(keyName):
            raise ValueError("Key name `" + keyName.toUri() +
               "` does not follow the naming conventions")

        # Trim everything after and including "KEY".
        return keyName.getPrefix(-CertificateV2.MIN_KEY_NAME_LENGTH)

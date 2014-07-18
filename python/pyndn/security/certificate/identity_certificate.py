# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
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
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU General Public License is in the file COPYING.
# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
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
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU General Public License is in the file COPYING.

from pyndn.security.certificate import Certificate
from pyndn.security.security_exception import SecurityException
from pyndn import Name,Data

"""
IdentityCertificate is a subclass of Certificate that provides convenience methods
for getting the public key name from the certificate name.
"""

class IdentityCertificate(Certificate):
    def __init__(self, value=None):
        """
        Create a new identity certificate.
        :param data: (optional) A Data object to copy the contents of
        :type data: Data
        :throws: SecurityException if the name of this Data object is 
        not a valid identity certificate name.
        """
        super(IdentityCertificate,self).__init__(value)

        if isinstance(value, Name):
            if not self._isCorrectName(self.getName()):
                raise SecurityException("Bad format for identity certificate name: " + self.getName().toUri())
        self._setPublicKeyName()

    @classmethod
    def _isCorrectName(cls, name):
        """
        Checks that the important name components are present
        """
        if cls._idxOfNameComponent(name, "ID-CERT") < 0 or cls._idxOfNameComponent(name, "KEY") < 0:
            return False

        return True

    @staticmethod
    def _idxOfNameComponent(name, string):
        """
        A helper method to locate name components
        """
        loc = -1
        for i in range(name.size()-1,0, -1):
            if name.get(i).toEscapedString() == string:
                loc = i
                break
        return loc

    def wireDecode(self, buf, wireFormat = None):
        """
        Data.wireDecode does not call setName, so we must make sure to update our public key name
        """
        Certificate.wireDecode(self, buf, wireFormat)
        self._setPublicKeyName()

    def getPublicKeyName(self):
        """
        :return: The name of the public key associated with this certificate
        :rtype: Name
        """
        return self._publicKeyName

    def setName(self, name):
        """
        Overrides Data.setName() to ensure that the new name is a valid identity 
        certificate name.
        :param name: The new name for this IdentityCertificate
        :type name: Name
        """
        if (not self._isCorrectName(name)):
            raise SecurityException("Bad format for identity certificate name!")

        Data.setName(self, name)
        self._setPublicKeyName()

    def _setPublicKeyName(self):
        """
        Private. Get the public key name from the name of this Data packet.
        """
        self._publicKeyName = self.certificateNameToPublicKeyName(self.getName())

    @classmethod
    def certificateNameToPublicKeyName(cls, certName):
        """
        Extract the name of a public key from the name of an identity certificate.
        :param certName: The certificate name
        :type certName: Name
        """
        if certName.size() == 0:
            return Name()

        certComponentIdx = cls._idxOfNameComponent(certName, "ID-CERT")

        if certComponentIdx < 0:
            raise SecurityException("Bad format for identity certificate name")
        tempName = certName.getSubName(0,certComponentIdx)

        keyComponentIdx = cls._idxOfNameComponent(tempName, "KEY")

        if keyComponentIdx < 0:
            raise SecurityException("Bad format for identity certificate name")
        # skip the /KEY/ component
        return tempName.getSubName(0, keyComponentIdx).append(
          tempName.getSubName(keyComponentIdx + 1))


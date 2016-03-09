# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
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

from pyndn.security.certificate.certificate import Certificate
from pyndn.security.security_exception import SecurityException
from pyndn.name import Name
from pyndn.data import Data

"""
IdentityCertificate is a subclass of Certificate that provides convenience methods
for getting the public key name from the certificate name.
"""

class IdentityCertificate(Certificate):
    def __init__(self, data = None):
        """
        Create a new identity certificate.
        :param data: (optional) A Data object to copy the contents of
        :type data: Data
        :throws: SecurityException if the name of this Data object is
        not a valid identity certificate name.
        """
        super(IdentityCertificate,self).__init__(data)

        if isinstance(data, IdentityCertificate):
            # The copy constructor.
            self._publicKeyName = Name(data._publicKeyName)
        elif isinstance(data, Data):
            if not self._isCorrectName(data.getName()):
                raise SecurityException("Wrong Identity Certificate Name!")

            self._setPublicKeyName()

    @staticmethod
    def _isCorrectName(name):
        """
        Checks that the important name components are present
        """
        i = name.size() - 1

        idString = "ID-CERT"
        while i >= 0:
            if name.get(i).toEscapedString() == idString:
                break
            i -= 1

        if i < 0:
            return False

        keyIdx = 0
        keyString = "KEY"
        while keyIdx < name.size():
            if name.get(keyIdx).toEscapedString() == keyString:
                break
            keyIdx += 1

        if keyIdx >= name.size():
            return False

        return True

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

    @staticmethod
    def certificateNameToPublicKeyName(certificateName):
        """
        Extract the name of a public key from the name of an identity certificate.
        :param Name certificateName: The certificate name.
        """
        idString = "ID-CERT"
        foundIdString = False
        idCertComponentIndex = certificateName.size() - 1
        while idCertComponentIndex + 1 > 0:
            if certificateName.get(idCertComponentIndex).toEscapedString() == idString:
                foundIdString = True
                break

            idCertComponentIndex -= 1

        if not foundIdString:
            raise RuntimeError(
              "Incorrect identity certificate name " + certificateName.toUri())

        tempName = certificateName.getSubName(0, idCertComponentIndex)
        keyString = "KEY"
        foundKeyString = False
        keyComponentIndex = 0
        while keyComponentIndex < tempName.size():
            if tempName.get(keyComponentIndex).toEscapedString() == keyString:
                foundKeyString = True
                break

            keyComponentIndex += 1

        if not foundKeyString:
            raise RuntimeError(
              "Incorrect identity certificate name " + certificateName.toUri())

        return (tempName
          .getSubName(0, keyComponentIndex)
          .append(tempName.getSubName
                  (keyComponentIndex + 1, tempName.size() - keyComponentIndex - 1)))

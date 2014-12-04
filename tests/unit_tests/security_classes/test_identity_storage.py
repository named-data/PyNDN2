# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Adeola Bannis <thecodemaiden@gmail.com>
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
This module is based on the BasicIdentityStorage class
"""
from pyndn.util import Blob
from pyndn.security.certificate import IdentityCertificate
from pyndn.security.security_exception import SecurityException
from pyndn import Name, Data
from pyndn.security.identity.basic_identity_storage import BasicIdentityStorage
import base64

class TestIdentityStorage(BasicIdentityStorage):
    def getAllKeyNamesOfIdentity(self, identityName, nameList, isDefault):
        """
        Append all the key names of a particular identity to the nameList.

        :param Name identityName: The identity name to search for.
        :param Array<Name> nameList: Append result names to nameList.
        :param bool isDefault: If true, add only the default key name. If false,
          add only the non-default key names.
        """
        if isDefault:
            query = "SELECT key_identifier FROM Key WHERE default_key=1 and identity_name=?"
        else:
            query = "SELECT key_identifier FROM Key WHERE default_key=0 and identity_name=?"

        cursor = self._database.cursor()
        cursor.execute(query, (identityName.toUri(), ))
        keyIds = cursor.fetchall()
        for (keyId, ) in keyIds:
            nameList.append(Name(identityName).append(keyId))
        cursor.close()

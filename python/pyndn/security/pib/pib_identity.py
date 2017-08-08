# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/identity.cpp
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
This module defines the PibIdentity class which is at the top level in PIB's
Identity-Key-Certificate hierarchy. An identity has a Name, and contains zero or
more keys, at most one of which is set as the default key of this identity.
Properties of a key can be accessed after obtaining a Key object.
"""

class PibIdentity(object):
    """
    Create a PibIdentity which uses the impl backend implementation. This
    constructor should only be called by PibIdentityContainer.
    """
    def __init__(self, impl):
        self._impl = impl

    def getName(self):
        """
        Get the name of the identity.

        :return: The name of the identity. You must not change the Name object.
          If you need to change it then make a copy.
        :rtype: Name
        :raises ValueError: If the backend implementation instance is invalid.
        """
        return self._lock().getName()

    def getKey(self, keyName):
        """
        Get the key with name keyName.

        :param Name keyName: The name of the key.
        :return: The PibKey object.
        :rtype: PibKey
        :raises ValueError: If keyName does not match the identity name, or if
          the backend implementation instance is invalid.
        :raises Pib.Error: if the key does not exist.
        """
        return self._lock().getKey(keyName)

    def getDefaultKey(self):
        """
        Get the default key of this Identity.

        :return: The default PibKey.
        :rtype: PibKey
        :raises ValueError: If the backend implementation instance is invalid.
        :raises Pib.Error: If the default key has not been set.
        """
        return self._lock().getDefaultKey()

    def _lock(self):
        """
        Check the validity of the _impl instance.

        :return: The PibIdentityImpl when the instance is valid.
        :rtype: PibIdentityImpl
        :raises ValueError: If the backend implementation instance is invalid.
        """
        if self._impl == None:
            raise ValueError("Invalid Identity instance")

        return self._impl

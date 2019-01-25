# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/pib/key-container.cpp
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
This module defines the PibKeyContainer class which is used to search/enumerate
the keys of an identity. (A PibKeyContainer object can only be created by
PibIdentity.)
"""

from pyndn.name import Name
from pyndn.security.pib.pib_key import PibKey
from pyndn.security.pib.detail.pib_key_impl import PibKeyImpl

class PibKeyContainer(object):
    """
    Create a PibKeyContainer for an identity with identityName. This constructor
    should only be called by PibIdentityImpl.

    :param Name identityName: The name of the identity, which is copied.
    :param PibImpl pibImpl: The PIB backend implementation.
    """
    def __init__(self, identityName, pibImpl):
        # Cache of loaded PibKeyImpl objects. Name => PibKeyImpl.
        self._keys = {}

        # Copy the Name.
        self._identityName = Name(identityName)
        self._pibImpl = pibImpl

        if pibImpl == None:
            raise ValueError("The pibImpl is None")

        self._keyNames = self._pibImpl.getKeysOfIdentity(identityName)

    def size(self):
        """
        Get the number of keys in the container.

        :return: The number of keys.
        :rtype: int
        """
        return len(self._keyNames)

    def add(self, key, keyName):
        """
        Add a key with name keyName into the container. If a key with the same
        name already exists, this replaces it.

        :param key: The buffer of encoded key bytes.
        :type key: an array which implements the buffer protocol
        :param Name keyName: The name of the key, which is copied.
        :return: The PibKey object.
        :rtype: PibKey
        :raises ValueError: If the name of the key does not match the identity
          name.
        """
        if not self._identityName.equals(PibKey.extractIdentityFromKeyName(keyName)):
            raise ValueError("The key name `" + keyName.toUri() +
              "` does not match the identity name `" +
              self._identityName.toUri() + "`")

        # Copy the Name.
        self._keyNames.add(Name(keyName))
        self._keys[Name(keyName)] = PibKeyImpl(keyName, key, self._pibImpl)

        return self.get(keyName)

    def remove(self, keyName):
        """
        Remove the key with name keyName from the container, and its related
        certificates. If the key does not exist, do nothing.

        :param Name keyName: The name of the key.
        :raises ValueError: If keyName does not match the identity name.
        """
        if not self._identityName.equals(PibKey.extractIdentityFromKeyName(keyName)):
          raise ValueError("Key name `" + keyName.toUri() +
            "` does not match identity `" + self._identityName.toUri() + "`")

        try:
            self._keyNames.remove(keyName)
        except KeyError:
            # Do nothing if it doesn't exist.
            pass

        try:
            del self._keys[keyName]
        except KeyError:
            # Do nothing if it doesn't exist.
            pass

        self._pibImpl.removeKey(keyName)

    def get(self, keyName):
        """
        Get the key with name keyName from the container.

        :param Name keyName: The name of the key.
        :return: The PibKey object.
        :rtype: PibKey
        :raises ValueError: If keyName does not match the identity name.
        :raises Pib.Error: If the key does not exist.
        """
        if not self._identityName.equals(PibKey.extractIdentityFromKeyName(keyName)):
            raise ValueError("Key name `" + keyName.toUri() +
              "` does not match identity `" + self._identityName.toUri() + "`")

        try:
            pibKeyImpl = self._keys[keyName]
        except KeyError:
            pibKeyImpl = None

        if pibKeyImpl == None:
          pibKeyImpl = PibKeyImpl(keyName, self._pibImpl)
          # Copy the Name.
          self._keys[Name(keyName)] = pibKeyImpl

        return PibKey(pibKeyImpl)

    def getKeyNames(self):
        """
        Get the names of all the keys in the container.

        :return:  A new list of Name.
        :rtype: Array<Name>
        """
        result = []

        for name in self._keys:
            # Copy the Name.
            result.append(Name(name))

        return result

    def isConsistent(self):
        """
        Check if the container is consistent with the backend storage.

        :return: True if the container is consistent, False otherwise.
        :rtype: bool
        :note: This method is heavy-weight and should be used in a debugging
          mode only.
        """
        return self._keyNames == self._pibImpl.getKeysOfIdentity(self._identityName)

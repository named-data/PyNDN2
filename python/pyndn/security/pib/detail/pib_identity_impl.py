# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/pib/detail/identity-impl.cpp
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
This module defines the PibIdentityImpl class which provides the backend
implementation for PibIdentity. A PibIdentity has only one backend instance, but
may have multiple frontend handles. Each frontend handle is associated with the
only one backend PibIdentityImpl.
"""

from pyndn.name import Name
from pyndn.security.pib.pib_key_container import PibKeyContainer
from pyndn.security.pib.pib import Pib

class PibIdentityImpl(object):
    """
    Create a PibIdentityImpl with identityName.

    :param Name identityName: The name of the identity, which is copied.
    :param PibImpl pibImpl: The Pib backend implementation.
    :param bool needInit: If true and the identity does not exist in the pibImpl
      back end, then create it (and If no default identity has been set,
      identityName becomes the default). If false, then throw Pib.Error if the
      identity does not exist in the pibImpl back end.
    :raises Pib.Error: If the identity does not exist in the pibImpl back end
      and needInit is false.
    """
    def __init__(self, identityName, pibImpl, needInit):
        self._defaultKey = None

        # Copy the Name.
        self._identityName = Name(identityName)
        self._keys = PibKeyContainer(identityName, pibImpl)
        self._pibImpl = pibImpl

        if pibImpl == None:
            raise ValueError("The pibImpl is None")

        if needInit:
            self._pibImpl.addIdentity(self._identityName)
        else:
            if not self._pibImpl.hasIdentity(self._identityName):
                raise Pib.Error("Identity " + self._identityName.toUri() +
                  " does not exist")

    def getName(self):
        """
        Get the name of the identity.

        :return: The name of the identity. You must not change the Name object.
          If you need to change it then make a copy.
        :rtype: Name
        """
        return self._identityName

    def addKey(self, key, keyName):
        """
        Add the key. If a key with the same name already exists, overwrite the
        key. If no default key for the identity has been set, then set the added
        key as default for the identity.

        :param key: The public key bits. This copies the buffer.
        :type key: an array which implements the buffer protocol
        :param Name keyName: The name of the key. This copies the name.
        :return: The PibKey object.
        :rtype: PibKey
        """
        # BOOST_ASSERT(keys_.isConsistent())

        return self._keys.add(key, keyName)

    def removeKey(self, keyName):
        """
        Remove the key with keyName and its related certificates. If the key
        does not exist, do nothing.

        :param Name keyName: The name of the key.
        """
        # BOOST_ASSERT(keys_.isConsistent())

        if (self._defaultKey != None and
            self._defaultKey.getName().equals(keyName)):
            self._defaultKey = None

        self._keys.remove(keyName)

    def getKey(self, keyName):
        """
        Get the key with name keyName.

        :param Name keyName: The name of the key.
        :return: The PibKey object.
        :rtype: PibKey
        :raises ValueError: If keyName does not match the identity name.
        :raises Pib.Error: If the key does not exist.
        """
        # BOOST_ASSERT(keys_.isConsistent())

        return self._keys.get(keyName)

    def setDefaultKey(self, keyOrKeyName, arg2 = None):
        """
        setDefaultKey has two forms:
        setDefaultKey(keyName) - Set the key with name keyName as the default
        key of the identity.
        setDefaultKey(key, keyName) - Add a key with name keyName and set it as
        the default key of the identity.

        :param key: The buffer of encoded key bytes. (This is only used when
          calling setDefaultKey(key, keyName). )
        :type key: an array which implements the buffer protocol
        :param Name keyName: The name of the key. This copies the name.
        :return: The PibKey object of the default key.
        :rtype: PibKey
        :raises ValueError: If the name of the key does not match the identity
          name.
        :raises Pib.Error: If calling setDefaultKey(keyName) and the key does
          not exist, or if calling setDefaultKey(key, keyName) and a key with
          the same name already exists.
        """
        # BOOST_ASSERT(keys_.isConsistent())

        if isinstance(keyOrKeyName, Name):
            keyName = keyOrKeyName

            self._defaultKey = self._keys.get(keyName)
            self._pibImpl.setDefaultKeyOfIdentity(self._identityName, keyName)
            return self._defaultKey
        else:
            key = keyOrKeyName
            keyName = arg2

            self.addKey(key, keyName)
            return self.setDefaultKey(keyName)

    def getDefaultKey(self):
        """
        Get the default key of this Identity.

        :return: The default PibKey.
        :rtype: PibKey
        :raises Pib.Error: If the default key has not been set.
        """
        # BOOST_ASSERT(keys_.isConsistent())

        if self._defaultKey == None:
            self._defaultKey = self._keys.get(
              self._pibImpl.getDefaultKeyOfIdentity(self._identityName))

        # BOOST_ASSERT(pibImpl_->getDefaultKeyOfIdentity(identityName_) == defaultKey_.getName());

        return self._defaultKey

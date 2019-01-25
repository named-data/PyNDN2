# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/pib/identity.cpp
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
Properties of a key can be accessed after obtaining a PibKey object.
"""

class PibIdentity(object):
    """
    Create a PibIdentity which uses the impl backend implementation. This
    constructor should only be called by PibIdentityContainer.

    :param PibIdentityImpl impl: The PibIdentityImpl.
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

    def _addKey(self,  key, keyName):
        """
        Add the key. If a key with the same name already exists, overwrite the
        key. If no default key for the identity has been set, then set the added
        key as default for the identity. This should only be called by KeyChain.

        :param key: The public key bits. This copies the buffer.
        :type key: an array which implements the buffer protocol
        :param Name keyName: The name of the key. This copies the name.
        :return: The PibKey object.
        :rtype: PibKey
        """
        return self._lock().addKey(key, keyName)

    def _removeKey(self, keyName):
        """
        Remove the key with keyName and its related certificates. If the key
        does not exist, do nothing. This should only be called by KeyChain.

        :param Name keyName: The name of the key.
        """
        self._lock().removeKey(keyName)

    def _setDefaultKey(self, keyOrKeyName, arg2 = None):
        """
        setDefaultKey has two forms:
        setDefaultKey(keyName) - Set the key with name keyName as the default
        key of the identity.
        setDefaultKey(key, keyName) - Add a key with name keyName and set it as
        the default key of the identity. This should only be called by KeyChain.

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
        return self._lock().setDefaultKey(keyOrKeyName, arg2)

    def _getKeys(self):
        """
        Get the PibKeyContainer in the PibIdentityImpl. This should only be
        called by KeyChain.

        :rtype: PibKeyContainer
        """
        return self._lock()._keys

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

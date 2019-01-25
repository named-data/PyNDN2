# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/pib/identity-container.cpp
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
This module defines the PibIdentityContainer class which is used to
search/enumerate the identities in a PIB. (A PibIdentityContainer object can
only be created by the Pib class.)
"""

from pyndn.name import Name
from pyndn.security.pib.detail.pib_identity_impl import PibIdentityImpl
from pyndn.security.pib.pib_identity import PibIdentity

class PibIdentityContainer(object):
    """
    Create a PibIdentityContainer using to use the pibImpl backend
    implementation. This constructor should only be called by the Pib class.

    :param PibImpl pibImpl: The PIB backend implementation.
    """
    def __init__(self, pibImpl):
        # Cache of loaded PibIdentityImpl objects. Name => PibIdentityImpl.
        self._identities = {}

        self._pibImpl = pibImpl

        if pibImpl == None:
            raise ValueError("The pibImpl is None")

        self._identityNames = self._pibImpl.getIdentities()

    def size(self):
        """
        Get the number of identities in the container.

        :return: The number of identities.
        :rtype: int
        """
        return len(self._identityNames)

    def add(self, identityName):
        """
        Add an identity with name identityName into the container. Create the
        identity if it does not exist.

        :param Name identityName: The name of the identity, which is copied.
        :return: The PibIdentity object.
        :rtype: PibIdentity
        """
        if not identityName in self._identityNames:
            identityNameCopy =  Name(identityName)
            self._identityNames.add(identityNameCopy)
            self._identities[identityNameCopy] = PibIdentityImpl(
              identityName, self._pibImpl, True)

        return self.get(identityName)

    def remove(self, identityName):
        """
        Remove the identity with name identityName from the container, and its
        related keys and certificates. If the default identity is being removed,
        no default identity will be selected.  If the identity does not exist,
        do nothing.

        :param Name identityName: The name of the identity.
        """
        try:
           self._identityNames.remove(identityName)
        except KeyError:
            # Do nothing if it doesn't exist.
            pass

        try:
            del self._identities[identityName]
        except KeyError:
            # Do nothing if it doesn't exist.
            pass

        self._pibImpl.removeIdentity(identityName)

    def get(self, identityName):
        """
        Get the identity with name identityName from the container.

        :param Name identityName: The name of the identity.
        :return: The PibIdentity object.
        :rtype: PibIdentity
        :raises Pib.Error: If the identity does not exist.
        """
        try:
            pibIdentityImpl = self._identities[identityName]
        except KeyError:
            pibIdentityImpl = None

        if pibIdentityImpl == None:
            pibIdentityImpl = PibIdentityImpl(identityName, self._pibImpl, False)
            # Copy the Name.
            self._identities[Name(identityName)] = pibIdentityImpl

        return PibIdentity(pibIdentityImpl)

    def reset(self):
        """
        Reset the state of the container. This method removes all loaded
        identities and retrieves identity names from the PIB implementation.
        """
        self._identities = {}
        self._identityNames = self._pibImpl.getIdentities()

    def isConsistent(self):
        """
        Check if the container is consistent with the backend storage.

        :return:  True if the container is consistent, False otherwise.
        :rtype: bool
        :note: This method is heavy-weight and should be used in a debugging
          mode only.
        """
        return self._identityNames == self._pibImpl.getIdentities()

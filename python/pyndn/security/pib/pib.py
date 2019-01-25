# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/pib/pib.cpp
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
    """
    Create a Pib instance. This constructor should only be called by KeyChain.

    :param str scheme: The scheme for the PIB.
    :param str location: The location for the PIB.
    :param PibImpl pibImpl: The PIB backend implementation.
    """
    def __init__(self, scheme, location, pibImpl):
        self._defaultIdentity = None
        self._scheme = scheme
        self._location = location
        self._identities = PibIdentityContainer(pibImpl)
        self._pibImpl = pibImpl

        if pibImpl == None:
            raise ValueError("The pibImpl is None")

    class Error(Exception):
        """
        Create a Pib.Error which represents a semantic error in PIB processing.

        :param str message: The error message.
        """
        def __init__(self, message):
            super(Pib.Error, self).__init__(message)

    def getScheme(self):
        """
        Get the scheme of the PIB locator.

        :return: The scheme string.
        :rtype: str
        """
        return self._scheme

    def getPibLocator(self):
        """
        Get the PIB locator.

        :return: The PIB locator.
        :type: str
        """
        return self._scheme + ":" + self._location

    def setTpmLocator(self, tpmLocator):
        """
        Set the corresponding TPM information to tpmLocator. If the tpmLocator
        is different from the existing one, the PIB will be reset. Otherwise,
        nothing will be changed.

        :param str tpmLocator: The TPM locator.
        """
        if tpmLocator == self._pibImpl.getTpmLocator():
            return

        self._reset
        self._pibImpl.setTpmLocator(tpmLocator)

    def getTpmLocator(self):
        """
        Get the TPM Locator.

        :return: The TPM Locator.
        :rtype: str
        :raises Pib.Error: If the TPM locator is empty.
        """
        tpmLocator = self._pibImpl.getTpmLocator()
        if tpmLocator == "":
            raise Pib.Error("TPM info does not exist")

        return tpmLocator

    def getIdentity(self, identityName):
        """
        Get the identity with name identityName.

        :param Name identityName: The name of the identity.
        :return: The PibIdentity object.
        :rtype: PibIdentity
        :raises Pib.Error: If the identity does not exist.
        """
        # BOOST_ASSERT(identities_.isConsistent()).

        return self._identities.get(identityName)

    def getDefaultIdentity(self):
        """
        Get the default identity.

        :return: The PibIdentity object.
        :rtype: PibIdentity
        :raises Pib.Error: If there is no default identity.
        """
        # BOOST_ASSERT(identities_.isConsistent())

        if self._defaultIdentity == None:
            self._defaultIdentity = self._identities.get(
              self._pibImpl.getDefaultIdentity())

        # BOOST_ASSERT(pibImpl_->getDefaultIdentity() == defaultIdentity_->getName())

        return self._defaultIdentity

    def _reset(self):
        """
        Reset the content in the PIB, including a reset of the TPM locator. This
        should only be called by KeyChain.
        """
        self._pibImpl.clearIdentities()
        self._pibImpl.setTpmLocator("")
        self._defaultIdentity = None
        self._identities.reset()

    def _addIdentity(self, identityName):
        """
        Add an identity with name identityName. Create the identity if it does
        not exist. This should only be called by KeyChain.

        :param Name identityName: The name of the identity, which is copied.
        :return: The PibIdentity object.
        :rtype: PibIdentity
        """
        # BOOST_ASSERT(identities_.isConsistent())

        return self._identities.add(identityName)

    def _removeIdentity(self, identityName):
        """
        Remove the identity with name identityName, and its related keys and
        certificates. If the default identity is being removed, no default
        identity will be selected.  If the identity does not exist, do nothing.
        This should only be called by KeyChain.

        :param Name identityName: The name of the identity.
        """
        # BOOST_ASSERT(identities_.isConsistent())

        if (self._defaultIdentity != None and
            self._defaultIdentity.getName().equals(identityName)):
            self._defaultIdentity = None

        self._identities.remove(identityName)

    def _setDefaultIdentity(self, identityName):
        """
        Set the identity with name identityName as the default identity. Create
        the identity if it does not exist. This should only be called by
        KeyChain.

        :param Name identityName: The name of the identity.
        :return: The PibIdentity object of the default identity.
        :rtype: PibIdentity
        """
        # BOOST_ASSERT(identities_.isConsistent())

        self._defaultIdentity = self._identities.add(identityName)

        self._pibImpl.setDefaultIdentity(identityName)
        return self._defaultIdentity

# Put this last to avoid an import loop.
from pyndn.security.pib.pib_identity_container import PibIdentityContainer

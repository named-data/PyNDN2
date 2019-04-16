# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From the PSync library https://github.com/named-data/PSync/blob/master/PSync/producer-base.cpp
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
This module defines the PSyncProducerBase class which is a base class for
PsyncPartialProducer and FullPSync2017.
"""

import logging
from pyndn.name import Name
from pyndn.sync.detail.invertible_bloom_lookup_table import InvertibleBloomLookupTable
from pyndn.util.common import Common

class PSyncProducerBase(object):
    """
    Create a PSyncProducerBase.

    :param int expectedNEntries: The expected number of entries in the IBLT.
    :param Name syncPrefix The prefix Name of the sync group, which is copied.
    :param float syncReplyFreshnessPeriod: The freshness period of the sync Data
      packet, in milliseconds.
    """
    def __init__(self, expectedNEntries, syncPrefix, syncReplyFreshnessPeriod):
        self._iblt = InvertibleBloomLookupTable(expectedNEntries)
        self._expectedNEntries = expectedNEntries
        self._threshold  = int(expectedNEntries / 2)
        self._syncPrefix = Name(syncPrefix)
        self._syncReplyFreshnessPeriod = syncReplyFreshnessPeriod

        # _nameToHash and _hashToName are just for looking up the hash more
        # quickly (instead of calculating it again).
        # The key is the Name. The value is the hash.
        self._nameToHash = {}
        # The key is the hash. The value is the Name.
        self._hashToName = {}

    def insertIntoIblt(self, name):
        """
        Insert the URI of the name into the _iblt, and update _nameToHash and
        _hashToName.

        :param Name name: The Name to insert.
        """
        newHash = Common.murmurHash3Blob(
          InvertibleBloomLookupTable.N_HASHCHECK, name.toUri())

        nameCopy = Name(name)
        self._nameToHash[nameCopy] = newHash
        self._hashToName[newHash] = nameCopy
        self._iblt.insert(newHash)

    def removeFromIblt(self, name):
        """
        If the Name is in _nameToHash, then remove the hash from the _iblt,
        _nameToHash and _hashToName. However, if the Name is not in _nameToHash
        then do nothing.

        :param Name name: The Name to remove.
        """
        if name in self._nameToHash:
            hashValue = self._nameToHash[name]
            del self._nameToHash[name]
            del self._hashToName[hashValue]
            self._iblt.erase(hashValue)

    @staticmethod
    def onRegisterFailed(prefix):
        """
        This is called when registerPrefix fails to log an error message.
        """
        logging.getLogger(__name__).error(
          "PSyncProduerBase: Failed to register prefix " + prefix.toUri())

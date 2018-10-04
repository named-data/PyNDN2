# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/ims/in-memory-storage-persistent.cpp
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
This module defines the InMemoryStorageRetaining class, which provides an
application cache with in-memory storage, of which no eviction policy will be
employed. Entries will only be evicted by explicit application control.
Note: In ndn-cxx, this class is called InMemoryStoragePersistent, but
"persistent" misleadingly sounds like persistent on-disk storage.
"""

from pyndn.data import Data

class InMemoryStorageRetaining(object):
    """
    Create an empty InMemoryStorageRetaining.
    """
    def __init__(self):
        # The dictionary key is the Data packet Name. The value is a Data.
        self._cache = {}

    def insert(self, data):
        """
        Insert a Data packet. If a Data packet with the same name, including the
        implicit digest, already exists, replace it.

        :param Data data: The packet to insert, which is copied.
        """
        self._cache[data.getFullName()] = Data(data)

    def find(self, interest):
        """
        Find the best match Data for an Interest.

        :param Interest interest: The Interest with the Name of the Data packet
          to find.
        :return: The best match if any, otherwise None. You should not modify
          the returned object. If you need to modify it then you must make a copy.
        :rtype: Data
        """
        for name, data in self._cache.items():
            # Debug: Check selectors, especially CanBePrefix.
            if interest.getName().isPrefixOf(name):
                return data

        return None

    def size(self):
        """
        Get the number of packets stored in the in-memory storage.

        :return: The number of packets.
        :rtype: int
        """
        return len(self._cache)
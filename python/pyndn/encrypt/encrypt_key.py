# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
# Author: From ndn-group-encrypt src/encrypt-key https://github.com/named-data/ndn-group-encrypt
#
# Copyright (C) 2015-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
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
This module defines the EncryptKey class which supplies the key for encrypt.
Note: This class is an experimental feature. The API may change.
"""

from pyndn.util.blob import Blob

class EncryptKey(object):
    """
    Create an EncryptKey with the given key value.

    :param value: If value is another EncryptKey then copy it. Otherwise, value
      is the key value.
    :type value: Blob or EncryptKey
    """
    def __init__(self, value):
        if type(value) is EncryptKey:
            # Make a deep copy.
            self._keyBits = value._keyBits
        else:
            keyBits = value
            self._keyBits = keyBits if isinstance(keyBits, Blob) else Blob(keyBits)

    def getKeyBits(self):
        """
        Get the key value.

        :return: The key value.
        :rtype: Blob
        """
        return self._keyBits

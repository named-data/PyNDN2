# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx packet.hpp https://github.com/named-data/ndn-cxx/blob/master/src/lp/packet.hpp
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
This module defines the LpPacket class which represents an NDNLPv2 packet
including header fields an an optional fragment. This is an internal class which
the application normally would not use.
http://redmine.named-data.net/projects/nfd/wiki/NDNLPv2
"""

from pyndn.util.blob import Blob

class LpPacket(object):
    def __init__(self):
        self._headerFields = []
        self._fragmentWireEncoding = Blob()

    def getFragmentWireEncoding(self):
        """
        Get the fragment wire encoding.

        :return:  The wire encoding, or an isNull Blob if not specified.
        :rtype: Blob
        """
        return self._fragmentWireEncoding

    def countHeaderFields(self):
        """
        Get the number of header fields. This does not include the fragment.

        :return: The number of header fields.
        :rtype: int
        """
        return len(self._headerFields)

    def getHeaderField(self, index):
        """
        Get the header field at the given index.
        
        :param int index: The index, starting from 0. It is an error if index is
           greater to or equal to countHeaderFields().
        :return: The header field at the index.
        :rtype: object
        """
        return self._headerFields[index]

    def clear(self):
        """
        Remove all header fields and set the fragment to an isNull Blob.
        """
        self._headerFields = []
        self._fragmentWireEncoding = Blob()

    def setFragmentWireEncoding(self, fragmentWireEncoding):
        """
        Set the fragment wire encoding.

        :param Blob fragmentWireEncoding: The fragment wire encoding or an
          isNull Blob if not specified.
        """
        self._fragmentWireEncoding = (
          fragmentWireEncoding if isinstance(fragmentWireEncoding, Blob)
            else Blob(fragmentWireEncoding))

    def addHeaderField(self, headerField):
        """
        Add a header field. To add the fragment, use setFragmentWireEncoding().
        
        :param object headerField: The header field to add.
        """
        self._headerFields.append(headerField)

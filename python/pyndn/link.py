# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2016 Regents of the University of California.
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
This module defines the Link class which extends Data and represents a Link instance
where the Data content is an encoded delegation set. The format is defined in
"link.pdf" attached to Redmine issue http://redmine.named-data.net/issues/2587 .
"""

from pyndn.data import Data
from pyndn.meta_info import ContentType
from pyndn.delegation_set import DelegationSet
from pyndn.encoding.wire_format import WireFormat

class Link(Data):
    def __init__(self, value = None):
        """
        Create a new Link with the optional values. There are 3 forms of the
        constructor:
        Link(name)
        Link(data)
        Link()

        :param Name name: The name for constructing the base Data.
        :param Data data: The Data object to copy values from. If the content
          can be decoded using the default wire encoding, then update the list
          of delegations.
        """
        self._delegations = DelegationSet()

        if isinstance(value, Data):
            super(Link, self).__init__(value)

            if not self.getContent().isNull():
                try:
                    self._delegations.wireDecode(self.getContent())
                    self.getMetaInfo().setType(ContentType.LINK)
                except:
                    self._delegations.clear()
        else:
            super(Link, self).__init__(value)
            self.getMetaInfo().setType(ContentType.LINK)

    def wireDecode(self, input, wireFormat = None):
        """
        Override to call the base class wireDecode then populate the list of
        delegations from the content.

        :param input: The array with the bytes to decode.
        :type input: A Blob or an array type with int elements
        :param wireFormat: (optional) A WireFormat object used to decode this
           DelegationSet. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        Data.wireDecode(self, input, wireFormat)
        if self.getMetaInfo().getType() != ContentType.LINK:
            raise RuntimeError(
              "Link.wireDecode: MetaInfo ContentType is not LINK.")

        self._delegations.wireDecode(self.getContent())

    def addDelegation(self, preference, name, wireFormat = None):
        """
        Add a new delegation to the list of delegations, sorted by preference
        number then by name. Re-encode this object's content using the optional
        wireFormat.

        :param int preference: The preference number.
        :param Name name: The delegation name. This makes a copy of the name. If
          there is already a delegation with the same name, this updates its
          preference.
        :param wireFormat: (optional) A WireFormat object used to encode the
           DelegationSet. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        :return: This Link so that you can chain calls to update values.
        :rtype: Link
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        self._delegations.add(preference, name)
        self.encodeContent(wireFormat)

        return self

    def removeDelegation(self, name, wireFormat = None):
        """
        Remove every delegation with the given name. Re-encode this object's
        content using the optional wireFormat.

        :param Name name: Then name to match the name of the delegation(s) to be
          removed.
        :param wireFormat: (optional) A WireFormat object used to encode the
           DelegationSet. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        :return: True if a delegation was removed, otherwise False.
        :rtype: bool
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        wasRemoved = self._delegations.remove(name)
        if wasRemoved:
            self.encodeContent(wireFormat)

        return wasRemoved

    def getDelegations(self):
        """
        Get the list of delegation for read only.

        :return: The list of delegation, which you should treat as read-only. To
          modify it, call Link.addDelegation, etc.
        :rtype: DelegationSet
        """
        return self._delegations

    def encodeContent(self, wireFormat):
        """
        A private method to encode the delegations and set this object's
        content. Also set the meta info content type to LINK.

        :param WireFormat wireFormat: A WireFormat object used to encode the
          DelegationSet.
        """
        self.setContent(self._delegations.wireEncode(wireFormat))
        self.getMetaInfo().setType(ContentType.LINK)

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Derived from ChronoChat-js by Qiuhan Ding and Wentao Shang.
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
This module defines the DigestTree class which maintains a digest tree for
ChronoSync.
"""

import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from pyndn.util.blob import Blob

class DigestTree(object):
    def __init__(self):
        self._digestNode = [] # of DigestTree.Node
        self._root = "00"

    class Node(object):
        """
        Create a new DigestTree.Node with the given fields and compute the
        digest.

        :param str dataPrefix: The data prefix. In Python3, this is encoded
          as UTF-8 to digest.
        :param int sessionNo: The session number.
        :param int sequenceNo: The sequence number.
        """
        def __init__(self, dataPrefix, sessionNo, sequenceNo):
            self._dataPrefix = dataPrefix
            self._sessionNo = sessionNo
            self._sequenceNo = sequenceNo
            self._digest = None

            self._recomputeDigest()

        def getDataPrefix(self):
            """
            Get the data prefix.

            :return: The data prefix.
            :rtype: str
            """
            return self._dataPrefix

        def getSessionNo(self):
            """
            Get the session number.

            :return: The session number.
            :rtype: int
            """
            return self._sessionNo

        def getSequenceNo(self):
            """
            Get the sequence number.

            :return: The sequence number.
            :rtype: int
            """
            return self._sequenceNo

        def getDigest(self):
            """
            Get the digest.

            :return: The digest as a hex string.
            :rtype: str
            """
            return self._digest

        def setSequenceNo(self, sequenceNo):
            """
            Set the sequence number and recompute the digest.

            :param int sequenceNo: The new sequence number.
            """
            self._sequenceNo = sequenceNo
            self._recomputeDigest()

        def lessThan(self, node2):
            """
            Compare this Node with node2 first comparing _dataPrefix then
            _sessionNo.

            :param DigestTree.Node node2: The other Node to compare.
            :return: True if this node is less than node2.
            :rtype: bool
            """
            if self._dataPrefix < node2._dataPrefix:
                return True
            if self._dataPrefix > node2._dataPrefix:
                return False

            return self._sessionNo < node2._sessionNo

        def _recomputeDigest(self):
            """
            Digest the fields and set self._digest to the hex digest.
            """
            sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
            number = bytearray(4)
            # Debug: sync-state.proto defines seq and session as uint64, but
            #   the original ChronoChat-js only digests 32 bits.
            self._int32ToLittleEndian(self._sessionNo, number)
            sha256.update(Blob(number, False).toBytes())
            self._int32ToLittleEndian(self._sequenceNo, number)
            sha256.update(Blob(number, False).toBytes())
            sequenceDigest = sha256.finalize()

            sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
            # Use Blob to convert a string to UTF-8 if needed.
            sha256.update(Blob(self._dataPrefix, False).toBytes());
            nameDigest = sha256.finalize()

            sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
            sha256.update(nameDigest)
            sha256.update(sequenceDigest)
            nodeDigest = sha256.finalize()
            # Use Blob to convert a str (Python 2) or bytes (Python 3) to hex.
            self._digest = Blob(nodeDigest, False).toHex()

        @staticmethod
        def _int32ToLittleEndian(value, result):
            for i in range(4):
                result[i] = value & 0xff
                value >>= 8

    def update(self, dataPrefix, sessionNo, sequenceNo):
        """
        Update the digest tree and recompute the root digest.  If the
        combination of dataPrefix and sessionNo already exists in the tree then
        update its sequenceNo (only if the given sequenceNo is newer), otherwise
        add a new node.

        :param str dataPrefix: The data prefix. In Python3, this is encoded
          as UTF-8 to digest.
        :param int sequenceNo: The sequence number.
        :param int sessionNo: The session number.
        :return: True if the digest tree is updated, False if not (because the
          given sequenceNo is not newer than the existing sequence number).
        :rtype: bool
        """
        nodeIndex = self.find(dataPrefix, sessionNo)
        logging.getLogger(__name__).info("%s, %d", dataPrefix, sessionNo)
        logging.getLogger(__name__).info(
          "DigestTree.update session %d, nodeIndex %d", sessionNo, nodeIndex)
        if nodeIndex >= 0:
            # Only update to a newer status.
            if self._digestNode[nodeIndex].getSequenceNo() < sequenceNo:
                self._digestNode[nodeIndex].setSequenceNo(sequenceNo)
            else:
                return False
        else:
            logging.getLogger(__name__).info(
              "new comer %s, session %d, sequence %d", dataPrefix, sessionNo,
              sequenceNo)
            # Insert into _digestnode sorted.
            temp = DigestTree.Node(dataPrefix, sessionNo, sequenceNo)
            # Find the index of the first node where it is not less than temp.
            i = 0
            while i < len(self._digestNode):
                if not self._digestNode[i].lessThan(temp):
                    break
                i += 1

            self._digestNode.insert(i, temp)

        self._recomputeRoot()
        return True

    def find(self, dataPrefix, sessionNo):
        for i in range(len(self._digestNode)):
          if (self._digestNode[i].getDataPrefix() == dataPrefix and
              self._digestNode[i].getSessionNo() == sessionNo):
            return i

        return -1

    def size(self):
        return len(self._digestNode)

    def get(self, i):
        return self._digestNode[i]

    def getRoot(self):
        """
        Get the root digest.

        :return: The root digest as a hex string.
        :rtype: str
        """
        return self._root

    @staticmethod
    def _updateHex(messageDigest, hex):
        """
        Convert the hex string to bytes and call messageDigest.update.

        :param messageDigest: The digest to update.
        :type messageDigest: A HashContext object, for example from
          hashes.Hash(hashes.SHA256(), backend=default_backend()).
        :param str hex: The hex string.
        """
        messageDigest.update(Blob(bytearray.fromhex(hex), False).toBytes())

    def _recomputeRoot(self):
        """
        Set _root to the digest of all digests in _digestnode. This sets
        _root to the hex value of the digest.
        """
        sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
        for i in range(len(self._digestNode)):
            self._updateHex(sha256, self._digestNode[i].getDigest())
        digestRoot = sha256.finalize()
        # Use Blob to convert a str (Python 2) or bytes (Python 3) to hex.
        self._root = Blob(digestRoot, False).toHex()
        logging.getLogger(__name__).info("update root to: %s", self._root)

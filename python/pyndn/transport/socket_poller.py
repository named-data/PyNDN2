# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
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
This module defines the SocketPoller class which is used by the socket-based
Transport classes to poll a socket on various platforms.
"""

import select

class SocketPoller(object):
    """
    Create a new SocketPoller and register with the given sock

    :param socket sock: The socket to register with.
    """
    def __init__(self, sock):
        self._socket = sock
        self._poll = None
        self._kqueue = None
        self._kevents = None

        if hasattr(select, "poll"):
            # Set up _poll.  (Ubuntu, etc.)
#pylint: disable=E1103
            self._poll = select.poll()
            self._poll.register(sock.fileno(), select.POLLIN)
#pylint: enable=E1103
        elif hasattr(select, "kqueue"):
            ## Set up _kqueue. (BSD and OS X)
            self._kqueue = select.kqueue()
            self._kevents = [select.kevent(
              sock.fileno(), filter = select.KQ_FILTER_READ,
              flags = select.KQ_EV_ADD | select.KQ_EV_ENABLE |
                      select.KQ_EV_CLEAR)]
        elif not hasattr(select, "select"):
            # Most Python implementations have this fallback, so we
            #   don't expect this error.
            raise RuntimeError("Cannot find a polling utility for sockets")

    def isReady(self):
        """
        Check if the socket given to the constructor has data to receive.

        :return: True if there is data ready to receive, otherwise False.
        :rtype: bool
        """
        if self._poll != None:
            isReady = False
            # Set timeout to 0 for an immediate check.
            for (fd, pollResult) in self._poll.poll(0):
#pylint: disable=E1103
                if pollResult > 0 and pollResult & select.POLLIN != 0:
                    return True
#pylint: enable=E1103

            # There is no data waiting.
            return False
        elif self._kqueue != None:
            # Set timeout to 0 for an immediate check.
            return len(self._kqueue.control(self._kevents, 1, 0)) != 0
        else:
            # Use the select fallback which is less efficient.
            # Set timeout to 0 for an immediate check.
            isReady, _, _ = select.select([self._socket], [], [], 0)
            return len(isReady) != 0

    def close(self):
        """
        Unregister with the socket given to the constructor.
        """
        if self._poll != None:
            self._poll.unregister(self._socket.fileno())
            self._poll = None

        self._kqueue = None
        self._kevents = None

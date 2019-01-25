# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2016-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/util/config-file.hpp
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
This module defines the ConfigFile class which locates, opens, and parses a
library configuration file, and holds the values for the application to get.
"""

import os

class ConfigFile(object):
    """
    Locate, open, and parse a library configuration file.
    """
    def __init__(self):
        self._path = ConfigFile._findConfigFile()
        self._config = {}

        if self._path != "":
            self._parse()

    def get(self, key, defaultValue):
        """
        Get the value for the key, or a default value if not found.

        :param str key: The key to search for.
        :param str defaultValue: The default value if the key is not found.
        :return: The value, or defaultValue if the key is not found.
        :rtype: str
        """
        if key in self._config:
            return self._config[key]
        else:
            return defaultValue

    def getPath(self):
        """
        Get the path of the configuration file.

        :return: The path or an empty string if not found.
        :rtype: str
        """
        return self._path

    def getParsedConfiguration(self):
        """
        Get the configuration key/value pairs.

        :return: A dict of key/value strings.
        :rtype: dict
        """
        return self._config

    @staticmethod
    def _findConfigFile():
        """
        Look for the configuration file in these well-known locations:
        1. $HOME/.ndn/client.conf
        2. /etc/ndn/client.conf
        We don't support the C++ #define value @SYSCONFDIR@.

        :return: The path of the config file or an empty string if not found.
        :rtype: str
        """
        if not "HOME" in os.environ:
            # Don't expect this to happen
            home = "."
        else:
            home = os.environ["HOME"]

        filePath = os.path.join(home, ".ndn", "client.conf")
        if os.path.exists(filePath):
            return filePath

        # Ignore the C++ SYSCONFDIR.

        filePath = "/etc/ndn/client.conf"
        if os.path.exists(filePath):
            return filePath

        return ""

    def _parse(self):
        """
        Open _path, parse the configuration file and set _config.
        """
        if self._path == "":
            raise RuntimeError(
              "ConfigFile._parse: Failed to locate the configuration file for parsing");

        with open(self._path) as input:
            for line in input:
                line = line.strip()
                if line == "" or line[0] == ';':
                    # Skip empty lines and comments.
                    continue

                iSeparator = line.find('=')
                if iSeparator < 0:
                    continue

                key = line[0:iSeparator].strip()
                value = line[iSeparator + 1:].strip()

                self._config[key] = value

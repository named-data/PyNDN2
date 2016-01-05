# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
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
This module defines the SecurityException class which extends Exception
to report an exception from the security library.
"""

class SecurityException(Exception):
    def __init__(self, message):
        super(SecurityException, self).__init__(message)

class UnrecognizedKeyFormatException(SecurityException):
    def __init__(self, message):
        super(UnrecognizedKeyFormatException, self).__init__(message)

class UnrecognizedDigestAlgorithmException(SecurityException):
    def __init__(self, message):
        super(UnrecognizedDigestAlgorithmException, self).__init__(message)

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
# Author: Adeola Bannis <thecodemaiden@gmail.com>
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
    Exceptions that may occur during DER encoding/decoding
    Correspond to exceptions in ndn-cpp
"""

class DerException(Exception):
    pass

class NegativeLengthException(DerException):
    def __init__(self, message):
        super(NegativeLengthException, self).__init__(self, message)

class DerEncodingException(DerException):
    def __init__(self, message):
        super(DerEncodingException, self).__init__(self, message)

class DerDecodingException(DerException):
    def __init__(self, message):
        super(DerDecodingException, self).__init__(self, message)


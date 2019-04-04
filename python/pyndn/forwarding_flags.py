# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2019 Regents of the University of California.
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
This module defines the ForwardingFlags class which is deprecated. Use
RegistrationOptions.
"""

from pyndn.registration_options import RegistrationOptions

class ForwardingFlags(RegistrationOptions):
    """
    Create a new ForwardingFlags object, possibly copying values from another
    object.

    :param RegistrationOptions value: (optional) If value is a
      RegistrationOptions (or ForwardingFlags), copy its values. If value is
      omitted, the type is the default with "childInherit" True and other flags
      False.
    :deprecated: Use RegistrationOptions.
    """
    def __init__(self, value = None):
        super(ForwardingFlags, self).__init__(value)

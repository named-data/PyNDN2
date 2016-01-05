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

from pyndn.security.identity import basic_identity_storage, file_private_key_storage
from pyndn.security.identity import identity_manager, identity_storage, memory_identity_storage
from pyndn.security.identity import memory_private_key_storage, osx_private_key_storage
from pyndn.security.identity import private_key_storage
__all__ = ['basic_identity_storage', 'file_private_key_storage',
           'identity_manager', 'identity_storage', 'memory_identity_storage',
           'memory_private_key_storage', 'osx_private_key_storage',
           'private_key_storage']

import sys as _sys

try:
    from pyndn.security.identity.basic_identity_storage import *
    from pyndn.security.identity.file_private_key_storage import *
    from pyndn.security.identity.identity_manager import *
    from pyndn.security.identity.identity_storage import *
    from pyndn.security.identity.memory_identity_storage import *
    from pyndn.security.identity.memory_private_key_storage import *
    from pyndn.security.identity.osx_private_key_storage import *
    from pyndn.security.identity.private_key_storage import *
except ImportError:
    del _sys.modules[__name__]
    raise

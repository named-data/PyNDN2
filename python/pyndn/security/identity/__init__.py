# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.

__all__ = ['memory_private_key_storage', 'private_key_storage']

import sys as _sys

try:
    from pyndn.security.identity.memory_private_key_storage import *
    from pyndn.security.identity.private_key_storage import *
except ImportError:
    del _sys.modules[__name__]
    raise

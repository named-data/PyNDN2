# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.

# Don't include internal modules.
__all__ = []

import sys as _sys

try:
    pass
except ImportError:
    del _sys.modules[__name__]
    raise

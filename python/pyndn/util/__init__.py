# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.

__all__ = ['dynamic_byte_array']

import sys as _sys

try:
	from pyndn.util.dynamic_byte_array import *
except ImportError:
	del _sys.modules[__name__]
	raise

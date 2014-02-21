# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the Common class which has static utility functions.
"""

import time

class Common(object):
    @staticmethod
    def getNowMilliseconds():
        """
        Get the current time in milliseconds.
        
        :return: The current time in milliseconds since 1/1/1970, including 
          fractions of a millisecond.
        :rtype: float
        """
        return time.time() * 1000.0
    
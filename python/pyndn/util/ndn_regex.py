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

import re
from pyndn.name import Name

"""
Convert an NDN regex (http://redmine.named-data.net/projects/ndn-cxx/wiki/Regex)
to a python regex that can match against URIs
"""

class NdnRegexMatcher(object):
    @staticmethod
    def _sanitizeSets(pattern):
        newPattern = pattern

        #positive sets can be changed to (comp1|comp2)
        #negative sets must be changed to negative lookahead assertions

        inSetMatches = re.finditer('\[(\^?)(.*?)\]', pattern)
        for match in inSetMatches:
            # insert | between components
            start, end = match.span(2)
            if start-end == 0:
                continue
            oldStr = match.group(2)
            newStr = re.sub('><', '>|<', oldStr)
            newPattern = newPattern[:start] + newStr + newPattern[end:]

        ## replace [] with (),  or (?! ) for negative lookahead
        ## if we use negative lookahead, we also have to consume one component
        isNegative = newPattern.find("[^") >= 0
        if isNegative:
            newPattern = newPattern.replace("[^", "(?:(?!")
            newPattern = newPattern.replace("]", ")(?:/.*)*)")
        else:
            newPattern = newPattern.replace("[", "(")
            newPattern = newPattern.replace("]", ")")

        return newPattern

    @staticmethod
    def match(pattern, name):
        """
        Determine if the provided NDN regex matches the given Name.
        :param str pattern: The NDN regex.
        :param Name name: The Name to match against the regex.
        """
        #nameParts = [name.get(i).getValue().toRawStr() for i in range(name.size())]
        #nameUri = '/'+'/'.join(nameParts)
        nameUri = name.toUri()

        pattern = NdnRegexMatcher._sanitizeSets(pattern)

        pattern = re.sub('<>', '(?:<.+?>)', pattern)
        pattern = pattern.replace('>', '')
        pattern = re.sub('<(?!!)', '/', pattern)

        return re.search(pattern, nameUri)




# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
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
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU General Public License is in the file COPYING.

import re
from pyndn import Name

"""
Convert an NDN regex (http://redmine.named-data.net/projects/ndn-css/wiki/Regex)
to a python regex that can match against URIs
"""

class NdnRegexMatcher(object):
    @staticmethod
    def _sanitizeSets(pattern):
        newPattern = pattern

        #positive sets can be changed to (comp1|comp2)
        #negative sets must be changed to negative lookbehind assertions

        inSetMatches = re.finditer('\[(\^?)(.*?)\]', pattern)
        for match in inSetMatches:
            # insert | between components
            start, end = match.span(2)
            if start-end == 0:
                continue
            oldStr = match.group(2)
            newStr = re.sub('><', '>|<', oldStr)
            newPattern = newPattern[:start] + newStr + newPattern[end:]
            
        ## replace [] with () or (?<! ) for negative lookbehind
        ## if we use negative lookbehind, we also have to consume one component
        isNegative = newPattern.find("[^") >= 0
        if isNegative:
            newPattern = newPattern.replace("[^", "(?:(?!")
            newPattern = newPattern.replace("]", ")(?:/.*)*)")
        else:
            newPattern = newPattern.replace("[", "(")
            newPattern = newPattern.replace("]", ")")

        return newPattern

    @staticmethod
    def _escapeComponents(pattern):
        # escape all the components in the pattern to match the toUri format
        componentPattern = '<(.*?)>(.*?)(?=<|$)'

        originalPattern = pattern

        componentMatches = re.finditer(componentPattern, pattern)
        modifiedStr = pattern
        for match in componentMatches:
            start, end = match.span(1)
            if start-end == 0:
                continue
            oldStr = match.group(1)
            newStr = Name.Component(oldStr).toEscapedString()
            modifiedStr = modifiedStr[:start] + newStr + modifiedStr[end:]

        return modifiedStr
    
    @staticmethod
    def match(pattern, name):
        #nameParts = [name.get(i).getValue().toRawStr() for i in range(name.size())]
        #nameUri = '/'+'/'.join(nameParts)
        nameUri = name.toUri()
        
        pattern = NdnRegexMatcher._sanitizeSets(pattern)
        
        pattern = re.sub('<>', '(?:<.+?>)', pattern)
        pattern = pattern.replace('>', '')
        pattern = re.sub('<(?!!)', '/', pattern)

        return re.search(pattern, nameUri)
    

if __name__ == '__main__':
    def testMatch(pattern, name):
        match = NdnRegexMatcher.match(pattern, name)
        resultStr =  'Matching {} to {}: '.format(name.toUri(), pattern)
        resultStr += 'Success'if match else 'Failure'
        print resultStr
        print
            
    testMatch('^<ndn>', Name("/ndn/KEY/ID-CERT")) 

    testMatch('<&EY>', Name("/ndn/&EY/ID-CERT")) 

    testMatch('<\\?EY>', Name("/ndn/?EY/ID-CERT")) 

    testMatch('^<KEY>', Name("/ndn/KEY/ID-CERT")) 

    testMatch('<KE\\.Y>', Name("/ndn/KE.Y/ID-CERT")) 

    testMatch('<K.+Y>', Name("/ndn/KE.Y/ID-CERT")) 

    testMatch('^<ndn><KEY><ID-CERT>$', Name("/ndn/KEY/ID-CERT")) 

    testMatch('^<ndn><KEY><>*<ID-CERT>$', Name("/ndn/KEY/ID-CERT")) 

    testMatch('^<ndn><KEY><>?<ID-CERT>$', Name("/ndn/KEY/ID-CERT")) 

    testMatch('^<ndn><KEY><>+<ID-CERT>$', Name("/ndn/KEY/ID-CERT")) 

    testMatch('^<ndn><KEY><>+<ID-CERT>$', Name("/ndn/KEY/lookhere/now/ID-CERT")) 

    testMatch('^[<ndn><something>]', Name("/ndn/KEY/lookhere/ID-CERT")) 

    testMatch('^[^<something>]', Name("/ndn/KEY/lookhere/ID-CERT")) 

    testMatch('^[<something>]', Name("/ndn/KEY/lookhere/ID-CERT")) 

    testMatch('<DNS><>*<NS>', Name("/ndn/edu/ucla/DNS/irl/NS/123456")) 

    testMatch('^([^<DNS>]+)<DNS>(<>*)<NS>', Name("/ndn/ucla.edu/DNS/irl/NS/123456")) 

    testMatch('^([^<KEY>]*)<KEY>(<>*)<ksk-.+><ID-CERT>', Name("/ndn/test/abannis/KEY/ksk-17837823/ID-CERT")) 

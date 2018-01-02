# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx Regex unit tests:
# https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/util/regex.t.cpp
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

import unittest as ut
from pyndn import Name
from pyndn.util.regex.ndn_regex_backref_manager import NdnRegexBackrefManager
from pyndn.util.regex.ndn_regex_component_matcher import NdnRegexComponentMatcher
from pyndn.util.regex.ndn_regex_component_set_matcher import NdnRegexComponentSetMatcher
from pyndn.util.regex.ndn_regex_repeat_matcher import NdnRegexRepeatMatcher
from pyndn.util.regex.ndn_regex_backref_matcher import NdnRegexBackrefMatcher
from pyndn.util.regex.ndn_regex_pattern_list_matcher import NdnRegexPatternListMatcher
from pyndn.util.regex.ndn_regex_top_matcher import NdnRegexTopMatcher

class TestRegex(ut.TestCase):
    def test_component_matcher(self):
        backRef = NdnRegexBackrefManager()
        cm = NdnRegexComponentMatcher("a", backRef)
        res = cm.match(Name("/a/b/"), 0, 1)
        self.assertEquals(True, res)
        self.assertEquals(1, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())

        backRef = NdnRegexBackrefManager()
        cm = NdnRegexComponentMatcher("a", backRef)
        res = cm.match(Name("/a/b/"), 1, 1)
        self.assertEquals(False, res)
        self.assertEquals(0, len(cm.getMatchResult()))

        backRef = NdnRegexBackrefManager()
        cm = NdnRegexComponentMatcher("(c+)\\.(cd)", backRef)
        res = cm.match(Name("/ccc.cd/b/"), 0, 1)
        self.assertEquals(True, res)
        self.assertEquals(1, len(cm.getMatchResult()))
        self.assertEquals("ccc.cd", cm.getMatchResult()[0].toEscapedString())

        self.assertEquals(2, backRef.size())
        self.assertEquals("ccc",
          backRef.getBackref(0).getMatchResult()[0].toEscapedString())
        self.assertEquals("cd",
          backRef.getBackref(1).getMatchResult()[0].toEscapedString())

    def test_component_set_matcher(self):
        backRef = NdnRegexBackrefManager()
        cm = NdnRegexComponentSetMatcher("<a>", backRef)
        res = cm.match(Name("/a/b/"), 0, 1)
        self.assertEquals(True, res)
        self.assertEquals(1, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())

        res = cm.match(Name("/a/b/"), 1, 1)
        self.assertEquals(False, res)
        self.assertEquals(0, len(cm.getMatchResult()))

        res = cm.match(Name("/a/b/"), 0, 2)
        self.assertEquals(False, res)
        self.assertEquals(0, len(cm.getMatchResult()))

        backRef = NdnRegexBackrefManager()
        cm = NdnRegexComponentSetMatcher("[<a><b><c>]", backRef)
        res = cm.match(Name("/a/b/d"), 1, 1)
        self.assertEquals(True, res)
        self.assertEquals(1, len(cm.getMatchResult()))
        self.assertEquals("b", cm.getMatchResult()[0].toEscapedString())

        res = cm.match(Name("/a/b/d"), 2, 1)
        self.assertEquals(False, res)
        self.assertEquals(0, len(cm.getMatchResult()))

        backRef = NdnRegexBackrefManager()
        cm = NdnRegexComponentSetMatcher("[^<a><b><c>]", backRef)
        res = cm.match(Name("/b/d"), 1, 1)
        self.assertEquals(True, res)
        self.assertEquals(1, len(cm.getMatchResult()))
        self.assertEquals("d", cm.getMatchResult()[0].toEscapedString())

        backRef = NdnRegexBackrefManager()
        try:
            NdnRegexComponentSetMatcher("[<a]", backRef)
            self.fail("Did not throw the expected exception")
        except NdnRegexMatcherBase.Error:
            pass
        else:
            self.fail("Did not throw the expected exception")

    def test_repeat_matcher(self):
        backRef = NdnRegexBackrefManager()
        cm = NdnRegexRepeatMatcher("[<a><b>]*", backRef, 8)
        res = cm.match(Name("/a/b/c"), 0, 0)
        self.assertEquals(True, res)
        self.assertEquals(0, len(cm.getMatchResult()))

        res = cm.match(Name("/a/b/c"), 0, 2)
        self.assertEquals(True, res)
        self.assertEquals(2, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())

        backRef = NdnRegexBackrefManager()
        cm = NdnRegexRepeatMatcher("[<a><b>]+", backRef, 8)
        res = cm.match(Name("/a/b/c"), 0, 0)
        self.assertEquals(False, res)
        self.assertEquals(0, len(cm.getMatchResult()))

        res = cm.match(Name("/a/b/c"), 0, 2)
        self.assertEquals(True, res)
        self.assertEquals(2, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())

        backRef = NdnRegexBackrefManager()
        cm = NdnRegexRepeatMatcher("<.*>*", backRef, 4)
        res = cm.match(Name("/a/b/c/d/e/f/"), 0, 6)
        self.assertEquals(True, res)
        self.assertEquals(6, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())
        self.assertEquals("c", cm.getMatchResult()[2].toEscapedString())
        self.assertEquals("d", cm.getMatchResult()[3].toEscapedString())
        self.assertEquals("e", cm.getMatchResult()[4].toEscapedString())
        self.assertEquals("f", cm.getMatchResult()[5].toEscapedString())

        backRef = NdnRegexBackrefManager()
        cm = NdnRegexRepeatMatcher("<>*", backRef, 2)
        res = cm.match(Name("/a/b/c/d/e/f/"), 0, 6)
        self.assertEquals(True, res)
        self.assertEquals(6, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())
        self.assertEquals("c", cm.getMatchResult()[2].toEscapedString())
        self.assertEquals("d", cm.getMatchResult()[3].toEscapedString())
        self.assertEquals("e", cm.getMatchResult()[4].toEscapedString())
        self.assertEquals("f", cm.getMatchResult()[5].toEscapedString())

        backRef = NdnRegexBackrefManager()
        cm = NdnRegexRepeatMatcher("<a>?", backRef, 3)
        res = cm.match(Name("/a/b/c"), 0, 0)
        self.assertEquals(True, res)
        self.assertEquals(0, len(cm.getMatchResult()))

        cm = NdnRegexRepeatMatcher("<a>?", backRef, 3)
        res = cm.match(Name("/a/b/c"), 0, 1)
        self.assertEquals(True, res)
        self.assertEquals(1, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())

        cm = NdnRegexRepeatMatcher("<a>?", backRef, 3)
        res = cm.match(Name("/a/b/c"), 0, 2)
        self.assertEquals(False, res)
        self.assertEquals(0, len(cm.getMatchResult()))

        backRef = NdnRegexBackrefManager()
        cm = NdnRegexRepeatMatcher("[<a><b>]{3}", backRef, 8)
        res = cm.match(Name("/a/b/a/d/"), 0, 2)
        self.assertEquals(False, res)
        self.assertEquals(0, len(cm.getMatchResult()))

        res = cm.match(Name("/a/b/a/d/"), 0, 3)
        self.assertEquals(True, res)
        self.assertEquals(3, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())
        self.assertEquals("a", cm.getMatchResult()[2].toEscapedString())

        res = cm.match(Name("/a/b/a/d/"), 0, 4)
        self.assertEquals(False, res)
        self.assertEquals(0, len(cm.getMatchResult()))

        backRef = NdnRegexBackrefManager()
        cm = NdnRegexRepeatMatcher("[<a><b>]{2,3}", backRef, 8)
        res = cm.match(Name("/a/b/a/d/e/"), 0, 2)
        self.assertEquals(True, res)
        self.assertEquals(2, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())

        res = cm.match(Name("/a/b/a/d/e/"), 0, 3)
        self.assertEquals(True, res)
        self.assertEquals(3, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())
        self.assertEquals("a", cm.getMatchResult()[2].toEscapedString())

        res = cm.match(Name("/a/b/a/b/e/"), 0, 4)
        self.assertEquals(False, res)
        self.assertEquals(0, len(cm.getMatchResult()))

        res = cm.match(Name("/a/b/a/d/e/"), 0, 1)
        self.assertEquals(False, res)
        self.assertEquals(0, len(cm.getMatchResult()))

        backRef = NdnRegexBackrefManager()
        cm = NdnRegexRepeatMatcher("[<a><b>]{2,}", backRef, 8)
        res = cm.match(Name("/a/b/a/d/e/"), 0, 2)
        self.assertEquals(True, res)
        self.assertEquals(2, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())

        res = cm.match(Name("/a/b/a/b/e/"), 0, 4)
        self.assertEquals(True, res)
        self.assertEquals(4, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())
        self.assertEquals("a", cm.getMatchResult()[2].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[3].toEscapedString())

        res = cm.match(Name("/a/b/a/d/e/"), 0, 1)
        self.assertEquals(False, res)
        self.assertEquals(0, len(cm.getMatchResult()))

        backRef = NdnRegexBackrefManager()
        cm = NdnRegexRepeatMatcher("[<a><b>]{,2}", backRef, 8)
        res = cm.match(Name("/a/b/a/b/e/"), 0, 3)
        self.assertEquals(False, res)
        self.assertEquals(0, len(cm.getMatchResult()))

        res = cm.match(Name("/a/b/a/b/e/"), 0, 2)
        self.assertEquals(True, res)
        self.assertEquals(2, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())

        res = cm.match(Name("/a/b/a/d/e/"), 0, 1)
        self.assertEquals(True, res)
        self.assertEquals(1, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())

        res = cm.match(Name("/a/b/a/d/e/"), 0, 0)
        self.assertEquals(True, res)
        self.assertEquals(0, len(cm.getMatchResult()))

    def test_backref_matcher(self):
        backRef = NdnRegexBackrefManager()
        cm = NdnRegexBackrefMatcher("(<a><b>)", backRef)
        backRef.pushRef(cm)
        cm.lateCompile()
        res = cm.match(Name("/a/b/c"), 0, 2)
        self.assertEquals(True, res)
        self.assertEquals(2, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())
        self.assertEquals(1, backRef.size())

        backRef = NdnRegexBackrefManager()
        cm = NdnRegexBackrefMatcher("(<a>(<b>))", backRef)
        backRef.pushRef(cm)
        cm.lateCompile()
        res = cm.match(Name("/a/b/c"), 0, 2)
        self.assertEquals(True, res)
        self.assertEquals(2, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())
        self.assertEquals(2, backRef.size())
        self.assertEquals("a",
          backRef.getBackref(0).getMatchResult()[0].toEscapedString())
        self.assertEquals("b",
          backRef.getBackref(0).getMatchResult()[1].toEscapedString())
        self.assertEquals("b",
          backRef.getBackref(1).getMatchResult()[0].toEscapedString())

    def test_backref_matcher_advanced(self):
        backRef = NdnRegexBackrefManager()
        cm = NdnRegexRepeatMatcher("([<a><b>])+", backRef, 10)
        res = cm.match(Name("/a/b/c"), 0, 2)
        self.assertEquals(True, res)
        self.assertEquals(2, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())
        self.assertEquals(1, backRef.size())
        self.assertEquals("b",
          backRef.getBackref(0).getMatchResult()[0].toEscapedString())

    def test_backref_matcher_advanced2(self):
        backRef = NdnRegexBackrefManager()
        cm = NdnRegexPatternListMatcher("(<a>(<b>))<c>", backRef)
        res = cm.match(Name("/a/b/c"), 0, 3)
        self.assertEquals(True, res)
        self.assertEquals(3, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())
        self.assertEquals("c", cm.getMatchResult()[2].toEscapedString())
        self.assertEquals(2, backRef.size())
        self.assertEquals("a",
          backRef.getBackref(0).getMatchResult()[0].toEscapedString())
        self.assertEquals("b",
          backRef.getBackref(0).getMatchResult()[1].toEscapedString())
        self.assertEquals("b",
          backRef.getBackref(1).getMatchResult()[0].toEscapedString())

    def test_pattern_list_matcher(self):
        backRef = NdnRegexBackrefManager()
        cm = NdnRegexPatternListMatcher("<a>[<a><b>]", backRef)
        res = cm.match(Name("/a/b/c"), 0, 2)
        self.assertEquals(True, res)
        self.assertEquals(2, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())

        backRef = NdnRegexBackrefManager()
        cm = NdnRegexPatternListMatcher("<>*<a>", backRef)
        res = cm.match(Name("/a/b/c"), 0, 1)
        self.assertEquals(True, res)
        self.assertEquals(1, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())

        backRef = NdnRegexBackrefManager()
        cm = NdnRegexPatternListMatcher("<>*<a>", backRef)
        res = cm.match(Name("/a/b/c"), 0, 2)
        self.assertEquals(False, res)
        self.assertEquals(0, len(cm.getMatchResult()))

        backRef = NdnRegexBackrefManager()
        cm = NdnRegexPatternListMatcher("<>*<a><>*", backRef)
        res = cm.match(Name("/a/b/c"), 0, 3)
        self.assertEquals(True, res)
        self.assertEquals(3, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())
        self.assertEquals("c", cm.getMatchResult()[2].toEscapedString())

    def test_top_matcher(self):
        cm = NdnRegexTopMatcher("^<a><b><c>")
        res = cm.match(Name("/a/b/c/d"))
        self.assertEquals(True, res)
        self.assertEquals(4, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())
        self.assertEquals("c", cm.getMatchResult()[2].toEscapedString())
        self.assertEquals("d", cm.getMatchResult()[3].toEscapedString())

        cm = NdnRegexTopMatcher("<b><c><d>$")
        res = cm.match(Name("/a/b/c/d"))
        self.assertEquals(True, res)
        self.assertEquals(4, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())
        self.assertEquals("c", cm.getMatchResult()[2].toEscapedString())
        self.assertEquals("d", cm.getMatchResult()[3].toEscapedString())

        cm = NdnRegexTopMatcher("^<a><b><c><d>$")
        res = cm.match(Name("/a/b/c/d"))
        self.assertEquals(True, res)
        self.assertEquals(4, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())
        self.assertEquals("c", cm.getMatchResult()[2].toEscapedString())
        self.assertEquals("d", cm.getMatchResult()[3].toEscapedString())

        res = cm.match(Name("/a/b/c/d/e"))
        self.assertEquals(False, res)
        self.assertEquals(0, len(cm.getMatchResult()))

        cm = NdnRegexTopMatcher("<a><b><c><d>")
        res = cm.match(Name("/a/b/c/d"))
        self.assertEquals(True, res)
        self.assertEquals(4, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())
        self.assertEquals("c", cm.getMatchResult()[2].toEscapedString())
        self.assertEquals("d", cm.getMatchResult()[3].toEscapedString())

        cm = NdnRegexTopMatcher("<b><c>")
        res = cm.match(Name("/a/b/c/d"))
        self.assertEquals(True, res)
        self.assertEquals(4, len(cm.getMatchResult()))
        self.assertEquals("a", cm.getMatchResult()[0].toEscapedString())
        self.assertEquals("b", cm.getMatchResult()[1].toEscapedString())
        self.assertEquals("c", cm.getMatchResult()[2].toEscapedString())
        self.assertEquals("d", cm.getMatchResult()[3].toEscapedString())

    def test_top_matcher_advanced(self):
        cm = NdnRegexTopMatcher("^(<.*>*)<.*>")
        res = cm.match(Name("/n/a/b/c"))
        self.assertEquals(True, res)
        self.assertEquals(4, len(cm.getMatchResult()))
        self.assertEquals(Name("/n/a/b/"), cm.expand("\\1"))

        cm = NdnRegexTopMatcher("^(<.*>*)<.*><c>(<.*>)<.*>")
        res = cm.match(Name("/n/a/b/c/d/e/"))
        self.assertEquals(True, res)
        self.assertEquals(6, len(cm.getMatchResult()))
        self.assertEquals(Name("/n/a/d/"), cm.expand("\\1\\2"))

        cm = NdnRegexTopMatcher("(<.*>*)<.*>$")
        res = cm.match(Name("/n/a/b/c/"))
        self.assertEquals(True, res)
        self.assertEquals(4, len(cm.getMatchResult()))
        self.assertEquals(Name("/n/a/b/"), cm.expand("\\1"))

        cm = NdnRegexTopMatcher("<.*>(<.*>*)<.*>$")
        res = cm.match(Name("/n/a/b/c/"))
        self.assertEquals(True, res)
        self.assertEquals(4, len(cm.getMatchResult()))
        self.assertEquals(Name("/a/b/"), cm.expand("\\1"))

        cm = NdnRegexTopMatcher("<a>(<>*)<>$")
        res = cm.match(Name("/n/a/b/c/"))
        self.assertEquals(True, res)
        self.assertEquals(4, len(cm.getMatchResult()))
        self.assertEquals(Name("/b/"), cm.expand("\\1"))

        cm = NdnRegexTopMatcher("^<ndn><(.*)\\.(.*)><DNS>(<>*)<>")
        res = cm.match(Name("/ndn/ucla.edu/DNS/yingdi/mac/ksk-1/"))
        self.assertEquals(True, res)
        self.assertEquals(6, len(cm.getMatchResult()))
        self.assertEquals(Name("/ndn/edu/ucla/yingdi/mac/"),
          cm.expand("<ndn>\\2\\1\\3"))

        cm = NdnRegexTopMatcher(
          "^<ndn><(.*)\\.(.*)><DNS>(<>*)<>", "<ndn>\\2\\1\\3")
        res = cm.match(Name("/ndn/ucla.edu/DNS/yingdi/mac/ksk-1/"))
        self.assertEquals(True, res)
        self.assertEquals(6, len(cm.getMatchResult()))
        self.assertEquals(Name("/ndn/edu/ucla/yingdi/mac/"), cm.expand())

from pyndn.util.regex.ndn_regex_matcher_base import NdnRegexMatcherBase

if __name__ == '__main__':
    ut.main(verbosity=2)

# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2015 Regents of the University of California.
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

import unittest as ut
from pyndn import Name
from pyndn.util import Blob


class TestNameComponentMethods(ut.TestCase):
    def setUp(self):
        pass

    def test_unicode(self):
        comp1 = Name.Component(u"entr\u00E9e")
        expected = "entr%C3%A9e"
        self.assertEqual(comp1.toEscapedString(), expected)

    def test_bytearray(self):
        pass

    ## many more component methods to be tested!

class TestNameMethods(ut.TestCase):

    def setUp(self):
        self.entree = Name.Component(u"entr\u00E9e")
        self.comp1 = Name.Component(bytearray([ord('.')]*4))
        self.comp2 = Name.Component(bytearray([0x00, 0x01, 0x02, 0x03]))
        self.expectedURI = "/entr%C3%A9e/..../%00%01%02%03"

    def tearDown(self):
        pass

    def test_uri_constructor(self):
        name = Name(self.expectedURI)
        self.assertEqual(len(name), 3, 'Constructed name has ' + str(len(name)) + ' components instead of 3')
        self.assertEqual(name.toUri(), self.expectedURI, 'URI is incorrect')

    def test_copy_constructor(self):
        name = Name(self.expectedURI)
        name2 = Name(name)
        self.assertTrue(name == name2, 'Name from copy constructor does not match original')

    def test_get_component(self):
        name = Name(self.expectedURI)
        comp2 = name[2]
        self.assertTrue(self.comp2 == comp2, 'Component at index 2 is incorrect')

    def test_append(self):
        # could possibly split this into different tests
        uri = "/localhost/user/folders/files/%00%0F"
        name = Name(uri)
        name2 = Name("/localhost").append(Name("/user/folders/"))
        self.assertEqual(len(name2), 3, 'Name constructed by appending names has ' + str(len(name2)) + ' components instead of 3')
        self.assertTrue(name2[2].getValue() == Blob("folders"), 'Name constructed with append has wrong suffix')
        name2 = name2.append("files")
        self.assertEqual(len(name2), 4, 'Name constructed by appending string has ' + str(len(name2)) + ' components instead of 4')
        name2 = name2.appendSegment(15)
        self.assertTrue(name2[4].getValue() == Blob(bytearray([0x00, 0x0F])), 'Name constructed by appending segment has wrong segment value')

        self.assertTrue(name2 == name, 'Name constructed with append is not equal to URI constructed name')
        self.assertEqual(name2.toUri(), name.toUri(), 'Name constructed with append has wrong URI')

    def test_slice(self):
        name = Name("/edu/cmu/andrew/user/3498478")
        subName1 = name[0:]
        self.assertEqual(subName1, name, 'Slice from first component does not match original name')
        subName2 = name[3:]
        self.assertEqual(subName2, Name("/user/3498478"))

        subName3 = name[1:1+3]
        self.assertEqual(subName3, Name("/cmu/andrew/user"))

        subName4 = name[0:100]
        self.assertEqual(name, subName4, 'Slice with more components than original should stop at end of original name')

        subName5 = name[7:9]
        self.assertEqual(Name(), subName5, 'Slice beginning after end of name should be empty')

        subName6 = name[-3:-1]
        self.assertEqual(subName6, Name("/andrew/user"))

        subName7 = name[-5:]
        self.assertEqual(subName7, name, 'Slice with negative indices does not match name')

        prefix1 = name[:2]
        self.assertEqual(len(prefix1), 2, 'Name prefix has ' + str(len(prefix1)) + ' components instead of 2')
        for i in range(2):
            self.assertTrue(name[i].getValue() == prefix1[i].getValue())

    def test_prefix(self):
        name = Name("/edu/cmu/andrew/user/3498478")
        prefix1 = name.getPrefix(2)

        self.assertEqual(len(prefix1), 2, 'Name prefix has ' + str(len(prefix1)) + ' components instead of 2')
        for i in range(2):
            self.assertTrue(name[i].getValue() == prefix1[i].getValue())

        prefix2 = name.getPrefix(100)
        self.assertEqual(prefix2, name, 'Prefix with more components than original should stop at end of original name')

    def test_subname(self):
        name = Name("/edu/cmu/andrew/user/3498478")
        subName1 = name.getSubName(0)
        self.assertEqual(subName1, name, 'Subname from first component does not match original name')
        subName2 = name.getSubName(3)
        self.assertEqual(subName2, Name("/user/3498478"))

        subName3 = name.getSubName(1,3)
        self.assertEqual(subName3, Name("/cmu/andrew/user"))

        subName4 = name.getSubName(0,100)
        self.assertEqual(name, subName4, 'Subname with more components than original should stop at end of original name')

        subName5 = name.getSubName(7,2)
        self.assertEqual(Name(), subName5, 'Subname beginning after end of name should be empty')

        subName6 = name.getSubName(-1,7)
        self.assertEqual(subName6, Name("/3498478"), 'Negative subname with more components than original should stop at end of original name')

        subName7 = name.getSubName(-5,5)
        self.assertEqual(subName7, name, 'Subname from (-length) should match original name')

    def test_clear(self):
        name = Name(self.expectedURI)
        name.clear()
        self.assertTrue(Name() == name, 'Cleared name is not empty')

    def test_compare(self):
        names = [Name(x) for x in  [ "/a/b/d", "/c", "/c/a", "/bb", "/a/b/cc"]]
        expectedOrder = ["/a/b/d", "/a/b/cc", "/c", "/c/a", "/bb"]
        sortedNames = sorted(names, cmp=lambda x,y: x.compare(y))
        sortedURIs = [x.toUri() for x in sortedNames]
        self.assertEqual(sortedURIs, expectedOrder, 'Name comparison gave incorrect order')

    def test_match(self):
        name = Name("/edu/cmu/andrew/user/3498478")
        name2 = Name(name)
        self.assertTrue(name.match(name2), 'Name does not match deep copy of itself')

        name2 = name[:2]
        self.assertTrue(name2.match(name), 'Name did not match prefix')
        self.assertFalse(name.match(name2), 'Name should not match shorter name')
        self.assertTrue(Name().match(name), 'Empty name should always match another')

#   def test_component_constructor(self):
#       name1 = Name([self.entree, self.comp1, self.comp2])
#       self.assertEqual(name1.toUri(), self.expectedURI)

if __name__ == '__main__':
    ut.main(verbosity=2)

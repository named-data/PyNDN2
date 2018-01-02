# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2018 Regents of the University of California.
# Author: Adeola Bannis <thecodemaiden@gmail.com>
# From ndn-cxx unit tests:
# https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/name.t.cpp
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
from pyndn.encoding import TlvWireFormat

TEST_NAME = Blob(bytearray([
  0x7,  0x14, # Name
    0x8,  0x5, # NameComponent
        0x6c,  0x6f,  0x63,  0x61,  0x6c,
    0x8,  0x3, # NameComponent
        0x6e,  0x64,  0x6e,
    0x8,  0x6, # NameComponent
        0x70,  0x72,  0x65,  0x66,  0x69,  0x78
  ]))

TEST_NAME_IMPLICIT_DIGEST = Blob(bytearray([
  0x7,  0x36, # Name
    0x8,  0x5, # NameComponent
        0x6c,  0x6f,  0x63,  0x61,  0x6c,
    0x8,  0x3, # NameComponent
        0x6e,  0x64,  0x6e,
    0x8,  0x6, # NameComponent
        0x70,  0x72,  0x65,  0x66,  0x69,  0x78,
    0x01, 0x20, # ImplicitSha256DigestComponent
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  ]))

class TestNameComponentMethods(ut.TestCase):
    def setUp(self):
        pass

    def test_unicode(self):
        comp1 = Name.Component(u"entr\u00E9e")
        expected = "entr%C3%A9e"
        self.assertEqual(comp1.toEscapedString(), expected)

    def test_compare(self):
        c7f = Name("/%7F").get(0)
        c80 = Name("/%80").get(0)
        c81 = Name("/%81").get(0)

        self.assertTrue(c81.compare(c80) > 0, "%81 should be greater than %80")
        self.assertTrue(c80.compare(c7f) > 0, "%80 should be greater than %7f")

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
        sortedNames = sorted(names)
        sortedURIs = [x.toUri() for x in sortedNames]
        self.assertEqual(sortedURIs, expectedOrder, 'Name comparison gave incorrect order')

        # Tests from ndn-cxx name.t.cpp Compare.
        self.assertEqual(Name("/A")  .compare(Name("/A")),    0)
        self.assertEqual(Name("/A")  .compare(Name("/A")),    0)
        self.assertTrue (Name("/A")  .compare(Name("/B"))   < 0)
        self.assertTrue (Name("/B")  .compare(Name("/A"))   > 0)
        self.assertTrue (Name("/A")  .compare(Name("/AA"))  < 0)
        self.assertTrue (Name("/AA") .compare(Name("/A"))   > 0)
        self.assertTrue (Name("/A")  .compare(Name("/A/C")) < 0)
        self.assertTrue (Name("/A/C").compare(Name("/A"))   > 0)

        self.assertEqual(Name("/Z/A/Y")  .compare(1, 1, Name("/A")),    0)
        self.assertEqual(Name("/Z/A/Y")  .compare(1, 1, Name("/A")),    0)
        self.assertTrue (Name("/Z/A/Y")  .compare(1, 1, Name("/B"))   < 0)
        self.assertTrue (Name("/Z/B/Y")  .compare(1, 1, Name("/A"))   > 0)
        self.assertTrue (Name("/Z/A/Y")  .compare(1, 1, Name("/AA"))  < 0)
        self.assertTrue (Name("/Z/AA/Y") .compare(1, 1, Name("/A"))   > 0)
        self.assertTrue (Name("/Z/A/Y")  .compare(1, 1, Name("/A/C")) < 0)
        self.assertTrue (Name("/Z/A/C/Y").compare(1, 2, Name("/A"))   > 0)

        self.assertEqual(Name("/Z/A")  .compare(1, 9, Name("/A")),    0)
        self.assertEqual(Name("/Z/A")  .compare(1, 9, Name("/A")),    0)
        self.assertTrue (Name("/Z/A")  .compare(1, 9, Name("/B"))   < 0)
        self.assertTrue (Name("/Z/B")  .compare(1, 9, Name("/A"))   > 0)
        self.assertTrue (Name("/Z/A")  .compare(1, 9, Name("/AA"))  < 0)
        self.assertTrue (Name("/Z/AA") .compare(1, 9, Name("/A"))   > 0)
        self.assertTrue (Name("/Z/A")  .compare(1, 9, Name("/A/C")) < 0)
        self.assertTrue (Name("/Z/A/C").compare(1, 9, Name("/A"))   > 0)

        self.assertEqual(Name("/Z/A/Y")  .compare(1, 1, Name("/X/A/W"),   1, 1),  0)
        self.assertEqual(Name("/Z/A/Y")  .compare(1, 1, Name("/X/A/W"),   1, 1),  0)
        self.assertTrue (Name("/Z/A/Y")  .compare(1, 1, Name("/X/B/W"),   1, 1) < 0)
        self.assertTrue (Name("/Z/B/Y")  .compare(1, 1, Name("/X/A/W"),   1, 1) > 0)
        self.assertTrue (Name("/Z/A/Y")  .compare(1, 1, Name("/X/AA/W"),  1, 1) < 0)
        self.assertTrue (Name("/Z/AA/Y") .compare(1, 1, Name("/X/A/W"),   1, 1) > 0)
        self.assertTrue (Name("/Z/A/Y")  .compare(1, 1, Name("/X/A/C/W"), 1, 2) < 0)
        self.assertTrue (Name("/Z/A/C/Y").compare(1, 2, Name("/X/A/W"),   1, 1) > 0)

        self.assertEqual(Name("/Z/A/Y")  .compare(1, 1, Name("/X/A"),   1),  0)
        self.assertEqual(Name("/Z/A/Y")  .compare(1, 1, Name("/X/A"),   1),  0)
        self.assertTrue (Name("/Z/A/Y")  .compare(1, 1, Name("/X/B"),   1) < 0)
        self.assertTrue (Name("/Z/B/Y")  .compare(1, 1, Name("/X/A"),   1) > 0)
        self.assertTrue (Name("/Z/A/Y")  .compare(1, 1, Name("/X/AA"),  1) < 0)
        self.assertTrue (Name("/Z/AA/Y") .compare(1, 1, Name("/X/A"),   1) > 0)
        self.assertTrue (Name("/Z/A/Y")  .compare(1, 1, Name("/X/A/C"), 1) < 0)
        self.assertTrue (Name("/Z/A/C/Y").compare(1, 2, Name("/X/A"),   1) > 0)

    def test_match(self):
        name = Name("/edu/cmu/andrew/user/3498478")
        name2 = Name(name)
        self.assertTrue(name.match(name2), 'Name does not match deep copy of itself')

        name2 = name[:2]
        self.assertTrue(name2.match(name), 'Name did not match prefix')
        self.assertFalse(name.match(name2), 'Name should not match shorter name')
        self.assertTrue(Name().match(name), 'Empty name should always match another')

    def test_get_successor(self):
        self.assertEqual(Name("ndn:/%00%01/%01%03"), Name("ndn:/%00%01/%01%02").getSuccessor())
        self.assertEqual(Name("ndn:/%00%01/%02%00"), Name("ndn:/%00%01/%01%FF").getSuccessor())
        self.assertEqual(Name("ndn:/%00%01/%00%00%00"), Name("ndn:/%00%01/%FF%FF").getSuccessor())
        self.assertEqual(Name("/%00"), Name().getSuccessor())
        self.assertEqual(Name("/%00%01/%00"), Name("/%00%01/...").getSuccessor())

    def test_encode_decode(self):
        name = Name("/local/ndn/prefix")

        encoding = name.wireEncode(TlvWireFormat.get())
        self.assertTrue(encoding.equals(Blob(TEST_NAME)))

        decodedName = Name()
        decodedName.wireDecode(Blob(TEST_NAME), TlvWireFormat.get())
        self.assertEqual(decodedName, name)

        # Test ImplicitSha256Digest.
        name2 = Name(
          "/local/ndn/prefix/sha256digest=" +
          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

        encoding2 = name2.wireEncode(TlvWireFormat.get())
        self.assertTrue(encoding2.equals(Blob(TEST_NAME_IMPLICIT_DIGEST)))

        decodedName2 = Name()
        decodedName2.wireDecode(Blob(TEST_NAME_IMPLICIT_DIGEST), TlvWireFormat.get())
        self.assertEqual(decodedName2, name2)

    def test_implicit_sha256_digest(self):
        name = Name()

        digest = bytearray([
          0x28, 0xba, 0xd4, 0xb5, 0x27, 0x5b, 0xd3, 0x92,
          0xdb, 0xb6, 0x70, 0xc7, 0x5c, 0xf0, 0xb6, 0x6f,
          0x13, 0xf7, 0x94, 0x2b, 0x21, 0xe8, 0x0f, 0x55,
          0xc0, 0xe8, 0x6b, 0x37, 0x47, 0x53, 0xa5, 0x48,
          0x00, 0x00
        ])

        name.appendImplicitSha256Digest(digest[0:32])
        name.appendImplicitSha256Digest(digest[0:32])
        self.assertEqual(name.get(0), name.get(1))

        gotError = True
        try:
            name.appendImplicitSha256Digest(digest[0:34])
            gotError = False
        except:
            pass
        if not gotError:
          self.fail("Expected error in appendImplicitSha256Digest")

        gotError = True
        try:
            name.appendImplicitSha256Digest(digest[0:30])
            gotError = False
        except:
            pass
        if not gotError:
          self.fail("Expected error in appendImplicitSha256Digest")

        # Add name.get(2) as a generic component.
        name.append(digest[0:32])
        self.assertTrue(name.get(0).compare(name.get(2)) < 0)
        self.assertEqual(name.get(0).getValue(), name.get(2).getValue())

        # Add name.get(3) as a generic component whose first byte is greater.
        name.append(digest[1:32])
        self.assertTrue(name.get(0).compare(name.get(3)) < 0)

        self.assertEqual(
          name.get(0).toEscapedString(),
          "sha256digest=" +
          "28bad4b5275bd392dbb670c75cf0b66f13f7942b21e80f55c0e86b374753a548")

        self.assertEqual(name.get(0).isImplicitSha256Digest(), True)
        self.assertEqual(name.get(2).isImplicitSha256Digest(), False)

        gotError = True
        try:
            Name("/hello/sha256digest=hmm")
            gotError = False
        except:
            pass
        if not gotError:
          self.fail("Expected error in new Name from URI")

        # Check canonical URI encoding (lower case).
        name2 = Name(
          "/hello/sha256digest=" +
          "28bad4b5275bd392dbb670c75cf0b66f13f7942b21e80f55c0e86b374753a548")
        self.assertEqual(name.get(0), name2.get(1))

        # Check that it will accept a hex value in upper case too.
        name2 = Name(
          "/hello/sha256digest=" +
          "28BAD4B5275BD392DBB670C75CF0B66F13F7942B21E80F55C0E86B374753A548")
        self.assertEqual(name.get(0), name2.get(1))

        # This is not a valid sha256digest component. It should be treated as generic.
        name2 = Name(
          "/hello/SHA256DIGEST=" +
          "28BAD4B5275BD392DBB670C75CF0B66F13F7942B21E80F55C0E86B374753A548")
        self.assertNotEqual(name.get(0), name2.get(1))
        self.assertTrue(name2.get(1).isGeneric())

#   def test_component_constructor(self):
#       name1 = Name([self.entree, self.comp1, self.comp2])
#       self.assertEqual(name1.toUri(), self.expectedURI)

if __name__ == '__main__':
    ut.main(verbosity=2)

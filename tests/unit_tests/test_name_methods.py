import unittest as ut
from pyndn import Name
from pyndn import Interest
from pyndn import KeyLocatorType
from pyndn.util import Blob

from test_utils import dump

class TestNameComponentMethods(ut.TestCase):
    def setUp(self):
        pass

    def test_unicode(self):
        comp1 = Name.Component(u"entr\u00E9e")
        expected = "entr%C3%A9e"
        #self.assertEqual(comp1.toEscapedString(), expected)
        self.assertEqual(comp1.toEscapedString(), "test Jenkins alert")
    
    def test_bytearray(self):
        pass

    ## many more component methods to be tested!

class TestNameMethods(ut.TestCase):

    def setUp(self):
        self.entree = Name.Component(u"entr\u00E9e")
        self.comp1 = Name.Component(bytearray(['.']*4))
        self.comp2 = Name.Component(bytearray([0x00, 0x01, 0x02, 0x03]))
        self.expectedURI = "/entr%C3%A9e/..../%00%01%02%03"

    def tearDown(self):
        pass

    def test_uri_constructor(self):
        name = Name(self.expectedURI)
        self.assertEqual(name.size(),3, 'Constructed name has ' + str(name.size()) + ' components instead of 3')
        self.assertEqual(name.toUri(), self.expectedURI, 'URI is incorrect')

    def test_copy_constructor(self):
        name = Name(self.expectedURI)
        name2 = Name(name)
        self.assertTrue(name.equals(name2), 'Name from copy constructor does not match original')

    def test_get_component(self):
        name = Name(self.expectedURI)
        comp2 = name.get(2)
        self.assertTrue(self.comp2.equals(comp2), 'Component at index 2 is incorrect')

    def test_prefix(self):
        name = Name(self.expectedURI)
        name2 = name.getPrefix(2)
        self.assertEqual(name2.size(),2, 'Name prefix has ' + str(name2.size()) + ' components instead of 2')
        for i in range(2):
            self.assertTrue(name.get(i).getValue().equals(name2.get(i).getValue()))

    def test_append(self):
        # could possibly split this into different tests
        uri = "/localhost/user/folders/files/%00%0F"
        name = Name(uri)
        name2 = Name("/localhost").append(Name("/user/folders/"))
        self.assertEqual(name2.size(), 3, 'Name constructed by appending names has ' + str(name2.size()) + ' components instead of 3')
        self.assertTrue(name2.get(2).getValue().equals(Blob(bytearray("folders"))), 'Name constructed with append has wrong suffix')
        name2 = name2.append("files")
        self.assertEqual(name2.size(), 4, 'Name constructed by appending string has ' + str(name2.size()) + ' components instead of 4')
        name2 = name2.appendSegment(15)
        self.assertTrue(name2.get(4).getValue().equals(Blob(bytearray([0x00, 0x0F]))), 'Name constructed by appending segment has wrong segment value')

        self.assertTrue(name2.equals(name), 'Name constructed with append is not equal to URI constructed name')
        self.assertEqual(name2.toUri(), name.toUri(), 'Name constructed with append has wrong URI')

    def test_subname(self):        
        name = Name("/edu/cmu/andrew/user/3498478")
        subName1 = name.getSubName(0)
        self.assertTrue(subName1.equals(name), 'Subname from first component does not match original name')
        subName2 = name.getSubName(3)
        self.assertEqual(subName2.toUri(), "/user/3498478")

        subName3 = name.getSubName(1,3)
        self.assertEqual(subName3.toUri(), "/cmu/andrew/user")

        subName4 = name.getSubName(0,100)
        self.assertTrue(name.equals(subName4), 'Subname with more components than original should stop at end of original name')

        subName5 = name.getSubName(7,9)
        self.assertTrue(Name().equals(subName5), 'Subname beginning after end of name should be empty')

    def test_clear(self):
        name = Name(self.expectedURI)
        name.clear()
        self.assertTrue(Name().equals(name), 'Cleared name is not empty')

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

        name2 = name.getPrefix(2)
        self.assertTrue(name2.match(name), 'Name did not match prefix')
        self.assertFalse(name.match(name2), 'Name should not match shorter name')
        self.assertTrue(Name().match(name), 'Empty name should always match another')

#   def test_component_constructor(self):
#       name1 = Name([self.entree, self.comp1, self.comp2])
#       self.assertEqual(name1.toUri(), self.expectedURI)

if __name__ == '__main__':
    ut.main(verbosity=2)

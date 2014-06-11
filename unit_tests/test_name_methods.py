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
        self.assertEqual(comp1.toEscapedString(), expected)
    
    def test_bytearray(self):
        pass

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

    def test_get_prefix(self):
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
        self.assertEqual(name2.size(), 3, 'Name constructed by adding names has ' + str(name2.size()) + ' components instead of 3')
        self.assertTrue(name2.get(2).getValue().equals(Blob(bytearray("folders"))), 'Name constructed with add has wrong suffix')
        name2 = name2.append("files")
        self.assertEqual(name2.size(), 4, 'Name constructed by adding string has ' + str(name2.size()) + ' components instead of 4')
        name2 = name2.appendSegment(15)
        self.assertTrue(name2.get(4).getValue().equals(Blob(bytearray([0x00, 0x0F]))), 'Name constructed by adding segment has wrong segment value')

        self.assertTrue(name2.equals(name), 'Name constructed with add is not equal to URI constructed name')
        self.assertEqual(name2.toUri(), name.toUri(), 'Name constructed with add has wrong URI')

#   def test_component_constructor(self):
#       name1 = Name([self.entree, self.comp1, self.comp2])
#       self.assertEqual(name1.toUri(), self.expectedURI)

if __name__ == '__main__':
    suite = ut.TestLoader().loadTestsFromTestCase(TestNameComponentMethods)
    ut.TextTestRunner(verbosity=2).run(suite)

    suite = ut.TestLoader().loadTestsFromTestCase(TestNameMethods)
    ut.TextTestRunner(verbosity=2).run(suite)

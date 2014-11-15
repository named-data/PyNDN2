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
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU Lesser General Public License is in the file COPYING.


from pyndn.security.policy import ConfigPolicyManager
from pyndn.security.identity import MemoryIdentityStorage, MemoryPrivateKeyStorage, IdentityManager
from pyndn.security import KeyChain
from pyndn.security.security_types import KeyType
from pyndn import Name, Data
from pyndn.util import Blob
from test_utils import DEFAULT_RSA_PUBLIC_KEY_DER, DEFAULT_RSA_PRIVATE_KEY_DER
from pyndn import Name
import unittest as ut

class TestRegexMatching(ut.TestCase):

    def _certNameFromKeyName(self, keyName, keyIdx=-1):
        return keyName[:keyIdx].append("KEY").append(keyName[keyIdx:]).\
                append("ID-CERT").append("0")

    def setUp(self):
        # set up the keychain so we can sign data
        self.identityStorage = MemoryIdentityStorage()
        self.privateKeyStorage = MemoryPrivateKeyStorage()
        self.keyChain = KeyChain(IdentityManager(self.identityStorage, self.privateKeyStorage))
        self.privateKeyStorage = MemoryPrivateKeyStorage()

        # not using keychain for verification so we don't neet to set the
        # policy manager
        self.keyChain = KeyChain(IdentityManager(self.identityStorage, self.privateKeyStorage))
        self.identityName = Name('/SecurityTestSecRule/Basic/Longer')
        keyName = Name(self.identityName).append('ksk-2439872')
        self.defaultCertName = self._certNameFromKeyName(keyName)
        self.identityStorage.addKey(keyName, KeyType.RSA, Blob(DEFAULT_RSA_PUBLIC_KEY_DER))
        self.privateKeyStorage.setKeyPairForKeyName(
      keyName, KeyType.RSA, DEFAULT_RSA_PUBLIC_KEY_DER, DEFAULT_RSA_PRIVATE_KEY_DER)

        keyName = Name('/SecurityTestSecRule/Basic/ksk-0923489')
        self.identityStorage.addKey(keyName, KeyType.RSA, Blob(DEFAULT_RSA_PUBLIC_KEY_DER))
        self.privateKeyStorage.setKeyPairForKeyName(
      keyName, KeyType.RSA, DEFAULT_RSA_PUBLIC_KEY_DER, DEFAULT_RSA_PRIVATE_KEY_DER)
        self.shortCertName = self._certNameFromKeyName(keyName, -2)

    def test_name_relation(self):
        policyManagerPrefix = ConfigPolicyManager("policy_config/relation_ruleset_prefix.conf")
        policyManagerStrict = ConfigPolicyManager("policy_config/relation_ruleset_strict.conf")
        policyManagerEqual = ConfigPolicyManager("policy_config/relation_ruleset_equal.conf")

        dataName = Name('/TestRule1')

        self.assertIsNotNone(
                policyManagerPrefix._findMatchingRule(dataName, 'data'),
                "Prefix relation should match prefix name")
        self.assertIsNotNone(
                policyManagerEqual._findMatchingRule(dataName, 'data'),
                "Equal relation should match prefix name")
        self.assertIsNone(
                policyManagerStrict._findMatchingRule(dataName, 'data'),
                "Strict-prefix relation should not match prefix name")

        dataName = Name('/TestRule1/hi')
        self.assertIsNotNone(
                policyManagerPrefix._findMatchingRule(dataName, 'data'),
                "Prefix relation should match longer name")
        self.assertIsNone(
                policyManagerEqual._findMatchingRule(dataName, 'data'),
                "Equal relation should not match longer name")
        self.assertIsNotNone(
                policyManagerStrict._findMatchingRule(dataName, 'data'),
                "Strict-prefix relation should match longer name")

        dataName = Name('/Bad/TestRule1/')
        self.assertIsNone(
                policyManagerPrefix._findMatchingRule(dataName, 'data'),
                "Prefix relation should not match inner components")
        self.assertIsNone(
                policyManagerEqual._findMatchingRule(dataName, 'data'),
                "Equal relation should not match inner components")
        self.assertIsNone(
                policyManagerStrict._findMatchingRule(dataName, 'data'),
                "Strict-prefix relation should  not match inner components")

    def test_simple_regex(self):
        policyManager = ConfigPolicyManager("policy_config/regex_ruleset.conf")
        dataName1 = Name('/SecurityTestSecRule/Basic')
        dataName2 = Name('/SecurityTestSecRule/Basic/More')
        dataName3 = Name('/SecurityTestSecRule/')
        dataName4 = Name('/SecurityTestSecRule/Other/TestData')
        dataName5 = Name('/Basic/Data')

        matchedRule1 = policyManager._findMatchingRule(dataName1, 'data')
        matchedRule2 = policyManager._findMatchingRule(dataName2, 'data')
        matchedRule3 = policyManager._findMatchingRule(dataName3, 'data')
        matchedRule4 = policyManager._findMatchingRule(dataName4, 'data')
        matchedRule5 = policyManager._findMatchingRule(dataName5, 'data')

        self.assertIsNotNone(matchedRule1)
        self.assertIsNone(matchedRule2)
        self.assertIsNotNone(matchedRule3)
        self.assertNotEqual(matchedRule3, matchedRule1,
                "Rule regex matched extra components")
        self.assertIsNotNone(matchedRule4)
        self.assertNotEqual(matchedRule4, matchedRule1,
                "Rule regex matched with missing component")

        self.assertIsNone(matchedRule5)

    def test_checker_hierarchical(self):
        policyManager = ConfigPolicyManager("policy_config/hierarchical_ruleset.conf")

        dataName1 = Name('/SecurityTestSecRule/Basic/Data1')
        dataName2 = Name('/SecurityTestSecRule/Basic/Longer/Data2')

        data1 = Data(dataName1)
        data2 = Data(dataName2)

        matchedRule = policyManager._findMatchingRule(dataName1, 'data')
        self.assertEqual(matchedRule,
                policyManager._findMatchingRule(dataName2, 'data'))

        self.keyChain.sign(data1, self.defaultCertName)
        self.keyChain.sign(data2, self.defaultCertName)

        signatureName1 = data1.getSignature().getKeyLocator().getKeyName()
        signatureName2 = data2.getSignature().getKeyLocator().getKeyName()

        self.assertFalse(policyManager._checkSignatureMatch(signatureName1,
            dataName1, matchedRule),
            "Hierarchical matcher matched short data name to long key name")

        self.assertTrue(policyManager._checkSignatureMatch(signatureName2,
            dataName2, matchedRule))

        self.keyChain.sign(data1, self.shortCertName)
        self.keyChain.sign(data2, self.shortCertName)

        signatureName1 = data1.getSignature().getKeyLocator().getKeyName()
        signatureName2 = data2.getSignature().getKeyLocator().getKeyName()

        self.assertTrue(policyManager._checkSignatureMatch(signatureName1,
            dataName1, matchedRule))
        self.assertTrue(policyManager._checkSignatureMatch(signatureName2,
            dataName2, matchedRule))


    def test_hyperrelation(self):
        policyManager = ConfigPolicyManager("policy_config/hyperrelation_ruleset.conf")

        dataName = Name('/SecurityTestSecRule/Basic/Longer/Data2')
        data1 = Data(dataName)
        data2 = Data(dataName)

        matchedRule = policyManager._findMatchingRule(dataName, 'data')
        self.keyChain.sign(data1, self.defaultCertName)
        self.keyChain.sign(data2, self.shortCertName)

        signatureName1 = data1.getSignature().getKeyLocator().getKeyName()
        signatureName2 = data2.getSignature().getKeyLocator().getKeyName()

        self.assertTrue(policyManager._checkSignatureMatch(signatureName1,
            dataName, matchedRule))
        self.assertFalse(policyManager._checkSignatureMatch(signatureName2,
            dataName, matchedRule))

        dataName = Name('/SecurityTestSecRule/Basic/Other/Data1')
        data1 = Data(dataName)
        data2 = Data(dataName)

        matchedRule = policyManager._findMatchingRule(dataName, 'data')
        self.keyChain.sign(data1, self.defaultCertName)
        self.keyChain.sign(data2, self.shortCertName)

        signatureName1 = data1.getSignature().getKeyLocator().getKeyName()
        signatureName2 = data2.getSignature().getKeyLocator().getKeyName()

        self.assertFalse(policyManager._checkSignatureMatch(signatureName1,
            dataName, matchedRule))
        self.assertTrue(policyManager._checkSignatureMatch(signatureName2,
            dataName, matchedRule))

    def test_interest_matching(self):
        # make sure we chop off timestamp, nonce, and signature info from
        # signed interests
        pass



if __name__ == '__main__':
    ut.main(verbosity=2)

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

    def _certNameFromKeyName(self, keyName):
        return keyName.getSubName(0, keyName.size() - 1).append(
      "KEY").append(keyName[-1]).append("ID-CERT").append("0")

    def setUp(self):
        # set up the keychain so we can sign data
        self.identityStorage = MemoryIdentityStorage()
        self.privateKeyStorage = MemoryPrivateKeyStorage()
        self.keyChain = KeyChain(IdentityManager(self.identityStorage, self.privateKeyStorage))
        self.privateKeyStorage = MemoryPrivateKeyStorage()
        
        # not using keychain for verification so we don't neet to set the
        # policy manager
        self.keyChain = KeyChain(IdentityManager(self.identityStorage, self.privateKeyStorage))
        self.identityName = Name('/SecurityTestSecRule/Basic/Rsa')
        keyName = Name(self.identityName).append('ksk-2439872')
        self.defaultCertName = self._certNameFromKeyName(keyName)
        self.identityStorage.addKey(keyName, KeyType.RSA, Blob(DEFAULT_RSA_PUBLIC_KEY_DER))
        self.privateKeyStorage.setKeyPairForKeyName(
      keyName, KeyType.RSA, DEFAULT_RSA_PUBLIC_KEY_DER, DEFAULT_RSA_PRIVATE_KEY_DER)

        keyName = Name('/SecurityTestSecRule/Basic')
        self.identityStorage.addKey(keyName, KeyType.RSA, Blob(DEFAULT_RSA_PUBLIC_KEY_DER))
        self.privateKeyStorage.setKeyPairForKeyName(
      keyName, KeyType.RSA, DEFAULT_RSA_PUBLIC_KEY_DER, DEFAULT_RSA_PRIVATE_KEY_DER)
        self.shortCertName = self._certNameFromKeyName(keyName)
    
    def test_name_relation(self):
        policyManagerPrefix = ConfigPolicyManager(self.identityStorage, 
            "policy_config/relation_ruleset_prefix.conf")
        policyManagerStrict = ConfigPolicyManager(self.identityStorage, 
            "policy_config/relation_ruleset_strict.conf")
        policyManagerEqual = ConfigPolicyManager(self.identityStorage, 
            "policy_config/relation_ruleset_equal.conf")

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
        """
        The rule in regex_ruleset.conf requires that the data name is
            /SecurityTestSecRule/Basic
        and the signer name has exactly 1 more component before the key parts
            i.e. /SecurityTestSecRule/Basic/?/KEY/?/?
            
        """
        policyManager = ConfigPolicyManager(self.identityStorage, 
            "policy_config/regex_ruleset.conf")
        data = Data(Name('/SecurityTestSecRule/Basic'))
        self.keyChain.sign(data, self.defaultCertName)

        matchingRule = policyManager._findMatchingRule(data.getName(), 'data')
        self.assertIsNotNone(matchingRule, "Validator did not match data name to rule")

        signatureName = data.getSignature().getKeyLocator().getKeyName()
        self.assertTrue(policyManager._checkSignatureMatch(signatureName,
            data.getName(), matchingRule))

        wrongNameData = Data(Name('/SecurityTestSecRule/Other'))
        self.keyChain.sign(wrongNameData, self.defaultCertName)
        matchingRule = policyManager._findMatchingRule(wrongNameData.getName(), 'data')
        self.assertIsNone(matchingRule, "Validator matched bad name to rule")

        wrongSignerData = Data(data)
        self.keyChain.sign(wrongSignerData, self.shortCertName)
        matchingRule = policyManager._findMatchingRule(wrongSignerData.getName(), 'data')
        self.assertIsNotNone(matchingRule, "Validator did not match data name to rule")

        signatureName = wrongSignerData.getSignature().getKeyLocator().getKeyName()
        self.assertFalse(policyManager._checkSignatureMatch(signatureName, 
            wrongSignerData.getName(), matchingRule), "Validator allows wrong signer")


    def test_hyper_relation(self):
        policyManager = ConfigPolicyManager(self.identityStorage, 
            "policy_config/hyperrelation_ruleset.conf")
        data = Data(Name('/SecurityTestSecRule/Basic'))
        self.keyChain.sign(data, self.defaultCertName)

        matchingRule = policyManager._findMatchingRule(data.getName(), 'data')
        self.assertTrue(matchingRule is not None)

        signatureName = data.getSignature().getKeyLocator().getKeyName()
        self.assertTrue(policyManager._checkSignatureMatch(signatureName,
            data.getName(), matchingRule))

if __name__ == '__main__':
    ut.main(verbosity=2)

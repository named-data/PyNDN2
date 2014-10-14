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
        self.defaultCertName = keyName.getSubName(0, keyName.size() - 1).append(
      "KEY").append(keyName[-1]).append("ID-CERT").append("0")

        self.identityStorage.addKey(keyName, KeyType.RSA, Blob(DEFAULT_RSA_PUBLIC_KEY_DER))
        self.privateKeyStorage.setKeyPairForKeyName(
      keyName, KeyType.RSA, DEFAULT_RSA_PUBLIC_KEY_DER, DEFAULT_RSA_PRIVATE_KEY_DER)
        self.identityStorage.setDefaultIdentity(self.identityName)
    
     
    def test_simple_regex(self):
        policyManager = ConfigPolicyManager(self.identityStorage, 
            "validator1.conf")
        rsaData = Data(Name('/SecurityTestSecRule/Basic'))
        self.keyChain.sign(rsaData, self.defaultCertName)

        matchingRule = policyManager._findMatchingRule(rsaData.getName(), 'data')
        self.assertTrue(matchingRule is not None)

        signatureName = rsaData.getSignature().getKeyLocator().getKeyName()
        self.assertTrue(policyManager._checkSignatureMatch(signatureName,
            rsaData.getName(), matchingRule))


    def test_hyper_relation(self):
        policyManager = ConfigPolicyManager(self.identityStorage, 
            "validator2.conf")
        rsaData = Data(Name('/SecurityTestSecRule/Basic'))
        self.keyChain.sign(rsaData, self.defaultCertName)

        matchingRule = policyManager._findMatchingRule(rsaData.getName(), 'data')
        self.assertTrue(matchingRule is not None)

        signatureName = rsaData.getSignature().getKeyLocator().getKeyName()
        self.assertTrue(policyManager._checkSignatureMatch(signatureName,
            rsaData.getName(), matchingRule))

if __name__ == '__main__':
    ut.main(verbosity=2)

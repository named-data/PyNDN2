# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# From ndn-cxx unit tests:
# https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/transform/private-key.t.cpp
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
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from pyndn.security import RsaKeyParams, EcKeyParams, DigestAlgorithm, KeyType
from pyndn.security.tpm.tpm_private_key import TpmPrivateKey
from pyndn.security.certificate import PublicKey
from pyndn.util import Blob

class TestTpmPrivateKey(ut.TestCase):
    class RsaKeyTestData(object):
        def __init__(self):
            self.keyParams = RsaKeyParams()

            self.privateKeyPkcs1 = (
"MIIEpAIBAAKCAQEAw0WM1/WhAxyLtEqsiAJgWDZWuzkYpeYVdeeZcqRZzzfRgBQT\n" +
"sNozS5t4HnwTZhwwXbH7k3QN0kRTV826Xobws3iigohnM9yTK+KKiayPhIAm/+5H\n" +
"GT6SgFJhYhqo1/upWdueojil6RP4/AgavHhopxlAVbk6G9VdVnlQcQ5Zv0OcGi73\n" +
"c+EnYD/YgURYGSngUi/Ynsh779p2U69/te9gZwIL5PuE9BiO6I39cL9z7EK1SfZh\n" +
"OWvDe/qH7YhD/BHwcWit8FjRww1glwRVTJsA9rH58ynaAix0tcR/nBMRLUX+e3rU\n" +
"RHg6UbSjJbdb9qmKM1fTGHKUzL/5pMG6uBU0ywIDAQABAoIBADQkckOIl4IZMUTn\n" +
"W8LFv6xOdkJwMKC8G6bsPRFbyY+HvC2TLt7epSvfS+f4AcYWaOPcDu2E49vt2sNr\n" +
"cASly8hgwiRRAB3dHH9vcsboiTo8bi2RFvMqvjv9w3tK2yMxVDtmZamzrrnaV3YV\n" +
"Q+5nyKo2F/PMDjQ4eUAKDOzjhBuKHsZBTFnA1MFNI+UKj5X4Yp64DFmKlxTX/U2b\n" +
"wzVywo5hzx2Uhw51jmoLls4YUvMJXD0wW5ZtYRuPogXvXb/of9ef/20/wU11WFKg\n" +
"Xb4gfR8zUXaXS1sXcnVm3+24vIs9dApUwykuoyjOqxWqcHRec2QT2FxVGkFEraze\n" +
"CPa4rMECgYEA5Y8CywomIcTgerFGFCeMHJr8nQGqY2V/owFb3k9maczPnC9p4a9R\n" +
"c5szLxA9FMYFxurQZMBWSEG2JS1HR2mnjigx8UKjYML/A+rvvjZOMe4M6Sy2ggh4\n" +
"SkLZKpWTzjTe07ByM/j5v/SjNZhWAG7sw4/LmPGRQkwJv+KZhGojuOkCgYEA2cOF\n" +
"T6cJRv6kvzTz9S0COZOVm+euJh/BXp7oAsAmbNfOpckPMzqHXy8/wpdKl6AAcB57\n" +
"OuztlNfV1D7qvbz7JuRlYwQ0cEfBgbZPcz1p18HHDXhwn57ZPb8G33Yh9Omg0HNA\n" +
"Imb4LsVuSqxA6NwSj7cpRekgTedrhLFPJ+Ydb5MCgYEAsM3Q7OjILcIg0t6uht9e\n" +
"vrlwTsz1mtCV2co2I6crzdj9HeI2vqf1KAElDt6G7PUHhglcr/yjd8uEqmWRPKNX\n" +
"ddnnfVZB10jYeP/93pac6z/Zmc3iU4yKeUe7U10ZFf0KkiiYDQd59CpLef/2XScS\n" +
"HB0oRofnxRQjfjLc4muNT+ECgYEAlcDk06MOOTly+F8lCc1bA1dgAmgwFd2usDBd\n" +
"Y07a3e0HGnGLN3Kfl7C5i0tZq64HvxLnMd2vgLVxQlXGPpdQrC1TH+XLXg+qnlZO\n" +
"ivSH7i0/gx75bHvj75eH1XK65V8pDVDEoSPottllAIs21CxLw3N1ObOZWJm2EfmR\n" +
"cuHICmsCgYAtFJ1idqMoHxES3mlRpf2JxyQudP3SCm2WpGmqVzhRYInqeatY5sUd\n" +
"lPLHm/p77RT7EyxQHTlwn8FJPuM/4ZH1rQd/vB+Y8qAtYJCexDMsbvLW+Js+VOvk\n" +
"jweEC0nrcL31j9mF0vz5E6tfRu4hhJ6L4yfWs0gSejskeVB/w8QY4g==\n")

            self.privateKeyPkcs8 = (
"MIIFCzA9BgkqhkiG9w0BBQ0wMDAbBgkqhkiG9w0BBQwwDgQIOKYJXvB6p8kCAggA\n" +
"MBEGBSsOAwIHBAiQgMK8kQXTyASCBMjeNiKYYw5/yHgs9BfSGrpqvV0LkkgMQNUW\n" +
"R4ZY8fuNjZynd+PxDuw2pyrv1Yv3jc+tupwUehZEzYOnGd53wQAuLO+Z0TBgRFN7\n" +
"Lhk+AxlT7hu0xaB3ZpJ/uvWpgEJHsq/aB/GYgyzXcQo2AiqzERVpMCWJVmE1L977\n" +
"CHwJmLm5mxclVLYp1UK5lkIBFu/M4nPavmNmYNUU1LOrXRo56TlJ2kUp8gQyQI1P\n" +
"VPxi4chmlsr/OnQ2d1eZN+euFm0CS+yP+LFgI9ZqdyH1w+J43SXdHDzauVcZp7oa\n" +
"Kw24OrhHfolLAnQIECXEJYeT7tZmhC4O9V6B18PFVyxWnEU4eFNpFE8kYSmm8Um2\n" +
"buvDKI71q43hm23moYT9uIM1f4M8UkoOliJGrlf4xgEcmDuokEX01PdOq1gc4nvG\n" +
"0DCwDI9cOsyn8cxhk9UVtFgzuG/seuznxIv1F5H0hzYOyloStXxRisJES0kgByBt\n" +
"FFTfyoFKRrmCjRIygwVKUSkSDR0DlQS5ZLvQyIswnSQFwxAHqfvoSL4dB9UAIAQ+\n" +
"ALVF1maaHgptbL6Ifqf0GFCv0hdNCVNDNCdy8R+S6nEYE+YdYSIdT1L88KD5PjU3\n" +
"YY/CMnxhTncMaT4acPO1UUYuSGRZ/JL6E0ihoqIU+bqUgLSHNzhPySPfN9uqN61Y\n" +
"HFBtxeEPWKU0f/JPkRBMmZdMI1/OVmA3QHSRBydI+CQN8no2gZRFoVbHTkG8IMpE\n" +
"1fiDJpwFkpzIv/JPiTSE7DeBH5NJk1bgu7TcuZfa4unyAqss0UuLnXzS06TppkUj\n" +
"QGft0g8VPW56eli6B4xrSzzuvAdbrxsVfxdmtHPyYxLb3/UG1g4x/H/yULhx7x9P\n" +
"iI6cw6JUE+8bwJV2ZIlHXXHO+wUp/gCFJ6MHo9wkR1QvnHP2ClJAzBm9OvYnUx2Y\n" +
"SX0HxEowW8BkhxOF184LEmxeua0yyZUqCdrYmErp7x9EY/LhD1zBwH8OGRa0qzmR\n" +
"VKxAPKihkb9OgxcUKbvKePx3k2cQ7fbCUspGPm4Kn1zwMgRAZ4fz/o8Lnwc8MSY3\n" +
"lPWnmLTFu420SRH2g9N0o/r195hiZ5cc+KfF4pwZWKbEbKFk/UfXA9vmOi7BBtDJ\n" +
"RWshOINhzMU6Ij3KuaEpHni1HoHjw0SQ97ow2x/aB8k2QC28tbsa49lD2KKJku6b\n" +
"2Or89adwFKqMgS2IXfXMXs/iG5EFLYN6r8e40Dn5f1vJfRLJl03XByIfT2n92pw3\n" +
"fP7muOIKLUsEKjOrmn94NwMlfeW13oQHEH2KjPOWFS/tyJHDdVU+of4COH5yg59a\n" +
"TZqFkOTGeliE1O+6sfF9fRuVxFUF3D8Hpr0JIjdc6+3RgIlGsXc8BwiSjDSI2XW+\n" +
"vo75/2zPU9t8OeXEIJk2CQGyqLwUJ6dyi/yDRrvZAgjrUvbpcxydnBAHrLbLUGXJ\n" +
"aEHH2tjEtnTqVyTchr1yHoupcFOCkA0dAA66XqwcssQxJiMGrWTpCbgd9mrTXQaZ\n" +
"U7afFN1jpO78tgBQUUpImXdHLLsqdN5tefqjileZGZ9x3/C6TNAfDwYJdsicNNn5\n" +
"y+JVsbltfLWlJxb9teb3dtQiFlJ7ofprLJnJVqI/Js8lozY+KaxV2vtbZkcD4dM=\n")

            self.privateKeyPkcs8Unencrypted = (
"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDDRYzX9aEDHIu0\n" +
"SqyIAmBYNla7ORil5hV155lypFnPN9GAFBOw2jNLm3gefBNmHDBdsfuTdA3SRFNX\n" +
"zbpehvCzeKKCiGcz3JMr4oqJrI+EgCb/7kcZPpKAUmFiGqjX+6lZ256iOKXpE/j8\n" +
"CBq8eGinGUBVuTob1V1WeVBxDlm/Q5waLvdz4SdgP9iBRFgZKeBSL9ieyHvv2nZT\n" +
"r3+172BnAgvk+4T0GI7ojf1wv3PsQrVJ9mE5a8N7+oftiEP8EfBxaK3wWNHDDWCX\n" +
"BFVMmwD2sfnzKdoCLHS1xH+cExEtRf57etREeDpRtKMlt1v2qYozV9MYcpTMv/mk\n" +
"wbq4FTTLAgMBAAECggEANCRyQ4iXghkxROdbwsW/rE52QnAwoLwbpuw9EVvJj4e8\n" +
"LZMu3t6lK99L5/gBxhZo49wO7YTj2+3aw2twBKXLyGDCJFEAHd0cf29yxuiJOjxu\n" +
"LZEW8yq+O/3De0rbIzFUO2ZlqbOuudpXdhVD7mfIqjYX88wONDh5QAoM7OOEG4oe\n" +
"xkFMWcDUwU0j5QqPlfhinrgMWYqXFNf9TZvDNXLCjmHPHZSHDnWOaguWzhhS8wlc\n" +
"PTBblm1hG4+iBe9dv+h/15//bT/BTXVYUqBdviB9HzNRdpdLWxdydWbf7bi8iz10\n" +
"ClTDKS6jKM6rFapwdF5zZBPYXFUaQUStrN4I9riswQKBgQDljwLLCiYhxOB6sUYU\n" +
"J4wcmvydAapjZX+jAVveT2ZpzM+cL2nhr1FzmzMvED0UxgXG6tBkwFZIQbYlLUdH\n" +
"aaeOKDHxQqNgwv8D6u++Nk4x7gzpLLaCCHhKQtkqlZPONN7TsHIz+Pm/9KM1mFYA\n" +
"buzDj8uY8ZFCTAm/4pmEaiO46QKBgQDZw4VPpwlG/qS/NPP1LQI5k5Wb564mH8Fe\n" +
"nugCwCZs186lyQ8zOodfLz/Cl0qXoABwHns67O2U19XUPuq9vPsm5GVjBDRwR8GB\n" +
"tk9zPWnXwccNeHCfntk9vwbfdiH06aDQc0AiZvguxW5KrEDo3BKPtylF6SBN52uE\n" +
"sU8n5h1vkwKBgQCwzdDs6MgtwiDS3q6G316+uXBOzPWa0JXZyjYjpyvN2P0d4ja+\n" +
"p/UoASUO3obs9QeGCVyv/KN3y4SqZZE8o1d12ed9VkHXSNh4//3elpzrP9mZzeJT\n" +
"jIp5R7tTXRkV/QqSKJgNB3n0Kkt5//ZdJxIcHShGh+fFFCN+Mtzia41P4QKBgQCV\n" +
"wOTTow45OXL4XyUJzVsDV2ACaDAV3a6wMF1jTtrd7QcacYs3cp+XsLmLS1mrrge/\n" +
"Eucx3a+AtXFCVcY+l1CsLVMf5cteD6qeVk6K9IfuLT+DHvlse+Pvl4fVcrrlXykN\n" +
"UMShI+i22WUAizbULEvDc3U5s5lYmbYR+ZFy4cgKawKBgC0UnWJ2oygfERLeaVGl\n" +
"/YnHJC50/dIKbZakaapXOFFgiep5q1jmxR2U8seb+nvtFPsTLFAdOXCfwUk+4z/h\n" +
"kfWtB3+8H5jyoC1gkJ7EMyxu8tb4mz5U6+SPB4QLSetwvfWP2YXS/PkTq19G7iGE\n" +
"novjJ9azSBJ6OyR5UH/DxBji\n")

            self.publicKeyEncoding = (
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw0WM1/WhAxyLtEqsiAJg\n" +
"WDZWuzkYpeYVdeeZcqRZzzfRgBQTsNozS5t4HnwTZhwwXbH7k3QN0kRTV826Xobw\n" +
"s3iigohnM9yTK+KKiayPhIAm/+5HGT6SgFJhYhqo1/upWdueojil6RP4/AgavHho\n" +
"pxlAVbk6G9VdVnlQcQ5Zv0OcGi73c+EnYD/YgURYGSngUi/Ynsh779p2U69/te9g\n" +
"ZwIL5PuE9BiO6I39cL9z7EK1SfZhOWvDe/qH7YhD/BHwcWit8FjRww1glwRVTJsA\n" +
"9rH58ynaAix0tcR/nBMRLUX+e3rURHg6UbSjJbdb9qmKM1fTGHKUzL/5pMG6uBU0\n" +
"ywIDAQAB\n")

    class EcKeyTestData(object):
        def __init__(self) :
            self.keyParams = EcKeyParams()

            self.privateKeyPkcs1 = (
"MIIBaAIBAQQgRxwcbzK9RV6AHYFsDcykI86o3M/a1KlJn0z8PcLMBZOggfowgfcC\n" +
"AQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA////////////////\n" +
"MFsEIP////8AAAABAAAAAAAAAAAAAAAA///////////////8BCBaxjXYqjqT57Pr\n" +
"vVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSdNgiG5wSTamZ44ROdJreBn36QBEEE\n" +
"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54W\n" +
"K84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8\n" +
"YyVRAgEBoUQDQgAEaG4WJuDAt0QkEM4t29KDUdzkQlMPGrqWzkWhgt9OGnwc6O7A\n" +
"ZLPSrDyhwyrKS7XLRXml5DisQ93RvByll32y8A==\n")

            self.privateKeyPkcs8 = (
"MIIBwzA9BgkqhkiG9w0BBQ0wMDAbBgkqhkiG9w0BBQwwDgQIVHkBzLGtDvICAggA\n" +
"MBEGBSsOAwIHBAhk6g9eI3toNwSCAYDd+LWPDBTrKV7vUyxTvDbpUd0eXfh73DKA\n" +
"MHkdHuVmhpmpBbsF9XvaFuL8J/1xi1Yl2XGw8j3WyrprD2YEhl/+zKjNbdTDJmNO\n" +
"SlomuwWb5AVCJ9reT94zIXKCnexUcyBFS7ep+P4dwuef0VjzprjfmnAZHrP+u594\n" +
"ELHpKwi0ZpQLtcJjjud13bn43vbXb+aU7jmPV5lU2XP8TxaQJiYIibNEh1Y3TZGr\n" +
"akJormYvhaYbiZkKLHQ9AvQMEjhoIW5WCB3q+tKZUKTzcQpjNnf9FOTeKN3jk3Kd\n" +
"2OmibPZcbMJdgCD/nRVn1cBo7Hjn3IMjgtszQHtEUphOQiAkOJUnKmy9MTYqtcNN\n" +
"6cuFItbu4QvbVwailgdUjOYwIJCmIxExlPV0ohS24pFGsO03Yn7W8rBB9VWENYmG\n" +
"HkZIbGsHv7O9Wy7fv+FJgZkjeti0807IsNXSJl8LUK0ZIhAR7OU8uONWMsbHdQnk\n" +
"q1HB1ZKa52ugACl7g/DF9b7CoSAjFeE=\n")

            self.publicKeyEncoding = (
"MIIBSzCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAA\n" +
"AAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA////\n" +
"///////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSd\n" +
"NgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5\n" +
"RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA\n" +
"//////////+85vqtpxeehPO5ysL8YyVRAgEBA0IABGhuFibgwLdEJBDOLdvSg1Hc\n" +
"5EJTDxq6ls5FoYLfThp8HOjuwGSz0qw8ocMqyku1y0V5peQ4rEPd0bwcpZd9svA=\n")

    def setUp(self):
        self.rsaKeyTestData = TestTpmPrivateKey.RsaKeyTestData()
        self.ecKeyTestData = TestTpmPrivateKey.EcKeyTestData()

        self.keyTestData = [None]
        self.keyTestData[0] = self.rsaKeyTestData
        # debug self.keyTestData[1] = self.ecKeyTestData
        
    def test_save_load(self):
        for dataSet in self.keyTestData:
            # Load the key in PKCS #1 format.
            pkcs1 = base64.b64decode(dataSet.privateKeyPkcs1)
            key1 =  TpmPrivateKey()
            key1.loadPkcs1(pkcs1)

            # Save the key in PKCS #1 format.
            savedPkcs1Key = key1.toPkcs1()
            self.assertTrue(savedPkcs1Key.equals(Blob(pkcs1)))

            pkcs8 = base64.b64decode(dataSet.privateKeyPkcs8Unencrypted)
            key8 =  TpmPrivateKey()
            key8.loadPkcs8(pkcs8)

            # Save the key in PKCS #8 format.
            savedPkcs8Key = key8.toPkcs8()
            self.assertTrue(savedPkcs8Key.equals(Blob(pkcs8)))

    def test_derive_public_key(self):
        for dataSet in self.keyTestData:
            pkcs8 = base64.b64decode(dataSet.privateKeyPkcs8Unencrypted)
            key =  TpmPrivateKey()
            key.loadPkcs8(pkcs8)

            # Derive the public key and compare.
            publicKeyBits = key.derivePublicKey()
            expected = base64.b64decode(dataSet.publicKeyEncoding)
            self.assertTrue(publicKeyBits.equals(Blob(expected)))

    def test_rsa_decryption(self):
        dataSet = self.rsaKeyTestData

        pkcs8 = base64.b64decode(dataSet.privateKeyPkcs8Unencrypted)
        key =  TpmPrivateKey()
        key.loadPkcs8(pkcs8)

        plainText = Blob([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])

        cipherTextBase64 = (
          "i2XNpZ2JbLa4JmBTdDrGmsd4/0C+p+BSCpW3MuPBNe5uChQ0eRO1dvjTnEqwSECY\n" +
          "38en9JZwcyb0It/TSFNXHlq+Z1ZpffnjIJxQR9HcgwvwQJh6WRH0vu38tvGkGuNv\n" +
          "60Rdn85hqSy1CikmXCeWXL9yCqeqcP21R94G/T3FuA+c1FtFko8KOzCwvrTXMO6n\n" +
          "5PNsqlLXabSGr+jz4EwOsSCgPkiDf9U6tXoSPRA2/YvqFQdaiUXIVlomESvaqqZ8\n" +
          "FxPs2BON0lobM8gT+xdzbRKofp+rNjNK+5uWyeOnXJwzCszh17cdJl2BH1dZwaVD\n" +
          "PmTiSdeDQXZ94U5boDQ4Aw==\n")

        cipherText = base64.b64decode(cipherTextBase64)

        decryptedText = key.decrypt(cipherText)

        self.assertTrue(decryptedText.equals(plainText))

    def test_generate_key(self):
        for dataSet in self.keyTestData:
            key = TpmPrivateKey.generatePrivateKey(dataSet.keyParams)
            publicKeyBits = key.derivePublicKey()
            publicKey = PublicKey(publicKeyBits)

            data = Blob([0x01, 0x02, 0x03, 0x04])

            # Sign and verify.
            signature = key.sign(data.toBytes(), DigestAlgorithm.SHA256)

            # TODO: Move verify into PublicKey?
            if dataSet.keyParams.getKeyType() == KeyType.EC:
                cryptoPublicKey = load_der_public_key(
                  publicKeyBits.toBytes(), backend = default_backend())
                verifier = cryptoPublicKey.verifier(
                  signature.toBytes(), ec.ECDSA(hashes.SHA256()))
                verifier.update(data.toBytes())
                try:
                    verifier.verify()
                    result = True
                except InvalidSignature:
                    result = False
            elif dataSet.keyParams.getKeyType() == KeyType.RSA:
                cryptoPublicKey = load_der_public_key(
                  publicKeyBits.toBytes(), backend = default_backend())
                verifier = cryptoPublicKey.verifier(
                  signature.toBytes(), padding.PKCS1v15(), hashes.SHA256())
                verifier.update(data.toBytes())
                try:
                    verifier.verify()
                    result = True
                except InvalidSignature:
                    result = False
            else:
                # We don't expect this.
                self.fail("Unrecognized key type")

            self.assertTrue(result)

            # Check that another generated private key is different.
            key2 = TpmPrivateKey.generatePrivateKey(dataSet.keyParams)
            self.assertTrue(not key.toPkcs8().equals(key2.toPkcs8()))

if __name__ == '__main__':
    ut.main(verbosity=2)

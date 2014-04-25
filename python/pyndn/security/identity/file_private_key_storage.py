# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the FilePrivateKeyStorage class which extends 
PrivateKeyStorage to implement private key storage using files.
"""

from pyndn.security.identity.private_key_storage import PrivateKeyStorage

class FilePrivateKeyStorage(PrivateKeyStorage):
    """
    Create a new FilePrivateKeyStorage to connect to the default directory.
    """
    def __init__(self):
        super(FilePrivateKeyStorage, self).__init__()

    def generateKeyPair(self, keyName, keyType = KeyType.RSA, keySize = 2048):
        """
        Generate a pair of asymmetric keys.
        
        :param Name keyName: The name of the key pair.
        :param keyType: (optional) The type of the key pair.  If omitted, use
          KeyType.RSA
        :type keyType: int from KeyType
        :param int keySize: (optional) The size of the key pair.  If omitted, 
          use 2048.
        """
        raise RuntimeError("generateKeyPair is not implemented")

    def getPublicKey(self, keyName):
        """
        Get the public key with the keyName.
        
        :param Name keyName: The name of public key.
        :return: The public key.
        :rtype: PublicKey
        """
        raise RuntimeError("getPublicKey is not implemented")        
    
    def sign(self, data, keyName, digestAlgorithm = DigestAlgorithm.SHA256):
        """
        Fetch the private key for keyName and sign the data, returning a 
        signature Blob.

        :param data: Pointer the input byte buffer to sign.
        :type data: An array type with int elements
        :param Name keyName: The name of the signing key.
        :param digestAlgorithm: (optional) the digest algorithm. If omitted,
          use DigestAlgorithm.SHA256.
        :type digestAlgorithm: int from DigestAlgorithm
        :return: The signature, or an isNull() Blob pointer if signing fails.
        :rtype: Blob
        """
        raise RuntimeError("sign is not implemented")        

    def decrypt(self, keyName, data, isSymmetric = False):
        """
        Decrypt data.
        
        :param Name keyName: The name of the decrypting key.
        :param data: The byte buffer to be decrypted.
        :type data: An array type with int elements
        :param bool isSymmetric: (optional) If True symmetric encryption is 
          used, otherwise asymmetric encryption is used. If omitted, use
          asymmetric encryption.
        :return: The decrypted data.
        :rtype: Blob
        """
        raise RuntimeError("decrypt is not implemented")                        

    def encrypt(self, keyName, data, isSymmetric = False):
        """
        Encrypt data.

        :param Name keyName: The name of the encrypting key.
        :param data: The byte buffer to be encrypted.
        :type data: An array type with int elements
        :param bool isSymmetric: (optional) If True symmetric encryption is 
          used, otherwise asymmetric encryption is used. If omitted, use
          asymmetric encryption.
        :return: The encrypted data.
        :rtype: Blob
        """
        raise RuntimeError("encrypt is not implemented")                        

    def generateKey(self, keyName, keyType = KeyType.AES, keySize = 256):
        """
        Generate a symmetric key.

        :param Name keyName: The name of the key.
        :param keyType: (optional) The type of the key. If omitted, use
          KeyType.AES .
        :type keyType: int from KeyType
        :param int keySize: (optional) The size of the key. If omitted, use 256.
        """
        raise RuntimeError("generateKey is not implemented")                        
    
    def doesKeyExist(self, keyName, keyClass):
        """
        Check if a particular key exists.
        
        :param Name keyName: The name of the key.
        :param keyClass: The class of the key, e.g. KeyClass.PUBLIC, 
           KeyClass.PRIVATE, or KeyClass.SYMMETRIC.
        :type keyClass: int from KeyClass
        :return: True if the key exists, otherwise false.
        :rtype: bool
        """
        raise RuntimeError("doesKeyExist is not implemented")                        

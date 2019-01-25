# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/pib/pib-sqlite3.cpp
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

"""
This module defines the PibSqlite3 class which extends PibImpl and is used by
the Pib class as an implementation of a PIB based on an SQLite3 database. All
the contents in the PIB are stored in an SQLite3 database file. This provides
more persistent storage than PibMemory.
"""

import os
import sqlite3
from pyndn.name import Name
from pyndn.util.blob import Blob
from pyndn.security.v2.certificate_v2 import CertificateV2
from pyndn.security.pib.pib import Pib
from pyndn.security.pib.pib_impl import PibImpl

INITIALIZATION = [
"""
CREATE TABLE IF NOT EXISTS
  tpmInfo(
    tpm_locator           BLOB
  );
""",
"""
CREATE TABLE IF NOT EXISTS
  identities(
    id                    INTEGER PRIMARY KEY,
    identity              BLOB NOT NULL,
    is_default            INTEGER DEFAULT 0
  );
""",
"""
CREATE UNIQUE INDEX IF NOT EXISTS
  identityIndex ON identities(identity);
""",
"""
CREATE TRIGGER IF NOT EXISTS
  identity_default_before_insert_trigger
  BEFORE INSERT ON identities
  FOR EACH ROW
  WHEN NEW.is_default=1
  BEGIN
    UPDATE identities SET is_default=0;
  END;
""",
"""
CREATE TRIGGER IF NOT EXISTS
  identity_default_after_insert_trigger
  AFTER INSERT ON identities
  FOR EACH ROW
  WHEN NOT EXISTS
    (SELECT id
       FROM identities
       WHERE is_default=1)
  BEGIN
    UPDATE identities
      SET is_default=1
      WHERE identity=NEW.identity;
  END;
""",
"""
CREATE TRIGGER IF NOT EXISTS
  identity_default_update_trigger
  BEFORE UPDATE ON identities
  FOR EACH ROW
  WHEN NEW.is_default=1 AND OLD.is_default=0
  BEGIN
    UPDATE identities SET is_default=0;
  END;
""",
"""
CREATE TABLE IF NOT EXISTS
  keys(
    id                    INTEGER PRIMARY KEY,
    identity_id           INTEGER NOT NULL,
    key_name              BLOB NOT NULL,
    key_bits              BLOB NOT NULL,
    is_default            INTEGER DEFAULT 0,
    FOREIGN KEY(identity_id)
      REFERENCES identities(id)
      ON DELETE CASCADE
      ON UPDATE CASCADE
  );
""",
"""
CREATE UNIQUE INDEX IF NOT EXISTS
  keyIndex ON keys(key_name);
""",
"""
CREATE TRIGGER IF NOT EXISTS
  key_default_before_insert_trigger
  BEFORE INSERT ON keys
  FOR EACH ROW
  WHEN NEW.is_default=1
  BEGIN
    UPDATE keys
      SET is_default=0
      WHERE identity_id=NEW.identity_id;
  END;
""",
"""
CREATE TRIGGER IF NOT EXISTS
  key_default_after_insert_trigger
  AFTER INSERT ON keys
  FOR EACH ROW
  WHEN NOT EXISTS
    (SELECT id
       FROM keys
       WHERE is_default=1
         AND identity_id=NEW.identity_id)
  BEGIN
    UPDATE keys
      SET is_default=1
      WHERE key_name=NEW.key_name;
  END;
""",
"""
CREATE TRIGGER IF NOT EXISTS
  key_default_update_trigger
  BEFORE UPDATE ON keys
  FOR EACH ROW
  WHEN NEW.is_default=1 AND OLD.is_default=0
  BEGIN
    UPDATE keys
      SET is_default=0
      WHERE identity_id=NEW.identity_id;
  END;
""",
"""
CREATE TABLE IF NOT EXISTS
  certificates(
    id                    INTEGER PRIMARY KEY,
    key_id                INTEGER NOT NULL,
    certificate_name      BLOB NOT NULL,
    certificate_data      BLOB NOT NULL,
    is_default            INTEGER DEFAULT 0,
    FOREIGN KEY(key_id)
      REFERENCES keys(id)
      ON DELETE CASCADE
      ON UPDATE CASCADE
  );
""",
"""
CREATE UNIQUE INDEX IF NOT EXISTS
  certIndex ON certificates(certificate_name);
""",
"""
CREATE TRIGGER IF NOT EXISTS
  cert_default_before_insert_trigger
  BEFORE INSERT ON certificates
  FOR EACH ROW
  WHEN NEW.is_default=1
  BEGIN
    UPDATE certificates
      SET is_default=0
      WHERE key_id=NEW.key_id;
  END;
""",
"""
CREATE TRIGGER IF NOT EXISTS
  cert_default_after_insert_trigger
  AFTER INSERT ON certificates
  FOR EACH ROW
  WHEN NOT EXISTS
    (SELECT id
       FROM certificates
       WHERE is_default=1
         AND key_id=NEW.key_id)
  BEGIN
    UPDATE certificates
      SET is_default=1
      WHERE certificate_name=NEW.certificate_name;
  END;
""",
"""
CREATE TRIGGER IF NOT EXISTS
  cert_default_update_trigger
  BEFORE UPDATE ON certificates
  FOR EACH ROW
  WHEN NEW.is_default=1 AND OLD.is_default=0
  BEGIN
    UPDATE certificates
      SET is_default=0
      WHERE key_id=NEW.key_id;
  END;
"""]

class PibSqlite3(PibImpl):
    """
    Create a new PibSqlite3 to work with an SQLite3 file. This assumes that the
    database directory does not contain a PIB database of an older version.

    :param str databaseDirectoryPath: (optional) The directory where the
      database file is located. If omitted, use $HOME/.ndn . If the directory
      does not exist, create it.
    :param str databaseFilename: (optional) The name if the database file in the
      databaseDirectoryPath. If omitted, use "pib.db".
    :raises PibImpl.Error: If initialization fails.
    """
    def __init__(self, databaseDirectoryPath = None,
          databaseFilename = "pib.db"):
        super(PibSqlite3, self).__init__()

        if databaseDirectoryPath == None or databaseDirectoryPath == "":
            databaseDirectoryPath = PibSqlite3.getDefaultDatabaseDirectoryPath()

        try:
            if not os.path.exists(databaseDirectoryPath):
                os.makedirs(databaseDirectoryPath)

            # Open the PIB.
            databaseFilePath = os.path.join(
              databaseDirectoryPath, databaseFilename)
            self._database = sqlite3.connect(databaseFilePath)
        except Exception as ex:
            raise PibImpl.Error("PIB database cannot be opened/created: " + str(ex))

        try:
            cursor = self._database.cursor()
            # Enable foreign keys.
            cursor.execute("PRAGMA foreign_keys = ON")

            # Initialize the PIB tables.
            for command in INITIALIZATION:
                cursor.execute(command)
            self._database.commit()
            cursor.close()
        except Exception as ex:
            raise PibImpl.Error("PIB database cannot be initialized: " + str(ex))

    @staticmethod
    def getScheme():
        return "pib-sqlite3"

    # TpmLocator management.

    def setTpmLocator(self, tpmLocator):
        """
        Set the corresponding TPM information to tpmLocator. This method does not
        reset the contents of the PIB.

        :param str tpmLocator: The TPM locator string.
        """
        try:
            if self.getTpmLocator() == "":
                # The tpmLocator does not exist. Insert it directly.
                cursor = self._database.cursor()
                cursor.execute(
                  "INSERT INTO tpmInfo (tpm_locator) values (?)", (tpmLocator, ))
                self._database.commit()
                cursor.close()
            else:
                # Update the existing tpmLocator.
                cursor = self._database.cursor()
                cursor.execute("UPDATE tpmInfo SET tpm_locator=?", (tpmLocator, ))
                self._database.commit()
                cursor.close()
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

    def getTpmLocator(self):
        """
        Get the TPM Locator.

        :return: The TPM locator string.
        :rtype: str
        """
        try:
            cursor = self._database.cursor()
            cursor.execute("SELECT tpm_locator FROM tpmInfo")
            row = cursor.fetchone()

            result = ""
            if row != None:
                (result,) = row

            cursor.close()
            return result
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

    # Identity management.

    def hasIdentity(self, identityName):
        """
        Check for the existence of an identity.

        :param Name identityName: The name of the identity.
        :return: True if the identity exists, otherwise False.
        :rtype: bool
        """
        try:
            cursor = self._database.cursor()
            cursor.execute(
              "SELECT id FROM identities WHERE identity=?",
              (sqlite3.Binary(bytearray(identityName.wireEncode().buf())), ))
            row = cursor.fetchone()

            result = (row != None)
            cursor.close()
            return result
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

    def addIdentity(self, identityName):
        """
        Add the identity. If the identity already exists, do nothing. If no
        default identity has been set, set the added identity as the default.

        :param Name identityName: The name of the identity to add. This copies
          the name.
        """
        if not self.hasIdentity(identityName):
            try:
                cursor = self._database.cursor()
                cursor.execute(
                  "INSERT INTO identities (identity) values (?)",
                  (sqlite3.Binary(bytearray(identityName.wireEncode().buf())), ))
                self._database.commit()
                cursor.close()
            except Exception as ex:
                raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

        if not self._hasDefaultIdentity():
            self.setDefaultIdentity(identityName)

    def removeIdentity(self, identityName):
        """
        Remove the identity and its related keys and certificates. If the
        default identity is being removed, no default identity will be selected.
        If the identity does not exist, do nothing.

        :param Name identityName: The name of the identity to remove.
        """
        try:
            cursor = self._database.cursor()
            cursor.execute(
              "DELETE FROM identities WHERE identity=?",
              (sqlite3.Binary(bytearray(identityName.wireEncode().buf())), ))
            self._database.commit()
            cursor.close()
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

    def clearIdentities(self):
        """
        Erase all certificates, keys, and identities.
        """
        try:
            cursor = self._database.cursor()
            cursor.execute("DELETE FROM identities")
            self._database.commit()
            cursor.close()
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

    def getIdentities(self):
        """
        Get the names of all the identities.

        :return: The a fresh set of identity names. The Name objects are fresh
          copies.
        :rtype: set of Name
        """
        identities = set()

        try:
            cursor = self._database.cursor()
            cursor.execute("SELECT identity FROM identities")
            rows = cursor.fetchall()
            for (encoding, ) in rows:
                name = Name()
                name.wireDecode(bytearray(encoding))
                identities.add(name)
            cursor.close()
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

        return identities

    def setDefaultIdentity(self, identityName):
        """
        Set the identity with the identityName as the default identity. If the
        identity with identityName does not exist, then it will be created.

        :param Name identityName: The name for the default identity. This copies
          the name.
        """
        if not self.hasIdentity(identityName):
            try:
                cursor = self._database.cursor()
                cursor.execute(
                  "INSERT INTO identities (identity) values (?)",
                  (sqlite3.Binary(bytearray(identityName.wireEncode().buf())), ))
                self._database.commit()
                cursor.close()
            except Exception as ex:
                raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

        try:
            cursor = self._database.cursor()
            cursor.execute(
              "UPDATE identities SET is_default=1 WHERE identity=?",
              (sqlite3.Binary(bytearray(identityName.wireEncode().buf())), ))
            self._database.commit()
            cursor.close()
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

    def getDefaultIdentity(self):
        """
        Get the default identity.

        :return: The name of the default identity, as a fresh copy.
        :rtype: Name
        :raises Pib.Error: For no default identity.
        """
        encoding = None
        try:
            cursor = self._database.cursor()
            cursor.execute("SELECT identity FROM identities WHERE is_default=1")
            row = cursor.fetchone()

            if row != None:
                (encoding,) = row
            cursor.close()
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

        if encoding != None:
            name = Name()
            name.wireDecode(bytearray(encoding))
            return name
        else:
            raise Pib.Error("No default identity")

    # Key management.

    def hasKey(self, keyName):
        """
        Check for the existence of a key with keyName.

        :param Name keyName: The name of the key.
        :return: True if the key exists, otherwise False. Return False if the
          identity does not exist.
        :rtype: bool
        """
        try:
            cursor = self._database.cursor()
            cursor.execute(
              "SELECT id FROM keys WHERE key_name=?",
              (sqlite3.Binary(bytearray(keyName.wireEncode().buf())), ))
            row = cursor.fetchone()

            result = (row != None)
            cursor.close()
            return result
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

    def addKey(self, identityName, keyName, key):
        """
        Add the key. If a key with the same name already exists, overwrite the
        key. If the identity does not exist, it will be created. If no default
        key for the identity has been set, then set the added key as the default
        for the identity.  If no default identity has been set, identity becomes
        the default.

        :param Name identityName: The name of the identity that the key belongs
          to. This copies the name.
        :param Name keyName:  The name of the key. This copies the name.
        :param key: The public key bits. This copies the array.
        :type key: an array which implements the buffer protocol
        """
        # Ensure the identity exists.
        self.addIdentity(identityName)

        if not self.hasKey(keyName):
            try:
                cursor = self._database.cursor()
                cursor.execute(
                   "INSERT INTO keys (identity_id, key_name, key_bits) " +
                   "VALUES ((SELECT id FROM identities WHERE identity=?), ?, ?)",
                  (sqlite3.Binary(bytearray(identityName.wireEncode().buf())),
                   sqlite3.Binary(bytearray(keyName.wireEncode().buf())),
                   sqlite3.Binary(bytearray(key))))
                self._database.commit()
                cursor.close()
            except Exception as ex:
                raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))
        else:
            try:
                cursor = self._database.cursor()
                cursor.execute(
                   "UPDATE keys SET key_bits=? WHERE key_name=?",
                  (sqlite3.Binary(bytearray(key)),
                   sqlite3.Binary(bytearray(keyName.wireEncode().buf()))))
                self._database.commit()
                cursor.close()
            except Exception as ex:
                raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

        if not self._hasDefaultKeyOfIdentity(identityName):
            self.setDefaultKeyOfIdentity(identityName, keyName)

    def removeKey(self, keyName):
        """
        Remove the key with keyName and its related certificates. If the key
        does not exist, do nothing.

        :param Name keyName: The name of the key.
        """
        try:
            cursor = self._database.cursor()
            cursor.execute(
              "DELETE FROM keys WHERE key_name=?",
              (sqlite3.Binary(bytearray(keyName.wireEncode().buf())), ))
            self._database.commit()
            cursor.close()
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

    def getKeyBits(self, keyName):
        """
        Get the key bits of a key with name keyName.

        :param Name keyName: The name of the key.
        :return: The key bits.
        :rtype: Blob
        :raises Pib.Error: If the key does not exist.
        """
        key = None
        try:
            cursor = self._database.cursor()
            cursor.execute(
              "SELECT key_bits FROM keys WHERE key_name=?",
              (sqlite3.Binary(bytearray(keyName.wireEncode().buf())), ))
            row = cursor.fetchone()

            if row != None:
                (key,) = row
            cursor.close()
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

        if key != None:
            return Blob(bytearray(key), False)
        else:
            raise Pib.Error("Key `" + keyName.toUri() + "` does not exist")

    def getKeysOfIdentity(self, identityName):
        """
        Get all the key names of the identity with the name identityName. The
        returned key names can be used to create a KeyContainer. With a key name
        and a backend implementation, one can create a Key front end instance.

        :param Name identityName: The name of the identity.
        :return: The set of key names. The Name objects are fresh copies. If the
          identity does not exist, return an empty set.
        :rtype: set of Name
        """
        keyNames = set()

        try:
            cursor = self._database.cursor()
            cursor.execute(
              "SELECT key_name " +
              "FROM keys JOIN identities ON keys.identity_id=identities.id " +
              "WHERE identities.identity=?",
              (sqlite3.Binary(bytearray(identityName.wireEncode().buf())), ))
            rows = cursor.fetchall()
            for (encoding, ) in rows:
                name = Name()
                name.wireDecode(bytearray(encoding))
                keyNames.add(name)
            cursor.close()
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

        return keyNames

    def setDefaultKeyOfIdentity(self, identityName, keyName):
        """
        Set the key with keyName as the default key for the identity with name
        identityName.

        :param Name identityName: The name of the identity. This copies the name.
        :param Name keyName: The name of the key. This copies the name.
        :raises Pib.Error: If the key does not exist.
        """
        if not self.hasKey(keyName):
            raise Pib.Error("Key `" + keyName.toUri() + "` does not exist")

        try:
            cursor = self._database.cursor()
            cursor.execute(
              "UPDATE keys SET is_default=1 WHERE key_name=?",
              (sqlite3.Binary(bytearray(keyName.wireEncode().buf())), ))
            self._database.commit()
            cursor.close()
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

    def getDefaultKeyOfIdentity(self, identityName):
        """
        Get the name of the default key for the identity with name identityName.

        :param Name identityName: The name of the identity.
        :return: The name of the default key, as a fresh copy.
        :rtype: Name
        :raises Pib.Error: If there is no default key or if the identity does
          not exist.
        """
        if not self.hasIdentity(identityName):
            raise Pib.Error(
              "Identity `" + identityName.toUri() + "` does not exist")

        encoding = None
        try:
            cursor = self._database.cursor()
            cursor.execute(
              "SELECT key_name " +
              "FROM keys JOIN identities ON keys.identity_id=identities.id " +
              "WHERE identities.identity=? AND keys.is_default=1",
              (sqlite3.Binary(bytearray(identityName.wireEncode().buf())), ))
            row = cursor.fetchone()

            if row != None:
                (encoding,) = row
            cursor.close()
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

        if encoding != None:
            name = Name()
            name.wireDecode(bytearray(encoding))
            return name
        else:
            raise Pib.Error(
              "No default key for identity `" + identityName.toUri() + "`")

    # Certificate management.

    def hasCertificate(self, certificateName):
        """
        Check for the existence of a certificate with name certificateName.

        :param Name certificateName: The name of the certificate.
        :return: True if the certificate exists, otherwise False.
        :rtype: bool
        """
        try:
            cursor = self._database.cursor()
            cursor.execute(
              "SELECT id FROM certificates WHERE certificate_name=?",
              (sqlite3.Binary(bytearray(certificateName.wireEncode().buf())), ))
            row = cursor.fetchone()

            result = (row != None)
            cursor.close()
            return result
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

    def addCertificate(self, certificate):
        """
        Add the certificate. If a certificate with the same name (without
        implicit digest) already exists, then overwrite the certificate. If the
        key or identity does not exist, they will be created. If no default
        certificate for the key has been set, then set the added certificate as
        the default for the key. If no default key was set for the identity, it
        will be set as the default key for the identity. If no default identity
        was selected, the certificate's identity becomes the default.

        :param CertificateV2 certificate: The certificate to add. This copies
          the object.
        """
        # Ensure the key exists.
        content = certificate.getContent()
        self.addKey(
          certificate.getIdentity(), certificate.getKeyName(),
          content.toBytes())

        if not self.hasCertificate(certificate.getName()):
            try:
                cursor = self._database.cursor()
                cursor.execute(
                   "INSERT INTO certificates " +
                   "(key_id, certificate_name, certificate_data) " +
                   "VALUES ((SELECT id FROM keys WHERE key_name=?), ?, ?)",
                  (sqlite3.Binary(bytearray(certificate.getKeyName().wireEncode().buf())),
                   sqlite3.Binary(bytearray(certificate.getName().wireEncode().buf())),
                   sqlite3.Binary(bytearray(certificate.wireEncode().buf()))))
                self._database.commit()
                cursor.close()
            except Exception as ex:
                raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))
        else:
            try:
                cursor = self._database.cursor()
                cursor.execute(
                   "UPDATE certificates SET certificate_data=? WHERE certificate_name=?",
                  (sqlite3.Binary(bytearray(certificate.wireEncode().buf())),
                   sqlite3.Binary(bytearray(certificate.getName().wireEncode().buf()))))
                self._database.commit()
                cursor.close()
            except Exception as ex:
                raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

        if not self._hasDefaultCertificateOfKey(certificate.getKeyName()):
            self.setDefaultCertificateOfKey(
              certificate.getKeyName(), certificate.getName())

    def removeCertificate(self, certificateName):
        """
        Remove the certificate with name certificateName. If the certificate
        does not exist, do nothing.

        :param Name certificateName: The name of the certificate.
        """
        try:
            cursor = self._database.cursor()
            cursor.execute(
             "DELETE FROM certificates WHERE certificate_name=?",
              (sqlite3.Binary(bytearray(certificateName.wireEncode().buf())), ))
            self._database.commit()
            cursor.close()
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

    def getCertificate(self, certificateName):
        """
        Get the certificate with name certificateName.

        :param Name certificateName: The name of the certificate.
        :return: A copy of the certificate.
        :rtype: CertificateV2
        :raises Pib.Error: If the certificate does not exist.
        """
        encoding = None
        try:
            cursor = self._database.cursor()
            cursor.execute(
              "SELECT certificate_data FROM certificates WHERE certificate_name=?",
              (sqlite3.Binary(bytearray(certificateName.wireEncode().buf())), ))
            row = cursor.fetchone()

            if row != None:
                (encoding,) = row
            cursor.close()
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

        if encoding != None:
            certificate = CertificateV2()
            certificate.wireDecode(bytearray(encoding))
            return certificate
        else:
            raise Pib.Error(
              "Certificate `" + certificateName.toUri() + "` does not exit")

    def getCertificatesOfKey(self, keyName):
        """
        Get a list of certificate names of the key with id keyName. The returned
        certificate names can be used to create a PibCertificateContainer. With a
        certificate name and a backend implementation, one can obtain the
        certificate.

        :param Name keyName: The name of the key.
        :return: The set of certificate names. The Name objects are fresh
          copies. If the key does not exist, return an empty set.
        :rtype: set of Name
        """
        certNames = set()

        try:
            cursor = self._database.cursor()
            cursor.execute(
              "SELECT certificate_name " +
              "FROM certificates JOIN keys ON certificates.key_id=keys.id " +
              "WHERE keys.key_name=?",
              (sqlite3.Binary(bytearray(keyName.wireEncode().buf())), ))
            rows = cursor.fetchall()
            for (encoding, ) in rows:
                name = Name()
                name.wireDecode(bytearray(encoding))
                certNames.add(name)
            cursor.close()
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

        return certNames

    def setDefaultCertificateOfKey(self, keyName, certificateName):
        """
        Set the cert with name certificateName as the default for the key with
        keyName.

        :param Name keyName: The name of the key.
        :param Name certificateName: The name of the certificate. This copies
          the name.
        :raises Pib.Error: If the certificate with name certificateName does not
          exist.
        """
        if not self.hasCertificate(certificateName):
            raise Pib.Error(
              "Certificate `" + certificateName.toUri() + "` does not exist")

        try:
            cursor = self._database.cursor()
            cursor.execute(
              "UPDATE certificates SET is_default=1 WHERE certificate_name=?",
              (sqlite3.Binary(bytearray(certificateName.wireEncode().buf())), ))
            self._database.commit()
            cursor.close()
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

    def getDefaultCertificateOfKey(self, keyName):
        """
        Get the default certificate for the key with eyName.

        :param Name keyName: The name of the key.
        :return: A copy of the default certificate.
        :rtype: CertificateV2
        :raises Pib.Error: If the default certificate does not exist.
        """
        encoding = None
        try:
            cursor = self._database.cursor()
            cursor.execute(
              "SELECT certificate_data " +
              "FROM certificates JOIN keys ON certificates.key_id=keys.id " +
              "WHERE certificates.is_default=1 AND keys.key_name=?",
              (sqlite3.Binary(bytearray(keyName.wireEncode().buf())), ))
            row = cursor.fetchone()

            if row != None:
                (encoding,) = row
            cursor.close()
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

        if encoding != None:
            certificate = CertificateV2()
            certificate.wireDecode(bytearray(encoding))
            return certificate
        else:
            raise Pib.Error(
             "No default certificate for key `" + keyName.toUri() + "`")

    @staticmethod
    def getDefaultDatabaseDirectoryPath():
        """
        Get the default that the constructor uses if databaseDirectoryPath is
        omitted. This does not try to create the directory.

        :return: The default database directory path.
        :rtype: str
        """
        if not "HOME" in os.environ:
            # Don't expect this to happen
            home = "."
        else:
            home = os.environ["HOME"]

        return os.path.join(home, ".ndn")

    @staticmethod
    def getDefaultDatabaseFilePath():
        """
        Get the default database file path that the constructor uses if
        databaseDirectoryPath and databaseFilename are omitted.

        :return: The default database file path.
        :rtype: str
        """
        return os.path.join(
          PibSqlite3.getDefaultDatabaseDirectoryPath(), "pib.db")

    def _hasDefaultIdentity(self):
        """
        Check if there is a default identity.

        :return: True if there is a default identity.
        :rtype: bool
        """
        try:
            cursor = self._database.cursor()
            cursor.execute("SELECT identity FROM identities WHERE is_default=1")
            row = cursor.fetchone()

            result = (row != None)
            cursor.close()
            return result
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

    def _hasDefaultKeyOfIdentity(self, identityName):
        """
        Check if there is a default key for the identity with identityName.

        :param Name identityName: The identity Name.
        :return: True if there is a default key.
        :rtype: bool
        """
        try:
            cursor = self._database.cursor()
            cursor.execute(
              "SELECT key_name " +
              "FROM keys JOIN identities ON keys.identity_id=identities.id " +
              "WHERE identities.identity=? AND keys.is_default=1",
              (sqlite3.Binary(bytearray(identityName.wireEncode().buf())), ))
            row = cursor.fetchone()

            result = (row != None)
            cursor.close()
            return result
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

    def _hasDefaultCertificateOfKey(self, keyName):
        """
        Check if there is a default certificate for the key with keyName.

        :param Name keyName: The key Name.
        :return: True if there is a default certificate.
        :rtype: bool
        """
        try:
            cursor = self._database.cursor()
            cursor.execute(
              "SELECT certificate_data " +
              "FROM certificates JOIN keys ON certificates.key_id=keys.id " +
              "WHERE certificates.is_default=1 AND keys.key_name=?",
              (sqlite3.Binary(bytearray(keyName.wireEncode().buf())), ))
            row = cursor.fetchone()

            result = (row != None)
            cursor.close()
            return result
        except Exception as ex:
            raise PibImpl.Error("PibSqlite3: SQLite error: " + str(ex))

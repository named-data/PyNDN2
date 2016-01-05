# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2016 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-group-encrypt src/group-manager https://github.com/named-data/ndn-group-encrypt
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
This module defines the GroupManager class which manages keys and schedules for
group members in a particular namespace.
Note: This class is an experimental feature. The API may change.
"""

from pyndn.name import Name
from pyndn.data import Data
from pyndn.security.certificate.identity_certificate import IdentityCertificate
from pyndn.security.key_params import RsaKeyParams
from pyndn.encrypt.algo.encryptor import Encryptor
from pyndn.encrypt.algo.rsa_algorithm import RsaAlgorithm
from pyndn.encrypt.algo.encrypt_params import EncryptParams, EncryptAlgorithmType
from pyndn.encrypt.interval import Interval
from pyndn.encrypt.schedule import Schedule

class GroupManager(object):
    """
    Create a GroupManager with the given values. The group manager namespace is
    <prefix>/read/<dataType> .

    :param Name prefix: The prefix for the group manager namespace.
    :param Name dataType: The data type for the group manager namespace.
    :param GroupManagerDb database: The GroupManagerDb for storing the group
      management information (including user public keys and schedules).
    :param int keySize: The group key will be an RSA key with keySize bits.
    :param int freshnessHours: The number of hours of the freshness period of
      data packets carrying the keys.
    :param KeyChain keyChain: The KeyChain to use for signing data packets. This
      signs with the default identity.
    """
    def __init__(self, prefix, dataType, database, keySize, freshnessHours,
                 keyChain):
        self._namespace = Name(prefix).append(
          Encryptor.NAME_COMPONENT_READ).append(dataType)
        self._database = database
        self._keySize = keySize
        self._freshnessHours = freshnessHours

        self._keyChain = keyChain

    def getGroupKey(self, timeSlot):
        """
        Create a group key for the interval into which timeSlot falls. This
        creates a group key if it doesn't exist, and encrypts the key using the
        public key of each eligible member.

        :param float timeSlot: The time slot to cover as milliseconds since
          Jan 1, 1970 UTC.
        :return: A List of Data packets where the first is the E-KEY data packet
          with the group's public key and the rest are the D-KEY data packets
          with the group's private key encrypted with the public key of each
          eligible member.
        :raises GroupManagerDb.Error: For a database error.
        :raises SecurityException: For an error using the security KeyChain.
        """
        unsortedMemberKeys = {}
        result = []

        # Get the time interval.
        finalInterval = self._calculateInterval(timeSlot, unsortedMemberKeys)
        if finalInterval.isValid() == False:
          return result

        startTimeStamp = Schedule.toIsoString(finalInterval.getStartTime())
        endTimeStamp = Schedule.toIsoString(finalInterval.getEndTime())

        # Generate the private and public keys.
        (privateKeyBlob, publicKeyBlob) = self._generateKeyPair()

        # Add the first element to the result.
        # The E-KEY (public key) data packet name convention is:
        # /<data_type>/E-KEY/[start-ts]/[end-ts]
        data = self._createEKeyData(startTimeStamp, endTimeStamp, publicKeyBlob)
        result.append(data)

        # Encrypt the private key with the public key from each member's certificate.
        # Sort the key names.
        for keyName in sorted(unsortedMemberKeys.keys()):
          certificateKey = unsortedMemberKeys[keyName]

          # Generate the name of the packet.
          # The D-KEY (private key) data packet name convention is:
          # /<data_type>/D-KEY/[start-ts]/[end-ts]/[member-name]
          data = self._createDKeyData(
            startTimeStamp, endTimeStamp, keyName, privateKeyBlob, certificateKey)
          result.append(data)

        return result

    def addSchedule(self, scheduleName, schedule):
        """
        Add a schedule with the given scheduleName.

        :param str scheduleName: The name of the schedule. The name cannot be empty.
        :param Schedule schedule: The Schedule to add.
        :raises GroupManagerDb.Error: If a schedule with the same name already
          exists, if the name is empty, or other database error.
        """
        self._database.addSchedule(scheduleName, schedule)

    def deleteSchedule(self, scheduleName):
        """
        Delete the schedule with the given scheduleName. Also delete members
        which use this schedule. If there is no schedule with the name, then do
        nothing.

        :param str scheduleName: The name of the schedule.
        :raises GroupManagerDb.Error: For a database error.
        """
        self._database.deleteSchedule(scheduleName)

    def updateSchedule(self, scheduleName, schedule):
        """
        Update the schedule with scheduleName and replace the old object with
        the given schedule. Otherwise, if no schedule with name exists, a new
        schedule with name and the given schedule will be added to database.

        :param str scheduleName: The name of the schedule. The name cannot be empty.
        :param Schedule schedule: The Schedule to update or add.
        :raises GroupManagerDb.Error: If the name is empty, or other database
          error.
        """
        self._database.updateSchedule(scheduleName, schedule)

    def addMember(self, scheduleName, memberCertificate):
        """
        Add a new member with the given memberCertificate into a schedule named
        scheduleName. If cert is an IdentityCertificate made from
        memberCertificate, then the member's identity name is
        cert.getPublicKeyName().getPrefix(-1).

        :param str scheduleName: The schedule name.
        :param Data memberCertificate: The member's certificate.
        :raises GroupManagerDb.Error: If there's no schedule named scheduleName,
          if the member's identity name already exists, or other database error.
        :raises DerDecodingException: for error decoding memberCertificate as a
          certificate.
        """
        cert = IdentityCertificate(memberCertificate)
        self._database.addMember(
          scheduleName, cert.getPublicKeyName(), cert.getPublicKeyInfo().getKeyDer())

    def removeMember(self, identity):
        """
        Remove a member with the given identity name. If there is no member with
        the identity name, then do nothing.

        :param Name identity: The member's identity name.
        :raises GroupManagerDb.Error: For a database error.
        """
        self._database.deleteMember(identity)

    def updateMemberSchedule(self, identity, scheduleName):
        """
        Change the name of the schedule for the given member's identity name.

        :param Name identity: The member's identity name.
        :param str scheduleName: The new schedule name.
        :raises GroupManagerDb.Error: If there's no member with the given
          identity name in the database, or there's no schedule named
          scheduleName.
        """
        self._database.updateMemberSchedule(identity, scheduleName)

    def _calculateInterval(self, timeSlot, unsortedMemberKeys):
        """
        Calculate an Interval that covers the timeSlot.

        :param float timeSlot: The time slot to cover as milliseconds since
          Jan 1, 1970 UTC.
        :param dictionary<Name, Blob> unsortedMemberKeys: First clear
          unsortedMemberKeys then fill it with the info of members who are
          allowed to access the interval. The dictionary's key is the Name of
          the public key and the value is the Blob of the public key DER. The
          dictionary keys are not sorted. (You can use
          sorted(unsortedMemberKeys.keys()).)
        :return: The Interval covering the time slot.
        :rtype: Interval
        :raises GroupManagerDb.Error: For a database error.
        :raises SecurityException: For an error using the security KeyChain.
        """
        # Prepare.
        positiveResult = Interval()
        negativeResult = Interval()
        unsortedMemberKeys.clear()

        # Get the all intervals from the schedules.
        scheduleNames = self._database.listAllScheduleNames()
        for i in range(len(scheduleNames)):
            scheduleName = scheduleNames[i]

            schedule = self._database.getSchedule(scheduleName)
            result = schedule.getCoveringInterval(timeSlot)
            tempInterval = result.interval

            if result.isPositive:
              if not positiveResult.isValid():
                  positiveResult = tempInterval
              positiveResult.intersectWith(tempInterval)

              map = self._database.getScheduleMembers(scheduleName)
              # Add all to unsortedMemberKeys.
              for name in map:
                  unsortedMemberKeys[name] = map[name]
            else:
                if not negativeResult.isValid():
                    negativeResult = tempInterval
                negativeResult.intersectWith(tempInterval)

        if not positiveResult.isValid():
            # Return an invalid interval when there is no member which has an
            # interval covering the time slot.
            return Interval(False)

        # Get the final interval result.
        if negativeResult.isValid():
            finalInterval = positiveResult.intersectWith(negativeResult)
        else:
            finalInterval = positiveResult

        return finalInterval

    def _generateKeyPair(self):
        """
        Generate an RSA key pair according to _keySize.

        :return: A tuple (privateKeyBlob, publicKeyBlob) where "privateKeyBlob"
          is the encoding Blob of the private key and "publicKeyBlob" is the
          encoding Blob of the public key.
        :rtype: (Blob, Blob)
        """
        params =  RsaKeyParams(self._keySize)
        privateKey = RsaAlgorithm.generateKey(params)
        privateKeyBlob = privateKey.getKeyBits()

        publicKey = RsaAlgorithm.deriveEncryptKey(privateKeyBlob)
        publicKeyBlob = publicKey.getKeyBits()

        return (privateKeyBlob, publicKeyBlob)

    def _createEKeyData(self, startTimeStamp, endTimeStamp, publicKeyBlob):
        """
        Create an E-KEY Data packet for the given public key.

        :param str startTimeStamp: The start time stamp string to put in the name.
        :param str endTimeStamp: The end time stamp string to put in the name.
        :param Blob publicKeyBlob: A Blob of the public key DER.
        :return: The Data packet.
        :rtype: Data
        """
        name = Name(self._namespace)
        name.append(Encryptor.NAME_COMPONENT_E_KEY).append(
          startTimeStamp).append(endTimeStamp)

        data = Data(name)
        data.getMetaInfo().setFreshnessPeriod(
          self._freshnessHours * GroupManager.MILLISECONDS_IN_HOUR)
        data.setContent(publicKeyBlob)
        self._keyChain.sign(data)
        return data

    def _createDKeyData(self, startTimeStamp, endTimeStamp, keyName,
                        privateKeyBlob, certificateKey):
        """
        Create a D-KEY Data packet with an EncryptedContent for the given
        private key, encrypted with the certificate key.

        :param str startTimeStamp: The start time stamp string to put in the name.
        :param str endTimeStamp: The end time stamp string to put in the name.
        :param Name keyName The key name to put in the data packet name and the
          EncryptedContent key locator.
        :param Blob privateKeyBlob: A Blob of the encoded private key.
        :param Blob certificateKey: The certificate key encoding, used to
          encrypt the private key.
        :return: The Data packet.
        :rtype: Data
        """
        name = Name(self._namespace)
        name.append(Encryptor.NAME_COMPONENT_D_KEY)
        name.append(startTimeStamp).append(endTimeStamp)
        data = Data(name)
        data.getMetaInfo().setFreshnessPeriod(
          self._freshnessHours * GroupManager.MILLISECONDS_IN_HOUR)
        encryptParams = EncryptParams(EncryptAlgorithmType.RsaOaep)
        Encryptor.encryptData(
          data, privateKeyBlob, keyName, certificateKey, encryptParams)
        self._keyChain.sign(data)
        return data

    MILLISECONDS_IN_HOUR = 3600 * 1000

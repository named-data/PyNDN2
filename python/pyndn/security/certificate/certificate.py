# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
# Author: Adeola Bannis <thecodemaiden@gmail.com>
# From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
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

from pyndn.encoding.oid import OID
from pyndn.encoding.der.der_node import *
from pyndn.encoding.der.der import *
from pyndn.security.certificate.public_key import PublicKey
from pyndn.util.blob import Blob
from pyndn.data import Data
from pyndn.meta_info import ContentType
from datetime import datetime

import base64

class Certificate(Data):
    epochStart = datetime(1970,1,1)
    def __init__(self, other=None):
        """
        Create a new certificate, optionally copying the
        contents of another Data object.
        :param other: (optional) A Data packet to copy the content from
        :type other: Data
        """
        super(Certificate,self).__init__(other)
        self._subjectDescriptionList = []
        self._extensionList = []
        if isinstance(other, Data):
            self.decode()
        else:
            self._notBefore = 1e37
            self._notAfter = -1e37
            self._publicKey = None

    def isTooEarly(self):
        """
        Check if the certificate start date is in the future
        :return: True if the certificate cannot be used yet
        :rtype: boolean
        """

        secondsSince1970 = (datetime.now() - self.epochStart).total_seconds
        if secondsSince1970 < self._notBefore/1000:
            return True
        return False


    def isTooLate(self):
        """
        Check if the certificate end date is in the past
        :return: True if the certificate has expired
        :rtype: boolean
        """
        secondsSince1970 = (datetime.now() - self.epochStart).total_seconds
        if secondsSince1970 > self._notAfter/1000:
            return True
        return False

    def __str__(self):
        s = "Certificate name:\n"
        s += "  "+self.getName().toUri()+"\n"
        s += "Validity:\n"

        dateFormat = "%Y%m%dT%H%M%S"
        notBeforeStr = datetime.utcfromtimestamp(self._notBefore/1000).strftime(dateFormat)
        notAfterStr = datetime.utcfromtimestamp(self._notAfter/1000).strftime(dateFormat)

        s += "  NotBefore: " + notBeforeStr+"\n"
        s += "  NotAfter: " + notAfterStr + "\n"
        for sd in self._subjectDescriptionList:
            s += "Subject Description:\n"
            s += "  " + str(sd.getOid()) + ": " + sd.getValue().toRawStr() + "\n"

        s += "Public key bits:\n"
        keyDer = self._publicKey.getKeyDer()
        encodedKey = base64.b64encode(keyDer.toBytes())
        for idx in range(0, len(encodedKey), 64):
            # Use Blob to convert to a str.
            s += Blob(encodedKey[idx:idx+64], False).toRawStr() + "\n"


        if len(self._extensionList) > 0:
            s += "Extensions:\n"
            for ext in self._extensionList:
                s += "  OID: "+ext.getOid()+"\n"
                s += "  Is critical: " + ('Y' if ext.isCritical() else 'N') + "\n"

                s += "  Value: " + str(ext.getValue()).encode('hex') + "\n"

        return s


    def addSubjectDescription(self, descr):
        """
        Add a subject description field to the certificate.
        :param descr: The CertificateSubjectDescription object to add
        """
        self._subjectDescriptionList.append(descr)

    def addExtension(self, ext):
        """
        Add an extension field to the certificate.
        :param ext: Th CertificateExtension object to add
        """
        self._extensionList.append(ext)

    def toDer(self):
        """
        Encode the certificate fields in DER format.
        :return: The DER encoded contents of the certificate.
        :rtype: DerNode
        """
        root = DerSequence()
        validity = DerSequence()
        notBefore = DerGeneralizedTime(self._notBefore)
        notAfter = DerGeneralizedTime(self._notAfter)

        validity.addChild(notBefore)
        validity.addChild(notAfter)

        root.addChild(validity)

        subjectList = DerSequence()
        for sd in self._subjectDescriptionList:
            child = sd.toDer()
            subjectList.addChild(child)

        root.addChild(subjectList)
        root.addChild(self._publicKey.toDer())

        if (len(self._extensionList) > 0):
            extnList = DerSequence()
            for ext in self._extensionList:
                child = ext.toDer()
                extnList.addChild(child)
            root.addChild(extnList)

        return root

    def encode(self):
        """
            Encode the contents of the certificate in DER format and set the
            Content and MetaInfo fields.
        """
        root = self.toDer()
        outVal = root.encode()
        self.setContent(Blob(outVal))
        self.getMetaInfo().setType(ContentType.KEY)

    def decode(self):
        """
        Populates the fields by decoding DER data from the Content.
        """
        root = DerNode.parse(self.getContent())

        # we need to ensure that there are:
        #   validity (notBefore, notAfter)
        #   subject list
        #   public key
        #   (optional) extension list

        rootChildren = root.getChildren()
        # 1st: validity info
        validityChildren = DerNode.getSequence(rootChildren, 0).getChildren()
        self._notBefore = validityChildren[0].toVal()
        self._notAfter = validityChildren[1].toVal()

        # 2nd: subjectList
        subjectChildren = DerNode.getSequence(rootChildren, 1).getChildren()
        for sd in subjectChildren:
            descriptionChildren = sd.getChildren()
            oidStr = descriptionChildren[0].toVal()
            value = descriptionChildren[1].toVal()

            subjectDesc = CertificateSubjectDescription(oidStr, value)
            self.addSubjectDescription(subjectDesc)

        # 3rd: public key
        publicKeyInfo = rootChildren[2].encode()
        self._publicKey = PublicKey(publicKeyInfo)

        if len(rootChildren) > 3:
            extensionChildren = DerNode.getSequence(rootChildren, 3).getChildren()
            for extInfo in extensionChildren:
                children = extInfo.getChildren()
                oidStr = children[0].toVal()
                isCritical = children[1].toVal()
                value = children[2].toVal()
                extension = CertificateExtension(oidStr, isCritical, value)
                self.addExtension(extension)

    def wireDecode(self, buf, wireFormat = None):
        """
        Make sure the fields are populated after decoding
        """
        Data.wireDecode(self, buf, wireFormat)
        self.decode()

    def getNotBefore(self):
        """
        Returns the earliest date the certificate is valid at.
        :return: Timestamp as milliseconds since 1970.
        :rtype: float
        """
        return self._notBefore

    def getNotAfter(self):
        """
        Returns the latest date the certificate is valid at.
        :return: Timestamp as milliseconds since 1970.
        :rtype: float
        """
        return self._notAfter

    def getPublicKeyInfo(self):
        """
        :return: The PublicKey object stored in the certificate.
        :rtype: PublicKey
        """
        return self._publicKey

    def setNotBefore(self, notBefore):
        self._notBefore = notBefore

    def setNotAfter(self, notAfter):
        self._notAfter = notAfter

    def setPublicKeyInfo(self, publicKey):
        """
        Assign a new public key to the certificate.
        :param publicKey: The new public key
        :type publicKey: PublicKey
        """
        self._publicKey = publicKey

    def getSubjectDescriptions(self):
        """
        :return: The subject description fields of the certificate.
        :rtype: list of CertificateSubjectDescription
        """
        return self._subjectDescriptionList

    def getExtensionList(self):
        """
        :return: The extension fields of the certificate.
        :rtype: list of CertificateExtension
        """
        return self._extensionList

    def getExtensions(self):
        """
        :deprecated: Use getExtensionList.
        """
        return self.getExtensionList()

class CertificateSubjectDescription:
    def __init__(self, oid, value):
        """
        Create a subject description field for a certificate.
        :param oid: The object identifier
        :type oid: str or OID
        :param value: The value of the description field
        :type value: Blob or bytearray
        """
        if type(oid) is str:
            self._oid = OID(oid)
        else:
            # Assume oid is already an OID.
            self._oid = oid

        self._value = Blob(value)

    def getOid(self):
        """
        :return: The object identifier of the subject description field.
        :rtype: OID
        """
        return self._oid

    def getValue(self):
        """
        :return: The value of the subject description field.
        :rtype: Blob
        """
        return self._value

    def toDer(self):
        """
        Encode this field as a DerNode.
        :return: Encoded subject description
        :rtype: DerSequence
        """
        root = DerSequence()

        oid = DerOid(self._oid)
        value = DerPrintableString(self._value)

        root.addChild(oid)
        root.addChild(value)
        return root

class CertificateExtension:
    def __init__(self, oid, isCritical, value):
        """
        Create a certificate extension field.
        :param oid: The object identifier for the extension
        :type oid: str or OID
        :param isCritical: Whether this extension is critical to the certificate
        :type isCritical: boolean
        :param value: The value of the extension field
        :type value: bytearray or Blob
        """
        if type(oid) is str:
            self._oid = OID(oid)
        else:
            # Assume oid is already an OID.
            self._oid = oid

        self._isCritical = isCritical
        self._value = Blob(value)

    def toDer(self):
        """
        Encode this field as a DerNode.
        :return: Encoded certificate extension
        :rtype: DerSequence
        """
        root = DerSequence()

        extensionId = DerOid(self._oid)
        isCritical = DerBoolean(self._isCritical)
        extensionValue = DerOctetString(self._value)

        root.addChild(extensionId)
        root.addChild(isCritical)
        root.addChild(extensionValue)

        return root

    def getOid(self):
        """
        :return: The object identifier of the subject description field.
        :rtype: OID
        """
        return self._oid

    def getIsCritical(self):
        """
        :return: Whether the extension is critical to the certificate
        :rtype: boolean
        """
        return self._isCritical

    def isCritical(self):
        """
        :deprecated: Use getIsCritical.
        """
        return self.getIsCritical()

    def getValue(self):
        """
        :return: The value of the extension field
        :rtype: Blob
        """
        return self._value


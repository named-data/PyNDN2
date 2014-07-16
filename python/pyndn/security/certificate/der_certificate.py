from pyndn.encoding.der import DerNode, DerSequence, DerGeneralizedTime
from pyndn.security.certificate import PublicKey
from pyndn.security.security_types import KeyType
from datetime import datetime

import base64

class DerCertificate():
    epochStart = datetime(1970,1,1)
    def __init__(self):
        self._subjectDescriptionList = []
        self._notBefore = 1e37
        self._notAfter = -1e37
        self._publicKey = None
        self._extensionList = []

    def isTooEarly(self):
        secondsSince1970 = (datetime.now() - self.epochStart).total_seconds
        if secondsSince1970 < self._notBefore:
            return true
        return false


    def isTooLate(self):
        secondsSince1970 = (datetime.now() - self.epochStart).total_seconds
        if secondsSince1970 > self._notAfter:
            return true
        return false

    def __str__(self):
        #TODO: where does the name go?!!!

        s = "Certificate name:\n"
        s += "  /\n"
        s += "Validity:\n"

        dateFormat = "%Y%m%dT%H%M%S"
        notBeforeStr = datetime.utcfromtimestamp(self._notBefore/1000).strftime(dateFormat)
        notAfterStr = datetime.utcfromtimestamp(self._notAfter/1000).strftime(dateFormat)

        s += "  NotBefore: " + notBeforeStr+"\n"
        s += "  NotAfter: " + notAfterStr + "\n"
        for sd in self._subjectDescriptionList:
            s += "Subject Description: \n"
            s += "  "+sd.getOid()+": " + str(sd.getValue()) + "\n"

        s += "Public key bits:\n"
        keyDer = self._publicKey.getKeyDer()
        encodedKey = base64.b64encode(keyDer.toRawStr())
        for idx in range(0, len(encodedKey), 64):
            s += encodedKey[idx:idx+64] + "\n"

        return s


    def addSubjectDescription(self, descr):
        self._subjectDescriptionList.append(descr)

    def addExtension(self, ext):
        self._extensionList.append(ext)

    def toDer(self):
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
        root.addChild(self._key.toDer())

        if (len(self._extensionList) > 0):
            extnList = DerSequence()
            for ext in self._extensionList:
                child = ext.toDer()
                extnList.addChild(child)
            root.addChild(extnList)

        return root

    def encode(self):
        """
            Returns a Blob
        """
        root = self.toDer()
        outVal = root.encode()
        return outVal

    def decode(self, inputBuf):
        """
            Populates the fields by decoding DER data from inputBuf
        """
        root = DerNode.parse(inputBuf)
        
        # we need to ensure that there are:
        #   validity (notBefore, notAfter)
        #   subject list
        #   public key
        #   (optional) extension list

        rootChildren = root.getChildren()

        # 1st: validity info
        validityChildren = rootChildren[0].getChildren()
        self._notBefore = validityChildren[0].toVal()
        self._notAfter = validityChildren[0].toVal()

        # 2nd: subjectList
        subjectChildren = rootChildren[1].getChildren()
        for sd in subjectChildren:
            descriptionChildren = sd.getChildren()
            oidStr = descriptionChildren[0].toVal()
            value = descriptionChildren[1].toVal()

            subjectDesc = CertificateSubjectDescription(oidStr, value)
            self.addSubjectDescription(subjectDesc)

        # 3rd: public key
        publicKeyInfo = rootChildren[2].getRaw()
        self._publicKey = PublicKey(KeyType.RSA, publicKeyInfo)

        if len(rootChildren) > 3:
            extensionChildren = rootChildren[3]
            for extInfo in extensionChildren:
                children = extInfo.getChildren()
                oidStr = children[0].toVal()
                isCritical = children[1].toVal()
                value = children[2].getRaw()
                extension = CertificateExtension(oidStr, isCritical, value)
                self.addExtension(extension)

class CertificateSubjectDescription:
    def __init__(self, oidStr, value):
        self._oidStr = oidStr
        self._value = value

    def getOid(self):
        return self._oidStr

    def getValue(self):
        return self._value

    def toDer(self):
        root = DerSequence()

        oid = DerOid(self._oidStr)
        value = DerPrintableString(self._value)

        root.addChild(oid)
        root.addChild(value)

        return root

class CertificateExtension:
    def __init__(self, oidStr, isCritical, value):
        self._oidStr = oidStr
        self._isCritical = isCritical
        self._value = value

    def toDer(self):
        root = DerSequence()

        extensionId = DerOid(self._oidStr)
        isCritical = DerBoolean(self._isCritical)
        value = DerOctetString(self._value)

        root.addChild(extensionId)
        root.addChild(isCritical)
        root.addChild(extensionValue)

        return root

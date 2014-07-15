from der import Der
from pyndn.util import Blob
from der_exceptions import NegativeLengthException, DerEncodingException, DerDecodingException

from datetime import datetime

class DerNode (object):
    def __init__(self, nodeType):
        self._parent = None
        self._nodeType = chr(nodeType)
        self._header = bytearray()
        self._payload = bytearray()

    def getSize(self):
        return len(self._header) + len(self._payload)

    def getRaw(self):
        temp = self._header[:]
        return Blob(temp.extend(self._payload))

    def encodeHeader(self, size):
        self._header.append(self._nodeType)
        if size < 0:
            raise NegativeLengthException("DER object has negative length")
        elif size < 127:
            self._header.append(size & 0xff)
        else:
            tempBuf = bytearray()
            n = 0
            val = size
            while val != 0:
                tempBuf.insert(0, (val & 0xff))
                val >>= 8
                n += 1
            tempBuf.insert(0,chr(((1<<7)|n) & 0xff))
            self._header.extend(tempBuf)

    def decodeHeader(self, inputBuf, startIdx=0):
        """
            Extracts the header from an input buffer
        """

        if type(inputBuf) is Blob:
            inputBuf = inputBuf.buf()

        idx = startIdx

        nodeType = inputBuf[idx]
        idx += 1

        self.nodeType = nodeType

        sizeLen = inputBuf[idx]
        idx += 1

        self._header = bytearray([nodeType, sizeLen])

        size = sizeLen
        isLongFormat = sizeLen & (1 << 7)
        if isLongFormat:
            lenCount = sizeLen & ((1<<7) -1)
            size = 0
            while lenCount > 0:
                b = inputBuf[idx]
                idx += 1
                self._header.append(b)
                size = 256*size + int(b)
                lenCount -= 1

        return size

    def encode(self):
        """ 
            Returns a Blob 
        """
        val = self._header+self._payload
        return Blob(val)

    def decode(self, inputBuf, startIdx=0):
        if type(inputBuf) is Blob:
            inputBuf = inputBuf.buf()

        idx = startIdx
        payloadSize = self.decodeHeader(inputBuf, idx)
        skipBytes = len(self._header)
        if payloadSize > 0:
            idx += skipBytes
            self._payload.extend(inputBuf[idx:idx+payloadSize])

    @staticmethod
    def parse(inputBuf, startIdx=0):
        """
            Returns a DerNode according to the type at the head of the buffer
        """
        if type(inputBuf) is Blob:
            inputBuf = inputBuf.buf()

        idx = startIdx
        nodeType = inputBuf[idx] # don't increment, we're just peeking

        outputType = None

        if nodeType == Der.Boolean:
            outputType = DerBoolean
        elif nodeType == Der.Integer:
            outputType = DerInteger
        elif nodeType == Der.BitString:
            outputType = DerBitString
        elif nodeType == Der.OctetString:
            outputType = DerOctetString
        elif nodeType == Der.Null:
            outputType = DerNull
        elif nodeType == Der.ObjectIdentifier:
            outputType = DerOid
        elif nodeType == Der.Sequence:
            outputType = DerSequence
        elif nodeType == Der.PrintableString:
            outputType = DerPrintableString
        elif nodeType == Der.GeneralizedTime:
            outputType = DerGeneralizedTime
        else:
            raise DerDecodingException("Unimplemented DER type {}".format(nodeType))

        newNode = outputType()
        newNode.decode(inputBuf, idx)
        return newNode

    def toVal(self):
        return self.getRaw()

class DerStructure(DerNode):
    def __init__(self, nodeType):
       super(DerStructure, self).__init__(nodeType)
       self._childChanged = False
       self._nodeList = []
       self._size = 0
       
    def getSize(self):
        if self._childChanged:
            self.updateSize()
            self._childChanged = False

        self._header = bytearray()
        self.encodeHeader(self._size)
        return self._size + len(self._header)

    def getChildren(self):
        return self._nodeList

    def updateSize(self):
        """
            Returns a Blob
        """
        newSize = 0

        for n in self._nodeList:
            newSize += n.getSize()

        self._size = newSize
        self._childChanged = False

    def getRaw(self):
        temp = self._header[:]

        for n in self._nodeList:
            childBlob = n.getRaw()
            temp.extend(childBlob)

        return Blob(temp)
            
    def addChild(self, node, notifyParent=False):
        node._parent = self
        self._nodeList.append(node)
        if notifyParent:
            if not self._childChanged:
                self._childChanged = True
            if self._parent is not None:
                self._parent.setChildChanged()

    def setChildChanged(self):
        if self._parent is not None:
            self._parent.setChildChanged()
        self._childChanged = True

    def encode(self):
        """ 
            Returns the encoded DER object in a Blob
        """
        temp = bytearray()
        self.updateSize()
        self._header = bytearray()
        self.encodeHeader(self._size)
        temp.extend(self._header)
        for n in self._nodeList:
            encodedChild = n.encode()
            temp.extend(encodedChild.buf())

        return Blob(temp)

    def decode(self, inputBuf, startIdx = 0):
       idx = startIdx 
       self._size = self.decodeHeader(inputBuf, idx)
       idx += len(self._header)
       accSize = 0
       while accSize < self._size:
           node = self.parse(inputBuf, idx)
           idx += node.getSize()
           accSize += node.getSize()
           self.addChild(node, False)

########
# Now for all the node types...
########

class DerByteString(DerNode):
    def __init__(self, inputData, nodeType):
        super(DerByteString, self).__init__(nodeType)
        if inputData is not None:
            if type(inputData) is Blob:
                inputData = inputData.buf
            else:
                inputData = bytearray(inputData)
            
            self._payload.extend(inputData)
            self.encodeHeader(len(self._payload))

    def toVal(self):
        return self._payload # already a byte string

class DerBoolean(DerNode):
    def __init__(self, val=None):
        super(DerBoolean, self).__init__(Der.Boolean)
        if val is not None:
            val = 0xff if val else 0x00
            self._payload.append(val)
            self.encodeHeader(len(self._payload))

    def toVal(self):
        val = self._payload[0]
        return val != 0x00

class DerInteger(DerNode):
    def __init__(self, inputBuf):
        # TODO: I think this is not mplemented correctly
        super(DerInteger, self).__init__(Der.Integer)
        if type(inputBuf) is Blob:
            inputBuf = inputBuf.buf()
        else:
            inputBuf = bytearray(inputBuf)
        self._payload.extend(inputBuf)
        self.encodeHeader(len(self._payload))

class DerBitString(DerNode):
    def __init__(self, inputBuf, padding):
        super(DerBitString, self).__init__(Der.BitString)
        if type(inputBuf) is Blob:
            inputBuf = inputBuf.buf()
        self._payload.append(chr(padding))
        self._payload.extend(inputBuf)

        self.encodeHeader(len(self._payload))


class DerOctetString(DerByteString):
    def __init__(self, inputData = None):
        super(DerOctetString, self).__init__(inputData, Der.OctetString)

class DerNull(DerNode):
    def __init__(self):
        super(DerNull, self).__init__(Der.Null)
        self.encodeHeader(0)

class DerOid(DerNode):
    ### TODO: add setter for OIDStr?
    def __init__(self, oidStr=None):
        super(DerOid, self).__init__(Der.ObjectIdentifier)
        if oidStr is not None:
            parts = [int(p) for p in oidStr.split('.')]

            self.prepareEncoding(parts)

    def prepareEncoding(self, value):
        firstNumber = 0

        if len(value) == 0:
            raise DerEncodingException("No integer in OID")
        else:
            if value[0] >= 0 and value[0] <= 2:
                firstNumber = value[0]*40
            else:
                raise DerEncodingException("First integer in OID is out of range")

        if len(value) >= 2:
            if value[1] >= 0 and value[1] <= 39:
                firstNumber += value[1]
            else:
                raise DerEncodingException("Second integer in OID is out of range")

        encodedStr = self.encode128(firstNumber)

        if len(value) > 2:
            for i in range(2,len(value)):
                encodedStr.append(self.encode128(value[i]))

        self.encodeHeader(len(encodedStr))
        self._payload.extend(encodedStr)

    def encode128(self, value):
        """
            Returns a bytearray with the encoded value
        """

        mask = (1 << 7) - 1
        outBytes = bytearray()
        if value < 128:
            outBytes.append(chr(value & mask))
        else:
            n = 1
            outBytes.insert(0, value & mask)
            value >>= 7
            while value != 0:
                outBytes.insert(0, (value & mask) | (1 << 7))
                n += 1
                value >>= 7

        return outBytes

    def decode128(self, offset):
        """
            For internal use only
        """
        flagMask = 0x80
        result = 0
        oldOffset = offset

        while self._payload[offset] & flagMask:
            result = 128 * result + chr(self._payload[offset]-128)
            offset += 1

        result = result * 128 + self._payload[offset]
        return (result, offset-oldOffset+1)

    def toVal(self):
        """
            Returns the OID as a string
        """
        offset = 0
        components = []
        while offset < len(self._payload):
            nextVal,skip = self.decode128(offset)
            offset += skip
            components.append(str(nextVal))
        return '.'.join(components)



class DerSequence(DerStructure):
    def __init__(self):
        super(DerSequence, self).__init__(Der.Sequence)


class DerPrintableString(DerByteString):
    def __init__(self, inputData = None):
        super(DerPrintableString, self).__init__(inputData, Der.PrintableString)

    def toVal(self):
        return str(self._payload)

class DerGeneralizedTime(DerNode):
    def __init__(self, timeSince1970 = None):
        super(DerGeneralizedTime, self).__init__(Der.GeneralizedTime)
        if timeSince1970 is not None:
            derTime = self.toDerTimeString(timeSince1970)
            self._payload.extend(bytearray(derTime))
            self.encodeHeader(len(self._payload))

    def toDerTimeString(self, msSince1970):
        secondsSince1970 = msSince1970/1000.0
        utcTime = datetime.utcfromtimestamp(secondsSince1970)

        derTime = utcTime.strftime("%Y%m%d%H%M%S.%fZ")
        return derTime

    def toVal(self):
        # return the milliseconds since 1970
        timeStr = str(self._payload)
        dt = datetime.strptime(timeStr, "%Y%m%d%H%M%S.%fZ")
        epochStart = datetime(1970, 1,1)
        msSince1970 = (dt-epochStart).total_seconds()

        return msSince1970

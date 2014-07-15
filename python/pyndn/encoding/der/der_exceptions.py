
"""
    Exceptions that may occur during DER encoding/decoding
    Correspond to exceptions in ndn-cpp
"""

class DerException(Exception):
    pass

class NegativeLengthException(DerException):
    def __init__(self, message):
        super(self, NegativeLengthException).__init__(self, message)

class DerEncodingException(DerException):
    def __init__(self, message):
        super(self, NegativeLengthException).__init__(self, message)

class DerDecodingException(DerException):
    def __init__(self, message):
        super(self, NegativeLengthException).__init__(self, message)


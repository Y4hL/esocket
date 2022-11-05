class ESocketException(Exception):
    """ ESocket Exception """




class HandshakeException(ESocketException):
    """ Handshake Exception """

class InvalidCertificate(HandshakeException):
    """ Invalid Certificate """

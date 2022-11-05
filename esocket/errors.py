class ESocketException(Exception):
    """ ESocket Exception """


class MissingArgument(ESocketException):
    """ Missing required argument """


class HandshakeException(ESocketException):
    """ Handshake Exception """


class InvalidCertificate(HandshakeException):
    """ Invalid Certificate """

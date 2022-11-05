import socket
import os
import socket
import logging
from typing import Tuple, Union
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class ESocket:
    """
    ESocket - Encrypted Socket Wrapper

    Communication

    ESocket generates a header for each message, ensuring both ends don't end up
    just listening to eachother (ESocket uses blocking sockets). The ESocket header
    size is 8 bytes. The header is used define the size of the incoming message.
    This means message do have a max size of 18,446,744,073,709,551,616 bits
    (2.3 Exabytes for those who are curious), which is probably higher than anyone
    will use this software for.

    Encryption

    ESocket uses elliptic-curve cryptography to provide a secure handshake with peers.
    This is achived using certificates and a Diffie-Hellman key exchange.
    The handshake ensures perferct forward secrecy and uses AES256 for further communication.

    Specifications:

    EC alogorithm: SECP521R1 (Equivalent to 7680 RSA key size)
    Hashing algorithm: SHA512
    AES algorithm: AES256
    AES padding algorithm: PKCS7
    """

    # Define header size
    header_length = 8

    # AES cipher
    _cipher = None
    
    # Padding for AES
    _pad = padding.PKCS7(256)

    def __init__(self,
        socket: socket.socket,
        server: bool,
        require_cert: bool = True,
        cert: x509.Certificate = None
        ) -> None:
        """
        Initialize class

        socket: socket object to wrap
        server: bool if socket is the server
        require_cert: require a valid certificate during handshake
        cert: in the servers case its own certificate, in clients case certificate it supports
        """
        self.sock = socket
        self.server = server
        self.require_cert = require_cert
        self.cert = cert

        # Start handshake
        self.handshake()

    def close(self) -> None:
        """ Close socket """
        self.sock.close()

    def _encrypt(self, data: bytes) -> bytes:
        """ Encrypt data """
        # Create padder and pad data
        padder = self._pad.padder()
        data = padder.update(data) + padder.finalize()

        # Create encryptor and encrypt data
        encryptor = self._cipher.encryptor()
        data = encryptor.update(data) + encryptor.finalize()
    
        return data

    def _decrypt(self, data: bytes) -> bytes:
        """ Decrypt data """

        # Create decryptor and decrypt data
        decryptor = self._cipher.decryptor()
        data = decryptor.update(data) + decryptor.finalize()

        # Create unpadder and unpad data
        unpadder = self._pad.unpadder()
        data = unpadder.update(data) + unpadder.finalize()

        return data

    def handshake(self) -> None:
        """
        Handshake 
        
        Verify certificate
        Generate keypair
        Exchange public keys
        Generate shared session key
        Server sends IV for AES256
        Create AES cipher
        """

    def _send(self, data: bytes) -> None:
        """ Send raw message to peer """

        # Create header
        header = len(data).to_bytes(self.header_length, byteorder='big')

        # Add header to message and send
        self.sock.send(header + data)

    def _recv(self) -> bytes:
        """ Receive raw message from peer """

        def recvall(amount: int) -> bytes:
            """ Receive x amount of bytes """
            data = b''
            while len(data) < amount:
                data += self.sock.recv(amount - len(data))
            return data

        # Receive header and parse message length
        header = recvall(self.header_length)
        message_length = int.from_bytes(header, 'big')

        # Receive data
        return recvall(message_length)

    # Main functions to use
    def send(self, data: bytes) -> None:
        """ Send message to peer """
        # Process, encrypt and send data
        self._send(self._encrypt(self.presend(data)))

    def recv(self) -> bytes:
        """ Receive message from peer """
        # Receive, decrypt and process data
        return self.postrecv(self._decrypt(self._recv()))

    # Public functions to be overwritten
    def presend(self, data: bytes) -> bytes:
        """ Process data before sending (pre-encryption) """
        return data

    def postrecv(self, data: bytes) -> bytes:
        """ Process data after receiving (post-decryption) """
        return data

""" Core ESocket of the esocket module """
import os
import socket
import logging

from cryptography import x509
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# local imports
import errors
import utils


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
        cert: x509.Certificate,
        private_key: ec.EllipticCurvePrivateKeyWithSerialization = None
        ) -> None:
        """
        Initialize class

        socket: socket object to wrap
        server: bool if socket is the server
        cert: in the servers case its own certificate, in clients case certificate it trusts
        private_key: private key used to generate certificate (server only)
        """
        self.sock = socket
        self.server = server
        self.cert = utils.load_cert(cert)

        if self.server:
            if private_key is None:
                raise errors.MissingArgument('server requires private key')
            else:
                self.private_key = utils.load_key(private_key)

        # Perform handshake
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

        Generate keypair
        Exchange public keys
        Verify signature
        Generate shared session key
        Server sends IV for AES256
        Create AES cipher
        """

        # Keys used for session
        private_key = ec.generate_private_key(ec.SECP521R1())
        pem_public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if self.server:
            # Sign public key using certificate private key
            signature = self.private_key.sign(
                pem_public_key,
                ec.ECDSA(hashes.SHA512())
            )
            self._send(pem_public_key)
            serialized_peer_public_key = self._recv()
            self._send(signature)
        else:
            serialized_peer_public_key = self._recv()
            self._send(pem_public_key)
            signature = self._recv()

            # Verify signature
            self.cert.public_key().verify(
                signature,
                serialized_peer_public_key,
                ec.ECDSA(hashes.SHA512())
            )

        # Exchange private and peer public key for shared key
        peer_public_key = serialization.load_pem_public_key(serialized_peer_public_key)
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

        # Derive key
        derived_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=None
        ).derive(shared_key)

        # Share IV for AES
        if self.server:
            iv = os.urandom(16)
            self._send(iv)
        else:
            iv = self._recv()

        self._cipher = Cipher(
            algorithm=algorithms.AES256(derived_key),
            mode=modes.CBC(iv)
        )
        logging.info('Handshake completed successfully')

        return True

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

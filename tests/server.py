""" Server test for esocket """
import os
import socket

from esocket import ESocket

# Define path and filenames
PATH = os.path.dirname(os.path.abspath(__file__))
CERT_FILENAME = 'cert.pem'
KEY_FILENAME = 'key.pem'

# Set up socket connection
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setblocking(True)

sock.bind(('localhost', 6969))
sock.listen(5)

conn, address = sock.accept()

# Read private key
with open(os.path.join(PATH, KEY_FILENAME), 'rb') as file:
    key = file.read()

# Read certificate
with open(os.path.join(PATH, CERT_FILENAME), 'rb') as file:
    cert = file.read()

# Wrap socket in esocket
esock = ESocket(conn, True, cert, key)

# Send message to client
esock._send(b'Connected successfully.')

""" Client test for esocket """
import os
import socket

from esocket import ESocket

# Define path and filename
PATH = os.path.dirname(os.path.abspath(__file__))
CERT_FILENAME = 'cert.pem'

# Connect to socket
sock = socket.socket()
sock.connect(('localhost', 6969))

# Read certificate
with open(os.path.join(PATH, CERT_FILENAME), 'rb') as file:
    cert = file.read()

# Wrap socket in esocket
esock = ESocket(sock, False, cert)

# Print incoming data from server
print(esock._recv())
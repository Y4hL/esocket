import socket
from esocket import ESocket

sock = socket.socket()
sock.connect(('localhost', 6969))

with open('cert.pem', 'rb') as file:
    cert = file.read()

esock = ESocket(sock, False, cert)


print(esock._recv())
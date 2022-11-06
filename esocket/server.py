import socket

from esocket import ESocket

sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setblocking(True)

sock.bind(('localhost', 6969))
sock.listen(5)

conn, address = sock.accept()

with open('key.pem', 'rb') as file:
    key = file.read()

with open('cert.pem', 'rb') as file:
    cert = file.read()

esock = ESocket(conn, True, cert, key)

esock._send(b'Successfully opened file.')
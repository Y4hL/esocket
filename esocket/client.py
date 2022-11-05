import socket
from esocket import ESocket

sock = socket.socket()
sock.connect(('', 6969))

esock = ESocket(sock, False, False)


print(esock._recv())
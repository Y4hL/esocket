# esocket

ESocket - Encrypted Socket Wrapper

## Communication

ESocket generates a header for each message, ensuring both ends don't end up
just listening to eachother (ESocket uses blocking sockets). The ESocket header
size is 8 bytes. The header is used define the size of the incoming message.
This means message do have a max size of 18,446,744,073,709,551,616 bits
(2.3 Exabytes for those who are curious), which is probably higher than anyone
will use this software for.

## Encryption

ESocket uses elliptic-curve cryptography to provide a secure handshake with peers.
This is achived using certificates and a Diffie-Hellman key exchange.
The handshake ensures perferct forward secrecy and uses AES256 for further communication.

### Specifications:

EC alogorithm: SECP521R1 (Equivalent to 7680 RSA key size)
Hashing algorithm: SHA512
AES algorithm: AES256
AES padding algorithm: PKCS7

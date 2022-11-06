""" CLI for esocket """
import os

import esocket


def make_keys():
    """ CLI for generating new keys """
    response = input('Do you want to generate new keys (yes/no)? ')
    if response.strip().lower() != 'yes':
        return

    KEY_PATH = 'key.pem'
    CERT_PATH = 'cert.pem'

    # Check whether key or cert already exist
    if os.path.isfile(KEY_PATH) or os.path.isfile(CERT_PATH):
        response = input('Found existing keys. Do you want to overwrite them (yes/no)? ')
        if response.strip().lower() != 'yes':
            return

    # Generate private key
    key = esocket.utils.generate()
    with open(KEY_PATH, 'wb') as file:
        file.write(key)

    # Generate Certificate
    cert = esocket.utils.make_cert(esocket.utils.load_key(key))
    with open(CERT_PATH, 'wb') as file:
        file.write(cert)


if __name__ == '__main__':
    make_keys()
import base64
import binascii
import codecs
import io
import json
import os
import re
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import Hash, SHA256, SHA512
from pprint import pprint
from shutil import copytree, rmtree

if __name__ == "__main__":

    secret = sys.argv[1]
    iv = sys.argv[2]
    tag = sys.argv[3]
    key = sys.argv[4]
    
    # Backend setting
    backend = default_backend()
    
    
    print(len(key))
    print(bytes(key.encode("UTF-8")))

    print(base64.b16decode(bytes(key)).decode())


    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(secret) + decryptor.finalize()

    print(plaintext)
    
    exit(0)
    
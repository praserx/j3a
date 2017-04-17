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

    plaintext = '{ "secret": "test" }'

    plaintext = json.dumps(json.loads(plaintext))

    digest = Hash(SHA256(), backend=default_backend())
    digest.update(bytes(plaintext.encode('UTF-8')))
    hash = digest.finalize()
   
    print(base64.b16encode(hash).decode())
    print(plaintext)
    
    exit(0)
    
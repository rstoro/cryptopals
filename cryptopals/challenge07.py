#!/usr/bin/env python3
from utils.aes_ecb import AES_ECB
from utils.conversion_util import ConversionUtil as c_util

if __name__ == '__main__':
  with open('challenge07_b64.txt', 'r') as f:
    ciphertext = f.read()

  key = c_util.str_to_bytes('YELLOW SUBMARINE')
  cipherbytes = c_util.base64_to_bytes(ciphertext)
  plaintext = AES_ECB.decrypt(cipherbytes, key)
  print(plaintext)

#!/usr/bin/env python3
from utils.pkcs7 import pkcs7

if __name__ == '__main__':
  ciphertext = 'YELLOW SUBMARINE'.encode('utf-8')
  assert(pkcs7(ciphertext, 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04')

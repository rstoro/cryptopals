#!/usr/bin/env python3
from utils.encryption_oracle import EncryptionOracle
from utils.conversion_util import ConversionUtil as c_util

if __name__ == '__main__':
  with open('challenge10_b64.txt', 'r') as f:
    ciphertext = ''.join(l.strip() for l in f.readlines())
  cipherbytes = c_util.base64_to_bytes(ciphertext)
  enc_used = 'CBC'
  guess = EncryptionOracle.detect_encryption_type(cipherbytes)
  assert(enc_used == guess)

  with open('challenge08_hex.txt', 'r') as f:
    ciphertext = ''.join(line.strip() for line in f.readlines())
  cipherbytes = c_util.hex_to_bytes(ciphertext)
  enc_used = 'ECB'
  guess = EncryptionOracle.detect_encryption_type(cipherbytes)
  assert(enc_used == guess)

  EncryptionOracle().run_test()


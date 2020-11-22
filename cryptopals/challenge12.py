#!/usr/bin/env python3
from os import urandom
from utils.encryption_oracle import EncryptionOracle
from utils.conversion_util import ConversionUtil as c_util

if __name__ == '__main__':
  #we are not supposed to know this info, but it is needed for initial part
  #of the challenge
  blocksize = 16
  key = urandom(blocksize)

  #initial data
  with open('challenge12_input.txt', 'r') as f:
    text = ''.join(l.strip() for l in f.readlines())
  appendtext = 'bGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg' +\
      'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq' +\
      'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg' +\
      'YnkK'

  #bytes
  textbytes = c_util.str_to_bytes(text)
  appendbytes = c_util.base64_to_bytes(appendtext)
  full_textbytes = appendbytes + textbytes

  #ciphertext
  ciphertext = EncryptionOracle.ecb_encrypt(textbytes=full_textbytes, key=key)

  #begin break
  #1) discover block size
  #TODO:what was it saying about repeating?  did I impliment this wrong?
  identical_bytes = c_util.str_to_bytes('A')
  rand_key = urandom(16)  #all encryption types keys must be modulus 16
  temp_ciphertext = EncryptionOracle.ecb_encrypt(
      textbytes=identical_bytes, 
      key=rand_key)
  blocksize = len(temp_ciphertext)

  #2) detect if ecb or cbc
  EncryptionOracle.detect_encryption_type(ciphertext, blocksize)

  #3) enc bytes one byte short of the blocksize
  temp_bytes = c_util.str_to_bytes('A' * (blocksize-1))
  possibilities = [
      EncryptionOracle.ecb_encrypt(
          textbytes=temp_bytes + c_util.str_to_bytes(chr(i)),
          key=key) \
      for i in range(ord('A'), ord('Z'))]
  print(*possibilities,sep='\n')


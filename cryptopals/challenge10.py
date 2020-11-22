#!/usr/bin/env python
from utils.aes_cbc import AES_CBC
from utils.conversion_util import ConversionUtil as c_util

def testbed():
  key = 'YELLOW SUBMARINE'
  text = 'Episiotomy, episi-pleasey-me. I\'m gonna do it to you, until you do it to me.  I take you to a place you\'ve never been, beceause I told you before: My name is Dr. Fucking Ken.'

  key = c_util.str_to_bytes(key)
  text = c_util.str_to_bytes(text)
  iv = AES_CBC.generate_initialization_vector()

  enc_test = AES_CBC.encrypt(text, key, iv)
  dec_test = AES_CBC.decrypt(enc_test, key, iv)

  #a few leftover bytes from pkcs7, so a not direct comparison
  assert(text in dec_test)

if __name__ == '__main__':
  testbed()

  with open('challenge10_b64.txt', 'r') as f:
    ciphertext = ''.join(l.strip() for l in f.readlines())

  key = 'YELLOW SUBMARINE'

  key = c_util.str_to_bytes(key)
  ciphertext = c_util.base64_to_bytes(ciphertext)
  iv = AES_CBC.generate_initialization_vector(randomize=False)

  cbc_dec = AES_CBC.decrypt(ciphertext, key, iv)
  print(str(cbc_dec, 'utf-8'))


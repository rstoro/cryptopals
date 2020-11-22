#!/usr/bin/env python3
from Crypto.Cipher import AES
from .pkcs7 import pkcs7

class AES_ECB(object):

  @staticmethod
  def decrypt(cipherbytes, key):
    assert(all(isinstance(b, bytes) for b in [cipherbytes, key]))

    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(cipherbytes)

  @staticmethod
  def encrypt(textbytes, key, blocksize=16):
    assert(all(isinstance(b, bytes) for b in [textbytes, key]))

    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pkcs7(textbytes, blocksize)
    return cipher.encrypt(padded_text)


#!/usr/bin/env python3
from os import urandom
from Crypto.Cipher import AES
from .conversion_util import ConversionUtil as c_util
from .pkcs7 import pkcs7

class AES_CBC(object):
  
  @staticmethod
  def generate_initialization_vector(blocksize=16, randomize=True):
    return urandom(8 * blocksize) \
      if randomize \
      else c_util.str_to_bytes(chr(0) * blocksize)

  @staticmethod
  def encrypt(bytetext, key, iv, blocksize=16):
    assert(isinstance(blocksize, int))
    assert(all(isinstance(item, bytes) for item in [bytetext, key, iv]))

    #AES cipher
    cipher = AES.new(key, AES.MODE_ECB)

    #pad text
    padded_bytetext = pkcs7(bytetext, blocksize)

    #get blocks from pkcs7 padded text 
    byte_chunks = [padded_bytetext[i:i + blocksize] \
      for i in range(0, len(padded_bytetext), blocksize)]

    #ciphertext becomes the iv which is passed to the next block
    cipherbytes = bytes()
    for byte_chunk in byte_chunks:
      ored_text = bytes( (a ^ b for a, b in zip(byte_chunk, iv)) )
      iv = cipher.encrypt(ored_text)
      cipherbytes += iv

    return cipherbytes

  @staticmethod
  def decrypt(cipherbytes, key, iv, blocksize=16):
    assert(isinstance(blocksize, int))
    assert(all(isinstance(item, bytes) for item in [cipherbytes, key, iv]))

    #AES cipher
    cipher = AES.new(key, AES.MODE_ECB)

    #get blocks from pkcs7 padded text 
    byte_chunks = [cipherbytes[i:i + blocksize] \
      for i in range(0, len(cipherbytes), blocksize)]

    #iv is the block we used before deciphering
    bytetext = bytes()
    for byte_chunk in byte_chunks:
      ored_text = cipher.decrypt(byte_chunk)
      bytetext += bytes(a ^ b for a, b in zip(ored_text, iv))
      iv = byte_chunk

    return bytetext


#!/usr/bin/env python3
from os import urandom 
from random import random as rand
from random import randrange as randrange
from .conversion_util import ConversionUtil as c_util
from .aes_ecb import AES_ECB
from .aes_cbc import AES_CBC

class EncryptionOracle(object):

  def run_test(self):
    for _ in range(1000):
      textbytes = bytes([0 for _ in range(randrange(40, 80))])
      enc, cipherbytes = self.__generate_random_encryption(textbytes)
      guess = self.detect_encryption_type(cipherbytes)


  def __generate_random_encryption(self, textbytes, blocksize=16):
    assert(isinstance(textbytes, bytes))
    assert(isinstance(blocksize, int) and blocksize % 16 == 0)

    ECB = 0
    CBC = 1
    ENC_TYPES = { ECB: 'ECB', CBC: 'CBC' }

    #generate random 16 bytes for AES key
    rand_key = urandom(blocksize)

    #get 5-10 random bytes
    start_bytes = urandom(randrange(5, 11))
    end_bytes = urandom(randrange(5, 11))

    #prepend and append randomized bytes to textbytes
    textbytes_with_randbytes = start_bytes + textbytes + end_bytes

    #random selection 
    selection = randrange(2) 

    #get cipherbytes
    cipherbytes = None
    if selection == ECB:
      cipherbytes = EncryptionOracle.ecb_encrypt(
          textbytes=textbytes_with_randbytes, 
          key=rand_key,
          blocksize=blocksize)
    elif selection == CBC:
      cipherbytes = EncryptionOracle.ecb_encrypt(
          textbytes=textbytes_with_randbytes, 
          key=rand_key, 
          blocksize=blocksize)
    else:
      raise NotImplementedError('Encryption type not implemented.')

    return ENC_TYPES[selection], cipherbytes

  @staticmethod
  def ecb_encrypt(textbytes, key, blocksize=16):
    assert(isinstance(textbytes, bytes))
    assert(isinstance(blocksize, int) and blocksize % 16 == 0)
    return AES_ECB.encrypt(
        textbytes=textbytes, 
        key=key, 
        blocksize=blocksize)

  @staticmethod
  def cbc_encrypt(textbytes, key, iv=None, blocksize=16):
    assert(isinstance(blocksize, int) and blocksize % 16 == 0)
    iv = iv if iv else AES_CBC.generate_initialization_vector()
    assert(all(isinstance(b, bytes) for b in [textbytes, key, iv]))
    return AES_CBC.encrypt(
        textbytes=textbytes, 
        key=key, 
        iv=iv, 
        blocksize=blocksize)

  @staticmethod
  def detect_encryption_type(cipherbytes, blocksize=16):
    assert(isinstance(cipherbytes, bytes))
    assert(isinstance(blocksize, int) and blocksize % 16 == 0)

    #get blocksize chunks of bytes
    byte_chunks = [cipherbytes[i:i+blocksize] \
      for i in range(0, len(cipherbytes), blocksize)]

    #get repeating chunks
    repeating_chunks = len(byte_chunks) - len(set(byte_chunks))

    #ECB is more likely to leave repeating data patterns
    #because text will always encrypt the same based on the key
    return 'ECB' if repeating_chunks > 0 else 'CBC'


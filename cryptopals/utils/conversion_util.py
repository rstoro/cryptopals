#!/usr/bin/env python3
from base64 import b64encode, b64decode
from sys import byteorder

class ConversionUtil(object):
  
  @staticmethod
  def hex_to_bytes(h):
    return bytes.fromhex(h)

  @staticmethod
  def str_to_bytes(s, encoding='utf-8'):
    return bytes(s, encoding)

  @staticmethod
  def bytes_to_str(bs):
    return ''.join(chr(b) for b in bs)

  @staticmethod
  def int_to_bytes(i):
    if i > 255:
      raise ValueError('Int cannot be greater than 255.')

    return bytes([i])

  @staticmethod
  def bytes_to_int(bs):
    return int.from_bytes(bs, byteorder)

  @staticmethod
  def base64_to_bytes(bs):
    return b64decode(bs)

  @staticmethod
  def bytes_to_base64(bs):
    return b64encode(bs)


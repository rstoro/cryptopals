#!/usr/bin/env python3

def pkcs7(s, b=16):
  if isinstance(s, str):
    s = s.encode('utf-8')
  elif not isinstance(s, bytes):
    raise TypeError('Input must be of type <str> or <bytes>')
  
  return s + bytes((chr(b-len(s) % b) * (b-len(s) % b)).encode('utf-8'))

if __name__ == '__main__':
  ciphertext = 'YELLOW SUBMARINE'
  assert(pkcs7(ciphertext, 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04')

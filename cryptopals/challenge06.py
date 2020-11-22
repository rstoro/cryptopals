#!/usr/bin/env python3
import binascii
from itertools import combinations, islice

#keysize 2-40
KEYMIN = 2
KEYMAX = 40

#not the best metric
freq_map = {
  'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835,
  'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610, 'h': 0.0492888,
  'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490,
  'm': 0.0202124, 'n': 0.0564513, 'o': 0.0596302, 'p': 0.0137645,
  'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357,
  'u': 0.0225134, 'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692,
  'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182 
}


def hamming_dist(s1, s2):
  if len(s1) != len(s2):
    raise ValueError('Undefined for sequences of unequal length')

  #obviously not the best way to do this, but its working
  #there are also time complexity issues pertianing to using zip
  return sum(bin(x ^ y).count('1') for x, y in zip(s1, s2))


def get_probalistic_xor_key(byte_arr):
  return max(
    range(0, 256), 
    key=lambda k: sum(score_string(chr(c^k)) for c in byte_arr)
  )


def score_string(s):
  return sum(freq_map[c.lower()] for c in s if c in freq_map)


def repeating_key_xor(value, key):
  return bytes(
    key[i % len(key)] ^ value[i] for i in range(0, len(value))
  )


def chunks(l, n):
  for i in range(0, len(l), n):
    yield l[i:i+n]

def transpose(l):
  tl = []
  for item in l:
    for i in range(0, len(item)):
      if len(tl) < i + 1:
        tl.append(bytearray())

      tl[i].append(item[i])

  return tl


def normalized_hamming_dist(l, keysize):
  #take first 4 combinations of keysize length
  pairs = list(combinations(islice(chunks(l, keysize),0 ,4), 2))

  #find hamming dist between
  dists = [
    hamming_dist(pair[0], pair[1]) / keysize for pair in pairs
  ]

  #avg dist
  return sum(dists) / len(dists)


if __name__ == '__main__':
  assert(hamming_dist(
    b'this is a test',
    b'wokka wokka!!!'
  ) == 37)

  #potentially not space safe
  with open('challenge06_b64.txt', 'r') as f:
    lines = bytearray([b for b in binascii.a2b_base64(f.read())])

  #keysize with smallest normalized ham dist is probably key
  keysize = min(
    range(KEYMIN, KEYMAX+1),
    key=lambda k: normalized_hamming_dist(lines, k)
  )

  #once keysize, break cyphertext into blocks of keysize len
  #transpose blocks (make block that is first byte of every block
  # second block that is second byte of every block, etc.)
  t_blocks = transpose(chunks(lines, keysize))

  #foreach block, break single-byte xor, the best looking
  # histogram is probably the repeating-key xor for 
  # that byte block put them together and you have the key
  potential_key = ''.join(
    chr(get_probalistic_xor_key(t_block)) for t_block in t_blocks
  )

  decrypted_potential_solution = ''.join(
    chr(c) for c in repeating_key_xor(
      lines,
      potential_key.encode('utf-8')
    )
  )

  print('key:', potential_key)
  print('text:', decrypted_potential_solution)


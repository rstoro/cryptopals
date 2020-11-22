#!/usr/bin/env python3

if __name__ == '__main__':
  BLOCK_SIZE = 16

  #one of these is using aes in ecb mode
  with open('challenge08_hex.txt', 'r') as f:
    ciphertexts = [bytes.fromhex(line.strip()) for line in f.readlines()]

  #the problem with electronic codebook is that identical plaintext blocks
  #will encrypt into identical ciphertext blocks

  #is this enough to determine ecb mode by finding which hex array contains
  #the most matching (or closest to matching) blocks?

  #byte chunks of block size
  get_chunks = lambda ciphertext: [ciphertext[i:i+BLOCK_SIZE] \
    for i in range(0, len(ciphertext), BLOCK_SIZE)]

  #returns the number of matching chunks
  repeating_chunks = lambda chunks: len(chunks) - len(set(chunks))

  index, text = max(enumerate(ciphertexts), \
    key=lambda ciphertext: repeating_chunks(get_chunks(ciphertext[1])))

  #had to lookup to see if this was correct.  it made sense, and it turns out
  #it was infact correct.  just difficult to trust in yourself at times.
  print('index', index)
  print('matching chunks', repeating_chunks(text))
  print('ciphertext', text)


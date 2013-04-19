CCA-Secure Symmetric Key Encryption scheme

Dylan Hutchison
CS 579 Crypto
Lab 1 due 5 April 2013
http://www.cs.stevens.edu/~nicolosi/classes/13sp-cs579/lab1/lab1.html

Please see 'typescript' for a run-through test of the program.

COMPILE-TIME PARAMETERS in pv.h
* CCA_STRENGTH	2 * the length of the key used in AES and HMAC.  Must be 16, 24 or 32.
* BLOCK_SIZE    The size of an AES block.  Keep this as 16 regardless of CCA_STRENGTH.

  pv_misc.c contains the given helper function.  In addition, I define
xor_buffers(a,b,c,len), a function that does a := b ^ c for length len.  Note that a
couple free() calls are added in other functions to prevent memory leaks.

  pv_keygen.c creates a key of length CCA_STRENGTH from a random number generator
initizlized via ri().

  make_big_file.bash generates arbitrarily large bigfile.txt files by
repeatedly appending the results of 'fortune'.

pv_encrypt.c encrypts a given plintext file using a given key file and stores the result
in a new ciphertext file.  Encryption occurs in blocks beginning with a random IV.  Along
the way, I maintain a running HMAC of the ciphertexts.  Once finished with processing the
plaintext (padding the last block with zeros), I output the HMAC in 20 bytes and output
the number of padded zeros in 4 bytes.

pv_decrypt.c decrpyts an encrypted file using a given key file and storees the resulting
plaintext in a new file.  Decryption occurrs in blocks.  Because the length of the
ciphertext is not known, an extra 24 bytes are "read ahead" and stored in a buffer.  After
all blocks are read, future reads return 0 additional bytes and the 24 extra bytes can be
decomposed into the 20 bytes HMAC integrity key and the 4 byte number of appended zeros.
If the integrity key and the HMAC key calculated while decrypting blocks do not match, the
decryption is aborted.  The resulting file is truncated by a number of bytes equal to the
number of appended zeros.


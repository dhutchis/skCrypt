#include "pv.h"

void
encrypt_file (const char *ctxt_fname, void *raw_sk, size_t raw_len, int fin)
{
  /*************************************************************************** 
   * Task: Read the content from file descriptor fin, encrypt it using raw_sk,
   *       and place the resulting ciphertext in a file named ctxt_fname.
   *       The encryption should be CCA-secure, which is the level of 
   *       cryptographic protection that you should always expect of any 
   *       implementation of an encryption algorithm.
   * 
   * Here are some guidelines, but you are welcome to make variations, as long
   * as you can argue that your code still attains CCA security.
   *
   * One approach is to use AES in CBC-mode, and then append an HSHA-1  
   * mac of the resulting ciphertext. (Always mac after encrypting!)  
   * The libdcrypt library also contains implementations of AES 
   * (~class/src/dcrypt/aes.c) and of HSHA-1 (~class/src/dcrypt/sha1.c).  
   * However, you should take care of using AES in CBC-mode, as the
   * library only gives access to the basic AES block cipher functionality.
   * (You can use another mode of operation instead of CBC-mode.)
   *
   * Notice that the key used to compute the HSHA-1 mac must be different 
   * from the one used by AES. (Never use the same cryptographic key for 
   * two different purposes: bad interference could occur.) 
   *
   * Recall that AES can only encrypt blocks of 128 bits, so you should use
   * some padding in the case that the length (in bytes) of the plaintext 
   * is not a multiple of 16.  This should be done in a way that allow proper 
   * decoding after decryption: in particualr,  the recipient must have a way 
   * to know where the padding begins so that it can be chopped off. 
   * One possible design is to add enough 0 bytes to the plaintext so as to
   * make its length a multiple of 16, and then append a byte at the end
   * specifying how many zero-bytes were appended.
   *
   * Thus, the overall layout of an encrypted file will be:
   *
   *         +----+----------------------+--------+
   *         |  Y | HSHA-1 (K_HSHA-1, Y) | padlen |
   *         +----+----------------------+--------+
   *
   * where Y = CBC-AES (K_AES, {plaintext, 0^padlen})
   *       padlen = no. of zero-bytes added to the plaintext to make its
   *                length a multiple of 16.
   * 
   * Moreover, the length of Y (in bytes) is a multiple of 16, the hash value 
   * HSHA-1 (K_HSHA-1, Y) is 20-byte-long, and padlen is a sigle byte.
   *
   ***************************************************************************/

  /* Create the ciphertext file---the content will be encrypted, 
   * so it can be world-readable! */

  /* initialize the pseudorandom generator (for the IV) */

  /* The buffer for the symmetric key actually holds two keys: */
  /* use the first key for the CBC-AES encryption ...*/

  /* ... and the second part for the HMAC-SHA1 */

  /* Now start processing the actual file content using symmetric encryption */
  /* Remember that CBC-mode needs a random IV (Initialization Vector) */

  /* Compute the HSHA-1 mac while you go */

  /* CBC (Cipher-Block Chaining)---Encryption
   * xor the previous ciphertext's block with the next plaintext's block;
   * then encrypt it with AES and write the resulting block */
  
  /* Don't forget to pad the last block with trailing zeroes */

  /* write the last chunk */

  /* Finish up computing the HSHA-1 mac and write the 20-byte mac after
   * the last chunk of the CBC ciphertext */

  /* Remember to write a byte at the end specifying how many trailing zeroes
   * (possibly none) were added */
}

void 
usage (const char *pname)
{
  printf ("Personal Vault: Encryption \n");
  printf ("Usage: %s SK-FILE PTEXT-FILE CTEXT-FILE\n", pname);
  printf ("       Exits if either SK-FILE or PTEXT-FILE don't exist.\n");
  printf ("       Otherwise, encrpyts the content of PTEXT-FILE under\n");
  printf ("       sk, and place the resulting ciphertext in CTEXT-FILE.\n");
  printf ("       If CTEXT-FILE existed, any previous content is lost.\n");

  exit (1);
}

int 
main (int argc, char **argv)
{
  int fdsk, fdptxt;
  char *raw_sk;
  size_t raw_len;

  /* YOUR CODE HERE */


  if (argc != 4) {
    usage (argv[0]);
  }   /* Check if argv[1] and argv[2] are existing files */
  else if (((fdsk = open (argv[1], O_RDONLY)) == -1)
	   || ((fdptxt = open (argv[2], O_RDONLY)) == -1)) {
    if (errno == ENOENT) {
      usage (argv[0]);
    }
    else {
      perror (argv[0]);
      
      exit (-1);
    }
  }
  else {
    setprogname (argv[0]);
    
    /* Import symmetric key from argv[1] */
    if (!(import_sk_from_file (&raw_sk, &raw_len, fdsk))) {
      printf ("%s: no symmetric key found in %s\n", argv[0], argv[1]);
      
      close (fdsk);
      exit (2);
    }
    close (fdsk);

    /* Enough setting up---let's get to the crypto... */
    encrypt_file (argv[3], raw_sk, raw_len, fdptxt);    

    /* scrub the buffer that's holding the key before exiting */

    /* YOUR CODE HERE */

    close (fdptxt);
  }

  return 0;
}

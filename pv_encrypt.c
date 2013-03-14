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
  int fctxt = open(ctxt_fname, O_WRONLY | O_TRUNC | O_CREAT, 0644);
  if (fctxt == -1) {
    perror("encrypt_file: error opening ctxt file");
    return;
  }

  /* initialize the pseudorandom generator (for the IV) */
  ri();

  /* The buffer for the symmetric key actually holds two keys: */
  /* use the first key for the CBC-AES encryption ...*/
  assert(raw_len % 2 == 0);  /* really should be == 2*CCA_STRENGTH */
  const size_t sk_len = raw_len / 2;
  const char *sk_aes = (const char*)raw_sk;
  /* ... and the second part for the HMAC-SHA1 */
  const char *sk_hmac = (const char*)raw_sk+sk_len;

  /* Now start processing the actual file content using symmetric encryption */
  /* Remember that CBC-mode needs a random IV (Initialization Vector) */
  char *cprev = (char*)malloc(sk_len * sizeof(char));
  if (!cprev) {
    fprintf(stderr, "encrypt_file: Cannot allocate %zu bytes\n",sk_len);
    close(fctxt); unlink(ctxt_fname);
    return;
  }
  prng_getbytes(cprev, sk_len); /* IV */

  struct aes_ctx aes_s;		/* init AES */
  aes_setkey(&aes_s, sk_aes, sk_len);

  struct sha1_ctx hmac_s;	/* init HMAC */
  hmac_sha1_init(sk_hmac, sk_len, &hmac_s);

  /* output IV as first part of ctxt and pass to HMAC */
  if (write_chunk(fctxt, cprev, sk_len) != 0) {
    fprintf(stderr,"encrypt_file: error writing to %s\n", ctxt_fname);
    aes_clrkey(&aes_s);
    close(fctxt); unlink(ctxt_fname);
    free(cprev);
    return;
  }
  hmac_sha1_update(&hmac_s, cprev, sk_len);

  char *bufin = (char*)malloc(sk_len * sizeof(char)); /* buffer to hold chunks of plaintext */
  if (!bufin) {
    fprintf(stderr, "encrypt_file: Cannot allocate %zu bytes\n",sk_len);
    aes_clrkey(&aes_s);
    close(fctxt); unlink(ctxt_fname);
    free(cprev);
    return;
  }
  int numread = read(fin, bufin, sk_len); /* first ptxt read */
  u_int32_t numpad0 = 0u; 	/* number of 0-pad bits */

  while (numread > 0) {
    if ((size_t)numread < sk_len) { 	/* final block; 0-pad */
      numpad0 = sk_len - numread;
      bzero(bufin+numread, numpad0);
    }
    
    xor_buffers(bufin, bufin, cprev, sk_len); /* bufin := bufin ^ cprev */
    aes_encrypt(&aes_s, cprev, bufin); /* cprev := AES(bufin) */

    hmac_sha1_update(&hmac_s, cprev, sk_len); /* update HMAC with next ctxt piece */
    if (write_chunk(fctxt, cprev, sk_len) != 0) {
      fprintf(stderr,"encrypt_file: error writing to %s\n", ctxt_fname);
      aes_clrkey(&aes_s);
      close(fctxt); unlink(ctxt_fname);
      free(cprev); free(bufin);
      return;
    }
    
    numread = read(fin, bufin, sk_len);
  }
  /* numread == 0 is normal EOF */
  if (numread == -1) {
    fprintf(stderr,"encrypt_file: error reading ctxt file\n");
    aes_clrkey(&aes_s);
    close(fctxt); unlink(ctxt_fname);
    free(cprev); free(bufin);
    return;
  }

  /* AES done; finish HMAC and writeout, then write numpad0 */
  aes_clrkey(&aes_s);
  free(cprev);
  bufin = (char*)realloc(bufin, 20); /* ensure bufin has 20 bytes capacity */
  if (!bufin) {
    fprintf(stderr,"encrypt_file: failed to reallocate 20 bytes\n");
    close(fctxt); unlink(ctxt_fname);
    free(bufin);
    return;
  }
  hmac_sha1_final(sk_hmac, sk_len, &hmac_s, (u_char*)bufin);
  if (write_chunk(fctxt, bufin, sk_len) != 0) {
    fprintf(stderr,"encrypt_file: error writing HMAC 20 bytes to %s\n", ctxt_fname);
    close(fctxt); unlink(ctxt_fname);
    free(bufin);
    return;
  }
  putint(bufin, numpad0); 	/* cross-platform stability */
  if (write_chunk(fctxt, bufin, 4) != 0) {
    fprintf(stderr,"encrypt_file: error writing last 4 bytes to %s\n", ctxt_fname);
    close(fctxt); unlink(ctxt_fname);
    free(bufin);
    return;
  }
  
  close(fctxt);
  free(bufin);
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
	   || ((fdptxt = open (argv[2], O_RDONLY)) == -1)) { /* WRONLY? Prompt for overrite? */
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
    if (!(import_sk_from_file (&raw_sk, &raw_len, fdsk))) { /* SETS raw_sk, raw_len */
      printf ("%s: no symmetric key found in %s\n", argv[0], argv[1]);
      close (fdsk);
      exit (2);
    }
    close (fdsk);

    /* Enough setting up---let's get to the crypto... */
    encrypt_file (argv[3], raw_sk, raw_len, fdptxt);    

    /* scrub the buffer that's holding the key before exiting */
    bzero(raw_sk, raw_len);
    free(raw_sk);

    close (fdptxt);
  }

  return 0;
}

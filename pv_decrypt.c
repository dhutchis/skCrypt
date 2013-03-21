#include "pv.h"

void
decrypt_file (const char *ptxt_fname, void *raw_sk, size_t raw_len, int fin)
{
  /*************************************************************************** 
   * Task: Read the ciphertext from the file descriptor fin, decrypt it using
   *       sk, and place the resulting plaintext in a file named ptxt_fname.
   *
   * This procedure basically `undoes' the operations performed by edu_encrypt;
   * it expects a ciphertext featuring the following structure (please refer 
   * to the comments in edu_encrypt.c for more details):
   *
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
   * Reading Y (and then the mac and the pad length) it's a bit tricky: 
   * below we sketch one possible approach, but you are free to implement 
   * this as you wish.
   *
   * The idea is based on the fact that the ciphertext files ends with 
   * 21 bytes (i.e., sha1_hashsize + 1) used up by the HSHA-1 mac and by the 
   * pad length.  Thus, we will repeatedly attempt to perform `long read' of 
   * (aes_blocklen + sha1_hashsize + 2) bytes: once we get at the end of the 
   * ciphertext and only the last chunk of Y has to be read, such `long read'
   * will encounter the end-of-file, at which point we will know where Y ends,
   * and how to finish reading the last bytes of the ciphertext.
   */
  int i;
  /* Create plaintext file---may be confidential info, so permission is 0600 */
  int fptxt = open(ptxt_fname, O_RDWR | O_TRUNC | O_CREAT, 0600); /* RDWR for ftruncate */
  if (fptxt == -1) {
    perror("encrypt_file: error opening ptxt file");
    return;
  }

  /* use the first part of the symmetric key for the CBC-AES decryption ...*/
  /* ... and the second for the HMAC-SHA1 */
  assert(raw_len % 2 == 0);  /* really should be == 2*CCA_STRENGTH */
  const size_t sk_len = raw_len / 2;
  const char *sk_aes = (const char*)raw_sk;
  /* ... and the second part for the HMAC-SHA1 */
  const char *sk_hmac = (const char*)raw_sk+sk_len;

  /* Reading Y */
  /* First, read the IV (Initialization Vector) */
  char *cprev = (char*)malloc(BLOCK_LEN * sizeof(char));
  if (!cprev) {
    fprintf(stderr, "decrypt_file: Cannot allocate %d bytes\n",BLOCK_LEN);
    close(fptxt); unlink(ptxt_fname);
    return;
  }
  int numread = read(fin, cprev, BLOCK_LEN); /* read IV */
  /* printf("numread: %d\n",numread); */
  if (numread < BLOCK_LEN) {
    if (numread == -1) perror(0);
    fprintf(stderr,"decrypt_file: ctxt file is too short or read error\n");
    close(fptxt); unlink(ptxt_fname);
    free(cprev);
    return;
  }

  /* compute the HMAC-SHA1 as you go */
  struct sha1_ctx hmac_s;	/* init HMAC */
  hmac_sha1_init(sk_hmac, sk_len, &hmac_s);
  hmac_sha1_update(&hmac_s, cprev, BLOCK_LEN);
  
  struct aes_ctx aes_s;		/* init AES */
  aes_setkey(&aes_s, sk_aes, sk_len);

  char *bufin = (char*)malloc((BLOCK_LEN+24) * sizeof(char)); /* buffer to hold chunks of ctxt+24 */
  char *bufptxt = (char*)malloc(BLOCK_LEN * sizeof(char));	   /* buffer to hold chunks of ptxt */
  if (!bufin || !bufptxt) {
    fprintf(stderr, "decrypt_file: Cannot allocate memory\n");
    aes_clrkey(&aes_s);
    close(fptxt); unlink(ptxt_fname);
    free(cprev); if (bufptxt) free(bufptxt);
    if (bufin) free(bufin);
    return;
  }
  numread = read(fin, bufin, BLOCK_LEN+24); /* first long read */
  /* printf("numread: %d\n",numread);  */
  if (numread < 24) {
    if (numread == -1) perror(0);
    fprintf(stderr,"decrypt_file: ctxt file is too short or read error\n");
    aes_clrkey(&aes_s);
    close(fptxt); unlink(ptxt_fname);
    free(cprev); free(bufin); free(bufptxt);
    return;
  }
  numread -= 24;
 
  while (numread == BLOCK_LEN) {                   /* while we read a full block */
    aes_decrypt(&aes_s, bufptxt, bufin);           /* bufptxt := AES'(bufin[0..BLOCK_LEN]) */
    xor_buffers(bufptxt, bufptxt, cprev, BLOCK_LEN);  /* bufptxt := bufptxt ^ cprev */
    memcpy(cprev, bufin, BLOCK_LEN);		   /* cprev := bufin[0..BLOCK_LEN] */
    hmac_sha1_update(&hmac_s, cprev, BLOCK_LEN);   /* update HMAC with new ctxt */
    for (i=0; i < 24; i++)                         /* SHIFT bufin[BLOCK_LEN..BLOCK_LEN+24] to beginning*/
      bufin[i] = bufin[i+BLOCK_LEN];
    if (write_chunk(fptxt, bufptxt, BLOCK_LEN) != 0){ /* writeout ptxt block */
      fprintf(stderr,"decrypt_file: error writing to %s\n",ptxt_fname);
      aes_clrkey(&aes_s);
      close(fptxt); unlink(ptxt_fname);
      free(cprev); free(bufin); free(bufptxt);
      return;
    }
    numread = read(fin, bufin+24, BLOCK_LEN);         /* read next ctxt */
    /* printf("numread: %d\n",numread); */
  }
  /* numread == 0 expected on last block */
  if (numread != 0) {
    printf("expected %d\n",0);
    if (numread == -1) perror("decrypt_file: error reading ctx file");
    else fprintf(stderr,"decrypt_file: ctxt file has bad size (not multiple of block length)\n");
    aes_clrkey(&aes_s);
    close(fptxt); unlink(ptxt_fname);
    free(cprev); free(bufin); free(bufptxt);
    return;
  }

  aes_clrkey(&aes_s);
  /* bufin[0..24] holds the HMAC||numpad0 and bufptxt holds last ctxt block (possible extra 0s) */
  cprev = (char*)realloc(cprev, 20); /* ensure cprev has 20 bytes capacity */
  if (!cprev) {
    fprintf(stderr,"decrypt_file: failed to reallocate 20 bytes\n");
    close(fptxt); unlink(ptxt_fname);
    free(bufin); free(cprev); free(bufptxt);
    return;
  }
  hmac_sha1_final(sk_hmac, sk_len, &hmac_s, (u_char*)cprev); /* cprev := computed HMAC */
  for (i=0; i < 20; i++)
    if (bufin[i] != cprev[i]) { /* mismatch! */
      printf("WARNING: HMAC MISMATCH. Check key and ciphertext integrity.\n");
      close(fptxt); unlink(ptxt_fname);
      free(cprev); free(bufin); free(bufptxt);
      return;
    }
  
  /* now let's fix those last 0s */
  u_int32_t numpad0 = getint(bufin+20);
  /* printf("numpad0= %u\n", numpad0); */
  if (numpad0 > 0) {
    int sk = lseek(fptxt, -numpad0, SEEK_CUR); /* desired total file length */
    /* printf("sk= %d\n",sk); */
    if (ftruncate(fptxt, sk) != 0) 
      perror("decrypt_file: error truncating ptxt file to remove excess 0s");
  }
  
  close(fptxt);
  free(cprev);
  free(bufin);
  free(bufptxt);

  /* CBC (Cipher-Block Chaining)---Decryption
   * decrypt the current block and xor it with the previous one 
   */

  /* Recall that we are reading sha_hashsize + 2 bytes ahead: now that 
   * we just consumed aes_blocklen bytes from the front of the buffer, we
   * shift the unused sha_hashsize + 2 bytes left by aes_blocklen bytes 
   */
  
  /* write the decrypted chunk to the plaintext file */

  /* now we can finish computing the HMAC-SHA1 */
  
  /* compare the HMAC-SHA1 we computed with the value read from fin */
  /* NB: if the HMAC-SHA1 mac stored in the ciphertext file does not match 
   * what we just computed, destroy the whole plaintext file! That means
   * that somebody tampered with the ciphertext file, and you should not
   * decrypt it.  Otherwise, the CCA-security is gone.
   */

  /* write the last chunk of plaintext---remember to chop off the trailing
   * zeroes, (how many zeroes were added is specified by the last byte in 
   * the ciphertext (padlen).
   */

}

void 
usage (const char *pname)
{
  printf ("Simple File Decryption Utility\n");
  printf ("Usage: %s SK-FILE CTEXT-FILE PTEXT-FILE\n", pname);
  printf ("       Exits if either SK-FILE or CTEXT-FILE don't exist, or\n");
  printf ("       if a symmetric key sk cannot be found in SK-FILE.\n");
  printf ("       Otherwise, tries to use sk to decrypt the content of\n");
  printf ("       CTEXT-FILE: upon success, places the resulting plaintext\n");
  printf ("       in PTEXT-FILE; if a decryption problem is encountered\n"); 
  printf ("       after the processing started, PTEXT-FILE is truncated\n");
  printf ("       to zero-length and its previous content is lost.\n");

  exit (1);
}

int 
main (int argc, char **argv)
{
  int fdsk, fdctxt;
  char *raw_sk = NULL;
  size_t raw_len = 0;

  if (argc != 4) {
    usage (argv[0]);
  }   /* Check if argv[1] and argv[2] are existing files */
  else if (((fdsk = open (argv[1], O_RDONLY)) == -1)
	   || ((fdctxt = open (argv[2], O_RDONLY)) == -1)) {
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
    if (!(raw_sk = import_sk_from_file (&raw_sk, &raw_len, fdsk))) {
      printf ("%s: no symmetric key found in %s\n", argv[0], argv[1]);
      close (fdsk);
      exit (2);
    }
    close (fdsk);

    /* printf("raw_len: %zu\n",raw_len); */
    /* Enough setting up---let's get to the crypto... */
    decrypt_file (argv[3], raw_sk, raw_len, fdctxt);    

    /* scrub the buffer that's holding the key before exiting */
    bzero(raw_sk, raw_len);
    free(raw_sk);

    close (fdctxt);
  }

  return 0;
}

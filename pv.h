#ifndef _PV_H_
#define _PV_H_

#include "dcrypt.h"

/* pv_misc.c */
void ri (void);
char *import_sk_from_file (char **raw_sk_p, size_t *raw_len_p, int fdsk);
int write_chunk (int fd, const char *buf, u_int len);
void xor_buffers(void *dst, const void *a, const void *b, size_t len);

#ifndef HAVE_GETPROGNAME
# define MY_MAXNAME 80
extern char *my_progname;
const char *getprogname(void);
void setprogname(const char *n);
#endif /* HAVE_GETPROGNAME */

#define CCA_STRENGTH 32 /* must be one of 16, 24 or 32; used to set AES keys */
#define BLOCK_LEN 16

#endif /* _PV_H_ */

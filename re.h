#ifndef MN_RE_H
#define MN_RE_H

#include <stddef.h>

typedef struct re re;

typedef unsigned int u32;
typedef unsigned char u8;

/* return NULL on parse error or mem error */
re *re_init(const char *regex);
void re_destroy(re *r);

int re_fullmatch(re *r, const char *s, size_t n, u32 *match);

#endif /* MN_RE_H */

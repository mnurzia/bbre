#ifndef MN_RE_H
#define MN_RE_H

#include <stddef.h>

typedef struct re re;

typedef signed int s32;
typedef unsigned int u32;
typedef signed short s16;
typedef unsigned short u16;
typedef unsigned char u8;

#define ERR_MEM (-1)
#define ERR_PARSE (-2)

typedef void *(*re_alloc)(size_t, size_t, void *);

/* return NULL on parse error or mem error */
re *re_init(const char *regex);

int re_init_full(re **r, const char *s, re_alloc alloc);

int re_union(re *r, const char *s);
void re_destroy(re *r);

typedef struct span {
  size_t begin, end;
} span;

typedef enum anchor_type {
  A_BOTH = 'B',
  A_START = 'S',
  A_END = 'E',
  A_UNANCHORED = 'U'
} anchor_type;

/* max_span: 1 means match bounds, 2+ means match group n */
int re_match(re *r, const char *s, size_t n, u32 max_span, u32 max_set,
             span *out_span, u32 *out_set, anchor_type anchor);

int re_get_error(re *r, const char **out, size_t *pos);

#endif /* MN_RE_H */

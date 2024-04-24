#ifndef MN_RE_H
#define MN_RE_H

#include <stddef.h>

typedef struct re re;

typedef unsigned int u32;
typedef unsigned char u8;

/* return NULL on parse error or mem error */
re *re_init(const char *regex);

#define ERR_MEM 1
#define ERR_PARSE 2

int re_init_full(re **r, const char *s);

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

/* types of matches: */
/* G S A | Match Type                 | Aut | *BEFR */
/* 0 0 B | bool                       | DFA | ...F. */
/* 0 0 S | bool                       | DFA | .BEF. */
/* 0 0 E | bool                       | DFA | .BE.R */
/* 0 0 U | bool                       | DFA | *BEF. */
/* 0 n B | bool, idx                  | DFA | ...F. */
/* 0 n S | bool, idx                  | DFA | ..EF. */
/* 0 n E | bool, idx                  | DFA | ..E.R */
/* 0 n U | bool, idx                  | DFA | *.EF. */
/* 1 0 B | bool,      bounds          | DFA | ...F. */
/* 1 0 S | bool,      bounds          | DFA | ..EF. */
/* 1 0 E | bool,      bounds          | DFA | ..E.R */
/* 1 0 U | bool,      bounds          | DFA | *.EFR */
/* 1 n B | bool, idx, bounds          | DFA | ...F. */
/* 1 n S | bool, idx, bounds          | DFA | ..EF. */
/* 1 n E | bool, idx, bounds          | DFA | ..E.R */
/* 1 n U | bool, idx, bounds          | DFA | *.EFR */
/* n 0 B | bool,      bounds, groups  | NFA | ..... */
/* n 0 S | bool,      bounds, groups  | NFA | ..... */
/* n 0 E | bool,      bounds, groups  | NFA | ..... */
/* n 0 U | bool,      bounds, groups  | NFA | ..... */
/* n n B | bool, idx, bounds, groups  | NFA | ..... */
/* n n S | bool, idx, bounds, groups  | NFA | ..... */
/* n n E | bool, idx, bounds, groups  | NFA | ..... */
/* n n U | bool, idx, bounds, groups  | NFA | ..... */

int re_match(re *r, const char *s, size_t n, u32 max_span, u32 max_set,
             span *out_span, u32 *out_set, anchor_type anchor);

#endif /* MN_RE_H */

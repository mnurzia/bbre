#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "re.h"

#define REF_NONE 0
#define UTFMAX 0x10FFFF

typedef struct ast {
  u32 v;
} ast;

typedef struct stk {
  u32 *ptr, size, alloc;
} stk;

struct re {
  re_alloc alloc;
  ast *ast;
  u32 ast_size, ast_alloc, ast_root, ast_sets;
  stk arg_stk, op_stk, comp_stk, prog;
  stk cc_stk_a, cc_stk_b;
  u32 entry[4];
};

#define ENT_ONESHOT 0
#define ENT_DOTSTAR 2
#define ENT_FWD 0
#define ENT_REV 1

void *re_default_alloc(size_t prev, size_t next, void *ptr) {
  if (next) {
    assert(prev || !ptr);
    return realloc(ptr, next);
  } else if (ptr) {
    free(ptr);
  }
  return NULL;
}

void *re_ialloc(re *re, size_t prev, size_t next, void *ptr) {
  return re->alloc(prev, next, ptr);
}

void stk_init(re *r, stk *s) {
  (void)(r);
  s->ptr = NULL;
  s->size = s->alloc = 0;
}

void stk_destroy(re *r, stk *s) {
  re_ialloc(r, sizeof(*s->ptr) * s->alloc, 0, s->ptr);
}

int stk_push(re *r, stk *s, u32 v) {
  if (s->size == s->alloc) {
    size_t next_alloc = (s->alloc ? (s->alloc * 2) : 16);
    u32 *out = re_ialloc(r, sizeof(*s->ptr) * s->alloc,
                         sizeof(*s->ptr) * next_alloc, s->ptr);
    if (!out)
      return ERR_MEM;
    s->alloc = next_alloc;
    s->ptr = out;
  }
  s->ptr[s->size++] = v;
  return 0;
}

u32 stk_pop(re *r, stk *s) {
  (void)(r);
  assert(s->size);
  return s->ptr[--s->size];
}

u32 stk_peek(re *r, stk *s, u32 idx) {
  (void)(r);
  assert(idx < s->size);
  return s->ptr[s->size - 1 - idx];
}

int re_parse(re *r, const u8 *s, size_t sz, u32 *root);

re *re_init(const char *regex) {
  re *r;
  if (re_init_full(&r, regex, NULL))
    return NULL;
  return r;
}

int re_init_full(re **pr, const char *regex, re_alloc alloc) {
  int err = 0;
  re *r;
  if (!alloc)
    alloc = re_default_alloc;
  r = alloc(0, sizeof(re), NULL);
  *pr = r;
  if (!r)
    return (err = ERR_MEM);
  r->alloc = alloc;
  r->ast = NULL;
  r->ast_size = r->ast_alloc = r->ast_root = r->ast_sets = 0;
  stk_init(r, &r->arg_stk), stk_init(r, &r->op_stk), stk_init(r, &r->comp_stk);
  stk_init(r, &r->cc_stk_a), stk_init(r, &r->cc_stk_b);
  stk_init(r, &r->prog);
  memset(r->entry, 0, sizeof(r->entry));
  if (regex) {
    if ((err = re_parse(r, (const u8 *)regex, strlen(regex), &r->ast_root))) {
      re_destroy(r);
      return err;
    } else {
      r->ast_sets = 1;
    }
  }
  return err;
}

void re_destroy(re *re) {
  re_ialloc(re, re->ast_alloc * sizeof(*re->ast), 0, re->ast);
  stk_destroy(re, &re->op_stk), stk_destroy(re, &re->arg_stk),
      stk_destroy(re, &re->comp_stk);
  stk_destroy(re, &re->cc_stk_a), stk_destroy(re, &re->cc_stk_b);
  stk_destroy(re, &re->prog);
  re->alloc(sizeof(*re), 0, re);
}

u32 re_ast_new(re *re) {
  if (re->ast_size == re->ast_alloc) {
    u32 next_alloc = (re->ast_alloc ? re->ast_alloc * 2 : 16);
    re->ast = re_ialloc(re, re->ast_alloc * sizeof(ast),
                        next_alloc * sizeof(ast), re->ast);
    if (!re->ast)
      return REF_NONE;
    re->ast_alloc = next_alloc;
  }
  re->ast[re->ast_size].v = REF_NONE;
  if (re->ast_size == REF_NONE) {
    re->ast_size++;
    return re_ast_new(re);
  }
  return re->ast_size++;
}

typedef enum ast_type {
  REG = 1, /* entire subexpression */
  CHR,     /* single character */
  CAT,     /* concatenation */
  ALT,     /* alternation */
  QUANT,   /* quantifier */
  GROUP,   /* group */
  CLS,     /* character class */
  ICLS,    /* inverted character class */
  ANYBYTE  /* any byte (\C) */
} ast_type;

typedef struct byte_range {
  u8 l, h;
} byte_range;

byte_range mkbr(u8 l, u8 h) {
  byte_range out;
  out.l = l, out.h = h;
  return out;
}

u32 br2u(byte_range br) { return ((u32)br.l) | ((u32)br.h) << 8; }
byte_range u2br(u32 u) { return mkbr(u & 0xFF, u >> 8 & 0xFF); }

int br_isect(byte_range r, byte_range clip) {
  return r.l <= clip.h && clip.l <= r.h;
}

int br_adjace(byte_range left, byte_range right) {
  return ((u32)left.h) + 1 == ((u32)right.l);
}

#define BYTE_RANGE(l, h) mkbr(l, h)

u32 re_mkast_new(re *re, ast_type type, u32 nargs, u32 *args) {
  u32 root, i, v;
  assert(nargs || args == NULL);
  for (i = 0; i < nargs + 1; i++) {
    if (!(v = re_ast_new(re)))
      return v;
    if (!i)
      root = v, re->ast[root].v = type;
    else
      re->ast[v].v = args[i - 1];
  }
  return root;
}

void re_decompast(re *re, u32 root, u32 nargs, u32 *args) {
  u32 i;
  for (i = 0; i < nargs; i++) {
    args[i] = re->ast[root + i + 1].v;
  }
}

u32 *re_astarg(re *re, u32 root, u32 n, u32 nargs) {
  (void)(nargs);
  return &((re->ast + root + 1 + n)->v);
}

u32 *re_asttype(re *re, u32 root) { return &((re->ast + root)->v); }

void re_ast_dump(re *r, u32 root, u32 ilvl) {
  u32 i, first = r->ast[root].v, rest = r->ast[root + 1].v;
  printf("%04u ", root);
  for (i = 0; i < ilvl; i++)
    printf(" ");
  if (root == REF_NONE) {
    printf("<eps>\n");
  } else if (first == REG) {
    printf("REG\n");
    re_ast_dump(r, *re_astarg(r, root, 0, 1), ilvl + 1);
  } else if (first == CHR) {
    printf("CHR %02X\n", rest);
  } else if (first == CAT) {
    printf("CAT\n");
    re_ast_dump(r, *re_astarg(r, root, 0, 2), ilvl + 1);
    re_ast_dump(r, *re_astarg(r, root, 1, 2), ilvl + 1);
  } else if (first == ALT) {
    printf("ALT\n");
    re_ast_dump(r, *re_astarg(r, root, 0, 2), ilvl + 1);
    re_ast_dump(r, *re_astarg(r, root, 1, 2), ilvl + 1);
  } else if (first == GROUP) {
    printf("GRP flag=%u\n", *re_astarg(r, root, 1, 2));
    re_ast_dump(r, *re_astarg(r, root, 0, 2), ilvl + 1);
  } else if (first == QUANT) {
    printf("QNT min=%u max=%u\n", *re_astarg(r, root, 1, 3),
           *re_astarg(r, root, 2, 3));
    re_ast_dump(r, *re_astarg(r, root, 0, 3), ilvl + 1);
  } else if (first == CLS) {
    printf("CLS min=%02X max=%02X\n", *re_astarg(r, root, 0, 3),
           *re_astarg(r, root, 1, 3));
    re_ast_dump(r, *re_astarg(r, root, 2, 3), ilvl + 1);
  } else if (first == ICLS) {
    printf("ICLS min=%02X max=%02X\n", *re_astarg(r, root, 0, 3),
           *re_astarg(r, root, 1, 3));
    re_ast_dump(r, *re_astarg(r, root, 2, 3), ilvl + 1);
  }
}

int re_union(re *r, const char *regex) { /* add an ALT here */
  int err = 0;
  if (!r->ast_sets &&
      (err = re_parse(r, (const u8 *)regex, strlen(regex), &r->ast_root))) {
    return err;
  } else {
    u32 fork_args[2] = {0}, next_root;
    if ((err = re_parse(r, (const u8 *)regex, strlen(regex), fork_args + 1)))
      return ERR_MEM;
    fork_args[0] = r->ast_root;
    if (!(next_root = re_mkast_new(r, ALT, 2, fork_args)))
      return ERR_MEM;
    r->ast_root = next_root;
  }
  r->ast_sets++;
  return err;
}

#define UTF8_ACCEPT 0
#define UTF8_REJECT 1

static const uint8_t utf8d[] = {
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   1,   1,   1,   1,   1,   1,   1,
    1,   1,   1,   1,   1,   1,   1,   1,   1,   9,   9,   9,   9,   9,   9,
    9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   7,   7,   7,   7,   7,
    7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,
    7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   8,   8,   2,
    2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,
    2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   0xa,
    0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x4, 0x3, 0x3,
    0xb, 0x6, 0x6, 0x6, 0x5, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8,
    0x8, 0x0, 0x1, 0x2, 0x3, 0x5, 0x8, 0x7, 0x1, 0x1, 0x1, 0x4, 0x6, 0x1, 0x1,
    0x1, 0x1, 1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
    1,   1,   1,   1,   0,   1,   1,   1,   1,   1,   0,   1,   0,   1,   1,
    1,   1,   1,   1,   1,   2,   1,   1,   1,   1,   1,   2,   1,   2,   1,
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   2,   1,   1,
    1,   1,   1,   1,   1,   1,   1,   2,   1,   1,   1,   1,   1,   1,   1,
    2,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   3,
    1,   3,   1,   1,   1,   1,   1,   1,   1,   3,   1,   1,   1,   1,   1,
    3,   1,   3,   1,   1,   1,   1,   1,   1,   1,   3,   1,   1,   1,   1,
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
};

u32 utf8_decode(u32 *state, u32 *codep, u32 byte) {
  u32 type = utf8d[byte];
  *codep = (*state != UTF8_ACCEPT) ? (byte & 0x3fu) | (*codep << 6)
                                   : (0xff >> type) & (byte);

  *state = utf8d[256 + *state * 16 + type];
  return *state;
}

int re_next(const u8 **s, size_t *sz, u32 *first) {
  u32 state = UTF8_ACCEPT;
  assert(*sz && first);
  *first = 0;
  while (utf8_decode(&state, first, *((*s)++)), (*sz)--)
    if (!state)
      return 0;
  return state != UTF8_ACCEPT;
}

#define MAXREP 100000
#define INFTY (MAXREP + 1)

/* Given nodes R_1...R_N on the argument stack, fold them into a single CAT
 * node. If there are no nodes on the stack, create an epsilon node. */
int re_fold(re *r) {
  int err = 0;
  if (!r->arg_stk.size) {
    /* arg_stk: | */
    return stk_push(r, &r->arg_stk, REF_NONE);
    /* arg_stk: | eps |*/
  }
  while (r->arg_stk.size > 1) {
    /* arg_stk: | ... | R_N-1 | R_N | */
    u32 args[2], rest;
    args[1] = stk_pop(r, &r->arg_stk);
    args[0] = stk_pop(r, &r->arg_stk);
    rest = re_mkast_new(r, CAT, 2, args);
    if (!rest)
      return ERR_MEM;
    if ((err = stk_push(r, &r->arg_stk, rest)))
      return ERR_MEM;
    /* arg_stk: | ... | R_N-1R_N | */
  }
  /* arg_stk: | R1R2...Rn | */
  return 0;
}

/* Given a node R on the argument stack and an arbitrary number of ALT nodes at
 * the end of the operator stack, fold and finish each ALT node into a single
 * resulting ALT node on the argument stack. */
int re_fold_alts(re *r) {
  int err = 0;
  assert(r->arg_stk.size);
  /* arg_stk: |  R  | */
  /* op_stk:  | ... | */
  if (r->op_stk.size && *re_asttype(r, stk_peek(r, &r->op_stk, 0)) == ALT) {
    /* op_stk:  | ... |  A  | */
    /* finish the last alt */
    *re_astarg(r, stk_peek(r, &r->op_stk, 0), 1, 2) = stk_pop(r, &r->arg_stk);
    /* arg_stk: | */
    /* op_stk:  | ... | */
  }
  while (r->op_stk.size > 1 &&
         *re_asttype(r, stk_peek(r, &r->op_stk, 0)) == ALT &&
         *re_asttype(r, stk_peek(r, &r->op_stk, 1)) == ALT) {
    /* op_stk:  | ... | A_1 | A_2 | */
    u32 right = stk_pop(r, &r->op_stk), left = stk_pop(r, &r->op_stk);
    *re_astarg(r, left, 1, 2) = right;
    if ((err = stk_push(r, &r->op_stk, left)))
      return err;
    /* op_stk:  | ... | A_1(|A_2) | */
  }
  if (r->op_stk.size &&
      *re_asttype(r, r->op_stk.ptr[r->op_stk.size - 1]) == ALT) {
    /* op_stk:  | ... |  A  | */
    if ((err = stk_push(r, &r->arg_stk, stk_pop(r, &r->op_stk))))
      return err;
    /* arg_stk: |  A  | */
    /* op_stk:  | ... | */
  }
  return 0;
}

u32 re_mkcc(re *r, u32 rest, u32 min, u32 max) {
  u32 args[3];
  args[0] = min, args[1] = max, args[2] = rest;
  return re_mkast_new(r, CLS, 3, args);
}

u32 re_uncc(re *r, u32 rest, u32 first) {
  u32 cur = first, *next;
  assert(first);
  while (*(next = re_astarg(r, cur, 2, 3)))
    cur = *next;
  *next = rest;
  return first;
}

int re_parse_escape_addchr(re *r, u32 ch, u32 allowed_outputs) {
  int err = 0;
  u32 res, args[1];
  assert(allowed_outputs & (1 << CHR));
  args[0] = ch;
  if ((!(res = re_mkast_new(r, CHR, 1, args)) && (err = ERR_MEM)) ||
      (err = stk_push(r, &r->arg_stk, res)))
    return err;
  return 0;
}

int re_hexdig(u32 ch) {
  if (ch >= '0' && ch <= '9')
    return ch - '0';
  else if (ch >= 'a' && ch <= 'f')
    return ch - 'a' + 10;
  else if (ch >= 'A' && ch <= 'F')
    return ch - 'A' + 10;
  else
    return -1;
}

typedef struct ccdef {
  u8 name_len, cc_len;
  const char *name;
  const char *chars;
} ccdef;

const ccdef builtin_cc[] = {{5, 3, "alnum", "\x30\x39\x41\x5A\x61\x7A"},
                            {5, 2, "alpha", "\x41\x5A\x61\x7A"},
                            {5, 1, "ascii", "\x00\x7F"},
                            {5, 2, "blank", "\x09\x09\x20\x20"},
                            {5, 2, "cntrl", "\x00\x1F\x7F\x7F"},
                            {5, 1, "digit", "\x30\x39"},
                            {5, 1, "graph", "\x21\x7E"},
                            {5, 1, "lower", "\x61\x7A"},
                            {5, 1, "print", "\x20\x7E"},
                            {5, 4, "punct", "\x21\x2F\x3A\x40\x5B\x60\x7B\x7E"},
                            {5, 2, "space", "\x09\x0D\x20\x20"},
                            {10, 3, "perl_space", "\x09\x0A\x0C\x0D\x20\x20"},
                            {5, 1, "upper", "\x41\x5A"},
                            {4, 3, "word", "\x30\x39\x41\x5A\x61\x7A"},
                            {6, 3, "xdigit", "\x30\x39\x41\x46\x61\x66"},
                            {0}};

const ccdef *re_parse_namedcc(const u8 *s, size_t sz) {
  const ccdef *p = builtin_cc;
  while (p->name_len) {
    if ((size_t)p->name_len == sz && !memcmp(s, (const u8 *)p->name, sz))
      return p;
    p++;
  }
  return NULL;
}

int re_parse_add_namedcc(re *r, const u8 *s, size_t sz, int invert) {
  int err = 0;
  const ccdef *named = re_parse_namedcc(s, sz);
  u32 res = REF_NONE, i, max = 0, cur_min, cur_max;
  if (!named)
    return ERR_PARSE;
  for (i = 0; i < named->cc_len; i++) {
    cur_min = named->chars[i * 2], cur_max = named->chars[i * 2 + 1];
    if (!invert && !(res = re_mkcc(r, res, cur_min, cur_max)))
      return ERR_MEM;
    else if (invert && cur_min > max) {
      if (!(res = re_mkcc(r, res, max, cur_min - 1)))
        return ERR_MEM;
      else
        max = cur_max + 1;
    }
  }
  if (invert && i && cur_max < UTFMAX &&
      !(res = re_mkcc(r, res, cur_max + 1, UTFMAX)))
    return ERR_MEM;
  if ((err = stk_push(r, &r->arg_stk, res)))
    return err;
  return 0;
}

/* after a \ */
int re_parse_escape(re *r, const u8 **s, size_t *sz, u32 allowed_outputs) {
  u32 ch, args[3] = {0};
  size_t prev_sz;
  const u8 *prev_s;
  int err = 0;
  if (!*sz)
    return ERR_PARSE;
  if (re_next(s, sz, &ch))
    return ERR_PARSE;
  if (                              /* single character escapes */
      (ch == 'a' && (ch = '\a')) || /* bell */
      (ch == 'f' && (ch = '\f')) || /* form feed */
      (ch == 't' && (ch = '\t')) || /* tab */
      (ch == 'n' && (ch = '\n')) || /* newline */
      (ch == 'r' && (ch = '\r')) || /* carriage return */
      (ch == 'v' && (ch = '\v')) || /* vertical tab */
      (ch == '?') ||                /* question mark */
      (ch == '*') ||                /* asterisk */
      (ch == '+') ||                /* plus */
      (ch == '(') ||                /* open parenthesis */
      (ch == ')') ||                /* close parenthesis */
      (ch == '[') ||                /* open bracket */
      (ch == ']') ||                /* close bracket */
      (ch == '{') ||                /* open curly bracket */
      (ch == '}') ||                /* close curly bracket */
      (ch == '|') ||                /* pipe */
      (ch == '\\') /* escaped slash */) {
    return re_parse_escape_addchr(r, ch, allowed_outputs);
  } else if (ch >= '0' && ch <= '7') { /* octal escape */
    int digs = 1;
    u32 ord = ch - '0';
    while (digs++ < 3 && *sz && (prev_sz = *sz) && (prev_s = *s) &&
           !(err = re_next(s, sz, &ch)) && ch >= '0' && ch <= '7')
      ord = ord * 8 + ch - '0';
    if (err)
      return ERR_PARSE;                 /* malformed */
    else if (!(ch >= '0' && ch <= '7')) /* over-read */
      *sz = prev_sz, *s = prev_s;       /* backtrack */
    return re_parse_escape_addchr(r, ord, allowed_outputs);
  } else if (ch == 'x') { /* hex escape */
    u32 ord = 0;
    if (!*sz)
      return ERR_PARSE; /* expected two hex characters or a bracketed hex lit */
    else if ((err = re_next(s, sz, &ch)))
      return ERR_PARSE; /* malformed */
    if (ch == '{') {    /* bracketed hex lit */
      u32 i;
      for (i = 0; i < 8; i++) {
        if (i == 7 || !*sz)
          return ERR_PARSE; /* expected up to six hex characters */
        else if ((err = re_next(s, sz, &ch)))
          return ERR_PARSE; /* malformed */
        if (ch == '}')
          break;
        if ((err = re_hexdig(ch)) == -1)
          return ERR_PARSE; /* invalid hex digit */
        ord = ord * 16 + err;
      }
      if (!i)
        return ERR_PARSE; /* expected at least one hex character */
    } else if ((err = re_hexdig(ch)) == -1) {
      return ERR_PARSE; /* invalid hex digit */
    } else {
      ord = err;
      if (!*sz)
        return ERR_PARSE; /* expected two hex characters */
      else if ((err = re_next(s, sz, &ch)))
        return ERR_PARSE; /* malformed */
      else if ((err = re_hexdig(ch)) == -1)
        return ERR_PARSE; /* invalid hex digit */
      ord = ord * 16 + err;
    }
    if (ord > UTFMAX)
      return ERR_PARSE; /* ordinal out of range [0, 0x10FFFF] */
    return re_parse_escape_addchr(r, ord, allowed_outputs);
  } else if (ch == 'C') { /* any byte: \C */
    u32 res;
    if (!(allowed_outputs & (1 << ANYBYTE)))
      return ERR_PARSE; /* cannot use \C here */
    if (!(res = re_mkast_new(r, ANYBYTE, 0, NULL)) ||
        (err = stk_push(r, &r->arg_stk, res)))
      return err;
  } else if (ch == 'Q') { /* quote string */
    u32 cat = REF_NONE, chr = REF_NONE;
    if (!(allowed_outputs & (1 << CAT)))
      return ERR_PARSE; /* cannot use \Q...\E here */
    while (*sz) {
      if ((err = re_next(s, sz, &ch)))
        return err; /* malformed */
      if (ch == '\\' && *sz) {
        prev_s = *s, prev_sz = *sz;
        if ((err = re_next(s, sz, &ch)))
          return err; /* malformed */
        if (ch == 'E')
          return stk_push(r, &r->arg_stk, cat);
        else if (ch != '\\')
          /* backtrack */
          *s = prev_s, *sz = prev_sz, ch = '\\';
      }
      args[0] = ch;
      if (!(chr = re_mkast_new(r, CHR, 1, args)))
        return ERR_MEM;
      args[0] = cat, args[1] = chr;
      if (!(cat = re_mkast_new(r, CAT, 2, args)))
        return ERR_MEM;
    }
    if ((err = stk_push(r, &r->arg_stk, cat)))
      return err;
  } else if (ch == 'D' || ch == 'd' || ch == 'S' || ch == 's' || ch == 'W' ||
             ch == 'w') {
    /* Perl builtin character classes */
    const char *cc_name;
    int inverted = ch >= 'A' && ch <= 'Z'; /* uppercase are inverted */
    ch = inverted ? ch - 'A' + 'a' : ch;   /* convert to lowercase */
    cc_name = ch == 'd' ? "digit" : ch == 's' ? "perl_space" : "word";
    if (!(allowed_outputs & (1 << CLS)))
      return ERR_PARSE; /* character classes disallowed here */
    if ((err = re_parse_add_namedcc(r, (const u8 *)cc_name, strlen(cc_name),
                                    inverted)))
      return err;
  } else {
    return ERR_PARSE; /* invalid escape */
  }
  return 0;
}

int re_parse(re *r, const u8 *s, size_t sz, u32 *root) {
  int err;
  while (sz) {
    u32 ch;
    u32 args[3] = {REF_NONE}, res = REF_NONE;
    if (re_next(&s, &sz, &ch))
      return ERR_PARSE; /* invalid */
    if (ch == '*' || ch == '+' || ch == '?') {
      /* arg_stk: | ... |  R  | */
      /* pop one from arg stk, create quant, push to arg stk */
      if (!r->arg_stk.size)
        return ERR_PARSE; /* not enough values on the stk */
      args[0] = stk_pop(r, &r->arg_stk);
      args[1] = ch == '+', args[2] = (ch == '?' ? 1 : INFTY);
      if (!(res = re_mkast_new(r, QUANT, 3, args)))
        return ERR_MEM;
      if ((err = stk_push(r, &r->arg_stk, res)))
        return err;
      /* arg_stk: | ... | *(R) | */
    } else if (ch == '|') {
      /* fold the arg stk into a concat, create alt, push it to the arg stk */
      /* op_stk:  | ... | */
      /* arg_stk: | R_1 | R_2 | ... | R_N | */
      if (re_fold(r))
        return ERR_MEM;
      /* arg_stk: |  R  | */
      args[0] = stk_pop(r, &r->arg_stk);
      args[1] = REF_NONE;
      if (!(res = re_mkast_new(r, ALT, 2, args)))
        return ERR_MEM;
      if ((err = stk_push(r, &r->op_stk, res)))
        return err;
      /* arg_stk: | */
      /* op_stk:  | ... | R(|) | */
    } else if (ch == '(') {
      /* op_stk:  | ... | */
      if ((!(res = re_mkast_new(r, GROUP, 2, args)) && (err = ERR_MEM)) ||
          (err = stk_push(r, &r->op_stk, res)))
        return err;
      /* op_stk:  | ... | () | */
    } else if (ch == ')') {
      /* arg_stk: | R_1 | R_2 | ... | R_N | */
      /* op_stk:  | ... |  () | ... | */
      /* fold the arg stk into a concat, fold remaining alts, create group,
       * push it to the arg stk */
      if (re_fold(r) || re_fold_alts(r))
        return ERR_MEM;
      /* arg_stk has either 0 or 1 value */
      if (!r->op_stk.size)
        return ERR_PARSE;
      /* arg_stk: |  R  | */
      /* op_stk:  | ... |  () | */
      /* add it to the group */
      *(re_astarg(r, stk_peek(r, &r->op_stk, 0), 0, 2)) =
          stk_pop(r, &r->arg_stk);
      /* pop the group frame into arg_stk */
      if ((err = stk_push(r, &r->arg_stk, stk_pop(r, &r->op_stk))))
        return err;
      /* arg_stk: | (R) | */
      /* op_stk:  | ... | */
    } else if (ch == '.') { /* any char */
      /* arg_stk: | ... | */
      if ((!(res = re_mkcc(r, 0, 0, UTFMAX)) && (err = ERR_MEM)) ||
          (err = stk_push(r, &r->arg_stk, res)))
        return err;
      /* arg_stk: | ... |  .  | */
    } else if (ch == '[') { /* charclass */
      size_t start = sz;
      u32 inverted = 0, min, max;
      res = REF_NONE;
      while (1) {
        u32 next;
        if (!sz)
          return ERR_PARSE; /* unclosed charclass */
        if (re_next(&s, &sz, &ch))
          return ERR_PARSE; /* malformed */
        if ((start - sz == 1) && ch == '^') {
          inverted = 1; /* caret at start of CC */
          continue;
        }
        min = ch;
        if (ch == ']') {
          if ((start - sz == 1 || (start - sz == 2 && inverted))) {
            min = ch; /* charclass starts with ] */
          } else
            break;               /* charclass done */
        } else if (ch == '\\') { /* escape */
          if ((err = re_parse_escape(r, &s, &sz, (1 << CHR) | (1 << CLS))))
            return err;
          if (!(next = stk_pop(r, &r->arg_stk)))
            return ERR_MEM;
          assert(*re_asttype(r, next) == CHR || *re_asttype(r, next == CLS));
          if (*re_asttype(r, next) == CHR)
            min = *re_astarg(r, next, 0, 1); /* single-character escape */
          else if (*re_asttype(r, next) == CLS) {
            if (!(res = re_uncc(r, res, next)))
              return ERR_MEM;
            /* we parsed an entire class, so there's no ending character */
            continue;
          }
        } else if (ch == '[' && sz > 0 && s[0] == ':') { /* named class */
          int named_inverted = 0;
          size_t name_start, name_end;
          if (re_next(&s, &sz, &ch)) /* : */
            assert(0);
          if (sz && s[0] == '^') {     /* inverted named class */
            if (re_next(&s, &sz, &ch)) /* ^ */
              assert(0);
            named_inverted = 1;
          }
          name_start = name_end = sz;
          while (1) {
            if (!sz)
              return ERR_PARSE; /* expected character class name */
            if (re_next(&s, &sz, &ch))
              return ERR_PARSE; /* malformed */
            if (ch == ':')
              break;
            name_end = sz;
          }
          if (!sz)
            return ERR_PARSE; /* expected closing bracket for named character
                                 class */
          if (re_next(&s, &sz, &ch))
            return ERR_PARSE; /* malformed */
          if (ch != ']')
            return ERR_PARSE; /* expected closing bracket for named character
                                 class */
          if ((err = re_parse_add_namedcc(r, s - (name_start - sz),
                                          (name_start - name_end),
                                          named_inverted)))
            return err;
          next = stk_pop(r, &r->arg_stk);
          assert(next && *re_asttype(r, next) == CLS);
          if (!(res = re_uncc(r, res, next)))
            return ERR_MEM;
          continue;
        }
        max = min;
        if (sz > 1 && s[0] == '-') {
          /* range expression */
          if (re_next(&s, &sz, &ch))
            assert(0); /* - */
          if (re_next(&s, &sz, &ch))
            return ERR_PARSE; /* malformed */
          if (ch == '\\') {   /* start of escape */
            if ((err = re_parse_escape(r, &s, &sz, (1 << CHR))))
              return err;
            if (!(next = stk_pop(r, &r->arg_stk)))
              return ERR_MEM;
            assert(*re_asttype(r, next) == CHR);
            max = *re_astarg(r, next, 0, 1);
          } else {
            max = ch; /* non-escaped character */
          }
        }
        if (!(res = re_mkcc(r, res, min, max)))
          return ERR_MEM;
      }
      assert(res);  /* charclass cannot be empty */
      if (inverted) /* inverted character class */
        *re_asttype(r, res) = ICLS;
      if ((err = stk_push(r, &r->arg_stk, res)))
        return err;
    } else if (ch == '\\') { /* escape */
      if ((err = re_parse_escape(
               r, &s, &sz, 1 << CHR | 1 << CLS | 1 << ANYBYTE | 1 << CAT)))
        return err;
    } else { /* char: push to the arg stk */
             /* arg_stk: | ... | */
      args[0] = ch;
      if ((!(res = re_mkast_new(r, CHR, 1, args)) && (err = ERR_MEM)) ||
          (err = stk_push(r, &r->arg_stk, res)))
        return err;
      /* arg_stk: | ... | chr | */
    }
  }
  if (re_fold(r) || re_fold_alts(r))
    return ERR_MEM;
  if (r->op_stk.size)
    return ERR_PARSE;
  {
    u32 arg = stk_pop(r, &r->arg_stk);
    if (!(*root = re_mkast_new(r, REG, 1, &arg)))
      return ERR_MEM;
  }
  return 0;
}

typedef struct inst {
  u32 l, h;
} inst;

#define INST_OP(i) ((i).l & 3)
#define INST_N(i) ((i).l >> 2)
#define INST_P(i) ((i).h)
#define INST(op, n, p) mkinst((op) | ((n) << 2), (p))

inst mkinst(u32 l, u32 h) {
  inst out;
  out.l = l, out.h = h;
  return out;
}

void re_prog_set(re *r, u32 pc, inst i) {
  r->prog.ptr[pc * 2 + 0] = i.l;
  r->prog.ptr[pc * 2 + 1] = i.h;
}

inst re_prog_get(re *r, u32 pc) {
  inst i;
  i.l = r->prog.ptr[pc * 2 + 0];
  i.h = r->prog.ptr[pc * 2 + 1];
  return i;
}

u32 re_prog_size(re *r) { return r->prog.size >> 1; }

int re_emit(re *r, inst i) {
  int err = 0;
  if ((err = stk_push(r, &r->prog, 0)) || (err = stk_push(r, &r->prog, 0)))
    return err;
  re_prog_set(r, re_prog_size(r) - 1, i);
  return 0;
}

typedef struct compframe {
  u32 root_ref, child_ref, idx, patch_head, patch_tail, pc;
} compframe;

int compframe_push(re *r, compframe c) {
  int err = 0;
  if ((err = stk_push(r, &r->comp_stk, c.root_ref)) ||
      (err = stk_push(r, &r->comp_stk, c.child_ref)) ||
      (err = stk_push(r, &r->comp_stk, c.idx)) ||
      (err = stk_push(r, &r->comp_stk, c.patch_head)) ||
      (err = stk_push(r, &r->comp_stk, c.patch_tail)) ||
      (err = stk_push(r, &r->comp_stk, c.pc)))
    return err;
  return err;
}

compframe compframe_pop(re *r) {
  compframe out;
  out.pc = stk_pop(r, &r->comp_stk);
  out.patch_tail = stk_pop(r, &r->comp_stk);
  out.patch_head = stk_pop(r, &r->comp_stk);
  out.idx = stk_pop(r, &r->comp_stk);
  out.child_ref = stk_pop(r, &r->comp_stk);
  out.root_ref = stk_pop(r, &r->comp_stk);
  return out;
}

enum op { RANGE, ASSERT, MATCH, SPLIT };

enum asserts { A_EVERYTHING = 0xFF };

#define IMATCH(s, i) ((i) << 1 | (s))
#define IMATCH_S(m) ((m) & 1)
#define IMATCH_I(m) ((m) >> 1)

void re_prog_dump(re *r) {
  u32 i, j, k;
  for (i = 0; i < re_prog_size(r); i++) {
    inst ins = re_prog_get(r, i);
    static const char *ops[] = {"RANGE", "ASSRT", "MATCH", "SPLIT"};
    static const int colors[] = {91, 92, 93, 94};
    static const char *labels[] = {"F  ", "R  ", "F.*", "R.*", "   ", "+  "};
    k = 4;
    for (j = 0; j < 4; j++) {
      if (i == r->entry[j]) {
        k = k == 4 ? j : 5;
      }
    }
    printf("%04X \x1b[%im%s\x1b[0m %04X %04X %s", i, colors[INST_OP(ins)],
           ops[INST_OP(ins)], INST_N(ins), INST_P(ins), labels[k]);
    if (INST_OP(ins) == MATCH) {
      printf(" %c/%u", IMATCH_S(INST_P(ins)) ? 'G' : 'E',
             IMATCH_I(INST_P(ins)));
    }
    printf("\n");
  }
}

inst patch_set(re *r, u32 pc, u32 val) {
  inst prev = re_prog_get(r, pc >> 1);
  assert(pc);
  re_prog_set(r, pc >> 1,
              INST(INST_OP(prev), pc & 1 ? INST_N(prev) : val,
                   pc & 1 ? val : INST_P(prev)));
  return prev;
}

void patch_add(re *r, compframe *f, u32 dest_pc, int p) {
  u32 out_val = dest_pc << 1 | !!p;
  assert(dest_pc);
  if (!f->patch_head)
    f->patch_head = f->patch_tail = out_val;
  else {
    patch_set(r, f->patch_tail, out_val);
    f->patch_tail = out_val;
  }
}

void patch_merge(re *r, compframe *p, compframe *q) {
  if (!p->patch_head) {
    p->patch_head = q->patch_head;
    p->patch_tail = q->patch_tail;
    return;
  }
  patch_set(r, p->patch_tail, q->patch_head);
  p->patch_tail = q->patch_tail;
}

void patch_xfer(compframe *dst, compframe *src) {
  dst->patch_head = src->patch_head;
  dst->patch_tail = src->patch_tail;
  src->patch_head = src->patch_tail = REF_NONE;
}

void patch(re *r, compframe *p, u32 dest_pc) {
  u32 i = p->patch_head;
  while (i) {
    inst prev = patch_set(r, i, dest_pc);
    i = i & 1 ? INST_P(prev) : INST_N(prev);
  }
  p->patch_head = p->patch_tail = REF_NONE;
}

size_t i_lc(size_t i) { return 2 * i + 1; }

size_t i_rc(size_t i) { return 2 * i + 2; }

u32 cckey(stk *cc, size_t idx) { return cc->ptr[idx * 2]; }

int ccpush(re *r, stk *cc, u32 min, u32 max) {
  int err = 0;
  (err = stk_push(r, cc, min)) || (err = stk_push(r, cc, max));
  return err;
}

void ccget(stk *cc, size_t idx, u32 *min, u32 *max) {
  *min = cc->ptr[idx * 2], *max = cc->ptr[idx * 2 + 1];
}

void ccswap(stk *cc, size_t a, size_t b) {
  size_t t0 = cc->ptr[a * 2], t1 = cc->ptr[a * 2 + 1];
  cc->ptr[a * 2] = cc->ptr[b * 2];
  cc->ptr[a * 2 + 1] = cc->ptr[b * 2 + 1];
  cc->ptr[b * 2] = t0;
  cc->ptr[b * 2 + 1] = t1;
}

size_t ccsize(stk *cc) { return cc->size >> 1; }

void re_compcc_hsort(stk *cc, size_t n) {
  size_t start = n >> 1, end = n, root, child;
  while (end > 1) {
    if (start)
      start--;
    else {
      end--;
      ccswap(cc, end, 0);
    }
    root = start;
    while ((child = i_lc(root)) < end) {
      if (child + 1 < end && cckey(cc, child) < cckey(cc, child + 1))
        child--;
      if (cckey(cc, root) < cckey(cc, child)) {
        ccswap(cc, root, child);
        root = child;
      } else
        break;
    }
  }
}
typedef struct compcc_node {
  u32 range, child_ref, sibling_ref, hash;
} compcc_node;

void cc_treeget(stk *cc, u32 ref, compcc_node *out) {
  assert(ref < cc->size / 4);
  out->range = cc->ptr[ref * 4], out->child_ref = cc->ptr[ref * 4 + 1],
  out->sibling_ref = cc->ptr[ref * 4 + 2], out->hash = cc->ptr[ref * 4 + 3];
}

void cc_treeset(stk *cc, u32 ref, compcc_node in) {
  assert(ref < cc->size / 4);
  cc->ptr[ref * 4] = in.range, cc->ptr[ref * 4 + 1] = in.child_ref,
                cc->ptr[ref * 4 + 2] = in.sibling_ref,
                cc->ptr[ref * 4 + 3] = in.hash;
}

u32 cc_treesize(stk *cc) { return cc->size / 4; }

u32 cc_treenew(re *r, stk *cc_out, compcc_node node) {
  u32 out;
  int err = 0;
  if (!cc_out->size) {
    /* need to create sentinel node */
    if ((err = stk_push(r, cc_out, 0)) || (err = stk_push(r, cc_out, 0)) ||
        (err = stk_push(r, cc_out, 0)) || (err = stk_push(r, cc_out, 0)))
      return 0;
  }
  out = cc_out->size / 4;
  if ((err = stk_push(r, cc_out, node.range)) ||
      (err = stk_push(r, cc_out, node.child_ref)) ||
      (err = stk_push(r, cc_out, node.sibling_ref)) ||
      (err = stk_push(r, cc_out, node.hash)))
    return 0;
  return out;
}

u32 cc_treeappend(re *r, stk *cc, u32 range, u32 parent) {
  compcc_node parent_node, child_node = {0};
  cc_treeget(cc, parent, &parent_node);
  child_node.sibling_ref = parent_node.child_ref, child_node.range = range;
  parent_node.child_ref = cc_treenew(r, cc, child_node);
  if (!parent_node.child_ref)
    return 0;
  assert(parent_node.child_ref != parent);
  assert(parent_node.sibling_ref != parent);
  assert(child_node.child_ref != parent_node.child_ref);
  assert(child_node.sibling_ref != parent_node.child_ref);
  cc_treeset(cc, parent, parent_node);
  return parent_node.child_ref;
}

int re_compcc_buildtree_split(re *r, stk *cc_out, u32 parent, u32 min, u32 max,
                              u32 x_bits, u32 y_bits) {
  u32 x_mask = (1 << x_bits) - 1, y_min = min >> x_bits, y_max = max >> x_bits,
      u_mask = (0xFE << y_bits) & 0xFF, byte_min = (y_min & 0xFF) | u_mask,
      byte_max = (y_max & 0xFF) | u_mask, i;
  int err = 0;
  assert(y_bits <= 7);
  if (x_bits == 0) {
    if (!cc_treeappend(r, cc_out, br2u(mkbr(byte_min, byte_max)), parent))
      return ERR_MEM;
  } else {
    /* nonterminal */
    u32 x_min = min & x_mask, x_max = max & x_mask, brs[3], mins[3], maxs[3], n;
    if (y_min == y_max || (x_min == 0 && x_max == x_mask)) {
      /* Range can be split into either a single byte followed by a range,
       * _or_ one range followed by another maximal range */
      /* Output:
       * ---[Ymin-Ymax]---{tree for [Xmin-Xmax]} */
      brs[0] = br2u(mkbr(byte_min, byte_max));
      mins[0] = x_min, maxs[0] = x_max;
      n = 1;
    } else if (!x_min) {
      /* Range begins on zero, but has multiple starting bytes */
      /* Output:
       * ---[Ymin-(Ymax-1)]---{tree for [00-FF]}
       *           |
       *      [Ymax-Ymax]----{tree for [00-Xmax]} */
      brs[0] = br2u(mkbr(byte_min, byte_max - 1));
      mins[0] = 0, maxs[0] = x_mask;
      brs[1] = br2u(mkbr(byte_max, byte_max));
      mins[1] = 0, maxs[1] = x_max;
      n = 2;
    } else if (x_max == x_mask) {
      /* Range ends on all ones, but has multiple starting bytes */
      /* Output:
       * -----[Ymin-Ymin]----{tree for [Xmin-FF]}
       *           |
       *    [(Ymin+1)-Ymax]---{tree for [00-FF]} */
      brs[0] = br2u(mkbr(byte_min, byte_min));
      mins[0] = x_min, maxs[0] = x_mask;
      brs[1] = br2u(mkbr(byte_min + 1, byte_max));
      mins[1] = 0, maxs[1] = x_mask;
      n = 2;
    } else if (y_min == y_max - 1) {
      /* Range occupies exactly two starting bytes */
      /* Output:
       * -----[Ymin-Ymin]----{tree for [Xmin-FF]}
       *           |
       *      [Ymax-Ymax]----{tree for [00-Xmax]} */
      brs[0] = br2u(mkbr(byte_min, byte_min));
      mins[0] = x_min, maxs[0] = x_mask;
      brs[1] = br2u(mkbr(byte_min + 1, byte_max));
      mins[1] = 0, maxs[1] = x_max;
      n = 2;
    } else {
      /* Range doesn't begin on all zeroes or all ones, and takes up more
       * than 2 different starting bytes */
      /* Output:
       * -------[Ymin-Ymin]-------{tree for [Xmin-FF]}
       *             |
       *    [(Ymin+1)-(Ymax-1)]----{tree for [00-FF]}
       *             |
       *        [Ymax-Ymax]-------{tree for [00-Xmax]} */
      brs[0] = br2u(mkbr(byte_min, byte_min));
      mins[0] = x_min, maxs[0] = x_mask;
      brs[1] = br2u(mkbr(byte_min + 1, byte_max - 1));
      mins[1] = 0, maxs[1] = x_mask;
      brs[2] = br2u(mkbr(byte_max, byte_max));
      mins[2] = 0, maxs[2] = x_max;
      n = 3;
    }
    for (i = 0; i < n; i++) {
      compcc_node parent_node, sibling_node;
      u32 child_ref;
      /* check if previous child intersects and then compute intersection */
      assert(parent);
      cc_treeget(cc_out, parent, &parent_node);
      if (parent_node.sibling_ref &&
          (cc_treeget(cc_out, parent_node.sibling_ref, &sibling_node),
           br_isect(u2br(sibling_node.range), u2br(brs[i])))) {
        child_ref = parent_node.sibling_ref;
      } else {
        if (!(child_ref = cc_treeappend(r, cc_out, brs[i], parent)))
          return ERR_MEM;
      }
      if ((err = re_compcc_buildtree_split(r, cc_out, child_ref, mins[i],
                                           maxs[i], x_bits - 6, 6)))
        return err;
    }
  }
  return err;
}

/* format:
 * 0 byte range
 * 1 child
 * 2 sibling
 * 3 hash of this node and its descendants */
int re_compcc_buildtree(re *r, stk *cc_in, stk *cc_out) {
  size_t i, j;
  u32 root_ref;
  compcc_node root_node;
  int err = 0;
  root_node.child_ref = root_node.sibling_ref = root_node.hash =
      root_node.range = 0;
  /* clear output charclass */
  cc_out->size = 0;
  if (!(root_ref = cc_treenew(r, cc_out, root_node)))
    return err;
  for (i = 0; i < ccsize(cc_in); i++) {
    u32 min, max, min_bound = 0, max_bound;
    static const u32 y_bits[4] = {7, 5, 4, 3};
    static const u32 x_bits[4] = {0, 6, 12, 18};
    ccget(cc_in, i, &min, &max);
    for (j = 0; j < 4; j++) {
      max_bound = (1 << (x_bits[j] + y_bits[j])) - 1;
      if (min_bound <= max && min <= max_bound) {
        /* [min,max] intersects [min_bound,max_bound] */
        u32 clamped_min = min < min_bound ? min_bound : min, /* clamp range */
            clamped_max = max > max_bound ? max_bound : max;
        if ((err =
                 re_compcc_buildtree_split(r, cc_out, root_ref, clamped_min,
                                           clamped_max, x_bits[j], y_bits[j])))
          return err;
      }
      min_bound = max_bound + 1;
    }
  }
  return err;
}

void re_compcc_dumptree(stk *cc_tree, u32 ref, u32 lvl) {
  u32 i;
  compcc_node node;
  cc_treeget(cc_tree, ref, &node);
  printf("%04X [%08X] ", ref, node.hash);
  for (i = 0; i < lvl; i++)
    printf("  ");
  printf("%02X-%02X\n", u2br(node.range).l, u2br(node.range).h);
  if (node.child_ref)
    re_compcc_dumptree(cc_tree, node.child_ref, lvl + 1);
  if (node.sibling_ref)
    re_compcc_dumptree(cc_tree, node.sibling_ref, lvl);
}

int re_compcc_treeeq(re *r, stk *cc_tree_in, compcc_node *a, compcc_node *b) {
  u32 a_child_ref = a->child_ref, b_child_ref = b->child_ref;
  while (a_child_ref && b_child_ref) {
    compcc_node a_child, b_child;
    cc_treeget(cc_tree_in, a_child_ref, &a_child);
    cc_treeget(cc_tree_in, b_child_ref, &b_child);
    if (!re_compcc_treeeq(r, cc_tree_in, &a_child, &b_child))
      return 0;
    a_child_ref = a_child.sibling_ref, b_child_ref = b_child.sibling_ref;
  }
  if (a_child_ref != b_child_ref)
    return 0;
  return a->range == b->range;
}

void re_compcc_merge_one(stk *cc_tree_in, u32 child_ref, u32 sibling_ref) {
  compcc_node child, sibling;
  cc_treeget(cc_tree_in, child_ref, &child);
  cc_treeget(cc_tree_in, sibling_ref, &sibling);
  child.sibling_ref = sibling.sibling_ref;
  assert(br_adjace(u2br(child.range), u2br(sibling.range)));
  child.range = br2u(mkbr(u2br(child.range).l, u2br(sibling.range).h));
  cc_treeset(cc_tree_in, child_ref, child);
}

/*https://nullprogram.com/blog/2018/07/31/*/
u32 hashington(u32 x) {
  x ^= x >> 16;
  x *= 0x7feb352dU;
  x ^= x >> 15;
  x *= 0x846ca68bU;
  x ^= x >> 16;
  return x;
}

/* hash table */
/* pairs of <key, loc> */

u32 cc_htsize(stk *cc_ht) { return cc_ht->size / 2; }

int cc_htinit(re *r, stk *cc_tree_in, stk *cc_ht_out) {
  int err = 0;
  while (cc_htsize(cc_ht_out) <
         (cc_treesize(cc_tree_in) + (cc_treesize(cc_tree_in) >> 1)))
    if ((err = stk_push(r, cc_ht_out, 0)) || (err = stk_push(r, cc_ht_out, 0)))
      return err;
  memset(cc_ht_out->ptr, 0, cc_ht_out->size * sizeof(u32));
  return 0;
}

void re_compcc_hashtree(re *r, stk *cc_tree_in, stk *cc_ht_out,
                        u32 parent_ref) {
  /* flip links and hash everything */
  compcc_node parent_node;
  u32 child_ref, next_child_ref, sibling_ref = 0;
  cc_treeget(cc_tree_in, parent_ref, &parent_node);
  child_ref = parent_node.child_ref;
  while (child_ref) {
    compcc_node child_node, sibling_node;
    cc_treeget(cc_tree_in, child_ref, &child_node);
    next_child_ref = child_node.sibling_ref;
    child_node.sibling_ref = sibling_ref;
    cc_treeset(cc_tree_in, child_ref, child_node);
    re_compcc_hashtree(r, cc_tree_in, cc_ht_out, child_ref);
    if (sibling_ref) {
      cc_treeget(cc_tree_in, sibling_ref, &sibling_node);
      if (br_adjace(u2br(child_node.range), u2br(sibling_node.range))) {
        if (!sibling_node.child_ref) {
          if (!child_node.child_ref) {
            re_compcc_merge_one(cc_tree_in, child_ref, sibling_ref);
          }
        } else {
          if (child_node.child_ref) {
            compcc_node child_child, sibling_child;
            cc_treeget(cc_tree_in, child_node.child_ref, &child_child);
            cc_treeget(cc_tree_in, sibling_node.child_ref, &sibling_child);
            if (re_compcc_treeeq(r, cc_tree_in, &child_child, &sibling_child)) {
              re_compcc_merge_one(cc_tree_in, child_ref, sibling_ref);
            }
          }
        }
      }
    }
    {
      u32 hash_plain[3] = {0x6D99232E, 0xC281FF0B, 0x54978D96};
      memset(hash_plain, 0, sizeof(hash_plain));
      hash_plain[0] ^= child_node.range;
      if (child_node.sibling_ref) {
        compcc_node child_sibling_node;
        cc_treeget(cc_tree_in, child_node.sibling_ref, &child_sibling_node);
        hash_plain[1] = child_sibling_node.hash;
      }
      if (child_node.child_ref) {
        compcc_node child_child_node;
        cc_treeget(cc_tree_in, child_node.child_ref, &child_child_node);
        hash_plain[2] = child_child_node.hash;
      }
      child_node.hash =
          hashington(hashington(hashington(hash_plain[0]) + hash_plain[1]) +
                     hash_plain[2]);
      cc_treeset(cc_tree_in, child_ref, child_node);
    }
    sibling_ref = child_ref;
    sibling_node = child_node;
    child_ref = next_child_ref;
  }
  parent_node.child_ref = sibling_ref;
  cc_treeset(cc_tree_in, parent_ref, parent_node);
}

int re_compcc_rendertree(re *r, stk *cc_tree_in, stk *cc_ht, u32 node_ref,
                         u32 *my_out_pc, compframe *frame) {
  int err = 0;
  u32 split_from = 0, my_pc = 0, range_pc = 0;
  while (node_ref) {
    compcc_node node;
    u32 probe, found;
    cc_treeget(cc_tree_in, node_ref, &node);
    probe = node.hash << 1;
    /* check if child is in the hash table */
    while (1) {
      if (!((found = cc_ht->ptr[probe % cc_ht->size]) & 1))
        /* child is NOT in the cache */
        break;
      else {
        /* something is in the cache, but it might not be a child */
        compcc_node other_node;
        cc_treeget(cc_tree_in, found >> 1, &other_node);
        if (re_compcc_treeeq(r, cc_tree_in, &node, &other_node)) {
          if (split_from) {
            inst i = re_prog_get(r, split_from);
            /* found our child, patch into it */
            i = INST(INST_OP(i), INST_N(i),
                     cc_ht->ptr[(probe % cc_ht->size) + 1]);
            re_prog_set(r, split_from, i);
          } else if (!*my_out_pc)
            *my_out_pc = cc_ht->ptr[(probe % cc_ht->size) + 1];
          return 0;
        }
      }
      probe += 1 << 1; /* linear probe */
    }
    my_pc = re_prog_size(r);
    if (split_from) {
      inst i = re_prog_get(r, split_from);
      /* patch into it */
      i = INST(INST_OP(i), INST_N(i), my_pc);
      re_prog_set(r, split_from, i);
    }
    if (node.sibling_ref) {
      /* need a split */
      split_from = my_pc;
      if (re_emit(r, INST(SPLIT, my_pc + 1, 0)))
        return ERR_MEM;
    }
    if (!*my_out_pc)
      *my_out_pc = my_pc;
    range_pc = re_prog_size(r);
    if (re_emit(r,
                INST(RANGE, 0,
                     br2u(BYTE_RANGE(u2br(node.range).l, u2br(node.range).h)))))
      return ERR_MEM;
    if (node.child_ref) {
      /* need to down-compile */
      u32 their_pc = 0;
      inst i = re_prog_get(r, range_pc);
      if ((err = re_compcc_rendertree(r, cc_tree_in, cc_ht, node.child_ref,
                                      &their_pc, frame)))
        return err;
      i = INST(INST_OP(i), their_pc, INST_P(i));
      re_prog_set(r, range_pc, i);
    } else {
      /* terminal: patch out */
      patch_add(r, frame, range_pc, 0);
    }
    cc_ht->ptr[(probe % cc_ht->size) + 0] = node_ref << 1 | 1;
    cc_ht->ptr[(probe % cc_ht->size) + 1] = my_pc;
    node_ref = node.sibling_ref;
  }
  assert(*my_out_pc);
  return 0;
}

int re_compcc(re *r, u32 root, compframe *frame) {
  int err = 0, inverted = *re_asttype(r, frame->root_ref) == ICLS;
  u32 start_pc = 0;
  r->cc_stk_a.size = r->cc_stk_b.size = 0; /* clear stks */
  /* push ranges */
  while (root) {
    u32 args[3], min, max;
    re_decompast(r, root, 3, args);
    min = args[0], max = args[1], root = args[2];
    /* handle out-of-order ranges (min > max) */
    if ((err = stk_push(r, &r->cc_stk_a, min > max ? max : min)) ||
        (err = stk_push(r, &r->cc_stk_a, min > max ? min : max)))
      return ERR_MEM;
  }
  /* sort ranges */
  re_compcc_hsort(&r->cc_stk_a, ccsize(&r->cc_stk_a));
  /* normalize ranges */
  {
    u32 min, max;
    size_t i;
    for (i = 0; i < ccsize(&r->cc_stk_a); i++) {
      u32 cur_min, cur_max;
      ccget(&r->cc_stk_a, i, &cur_min, &cur_max);
      assert(cur_min <= cur_max);
      if (!i)
        min = cur_min, max = cur_max; /* first range */
      else if (cur_min <= max + 1) {
        max = cur_max > max ? cur_max : max; /* intersection */
      } else {
        /* disjoint */
        if (ccpush(r, &r->cc_stk_b, min, max))
          return ERR_MEM;
        min = cur_min, max = cur_max;
      }
    }
    if (i && ccpush(r, &r->cc_stk_b, min, max))
      return ERR_MEM;
  }
  /* invert ranges */
  if (inverted) {
    u32 max = 0, cur_min, cur_max, i, old_size = ccsize(&r->cc_stk_b);
    r->cc_stk_b.size = 0; /* TODO: this is shitty code */
    for (i = 0; i < old_size; i++) {
      ccget(&r->cc_stk_b, i, &cur_min, &cur_max);
      if (cur_min > max) {
        if (ccpush(r, &r->cc_stk_b, max, cur_min - 1))
          return ERR_MEM;
        else
          max = cur_max + 1;
      }
    }
    if (cur_max < UTFMAX && ccpush(r, &r->cc_stk_b, cur_max + 1, UTFMAX))
      return ERR_MEM;
  }
  if (!ccsize(&r->cc_stk_b)) {
    if (re_emit(r, INST(ASSERT, 0, A_EVERYTHING)))
      return ERR_MEM;
    patch_add(r, frame, re_prog_size(r) - 1, 0);
  }
  /* build tree */
  r->cc_stk_a.size = 0;
  if ((err = re_compcc_buildtree(r, &r->cc_stk_b, &r->cc_stk_a)))
    return err;
  /* hash tree */
  if (cc_htinit(r, &r->cc_stk_a, &r->cc_stk_b))
    return ERR_MEM;
  re_compcc_hashtree(r, &r->cc_stk_a, &r->cc_stk_b, 1);
  /* prune/render tree */
  if ((err = re_compcc_rendertree(r, &r->cc_stk_a, &r->cc_stk_b,
                                  2 /* root's first node */, &start_pc, frame)))
    return err;
  return err;
}

int re_compile(re *r, u32 root, u32 reverse) {
  int err = 0;
  compframe initial_frame, returned_frame, child_frame;
  u32 set_idx = 0, grp_idx = 0, tmp_cc_ast = REF_NONE;
  if (!r->prog.size &&
      ((err = stk_push(r, &r->prog, 0)) || (err = stk_push(r, &r->prog, 0))))
    return err;
  initial_frame.root_ref = root;
  initial_frame.child_ref = initial_frame.patch_head =
      initial_frame.patch_tail = REF_NONE;
  initial_frame.idx = 0;
  initial_frame.pc = re_prog_size(r);
  r->entry[ENT_ONESHOT | (reverse ? ENT_REV : ENT_FWD)] = initial_frame.pc;
  if ((err = compframe_push(r, initial_frame)))
    return err;
  while (r->comp_stk.size) {
    compframe frame = compframe_pop(r);
    ast_type type;
    u32 args[4], my_pc = re_prog_size(r);
    frame.child_ref = frame.root_ref;
    child_frame.child_ref = child_frame.root_ref = child_frame.patch_head =
        child_frame.patch_tail = REF_NONE;
    child_frame.idx = child_frame.pc = 0;
    type = *re_asttype(r, frame.root_ref);
    if (!frame.root_ref) {
      /* epsilon */
      /*  in  out  */
      /* --------> */
    } else if (type == REG) {
      /*  in                 out (none)
       * ---> M -> [A] -> M      */
      u32 child;
      re_decompast(r, frame.root_ref, 1, args);
      child = args[0];
      if (!frame.idx) { /* before child */
        patch(r, &frame, my_pc);
        if (re_emit(r, INST(MATCH, 0, IMATCH(1, 2 * grp_idx++ + reverse))))
          return ERR_MEM;
        patch_add(r, &child_frame, my_pc, 0);
        frame.child_ref = child, frame.idx++;
      } else if (frame.idx) { /* after child */
        patch(r, &returned_frame, my_pc);
        if (re_emit(r, INST(MATCH, 0, IMATCH(0, 1 + set_idx++))))
          return ERR_MEM;
      }
    } else if (type == CHR) {
      patch(r, &frame, my_pc);
      re_decompast(r, frame.root_ref, 1, args);
      if (args[0] < 128) { /* ascii */
        /*  in     out
         * ---> R ----> */
        if (re_emit(r, INST(RANGE, 0, br2u(BYTE_RANGE(args[0], args[0])))))
          return ERR_MEM;
        patch_add(r, &frame, my_pc, 0);
      } else { /* unicode */
        /* create temp ast */
        if (!tmp_cc_ast && !(tmp_cc_ast = re_mkcc(r, REF_NONE, 0, 0)))
          return ERR_MEM;
        *re_astarg(r, tmp_cc_ast, 0, tmp_cc_ast) =
            *re_astarg(r, tmp_cc_ast, 1, tmp_cc_ast) = args[0];
        if (re_compcc(r, tmp_cc_ast, &frame))
          return ERR_MEM;
      }
    } else if (type == ANYBYTE) {
      /*  in     out
       * ---> R ----> */
      patch(r, &frame, my_pc);
      if (re_emit(r, INST(RANGE, 0, br2u(BYTE_RANGE(0x00, 0xFF)))))
        return ERR_MEM;
      patch_add(r, &frame, my_pc, 0);
    } else if (type == CAT) {
      /*  in              out
       * ---> [A] -> [B] ----> */
      re_decompast(r, frame.root_ref, 2, args);
      if (frame.idx == 0) {              /* before left child */
        frame.child_ref = args[reverse]; /* push left child */
        patch_xfer(&child_frame, &frame);
        frame.idx++;
      } else if (frame.idx == 1) {        /* after left child */
        frame.child_ref = args[!reverse]; /* push right child */
        patch_xfer(&child_frame, &returned_frame);
        frame.idx++;
      } else if (frame.idx == 2) { /* after right child */
        patch_xfer(&frame, &returned_frame);
      }
    } else if (type == ALT) {
      /*  in             out
       * ---> S --> [A] ---->
       *       \         out
       *        --> [B] ----> */
      re_decompast(r, frame.root_ref, 2, args);
      if (frame.idx == 0) { /* before left child */
        patch(r, &frame, frame.pc);
        if (re_emit(r, INST(SPLIT, 0, 0)))
          return ERR_MEM;
        patch_add(r, &child_frame, frame.pc, 0);
        frame.child_ref = args[0], frame.idx++;
      } else if (frame.idx == 1) { /* after left child */
        patch_merge(r, &frame, &returned_frame);
        patch_add(r, &child_frame, frame.pc, 1);
        frame.child_ref = args[1], frame.idx++;
      } else if (frame.idx == 2) { /* after right child */
        patch_merge(r, &frame, &returned_frame);
      }
    } else if (type == QUANT) {
      /*  in
       *        +-------+
       *       /         \
       * ---> S -> [A] ---+
       *       \             out
       *        +-----------------> */
      u32 child, min, max;
      re_decompast(r, frame.root_ref, 3, args);
      child = args[0], min = args[1], max = args[2];
      if (frame.idx < min) { /* before minimum bound */
        patch_xfer(&child_frame, frame.idx ? &returned_frame : &frame);
        frame.child_ref = child;
      } else if (max == INFTY && frame.idx == min) { /* before inf. bound */
        patch(r, frame.idx ? &returned_frame : &frame, my_pc);
        if (re_emit(r, INST(SPLIT, 0, 0)))
          return ERR_MEM;
        frame.pc = my_pc;
        patch_add(r, &child_frame, my_pc, 0);
        patch_add(r, &frame, my_pc, 1);
        frame.child_ref = child;
      } else if (max == INFTY && frame.idx == min + 1) { /* after inf. bound */
        patch(r, &returned_frame, frame.pc);
      } else if (frame.idx < max) { /* before maximum bound */
        if (frame.idx == min)
          patch(r, frame.idx ? &returned_frame : &frame, my_pc);
        if (re_emit(r, INST(SPLIT, 0, 0)))
          return ERR_MEM;
        patch_add(r, &child_frame, my_pc, 0);
        patch_add(r, &frame, my_pc, 1);
        frame.child_ref = child;
      } else if (frame.idx == max) { /* after maximum bound */
        patch_merge(r, &frame, &returned_frame);
      }
      frame.idx++;
    } else if (type == GROUP) {
      /*  in                 out
       * ---> M -> [A] -> M ----> */
      u32 child;
      re_decompast(r, frame.root_ref, 2, args);
      child = args[0];
      if (!frame.idx) { /* before child */
        patch(r, &frame, my_pc);
        if (re_emit(r, INST(MATCH, 0, IMATCH(1, 2 * grp_idx++ + reverse))))
          return ERR_MEM;
        patch_add(r, &child_frame, my_pc, 0);
        frame.child_ref = child, frame.idx++;
      } else if (frame.idx) { /* after child */
        patch(r, &returned_frame, my_pc);
        if (re_emit(r,
                    INST(MATCH, 0,
                         IMATCH(1, IMATCH_I(INST_P(re_prog_get(r, frame.pc))) +
                                       (reverse ? -1 : 1)))))
          return ERR_MEM;
        patch_add(r, &frame, my_pc, 0);
      }
    } else if (type == CLS || type == ICLS) {
      patch(r, &frame, my_pc);
      if (re_compcc(r, frame.root_ref, &frame))
        return ERR_MEM;
    } else {
      assert(0);
    }
    if (frame.child_ref != frame.root_ref) {
      /* should we push a child? */
      if (compframe_push(r, frame))
        return ERR_MEM;
      child_frame.root_ref = frame.child_ref;
      child_frame.idx = 0;
      child_frame.pc = re_prog_size(r);
      if (compframe_push(r, child_frame))
        return ERR_MEM;
    }
    returned_frame = frame;
  }
  assert(!r->comp_stk.size);
  assert(!returned_frame.patch_head && !returned_frame.patch_tail);
  {
    u32 dstar = r->entry[ENT_DOTSTAR | (reverse ? ENT_REV : ENT_FWD)] =
        re_prog_size(r);
    if (re_emit(r, INST(SPLIT,
                        r->entry[ENT_ONESHOT | (reverse ? ENT_REV : ENT_FWD)],
                        dstar + 1)))
      return ERR_MEM;
    if (re_emit(r, INST(RANGE, dstar, br2u(mkbr(0, 255)))))
      return ERR_MEM;
  }
  return 0;
}

typedef struct thrdspec {
  u32 pc, slot;
} thrdspec;

typedef struct sset {
  u32 *sparse, sparse_alloc;
  thrdspec *dense;
  u32 dense_size, dense_alloc;
} sset;

int sset_reset(re *r, sset *s, size_t sz) {
  size_t next_alloc = sz;
  u32 *next_sparse;
  thrdspec *next_dense;
  if (!next_alloc)
    return 0;
  if (!(next_sparse = re_ialloc(r, sizeof(u32) * s->sparse_alloc,
                                sizeof(u32) * next_alloc, s->sparse)))
    return 1;
  s->sparse = next_sparse;
  if (!(next_dense = re_ialloc(r, sizeof(thrdspec) * s->dense_alloc,
                               sizeof(thrdspec) * next_alloc, s->dense)))
    return 1;
  s->dense = next_dense;
  s->dense_size = 0;
  s->dense_alloc = next_alloc;
  return 0;
}

void sset_clear(sset *s) { s->dense_size = 0; }

void sset_init(re *r, sset *s) {
  (void)(r);
  s->sparse = NULL;
  s->sparse_alloc = 0;
  s->dense = NULL;
  s->dense_alloc = s->dense_size = 0;
}

void sset_destroy(re *r, sset *s) {
  re_ialloc(r, sizeof(u32) * s->sparse_alloc, 0, s->sparse);
  re_ialloc(r, sizeof(thrdspec) * s->dense_alloc, 0, s->dense);
}

void sset_add(sset *s, thrdspec spec) {
  assert(spec.pc < s->dense_alloc);
  assert(s->dense_size < s->dense_alloc);
  assert(spec.pc);
  s->dense[s->dense_size] = spec;
  s->sparse[spec.pc] = s->dense_size++;
}

int sset_memb(sset *s, u32 pc) {
  assert(pc < s->dense_alloc);
  return s->sparse[pc] < s->dense_size && s->dense[s->sparse[pc]].pc == pc;
}

typedef struct save_slots {
  size_t *slots, slots_size, slots_alloc, last_empty, per_thrd;
} save_slots;

void save_slots_init(re *r, save_slots *s) {
  (void)r;
  s->slots = NULL;
  s->slots_size = s->slots_alloc = s->last_empty = s->per_thrd = 0;
}

void save_slots_destroy(re *r, save_slots *s) {
  re_ialloc(r, sizeof(size_t) * s->slots_alloc, 0, s->slots);
}

void save_slots_clear(save_slots *s, size_t per_thrd) {
  s->slots_size = 0, s->last_empty = 0,
  s->per_thrd = per_thrd + 1 /* for refcnt */;
}

u32 save_slots_new(re *r, save_slots *s) {
  u32 out;
  if (!s->per_thrd) {
    out = 1;
  } else {
    if (s->last_empty) {
      /* reclaim */
      out = s->last_empty;
      s->last_empty = s->slots[out * s->per_thrd];
    } else {
      if (s->slots_size + s->per_thrd > s->slots_alloc) {
        /* initial alloc / realloc */
        size_t new_alloc =
            (s->slots_alloc ? s->slots_alloc * 2 : 16) * s->per_thrd;
        size_t *new_slots = re_ialloc(r, s->slots_alloc * sizeof(size_t),
                                      new_alloc * sizeof(size_t), s->slots);
        if (!new_slots)
          return 0;
        s->slots = new_slots, s->slots_alloc = new_alloc;
      }
      if (s->slots_size++)
        out = s->slots_size;
      else
        out = save_slots_new(r, s); /* create sentinel 0th */
    }
    memset(s->slots + out * s->per_thrd, 0, sizeof(*s->slots) * s->per_thrd);
  }
  return out;
}

u32 save_slots_fork(save_slots *s, u32 ref) {
  if (s->per_thrd)
    s->slots[ref * s->per_thrd + s->per_thrd - 1]++;
  return ref;
}

void save_slots_kill(save_slots *s, u32 ref) {
  if (!s->per_thrd)
    return;
  if (!s->slots[ref * s->per_thrd + s->per_thrd - 1]--) {
    /* prepend to free list */
    s->slots[ref * s->per_thrd] = s->last_empty;
    s->last_empty = ref;
  }
}

u32 save_slots_set(re *r, save_slots *s, u32 ref, u32 idx, size_t v) {
  u32 out = ref;
  if (!s->per_thrd) {
    /* not saving anything */
    assert(0);
  } else if (v == s->slots[ref * s->per_thrd + idx]) {
    /* not changing anything */
  } else if (!s->slots[ref * s->per_thrd + s->per_thrd - 1]) {
    s->slots[ref * s->per_thrd + idx] = v;
  } else {
    if (!(out = save_slots_new(r, s)))
      return out;
    save_slots_kill(s, ref); /* decrement refcount */
    memcpy(s->slots + out * s->per_thrd, s->slots + ref * s->per_thrd,
           sizeof(*s->slots) * s->per_thrd);
    s->slots[out * s->per_thrd + idx] = v;
  }
  return out;
}

u32 save_slots_perthrd(save_slots *s) {
  return s->per_thrd ? s->per_thrd - 1 : s->per_thrd;
}

u32 save_slots_get(save_slots *s, u32 ref, u32 idx) {
  assert(idx < save_slots_perthrd(s));
  return s->slots[ref * s->per_thrd + idx];
}

typedef struct exec_nfa {
  sset a, b, c;
  stk thrd_stk;
  save_slots slots;
  stk pri_stk;
  int reversed, track;
} exec_nfa;

void exec_nfa_init(re *r, exec_nfa *n) {
  sset_init(r, &n->a), sset_init(r, &n->b), sset_init(r, &n->c);
  stk_init(r, &n->thrd_stk), stk_init(r, &n->pri_stk);
  save_slots_init(r, &n->slots);
  n->reversed = n->track = 0;
}

void exec_nfa_destroy(re *r, exec_nfa *n) {
  sset_destroy(r, &n->a), sset_destroy(r, &n->b), sset_destroy(r, &n->c);
  stk_destroy(r, &n->thrd_stk), stk_destroy(r, &n->pri_stk);
  save_slots_destroy(r, &n->slots);
}

int thrdstk_push(re *r, stk *s, thrdspec t) {
  int err = 0;
  assert(t.pc);
  (err = stk_push(r, s, t.pc)) || (err = stk_push(r, s, t.slot));
  return err;
}

thrdspec thrdstk_pop(re *r, stk *s) {
  thrdspec out;
  out.slot = stk_pop(r, s);
  out.pc = stk_pop(r, s);
  return out;
}

int exec_nfa_start(re *r, exec_nfa *n, u32 pc, u32 noff, int reversed,
                   int track) {
  thrdspec initial_thrd;
  u32 i;
  int err = 0;
  if (sset_reset(r, &n->a, r->prog.size) ||
      sset_reset(r, &n->b, r->prog.size) || sset_reset(r, &n->c, r->prog.size))
    return ERR_MEM;
  n->thrd_stk.size = 0, n->pri_stk.size = 0;
  save_slots_clear(&n->slots, noff);
  initial_thrd.pc = pc;
  if (!(initial_thrd.slot = save_slots_new(r, &n->slots)))
    return ERR_MEM;
  sset_add(&n->a, initial_thrd);
  initial_thrd.pc = initial_thrd.slot = 0;
  for (i = 0; i < r->ast_sets; i++)
    if ((err = stk_push(r, &n->pri_stk, 0)))
      return err;
  n->reversed = reversed;
  n->track = track;
  return 0;
}

int exec_nfa_eps(re *r, exec_nfa *n, size_t pos) {
  size_t i;
  sset_clear(&n->b);
  for (i = 0; i < n->a.dense_size; i++) {
    thrdspec thrd = n->a.dense[i];
    if (thrdstk_push(r, &n->thrd_stk, thrd))
      return ERR_MEM;
    sset_clear(&n->c);
    while (n->thrd_stk.size) {
      thrdspec top = thrdstk_pop(r, &n->thrd_stk);
      inst op = re_prog_get(r, top.pc);
      assert(top.pc);
      if (sset_memb(&n->c, top.pc))
        /* we already processed this thread */
        continue;
      sset_add(&n->c, top);
      switch (INST_OP(re_prog_get(r, top.pc))) {
      case MATCH:
        if (IMATCH_S(INST_P(op))) /* this is a save */ {
          if (IMATCH_I(INST_P(op)) < save_slots_perthrd(&n->slots)) {
            if (!(top.slot = save_slots_set(r, &n->slots, top.slot,
                                            IMATCH_I(INST_P(op)), pos)))
              return ERR_MEM;
          }
          top.pc = INST_N(op);
          if (thrdstk_push(r, &n->thrd_stk, top))
            return ERR_MEM;
          break;
        } /* else fall-through */
      case RANGE:
        sset_add(&n->b, top); /* this is a range or final match */
        break;
      case SPLIT: {
        thrdspec pri, sec;
        pri.pc = INST_N(op), pri.slot = top.slot;
        sec.pc = INST_P(op), sec.slot = save_slots_fork(&n->slots, top.slot);
        if (thrdstk_push(r, &n->thrd_stk, pri) ||
            thrdstk_push(r, &n->thrd_stk, sec))
          return ERR_MEM;
        break;
      }
      default:
        assert(0);
      }
    }
  }
  sset_clear(&n->a);
  return 0;
}

int exec_nfa_matchend(re *r, exec_nfa *n, u32 idx, thrdspec thrd, size_t pos,
                      unsigned int ch) {
  u32 *memo = n->pri_stk.ptr + idx - 1;
  if (!n->track && ch < 256)
    return 0;
  if (n->slots.per_thrd) {
    if (*memo)
      save_slots_kill(&n->slots, *memo);
    if (!(*memo = save_slots_set(r, &n->slots, thrd.slot, !n->reversed, pos)))
      return ERR_MEM;
  } else {
    *memo = 1; /* just mark that a set was matched */
  }
  return 0;
}

int exec_nfa_chr(re *r, exec_nfa *n, unsigned int ch, size_t pos) {
  size_t i;
  for (i = 0; i < n->b.dense_size; i++) {
    thrdspec thrd = n->b.dense[i];
    inst op = re_prog_get(r, thrd.pc);
    switch (INST_OP(op)) {
    case RANGE: {
      byte_range br = u2br(INST_P(op));
      if (ch >= br.l && ch <= br.h) {
        thrd.pc = INST_N(op);
        sset_add(&n->a, thrd);
      } else
        save_slots_kill(&n->slots, thrd.slot);
      break;
    }
    case MATCH: {
      assert(!IMATCH_S(INST_P(op)));
      if ((exec_nfa_matchend(r, n, IMATCH_I(INST_P(op)), thrd, pos, ch)))
        return ERR_MEM;
      break;
    }
    default:
      assert(0);
    }
  }
  return 0;
}

/* return number of sets matched, -n otherwise */
/* 0th span is the full bounds, 1st is first group, etc. */
int exec_nfa_end(re *r, size_t pos, exec_nfa *n, u32 max_span, u32 max_set,
                 span *out_span, u32 *out_set) {
  size_t j, sets = 0, nset = 0;
  if (exec_nfa_eps(r, n, pos) || exec_nfa_chr(r, n, 256, pos))
    return ERR_MEM;
  for (sets = 0; sets < r->ast_sets; sets++) {
    u32 slot = n->pri_stk.ptr[sets];
    if (!slot)
      continue; /* no match for this set */
    for (j = 0; j < max_span; j++) {
      out_span[nset * max_span + j].begin = save_slots_get(&n->slots, slot, j);
      out_span[nset * max_span + j].end =
          save_slots_get(&n->slots, slot, j + 1);
    }
    if (nset < max_set)
      out_set[nset] = sets;
    nset++;
  }
  return nset;
}

int exec_nfa_run(re *r, exec_nfa *n, unsigned int ch, size_t pos) {
  if (exec_nfa_eps(r, n, pos))
    return ERR_MEM;
  return exec_nfa_chr(r, n, ch, pos);
}

/* problem: how the fuck do we do unanchored set matches? */
/* solutions:
 * - introduce "partition" instructions
 *   - designate special instructions that never expire in the sparse set
 *   - we know a set member has died if its partition contains no threads
 * - introduce match instructions that detect bounds
 *   - performance penalty for other types of matches
 * - just don't support it!
 *   - are we hurting ourselves here? */

/* fully-anchored match: run every character */
/* start-anchored match: run until priority exhaustion */
/* end-anchored match:   run reverse until priority exhaustion */
/* unanchored match:     run dotstar */

int re_match(re *r, const char *s, size_t n, u32 max_span, u32 max_set,
             span *out_span, u32 *out_set, anchor_type anchor) {
  exec_nfa nfa;
  int err = 0;
  u32 entry = entry = anchor == A_END          ? ENT_REV
                      : anchor == A_UNANCHORED ? ENT_FWD | ENT_DOTSTAR
                                               : ENT_FWD;
  size_t i;
  if (!re_prog_size(r) && ((err = re_compile(r, r->ast_root, ENT_FWD)) ||
                           (err = re_compile(r, r->ast_root, ENT_REV))))
    return err;
  exec_nfa_init(r, &nfa);
  if ((err = exec_nfa_start(r, &nfa, r->entry[entry], max_span * 2,
                            entry & ENT_REV, entry & ENT_DOTSTAR)))
    goto done;
  for (i = 0; i < n; i++) {
    if ((err = exec_nfa_run(r, &nfa, ((const u8 *)s)[i], i)))
      goto done;
  }
  if ((err = exec_nfa_end(r, n, &nfa, max_span, max_set, out_span, out_set)))
    goto done;
done:
  exec_nfa_destroy(r, &nfa);
  return err;
}

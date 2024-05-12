#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "re.h"

#define REF_NONE 0
#define UTFMAX   0x10FFFF

typedef struct stk {
  u32 *ptr, size, alloc;
} stk;

struct re {
  re_alloc alloc;
  stk ast;
  u32 ast_root, ast_sets;
  stk arg_stk, op_stk, comp_stk, prog;
  stk cc_stk_a, cc_stk_b;
  u32 entry[4];
  const u8 *expr;
  size_t expr_pos, expr_size;
  const char *error;
  size_t error_pos;
};

#define ENT_ONESHOT 0
#define ENT_DOTSTAR 2
#define ENT_FWD     0
#define ENT_REV     1

#ifdef RE_TEST

  #include "mptest/_cpack/mptest.h"
  #define malloc  MPTEST_INJECT_MALLOC
  #define realloc MPTEST_INJECT_REALLOC
  #define free    MPTEST_INJECT_FREE

#endif

void *re_default_alloc(size_t prev, size_t next, void *ptr)
{
  if (next) {
    (void)prev, assert(prev || !ptr);
    return realloc(ptr, next);
  } else if (ptr) {
    free(ptr);
  }
  return NULL;
}

void *re_ialloc(re *re, size_t prev, size_t next, void *ptr)
{
  return re->alloc(prev, next, ptr);
}

void stk_init(re *r, stk *s)
{
  (void)(r);
  s->ptr = NULL;
  s->size = s->alloc = 0;
}

void stk_destroy(re *r, stk *s)
{
  re_ialloc(r, sizeof(*s->ptr) * s->alloc, 0, s->ptr);
}

int stk_pushn(re *r, stk *s, void *p, u32 n)
{
  u32 words = (n + (sizeof(u32) - 1)) / sizeof(u32); /* ceil */
  size_t next_alloc = s->alloc ? s->alloc : 16;
  while (s->size + words > next_alloc)
    next_alloc *= 2;
  if (next_alloc > s->alloc) {
    u32 *out = re_ialloc(
        r, sizeof(*s->ptr) * s->alloc, sizeof(*s->ptr) * next_alloc, s->ptr);
    if (!out)
      return ERR_MEM;
    s->alloc = next_alloc;
    s->ptr = out;
  }
  memcpy(s->ptr + s->size, p, n);
  s->size += words;
  return 0;
}

int stk_push(re *r, stk *s, u32 v) { return stk_pushn(r, s, &v, sizeof(v)); }

u32 stk_elemsize(size_t n) { return ((n + sizeof(u32) - 1) / sizeof(u32)); }

void stk_popn(re *r, stk *s, void *p, u32 n)
{
  u32 words = (n + (sizeof(u32) - 1)) / sizeof(u32); /* ceil */
  (void)(r);
  assert(s->size >= words);
  memcpy(p, s->ptr + s->size - words, n);
  s->size -= words;
}

u32 stk_pop(re *r, stk *s)
{
  u32 v;
  stk_popn(r, s, &v, sizeof(v));
  return v;
}

void *stk_getn(stk *s, u32 idx)
{
  assert(idx < s->size);
  return s->ptr + idx;
}

u32 stk_peek(re *r, stk *s, u32 idx)
{
  (void)(r);
  assert(idx < s->size);
  return s->ptr[s->size - 1 - idx];
}

u32 stk_size(stk *s, u32 n)
{
  return s->size / ((n + sizeof(u32) - 1) / sizeof(u32));
}

int re_parse(re *r, const u8 *s, size_t sz, u32 *root);

re *re_init(const char *regex)
{
  int err;
  re *r;
  if ((err = re_init_full(&r, regex, strlen(regex), NULL))) {
    re_destroy(r);
    r = NULL;
  }
  return r;
}

int re_init_full(re **pr, const char *regex, size_t n, re_alloc alloc)
{
  int err = 0;
  re *r;
  if (!alloc)
    alloc = re_default_alloc;
  r = alloc(0, sizeof(re), NULL);
  *pr = r;
  if (!r)
    return (err = ERR_MEM);
  r->alloc = alloc;
  stk_init(r, &r->ast);
  r->ast_root = r->ast_sets = 0;
  stk_init(r, &r->arg_stk), stk_init(r, &r->op_stk), stk_init(r, &r->comp_stk);
  stk_init(r, &r->cc_stk_a), stk_init(r, &r->cc_stk_b);
  stk_init(r, &r->prog);
  memset(r->entry, 0, sizeof(r->entry));
  if (regex) {
    if ((err = re_parse(r, (const u8 *)regex, n, &r->ast_root))) {
      return err;
    } else {
      r->ast_sets = 1;
    }
  }
  return err;
}

void re_destroy(re *r)
{
  if (!r)
    return;
  stk_destroy(r, &r->ast);
  stk_destroy(r, &r->op_stk), stk_destroy(r, &r->arg_stk),
      stk_destroy(r, &r->comp_stk);
  stk_destroy(r, &r->cc_stk_a), stk_destroy(r, &r->cc_stk_b);
  stk_destroy(r, &r->prog);
  r->alloc(sizeof(*r), 0, r);
}

typedef enum ast_type {
  CHR = 1, /* single character */
  CAT,     /* concatenation */
  ALT,     /* alternation */
  QUANT,   /* quantifier */
  UQUANT,  /* ungreedy quantifier */
  GROUP,   /* group */
  IGROUP,  /* inline group */
  CLS,     /* character class */
  ICLS,    /* inverted character class */
  ANYBYTE, /* any byte (\C) */
  AASSERT  /* epsilon assertion (^$\A\z\b\B) */
} ast_type;

const unsigned int ast_type_lens[] = {
    0, /* eps */
    1, /* CHR */
    2, /* CAT */
    2, /* ALT */
    3, /* QUANT */
    3, /* UQUANT */
    3, /* GROUP */
    3, /* IGROUP */
    3, /* CLS */
    3, /* ICLS */
    0, /* ANYBYTE */
    1, /* AASSERT */
};

typedef enum group_flag {
  INSENSITIVE = 1,   /* case-insensitive matching */
  MULTILINE = 2,     /* ^$ match beginning/end of each line */
  DOTNEWLINE = 4,    /* . matches \n */
  UNGREEDY = 8,      /* ungreedy quantifiers */
  NONCAPTURING = 16, /* non-capturing group (?:...) */
  SUBEXPRESSION = 32 /* set-match component */
} group_flag;

typedef enum assert_flag {
  LINE_BEGIN = 1,
  LINE_END = 2,
  TEXT_BEGIN = 4,
  TEXT_END = 8,
  WORD = 16,
  NOT_WORD = 32
} assert_flag;

typedef struct byte_range {
  u8 l, h;
} byte_range;

byte_range mkbr(u8 l, u8 h)
{
  byte_range out;
  out.l = l, out.h = h;
  return out;
}

u32 br2u(byte_range br) { return ((u32)br.l) | ((u32)br.h) << 8; }

byte_range u2br(u32 u) { return mkbr(u & 0xFF, u >> 8 & 0xFF); }

int br_isect(byte_range r, byte_range clip)
{
  return r.l <= clip.h && clip.l <= r.h;
}

int br_adjace(byte_range left, byte_range right)
{
  return ((u32)left.h) + 1 == ((u32)right.l);
}

#define BYTE_RANGE(l, h) mkbr(l, h)

int re_mkast(re *re, ast_type type, u32 p0, u32 p1, u32 p2, u32 *out)
{
  u32 args[4];
  int err;
  args[0] = type, args[1] = p0, args[2] = p1, args[3] = p2;
  if (type && !re->ast.size &&
      (err = re_mkast(re, 0, 0, 0, 0, out))) /* sentinel node */
    return err;
  *out = re->ast.size;
  return stk_pushn(re, &re->ast, args, (1 + ast_type_lens[type]) * sizeof(u32));
}

void re_decompast(re *re, u32 root, u32 *out_args)
{
  u32 *in_args = stk_getn(&re->ast, root);
  memcpy(out_args, in_args + 1, ast_type_lens[*in_args] * sizeof(u32));
}

u32 *re_astarg(re *re, u32 root, u32 n)
{
  assert(ast_type_lens[re->ast.ptr[root]] > n);
  return re->ast.ptr + root + 1 + n;
}

u32 *re_asttype(re *re, u32 root) { return re->ast.ptr + root; }

int re_union(re *r, const char *regex, size_t n)
{ /* add an ALT here */
  int err = 0;
  if (!r->ast_sets && (err = re_parse(r, (const u8 *)regex, n, &r->ast_root))) {
    return err;
  } else if (!r->ast_sets) {
    u32 next_reg, next_root;
    if ((err = re_parse(r, (const u8 *)regex, n, &next_reg)) ||
        (err = re_mkast(r, ALT, r->ast_root, next_reg, 0, &next_root)))
      return err;
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

u32 utf8_decode(u32 *state, u32 *codep, u32 byte)
{
  u32 type = utf8d[byte];
  *codep = (*state != UTF8_ACCEPT) ? (byte & 0x3fu) | (*codep << 6)
                                   : (0xff >> type) & (byte);

  *state = utf8d[256 + *state * 16 + type];
  return *state;
}

int re_parse_err(re *r, const char *msg)
{
  r->error = msg, r->error_pos = r->expr_pos;
  return ERR_PARSE;
}

int re_hasmore(re *r) { return r->expr_pos != r->expr_size; }

int re_next(re *r, u32 *first, const char *else_msg)
{
  u32 state = UTF8_ACCEPT;
  assert(else_msg || re_hasmore(r));
  if (!re_hasmore(r))
    return re_parse_err(r, else_msg);
  while (utf8_decode(&state, first, *(r->expr + r->expr_pos)),
         (++r->expr_pos != r->expr_size))
    if (!state)
      return 0;
  if (state != UTF8_ACCEPT)
    return re_parse_err(r, "invalid utf-8 sequence");
  return 0;
}

int re_peek_next(re *r, u32 *first)
{
  size_t prev_pos = r->expr_pos;
  int err;
  assert(re_hasmore(r));
  if ((err = re_next(r, first, NULL)))
    return err;
  r->expr_pos = prev_pos;
  return 0;
}

#define MAXREP 100000
#define INFTY  (MAXREP + 1)

/* Given nodes R_1i..R_N on the argument stack, fold them into a single CAT
 * node. If there are no nodes on the stack, create an epsilon node. */
int re_fold(re *r)
{
  int err = 0;
  if (!r->arg_stk.size) {
    /* arg_stk: | */
    return stk_push(r, &r->arg_stk, REF_NONE);
    /* arg_stk: | eps |*/
  }
  while (r->arg_stk.size > 1) {
    /* arg_stk: | ... | R_N-1 | R_N | */
    u32 right, left, rest;
    right = stk_pop(r, &r->arg_stk);
    left = stk_pop(r, &r->arg_stk);
    if ((err = re_mkast(r, CAT, left, right, 0, &rest)) ||
        (err = stk_push(r, &r->arg_stk, rest)))
      return err;
    /* arg_stk: | ... | R_N-1R_N | */
  }
  /* arg_stk: | R1R2...Rn | */
  return 0;
}

/* Given a node R on the argument stack and an arbitrary number of ALT nodes at
 * the end of the operator stack, fold and finish each ALT node into a single
 * resulting ALT node on the argument stack. */
int re_fold_alts(re *r, u32 *flags)
{
  int err = 0;
  assert(r->arg_stk.size == 1);
  /* First pop all inline groups. */
  while (r->op_stk.size &&
         *re_asttype(r, stk_peek(r, &r->op_stk, 0)) == IGROUP) {
    /* arg_stk: |  R  | */
    /* op_stk:  | ... | (S) | */
    u32 igrp = stk_pop(r, &r->op_stk), prev = *re_astarg(r, igrp, 0), cat,
        old_flags = *re_astarg(r, igrp, 2);
    *re_astarg(r, igrp, 0) = stk_pop(r, &r->arg_stk);
    *flags = old_flags;
    if ((err = re_mkast(r, CAT, prev, igrp, 0, &cat)) ||
        (err = stk_push(r, &r->arg_stk, cat)))
      return err;
    /* arg_stk: | S(R)| */
    /* op_stk:  | ... | */
  }
  assert(r->arg_stk.size == 1);
  /* arg_stk: |  R  | */
  /* op_stk:  | ... | */
  if (r->op_stk.size && *re_asttype(r, stk_peek(r, &r->op_stk, 0)) == ALT) {
    /* op_stk:  | ... |  A  | */
    /* finish the last alt */
    *re_astarg(r, stk_peek(r, &r->op_stk, 0), 1) = stk_pop(r, &r->arg_stk);
    /* arg_stk: | */
    /* op_stk:  | ... | */
  }
  while (r->op_stk.size > 1 &&
         *re_asttype(r, stk_peek(r, &r->op_stk, 0)) == ALT &&
         *re_asttype(r, stk_peek(r, &r->op_stk, 1)) == ALT) {
    /* op_stk:  | ... | A_1 | A_2 | */
    u32 right = stk_pop(r, &r->op_stk), left = stk_pop(r, &r->op_stk);
    *re_astarg(r, left, 1) = right;
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

u32 re_uncc(re *r, u32 rest, u32 first)
{
  u32 cur = first, *next;
  assert(first);
  while (*(next = re_astarg(r, cur, 2)))
    cur = *next;
  *next = rest;
  return first;
}

int re_parse_escape_addchr(re *r, u32 ch, u32 allowed_outputs)
{
  int err = 0;
  u32 res, args[1];
  (void)allowed_outputs, assert(allowed_outputs & (1 << CHR));
  args[0] = ch;
  if ((err = re_mkast(r, CHR, ch, 0, 0, &res)) ||
      (err = stk_push(r, &r->arg_stk, res)))
    return err;
  return 0;
}

int re_hexdig(u32 ch)
{
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

const ccdef builtin_cc[];

const ccdef *re_parse_namedcc(const u8 *s, size_t sz)
{
  const ccdef *p = builtin_cc;
  while (p->name_len) {
    if ((size_t)p->name_len == sz && !memcmp(s, (const u8 *)p->name, sz))
      return p;
    p++;
  }
  return NULL;
}

int re_parse_add_namedcc(re *r, const u8 *s, size_t sz, int invert)
{
  int err = 0;
  const ccdef *named = re_parse_namedcc(s, sz);
  u32 res = REF_NONE, i, max = 0, cur_min, cur_max;
  if (!named)
    return re_parse_err(r, "unknown builtin character class name");
  for (i = 0; i < named->cc_len; i++) {
    cur_min = named->chars[i * 2], cur_max = named->chars[i * 2 + 1];
    if (!invert && (err = re_mkast(r, CLS, cur_min, cur_max, res, &res)))
      return err;
    else if (invert) {
      assert(cur_min >= max); /* builtin charclasses are ordered. */
      if (max != cur_min &&
          (err = re_mkast(r, CLS, max, cur_min - 1, res, &res)))
        return err;
      else
        max = cur_max + 1;
    }
  }
  assert(cur_max < UTFMAX); /* builtin charclasses never reach UTFMAX */
  if (invert && i && (err = re_mkast(r, CLS, cur_max + 1, UTFMAX, res, &res)))
    return err;
  if ((err = stk_push(r, &r->arg_stk, res)))
    return err;
  return 0;
}

/* after a \ */
int re_parse_escape(re *r, u32 allowed_outputs)
{
  u32 ch;
  int err = 0;
  if ((err = re_next(r, &ch, "expected escape sequence")))
    return err;
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
    while (digs++ < 3 && re_hasmore(r) && !(err = re_peek_next(r, &ch)) &&
           ch >= '0' && ch <= '7') {
      err = re_next(r, &ch, NULL);
      assert(!err && ch >= '0' && ch <= '7');
      ord = ord * 8 + ch - '0';
    }
    if (err)
      return err; /* malformed */
    return re_parse_escape_addchr(r, ord, allowed_outputs);
  } else if (ch == 'x') { /* hex escape */
    u32 ord = 0;
    if ((err = re_next(
             r, &ch, "expected two hex characters or a bracketed hex literal")))
      return err;
    if (ch == '{') { /* bracketed hex lit */
      u32 i;
      for (i = 0; i < 8; i++) {
        if ((i == 7) ||
            (err = re_next(r, &ch, "expected up to six hex characters")))
          return re_parse_err(r, "expected up to six hex characters");
        if (ch == '}')
          break;
        if ((err = re_hexdig(ch)) == -1)
          return re_parse_err(r, "invalid hex digit");
        ord = ord * 16 + err;
      }
      if (!i)
        return re_parse_err(r, "expected at least one hex character");
    } else if ((err = re_hexdig(ch)) == -1) {
      return re_parse_err(r, "invalid hex digit");
    } else {
      ord = err;
      if ((err = re_next(r, &ch, "expected two hex characters")))
        return err;
      else if ((err = re_hexdig(ch)) == -1)
        return re_parse_err(r, "invalid hex digit");
      ord = ord * 16 + err;
    }
    if (ord > UTFMAX)
      return re_parse_err(r, "ordinal value out of range [0, 0x10FFFF]");
    return re_parse_escape_addchr(r, ord, allowed_outputs);
  } else if (ch == 'C') { /* any byte: \C */
    u32 res;
    if (!(allowed_outputs & (1 << ANYBYTE)))
      return re_parse_err(r, "cannot use \\C here");
    if ((err = re_mkast(r, ANYBYTE, 0, 0, 0, &res)) ||
        (err = stk_push(r, &r->arg_stk, res)))
      return err;
  } else if (ch == 'Q') { /* quote string */
    u32 cat = REF_NONE, chr = REF_NONE;
    if (!(allowed_outputs & (1 << CAT)))
      return re_parse_err(r, "cannot use \\Q...\\E here");
    while (re_hasmore(r)) {
      if ((err = re_next(r, &ch, NULL)))
        return err;
      if (ch == '\\' && re_hasmore(r)) {
        if ((err = re_peek_next(r, &ch)))
          return err;
        if (ch == 'E') {
          err = re_next(r, &ch, NULL);
          assert(!err); /* we already read this in the peeknext */
          return stk_push(r, &r->arg_stk, cat);
        } else if (ch == '\\') {
          err = re_next(r, &ch, NULL);
          assert(!err && ch == '\\');
        } else {
          ch = '\\';
        }
      }
      if ((err = re_mkast(r, CHR, ch, 0, 0, &chr)))
        return err;
      if ((err = re_mkast(r, CAT, cat, chr, 0, &cat)))
        return err;
    }
    if ((err = stk_push(r, &r->arg_stk, cat)))
      return err;
  } else if (
      ch == 'D' || ch == 'd' || ch == 'S' || ch == 's' || ch == 'W' ||
      ch == 'w') {
    /* Perl builtin character classes */
    const char *cc_name;
    int inverted = ch >= 'A' && ch <= 'Z'; /* uppercase are inverted */
    ch = inverted ? ch - 'A' + 'a' : ch;   /* convert to lowercase */
    cc_name = ch == 'd' ? "digit" : ch == 's' ? "perl_space" : "word";
    if (!(allowed_outputs & (1 << CLS)))
      return re_parse_err(r, "cannot use a character class here");
    if ((err = re_parse_add_namedcc(
             r, (const u8 *)cc_name, strlen(cc_name), inverted)))
      return err;
  } else if (ch == 'A' || ch == 'z' || ch == 'B' || ch == 'b') { /* empty
                                                                    asserts */
    u32 res;
    if (!(allowed_outputs & (1 << AASSERT)))
      return re_parse_err(r, "cannot use an epsilon assertion here");
    if ((err = re_mkast(
             r, AASSERT,
             ch == 'A'   ? TEXT_BEGIN
             : ch == 'z' ? TEXT_END
             : ch == 'B' ? NOT_WORD
                         : WORD,
             0, 0, &res)) ||
        (err = stk_push(r, &r->arg_stk, res)))
      return err;
  } else {
    return re_parse_err(r, "invalid escape sequence");
  }
  return 0;
}

int re_parse_number(re *r, u32 *out, u32 max_digits)
{
  int err = 0;
  u32 ch, acc = 0, ndigs = 0;
  if (!re_hasmore(r))
    return re_parse_err(r, "expected at least one decimal digit");
  while (re_hasmore(r) && !(err = re_peek_next(r, &ch)) && ch >= '0' &&
         ch <= '9' && (re_next(r, &ch, NULL), ++ndigs < max_digits))
    acc = acc * 10 + (ch - '0');
  if (err)
    return err;
  if (!ndigs && !(ch >= '0' && ch <= '9'))
    return re_parse_err(r, "expected at least one decimal digit");
  *out = acc;
  return err;
}

int re_parse(re *r, const u8 *ts, size_t tsz, u32 *root)
{
  int err;
  u32 flags = 0;
  r->expr = ts;
  r->expr_size = tsz, r->expr_pos = 0;
  while (re_hasmore(r)) {
    u32 ch, res = REF_NONE;
    if ((err = re_next(r, &ch, NULL)))
      return err;
    if (ch == '*' || ch == '+' || ch == '?') {
      u32 q = ch, greedy = 1;
      /* arg_stk: | ... |  R  | */
      /* pop one from arg stk, create quant, push to arg stk */
      if (!r->arg_stk.size)
        return re_parse_err(r, "cannot apply quantifier to empty regex");
      if (re_hasmore(r)) {
        if ((err = re_peek_next(r, &ch)))
          return err;
        else if (ch == '?') {
          re_next(r, &ch, NULL);
          greedy = 0;
        }
      }
      if ((err = re_mkast(
               r, greedy ? QUANT : UQUANT, stk_pop(r, &r->arg_stk) /* child */,
               q == '+' /* min */, q == '?' ? 1 : INFTY /* max */, &res)) ||
          (err = stk_push(r, &r->arg_stk, res)))
        return err;
      /* arg_stk: | ... | *(R) | */
    } else if (ch == '|') {
      /* fold the arg stk into a concat, create alt, push it to the arg stk */
      /* op_stk:  | ... | */
      /* arg_stk: | R_1 | R_2 | ... | R_N | */
      if ((err = re_fold(r)))
        return err;
      /* arg_stk: |  R  | */
      if ((err = re_mkast(
               r, ALT, stk_pop(r, &r->arg_stk) /* left */, REF_NONE /* right */,
               0, &res)) ||
          (err = stk_push(r, &r->op_stk, res)))
        return err;
      /* arg_stk: | */
      /* op_stk:  | ... | R(|) | */
    } else if (ch == '(') {
      u32 old_flags = flags, inline_group = 0;
      if (!re_hasmore(r))
        return re_parse_err(r, "expected ')' to close group");
      if ((err = re_peek_next(r, &ch)))
        return err;
      if (ch == '?') { /* start of group flags */
        re_next(r, &ch, NULL);
        if ((err = re_next(
                 r, &ch,
                 "expected 'P', '<', or group flags after special "
                 "group opener \"(?\"")))
          return err;
        if (ch == 'P' || ch == '<') {
          if (ch == 'P' &&
              (err = re_next(
                   r, &ch, "expected '<' after named group opener \"(?P\"")))
            return err;
          if (ch != '<')
            return re_parse_err(
                r, "expected '<' after named group opener \"(?P\"");
          /* parse group name */
          while (1) {
            if ((err = re_next(
                     r, &ch, "expected name followed by '>' for named group")))
              return err;
            if (ch == '>')
              break;
          }
        } else {
          u32 neg = 0, flag;
          while (1) {
            if (ch == ':' || ch == ')')
              break;
            else if (ch == '-') {
              if (neg)
                return re_parse_err(r, "cannot apply flag negation '-' twice");
              neg = 1;
            } else if (
                (ch == 'i' && (flag = INSENSITIVE)) ||
                (ch == 'm' && (flag = MULTILINE)) ||
                (ch == 's' && (flag = DOTNEWLINE)) ||
                (ch == 'u' && (flag = UNGREEDY))) {
              flags = neg ? flags & ~flag : flags | flag;
            } else {
              return re_parse_err(
                  r, "expected ':', ')', or group flags for special group");
            }
            if ((err = re_next(
                     r, &ch,
                     "expected ':', ')', or group flags for special group")))
              return err;
          }
          flags |= NONCAPTURING;
          if (ch == ')')
            inline_group = 1;
        }
      }
      /* op_stk:  | ... | */
      /* arg_stk: | R_1 | R_2 | ... | R_N | */
      if ((err = re_fold(r)))
        return err;
      /* arg_stk: |  R  | */
      if ((err = re_mkast(
               r, inline_group ? IGROUP : GROUP, stk_pop(r, &r->arg_stk), flags,
               old_flags, &res)) ||
          (err = stk_push(r, &r->op_stk, res)))
        return err;
      /* op_stk:  | ... | (R) | */
    } else if (ch == ')') {
      u32 grp, prev;
      /* arg_stk: | S_1 | S_2 | ... | S_N | */
      /* op_stk:  | ... | (R) | ... | */
      /* fold the arg stk into a concat, fold remaining alts, create group,
       * push it to the arg stk */
      if ((err = re_fold(r)) || (err = re_fold_alts(r, &flags)))
        return err;
      /* arg_stk has one value */
      assert(r->arg_stk.size == 1);
      if (!r->op_stk.size)
        return re_parse_err(r, "extra close parenthesis");
      /* arg_stk: |  S  | */
      /* op_stk:  | ... | (R) | */
      grp = stk_peek(r, &r->op_stk, 0);
      /* retrieve the previous contents of arg_stk */
      prev = *re_astarg(r, grp, 0);
      /* add it to the group */
      *(re_astarg(r, grp, 0)) = stk_pop(r, &r->arg_stk);
      /* restore group flags */
      flags = *(re_astarg(r, grp, 2));
      /* push the saved contents of arg_stk */
      if (prev && (err = stk_push(r, &r->arg_stk, prev)))
        return err;
      /* pop the group frame into arg_stk */
      if ((err = stk_push(r, &r->arg_stk, stk_pop(r, &r->op_stk))))
        return err;
      /* arg_stk: |  S  |  R  | */
      /* op_stk:  | ... | */
    } else if (ch == '.') { /* any char */
      /* arg_stk: | ... | */
      if (((flags & DOTNEWLINE) &&
           (err = re_mkast(r, CLS, 0, UTFMAX, REF_NONE, &res))) ||
          (!(flags & DOTNEWLINE) &&
           ((err = re_mkast(r, CLS, 0, '\n' - 1, REF_NONE, &res)) ||
            (err = re_mkast(r, CLS, '\n' + 1, UTFMAX, res, &res)))) ||
          (err = stk_push(r, &r->arg_stk, res)))
        return err;
      /* arg_stk: | ... |  .  | */
    } else if (ch == '[') { /* charclass */
      size_t start = r->expr_pos;
      u32 inverted = 0, min, max;
      res = REF_NONE;
      while (1) {
        u32 next;
        if ((err = re_next(r, &ch, "unclosed character class")))
          return err;
        if ((r->expr_pos - start == 1) && ch == '^') {
          inverted = 1; /* caret at start of CC */
          continue;
        }
        min = ch;
        if (ch == ']') {
          if ((r->expr_pos - start == 1 ||
               (r->expr_pos - start == 2 && inverted))) {
            min = ch; /* charclass starts with ] */
          } else
            break;               /* charclass done */
        } else if (ch == '\\') { /* escape */
          if ((err = re_parse_escape(r, (1 << CHR) | (1 << CLS))))
            return err;
          next = stk_pop(r, &r->arg_stk);
          assert(*re_asttype(r, next) == CHR || *re_asttype(r, next) == CLS);
          if (*re_asttype(r, next) == CHR)
            min = *re_astarg(r, next, 0); /* single-character escape */
          else if (*re_asttype(r, next) == CLS) {
            res = re_uncc(r, res, next);
            /* we parsed an entire class, so there's no ending character */
            continue;
          }
        } else if (
            ch == '[' && re_hasmore(r) && !re_peek_next(r, &ch) &&
            ch == ':') { /* named class */
          int named_inverted = 0;
          size_t name_start, name_end;
          err = re_next(r, &ch, NULL); /* : */
          assert(!err && ch == ':');
          if (re_hasmore(r) && !re_peek_next(r, &ch) &&
              ch == '^') {               /* inverted named class */
            err = re_next(r, &ch, NULL); /* ^ */
            assert(!err && ch == '^');
            named_inverted = 1;
          }
          name_start = name_end = r->expr_pos;
          while (1) {
            if ((err = re_next(r, &ch, "expected character class name")))
              return err;
            if (ch == ':')
              break;
            name_end = r->expr_pos;
          }
          if ((err = re_next(
                   r, &ch,
                   "expected closing bracket for named character class")))
            return err;
          if (ch != ']')
            return re_parse_err(
                r, "expected closing bracket for named character class");
          if ((err = re_parse_add_namedcc(
                   r, r->expr + name_start, (name_end - name_start),
                   named_inverted)))
            return err;
          next = stk_pop(r, &r->arg_stk);
          assert(next && *re_asttype(r, next) == CLS);
          res = re_uncc(r, res, next);
          continue;
        }
        max = min;
        if (re_hasmore(r) && !re_peek_next(r, &ch) && ch == '-') {
          /* range expression */
          err = re_next(r, &ch, NULL);
          assert(!err && ch == '-');
          if ((err = re_next(
                   r, &ch, "expected ending character for range expression")))
            return err;
          if (ch == '\\') { /* start of escape */
            if ((err = re_parse_escape(r, (1 << CHR))))
              return err;
            next = stk_pop(r, &r->arg_stk);
            assert(*re_asttype(r, next) == CHR);
            max = *re_astarg(r, next, 0);
          } else {
            max = ch; /* non-escaped character */
          }
        }
        if ((err = re_mkast(r, CLS, min, max, res, &res)))
          return err;
      }
      assert(res);  /* charclass cannot be empty */
      if (inverted) /* inverted character class */
        *re_asttype(r, res) = ICLS;
      if ((err = stk_push(r, &r->arg_stk, res)))
        return err;
    } else if (ch == '\\') { /* escape */
      if ((err = re_parse_escape(
               r,
               1 << CHR | 1 << CLS | 1 << ANYBYTE | 1 << CAT | 1 << AASSERT)))
        return err;
    } else if (ch == '{') { /* repetition */
      u32 min = 0, max = 0;
      if ((err = re_parse_number(r, &min, 6)))
        return err;
      if ((err = re_next(r, &ch, "expected } to end repetition expression")))
        return err;
      if (ch == '}')
        max = min;
      else if (ch == ',') {
        if (!re_hasmore(r))
          return re_parse_err(
              r, "expected upper bound or } to end repetition expression");
        if ((err = re_peek_next(r, &ch)))
          return err;
        if (ch == '}')
          re_next(r, &ch, NULL), max = INFTY;
        else {
          if ((err = re_parse_number(r, &max, 6)))
            return err;
          if ((err =
                   re_next(r, &ch, "expected } to end repetition expression")))
            return err;
          if (ch != '}')
            return re_parse_err(r, "expected } to end repetition expression");
        }
      } else
        return re_parse_err(r, "expected } or , for repetition expression");
      if (!r->arg_stk.size)
        return re_parse_err(r, "cannot apply quantifier to empty regex");
      if ((err = re_mkast(r, QUANT, stk_pop(r, &r->arg_stk), min, max, &res)) ||
          (err = stk_push(r, &r->arg_stk, res)))
        return err;
    } else if (ch == '^' || ch == '$') { /* beginning/end of text/line */
      if ((err = re_mkast(
               r, AASSERT,
               ch == '^' ? (flags & MULTILINE ? LINE_BEGIN : TEXT_BEGIN)
                         : (flags & MULTILINE ? LINE_END : TEXT_END),
               0, 0, &res)) ||
          (err = stk_push(r, &r->arg_stk, res)))
        return err;
    } else { /* char: push to the arg stk */
      /* arg_stk: | ... | */
      if ((err = re_mkast(r, CHR, ch, 0, 0, &res)) ||
          (err = stk_push(r, &r->arg_stk, res)))
        return err;
      /* arg_stk: | ... | chr | */
    }
  }
  if ((err = re_fold(r)) || (err = re_fold_alts(r, &flags)))
    return err;
  if (r->op_stk.size)
    return re_parse_err(r, "unmatched open parenthesis");
  if ((err =
           re_mkast(r, GROUP, stk_pop(r, &r->arg_stk), SUBEXPRESSION, 0, root)))
    return err;
  return 0;
}

typedef struct inst {
  u32 l, h;
} inst;

#define INST_OP(i)     ((i).l & 3)
#define INST_N(i)      ((i).l >> 2)
#define INST_P(i)      ((i).h)
#define INST(op, n, p) mkinst((op) | ((n) << 2), (p))

inst mkinst(u32 l, u32 h)
{
  inst out;
  out.l = l, out.h = h;
  return out;
}

void re_prog_set(re *r, u32 pc, inst i)
{
  r->prog.ptr[pc * 2 + 0] = i.l, r->prog.ptr[pc * 2 + 1] = i.h;
}

inst re_prog_get(re *r, u32 pc)
{
  return mkinst(r->prog.ptr[pc * 2 + 0], r->prog.ptr[pc * 2 + 1]);
}

u32 re_prog_size(re *r) { return r->prog.size >> 1; }

#define PROGMAX 100000

int re_emit(re *r, inst i)
{
  int err = 0;
  if (re_prog_size(r) == PROGMAX)
    return ERR_LIMIT;
  if ((err = stk_push(r, &r->prog, 0)) || (err = stk_push(r, &r->prog, 0)))
    return err;
  re_prog_set(r, re_prog_size(r) - 1, i);
  return err;
}

typedef struct compframe {
  u32 root_ref, child_ref, idx, patch_head, patch_tail, pc, flags;
} compframe;

int compframe_push(re *r, compframe c)
{
  return stk_pushn(r, &r->comp_stk, &c, sizeof(c));
}

compframe compframe_pop(re *r)
{
  compframe v;
  stk_popn(r, &r->comp_stk, &v, sizeof(v));
  return v;
}

enum op { RANGE, ASSERT, MATCH, SPLIT };

#define IMATCH(s, i) ((i) << 1 | (s))
#define IMATCH_S(m)  ((m) & 1)
#define IMATCH_I(m)  ((m) >> 1)

inst patch_set(re *r, u32 pc, u32 val)
{
  inst prev = re_prog_get(r, pc >> 1);
  assert(pc);
  re_prog_set(
      r, pc >> 1,
      INST(
          INST_OP(prev), pc & 1 ? INST_N(prev) : val,
          pc & 1 ? val : INST_P(prev)));
  return prev;
}

void patch_add(re *r, compframe *f, u32 dest_pc, int p)
{
  u32 out_val = dest_pc << 1 | !!p;
  assert(dest_pc);
  if (!f->patch_head)
    f->patch_head = f->patch_tail = out_val;
  else {
    patch_set(r, f->patch_tail, out_val);
    f->patch_tail = out_val;
  }
}

void patch_merge(re *r, compframe *p, compframe *q)
{
  if (!p->patch_head) {
    p->patch_head = q->patch_head;
    p->patch_tail = q->patch_tail;
    return;
  }
  patch_set(r, p->patch_tail, q->patch_head);
  p->patch_tail = q->patch_tail;
}

void patch_xfer(compframe *dst, compframe *src)
{
  dst->patch_head = src->patch_head;
  dst->patch_tail = src->patch_tail;
  src->patch_head = src->patch_tail = REF_NONE;
}

void patch(re *r, compframe *p, u32 dest_pc)
{
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

int ccpush(re *r, stk *cc, u32 min, u32 max)
{
  int err = 0;
  (err = stk_push(r, cc, min)) || (err = stk_push(r, cc, max));
  return err;
}

void ccget(stk *cc, size_t idx, u32 *min, u32 *max)
{
  *min = cc->ptr[idx * 2], *max = cc->ptr[idx * 2 + 1];
}

void ccswap(stk *cc, size_t a, size_t b)
{
  size_t t0 = cc->ptr[a * 2], t1 = cc->ptr[a * 2 + 1];
  cc->ptr[a * 2] = cc->ptr[b * 2];
  cc->ptr[a * 2 + 1] = cc->ptr[b * 2 + 1];
  cc->ptr[b * 2] = t0;
  cc->ptr[b * 2 + 1] = t1;
}

size_t ccsize(stk *cc) { return cc->size >> 1; }

void re_compcc_hsort(stk *cc, size_t n)
{
  size_t start = n >> 1, end = n, root, child;
  while (end > 1) {
    if (start)
      start--;
    else
      ccswap(cc, --end, 0);
    root = start;
    while ((child = i_lc(root)) < end) {
      if (child + 1 < end && cckey(cc, child) < cckey(cc, child + 1))
        child++;
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

compcc_node *cc_treeref(stk *cc, u32 ref)
{
  return (compcc_node *)stk_getn(cc, ref * stk_elemsize(sizeof(compcc_node)));
}

u32 cc_treesize(stk *cc) { return stk_size(cc, sizeof(compcc_node)); }

int cc_treenew(re *r, stk *cc_out, compcc_node node, u32 *out)
{
  int err = 0;
  if (!cc_out->size) {
    compcc_node sentinel = {0};
    /* need to create sentinel node */
    if ((err = stk_pushn(r, cc_out, &sentinel, sizeof(compcc_node))))
      return err;
  }
  *out = stk_size(cc_out, sizeof(compcc_node));
  if ((err = stk_pushn(r, cc_out, &node, sizeof(compcc_node))))
    return err;
  return 0;
}

int cc_treeappend(re *r, stk *cc, u32 range, u32 parent, u32 *out)
{
  compcc_node *parent_node, child_node = {0};
  u32 child_ref;
  int err;
  parent_node = cc_treeref(cc, parent);
  child_node.sibling_ref = parent_node->child_ref, child_node.range = range;
  if ((err = cc_treenew(r, cc, child_node, &child_ref)))
    return err;
  parent_node = cc_treeref(cc, parent); /* ref could be stale */
  parent_node->child_ref = child_ref;
  assert(parent_node->child_ref != parent);
  assert(parent_node->sibling_ref != parent);
  assert(child_node.child_ref != parent_node->child_ref);
  assert(child_node.sibling_ref != parent_node->child_ref);
  *out = parent_node->child_ref;
  return 0;
}

int re_compcc_buildtree_split(
    re *r, stk *cc_out, u32 parent, u32 min, u32 max, u32 x_bits, u32 y_bits)
{
  u32 x_mask = (1 << x_bits) - 1, y_min = min >> x_bits, y_max = max >> x_bits,
      u_mask = (0xFE << y_bits) & 0xFF, byte_min = (y_min & 0xFF) | u_mask,
      byte_max = (y_max & 0xFF) | u_mask, i, next;
  int err = 0;
  assert(y_bits <= 7);
  if (x_bits == 0) {
    if ((err = cc_treeappend(
             r, cc_out, br2u(mkbr(byte_min, byte_max)), parent, &next)))
      return err;
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
      compcc_node *parent_node;
      u32 child_ref;
      /* check if previous child intersects and then compute intersection */
      assert(parent);
      parent_node = cc_treeref(cc_out, parent);
      if (parent_node->sibling_ref &&

          br_isect(
              u2br(cc_treeref(cc_out, parent_node->sibling_ref)->range),
              u2br(brs[i]))) {
        child_ref = parent_node->sibling_ref;
      } else {
        if ((err = cc_treeappend(r, cc_out, brs[i], parent, &child_ref)))
          return err;
      }
      if ((err = re_compcc_buildtree_split(
               r, cc_out, child_ref, mins[i], maxs[i], x_bits - 6, 6)))
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
int re_compcc_buildtree(re *r, stk *cc_in, stk *cc_out)
{
  size_t i, j;
  u32 root_ref;
  compcc_node root_node;
  int err = 0;
  root_node.child_ref = root_node.sibling_ref = root_node.hash =
      root_node.range = 0;
  /* clear output charclass */
  cc_out->size = 0;
  if ((err = cc_treenew(r, cc_out, root_node, &root_ref)))
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
        if ((err = re_compcc_buildtree_split(
                 r, cc_out, root_ref, clamped_min, clamped_max, x_bits[j],
                 y_bits[j])))
          return err;
      }
      min_bound = max_bound + 1;
    }
  }
  return err;
}

int re_compcc_treeeq(re *r, stk *cc_tree_in, compcc_node *a, compcc_node *b)
{
  u32 a_child_ref = a->child_ref, b_child_ref = b->child_ref;
  while (a_child_ref && b_child_ref) {
    compcc_node *a_child = cc_treeref(cc_tree_in, a_child_ref),
                *b_child = cc_treeref(cc_tree_in, b_child_ref);
    if (!re_compcc_treeeq(r, cc_tree_in, a_child, b_child))
      return 0;
    a_child_ref = a_child->sibling_ref, b_child_ref = b_child->sibling_ref;
  }
  if (a_child_ref != b_child_ref)
    return 0;
  return a->range == b->range;
}

void re_compcc_merge_one(stk *cc_tree_in, u32 child_ref, u32 sibling_ref)
{
  compcc_node *child = cc_treeref(cc_tree_in, child_ref),
              *sibling = cc_treeref(cc_tree_in, sibling_ref);
  child->sibling_ref = sibling->sibling_ref;
  assert(br_adjace(u2br(child->range), u2br(sibling->range)));
  child->range = br2u(mkbr(u2br(child->range).l, u2br(sibling->range).h));
}

/*https://nullprogram.com/blog/2018/07/31/*/
u32 hashington(u32 x)
{
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

int cc_htinit(re *r, stk *cc_tree_in, stk *cc_ht_out)
{
  int err = 0;
  while (cc_htsize(cc_ht_out) <
         (cc_treesize(cc_tree_in) + (cc_treesize(cc_tree_in) >> 1)))
    if ((err = stk_push(r, cc_ht_out, 0)) || (err = stk_push(r, cc_ht_out, 0)))
      return err;
  memset(cc_ht_out->ptr, 0, cc_ht_out->size * sizeof(u32));
  return 0;
}

void re_compcc_hashtree(re *r, stk *cc_tree_in, stk *cc_ht_out, u32 parent_ref)
{
  /* flip links and hash everything */
  compcc_node *parent_node = cc_treeref(cc_tree_in, parent_ref);
  u32 child_ref, next_child_ref, sibling_ref = 0;
  child_ref = parent_node->child_ref;
  while (child_ref) {
    compcc_node *child_node = cc_treeref(cc_tree_in, child_ref), *sibling_node;
    next_child_ref = child_node->sibling_ref;
    child_node->sibling_ref = sibling_ref;
    re_compcc_hashtree(r, cc_tree_in, cc_ht_out, child_ref);
    if (sibling_ref) {
      sibling_node = cc_treeref(cc_tree_in, sibling_ref);
      if (br_adjace(u2br(child_node->range), u2br(sibling_node->range))) {
        if (!sibling_node->child_ref) {
          if (!child_node->child_ref) {
            re_compcc_merge_one(cc_tree_in, child_ref, sibling_ref);
          }
        } else {
          if (child_node->child_ref) {
            compcc_node *child_child =
                            cc_treeref(cc_tree_in, child_node->child_ref),
                        *sibling_child =
                            cc_treeref(cc_tree_in, sibling_node->child_ref);
            if (re_compcc_treeeq(r, cc_tree_in, child_child, sibling_child)) {
              re_compcc_merge_one(cc_tree_in, child_ref, sibling_ref);
            }
          }
        }
      }
    }
    {
      u32 hash_plain[3] = {0x6D99232E, 0xC281FF0B, 0x54978D96};
      memset(hash_plain, 0, sizeof(hash_plain));
      hash_plain[0] ^= child_node->range;
      if (child_node->sibling_ref) {
        compcc_node *child_sibling_node =
            cc_treeref(cc_tree_in, child_node->sibling_ref);
        hash_plain[1] = child_sibling_node->hash;
      }
      if (child_node->child_ref) {
        compcc_node *child_child_node =
            cc_treeref(cc_tree_in, child_node->child_ref);
        hash_plain[2] = child_child_node->hash;
      }
      child_node->hash = hashington(
          hashington(hashington(hash_plain[0]) + hash_plain[1]) +
          hash_plain[2]);
    }
    sibling_ref = child_ref;
    sibling_node = child_node;
    child_ref = next_child_ref;
  }
  parent_node->child_ref = sibling_ref;
}

int re_compcc_rendertree(
    re *r, stk *cc_tree_in, stk *cc_ht, u32 node_ref, u32 *my_out_pc,
    compframe *frame)
{
  int err = 0;
  u32 split_from = 0, my_pc = 0, range_pc = 0;
  while (node_ref) {
    compcc_node *node = cc_treeref(cc_tree_in, node_ref);
    u32 probe, found;
    probe = node->hash << 1;
    /* check if child is in the hash table */
    while (1) {
      if (!((found = cc_ht->ptr[probe % cc_ht->size]) & 1))
        /* child is NOT in the cache */
        break;
      else {
        /* something is in the cache, but it might not be a child */
        compcc_node *other_node = cc_treeref(cc_tree_in, found >> 1);
        if (re_compcc_treeeq(r, cc_tree_in, node, other_node)) {
          if (split_from) {
            inst i = re_prog_get(r, split_from);
            /* found our child, patch into it */
            i = INST(
                INST_OP(i), INST_N(i), cc_ht->ptr[(probe % cc_ht->size) + 1]);
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
    if (node->sibling_ref) {
      /* need a split */
      split_from = my_pc;
      if ((err = re_emit(r, INST(SPLIT, my_pc + 1, 0))))
        return err;
    }
    if (!*my_out_pc)
      *my_out_pc = my_pc;
    range_pc = re_prog_size(r);
    if ((err = re_emit(
             r,
             INST(
                 RANGE, 0,
                 br2u(BYTE_RANGE(u2br(node->range).l, u2br(node->range).h))))))
      return err;
    if (node->child_ref) {
      /* need to down-compile */
      u32 their_pc = 0;
      inst i = re_prog_get(r, range_pc);
      if ((err = re_compcc_rendertree(
               r, cc_tree_in, cc_ht, node->child_ref, &their_pc, frame)))
        return err;
      i = INST(INST_OP(i), their_pc, INST_P(i));
      re_prog_set(r, range_pc, i);
    } else {
      /* terminal: patch out */
      patch_add(r, frame, range_pc, 0);
    }
    cc_ht->ptr[(probe % cc_ht->size) + 0] = node_ref << 1 | 1;
    cc_ht->ptr[(probe % cc_ht->size) + 1] = my_pc;
    node_ref = node->sibling_ref;
  }
  assert(*my_out_pc);
  return 0;
}

int casefold_fold_range(re *r, u32 begin, u32 end, stk *cc_out);

int re_compcc(re *r, u32 root, compframe *frame)
{
  int err = 0, inverted = *re_asttype(r, frame->root_ref) == ICLS,
      insensitive = !!(frame->flags & INSENSITIVE);
  u32 start_pc = 0;
  r->cc_stk_a.size = r->cc_stk_b.size = 0; /* clear stks */
  /* push ranges */
  while (root) {
    u32 args[3], min, max;
    re_decompast(r, root, args);
    min = args[0], max = args[1], root = args[2];
    /* handle out-of-order ranges (min > max) */
    if ((err = stk_push(r, &r->cc_stk_a, min > max ? max : min)) ||
        (err = stk_push(r, &r->cc_stk_a, min > max ? min : max)))
      return err;
  }
  do {
    /* sort ranges */
    re_compcc_hsort(&r->cc_stk_a, ccsize(&r->cc_stk_a));
    /* normalize ranges */
    {
      u32 min, max, cur_min, cur_max;
      size_t i;
      for (i = 0; i < ccsize(&r->cc_stk_a); i++) {
        ccget(&r->cc_stk_a, i, &cur_min, &cur_max);
        assert(cur_min <= cur_max);
        if (!i)
          min = cur_min, max = cur_max; /* first range */
        else if (cur_min <= max + 1) {
          max = cur_max > max ? cur_max : max; /* intersection */
        } else {
          /* disjoint */
          if ((err = ccpush(r, &r->cc_stk_b, min, max)))
            return err;
          min = cur_min, max = cur_max;
        }
      }
      if (i && (err = ccpush(r, &r->cc_stk_b, min, max)))
        return err;
      if (insensitive) {
        /* casefold normalized ranges */
        r->cc_stk_a.size = 0;
        for (i = 0; i < ccsize(&r->cc_stk_b); i++) {
          ccget(&r->cc_stk_a, i, &cur_min, &cur_max);
          if ((err = ccpush(r, &r->cc_stk_a, cur_min, cur_max)))
            return err;
          if ((err = casefold_fold_range(r, cur_min, cur_max, &r->cc_stk_a)))
            return err;
        }
      }
    }
  } while (insensitive && insensitive-- /* re-normalize by looping again */);
  /* invert ranges */
  if (inverted) {
    u32 max = 0, cur_min, cur_max, i, old_size = ccsize(&r->cc_stk_b);
    r->cc_stk_b.size = 0; /* TODO: this is shitty code */
    for (i = 0; i < old_size; i++) {
      ccget(&r->cc_stk_b, i, &cur_min, &cur_max);
      if (cur_min > max) {
        if ((err = ccpush(r, &r->cc_stk_b, max, cur_min - 1)))
          return err;
        else
          max = cur_max + 1;
      }
    }
    if (cur_max < UTFMAX &&
        (err = ccpush(r, &r->cc_stk_b, cur_max + 1, UTFMAX)))
      return err;
  }
  if (!ccsize(&r->cc_stk_b)) {
    /* empty charclass */
    if ((err =
             re_emit(r, INST(ASSERT, 0, WORD | NOT_WORD)))) /* never matches */
      return err;
    patch_add(r, frame, re_prog_size(r) - 1, 0);
    return err;
  }
  /* build tree */
  r->cc_stk_a.size = 0;
  if ((err = re_compcc_buildtree(r, &r->cc_stk_b, &r->cc_stk_a)))
    return err;
  /* hash tree */
  if ((err = cc_htinit(r, &r->cc_stk_a, &r->cc_stk_b)))
    return err;
  re_compcc_hashtree(r, &r->cc_stk_a, &r->cc_stk_b, 1);
  /* prune/render tree */
  if ((err = re_compcc_rendertree(
           r, &r->cc_stk_a, &r->cc_stk_b, 2 /* root's first node */, &start_pc,
           frame)))
    return err;
  return err;
}

int re_compile(re *r, u32 root, u32 reverse)
{
  int err = 0;
  compframe initial_frame = {0}, returned_frame = {0}, child_frame = {0};
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
    if (frame.root_ref)
      re_decompast(r, frame.root_ref, args);
    if (!frame.root_ref) {
      /* epsilon */
      /*  in  out  */
      /* --------> */
    } else if (type == CHR) {
      patch(r, &frame, my_pc);
      if (args[0] < 128 && !(frame.flags & INSENSITIVE)) { /* ascii */
        /*  in     out
         * ---> R ----> */
        if ((err = re_emit(
                 r, INST(RANGE, 0, br2u(BYTE_RANGE(args[0], args[0]))))))
          return err;
        patch_add(r, &frame, my_pc, 0);
      } else { /* unicode */
        /* create temp ast */
        if (!tmp_cc_ast &&
            (err = re_mkast(r, CLS, 0, 0, REF_NONE, &tmp_cc_ast)))
          return err;
        *re_astarg(r, tmp_cc_ast, 0) = *re_astarg(r, tmp_cc_ast, 1) = args[0];
        if ((err = re_compcc(r, tmp_cc_ast, &frame)))
          return err;
      }
    } else if (type == ANYBYTE) {
      /*  in     out
       * ---> R ----> */
      patch(r, &frame, my_pc);
      if ((err = re_emit(r, INST(RANGE, 0, br2u(BYTE_RANGE(0x00, 0xFF))))))
        return err;
      patch_add(r, &frame, my_pc, 0);
    } else if (type == CAT) {
      /*  in              out
       * ---> [A] -> [B] ----> */
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
      if (frame.idx == 0) { /* before left child */
        patch(r, &frame, frame.pc);
        if ((err = re_emit(r, INST(SPLIT, 0, 0))))
          return err;
        patch_add(r, &child_frame, frame.pc, 0);
        frame.child_ref = args[0], frame.idx++;
      } else if (frame.idx == 1) { /* after left child */
        patch_merge(r, &frame, &returned_frame);
        patch_add(r, &child_frame, frame.pc, 1);
        frame.child_ref = args[1], frame.idx++;
      } else if (frame.idx == 2) { /* after right child */
        patch_merge(r, &frame, &returned_frame);
      }
    } else if (type == QUANT || type == UQUANT) {
      /*        +-------+
       *  in   /         \
       * ---> S -> [A] ---+
       *       \             out
       *        +-----------------> */
      u32 child = args[0], min = args[1], max = args[2],
          is_greedy = !(frame.flags & UNGREEDY) ^ (type == UQUANT);
      assert((min != INFTY && max != INFTY) || min != max);
      if (frame.idx < min) { /* before minimum bound */
        patch_xfer(&child_frame, frame.idx ? &returned_frame : &frame);
        frame.child_ref = child;
      } else if (max == INFTY && frame.idx == min) { /* before inf. bound */
        patch(r, frame.idx ? &returned_frame : &frame, my_pc);
        if ((err = re_emit(r, INST(SPLIT, 0, 0))))
          return err;
        frame.pc = my_pc;
        patch_add(r, &child_frame, my_pc, !is_greedy);
        patch_add(r, &frame, my_pc, is_greedy);
        frame.child_ref = child;
      } else if (max == INFTY && frame.idx == min + 1) { /* after inf. bound */
        patch(r, &returned_frame, frame.pc);
      } else if (frame.idx < max) { /* before maximum bound */
        patch(r, frame.idx ? &returned_frame : &frame, my_pc);
        if ((err = re_emit(r, INST(SPLIT, 0, 0))))
          return err;
        patch_add(r, &child_frame, my_pc, !is_greedy);
        patch_add(r, &frame, my_pc, is_greedy);
        frame.child_ref = child;
      } else if (frame.idx == max) { /* after maximum bound */
        patch_merge(r, &frame, &returned_frame);
      }
      frame.idx++;
    } else if (type == GROUP || type == IGROUP) {
      /*  in                 out
       * ---> M -> [A] -> M ----> */
      u32 child = args[0], flags = args[1];
      frame.flags = flags & ~SUBEXPRESSION; /* we shouldn't propagate this */
      if (!frame.idx) {                     /* before child */
        if (!(flags & NONCAPTURING)) {
          patch(r, &frame, my_pc);
          if (flags & SUBEXPRESSION) {
            /* for subexpressions: generate an initial match instruction */
            grp_idx = 1;
            if ((err = re_emit(r, INST(MATCH, 0, IMATCH(0, 1 + set_idx++)))))
              return err;
          } else if
              /* for regular groups: generate a save instruction corresponding
                 to the start of the group */
              ((err = re_emit(
                    r, INST(MATCH, 0, IMATCH(1, 2 * grp_idx++ + reverse)))))
            return err;
          patch_add(r, &child_frame, my_pc, 0);
        } else
          patch_xfer(&child_frame, &frame);
        frame.child_ref = child, frame.idx++;
      } else if (frame.idx) { /* after child */
        if (!(flags & NONCAPTURING)) {
          patch(r, &returned_frame, my_pc);
          if ((flags & SUBEXPRESSION)) {
            /* for subexpressions: generate the final match instruction */
            if ((err = re_emit(r, INST(MATCH, 0, IMATCH(1, reverse)))))
              return err;
          } else {
            /* for regular groups: generate a save instruction corresponding to
             * the end of the group */
            if ((err = re_emit(
                     r, INST(
                            MATCH, 0,
                            IMATCH(
                                1, IMATCH_I(INST_P(re_prog_get(r, frame.pc))) +
                                       (reverse ? -1 : 1))))))
              return err;
            patch_add(r, &frame, my_pc, 0);
          }
        } else
          patch_merge(r, &frame, &returned_frame);
      }
    } else if (type == CLS || type == ICLS) {
      patch(r, &frame, my_pc);
      if ((err = re_compcc(r, frame.root_ref, &frame)))
        return err;
    } else if (type == AASSERT) {
      u32 assert_flag = args[0];
      patch(r, &frame, my_pc);
      if ((err = re_emit(r, INST(ASSERT, 0, assert_flag))))
        return err;
      patch_add(r, &frame, my_pc, 0);
    } else {
      assert(0);
    }
    if (frame.child_ref != frame.root_ref) {
      /* should we push a child? */
      if ((err = compframe_push(r, frame)))
        return err;
      child_frame.root_ref = frame.child_ref;
      child_frame.idx = 0;
      child_frame.pc = re_prog_size(r);
      child_frame.flags = frame.flags;
      if ((err = compframe_push(r, child_frame)))
        return err;
    }
    returned_frame = frame;
  }
  assert(!r->comp_stk.size);
  assert(!returned_frame.patch_head && !returned_frame.patch_tail);
  {
    u32 dstar = r->entry[ENT_DOTSTAR | (reverse ? ENT_REV : ENT_FWD)] =
        re_prog_size(r);
    if ((err = re_emit(
             r,
             INST(
                 SPLIT, r->entry[ENT_ONESHOT | (reverse ? ENT_REV : ENT_FWD)],
                 dstar + 1))))
      return err;
    if ((err = re_emit(r, INST(RANGE, dstar, br2u(mkbr(0, 255))))))
      return err;
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

int sset_reset(re *r, sset *s, size_t sz)
{
  size_t next_alloc = sz;
  u32 *next_sparse;
  thrdspec *next_dense;
  if (!next_alloc)
    return 0;
  if (!(next_sparse = re_ialloc(
            r, sizeof(u32) * s->sparse_alloc, sizeof(u32) * next_alloc,
            s->sparse)))
    return ERR_MEM;
  s->sparse = next_sparse;
  if (!(next_dense = re_ialloc(
            r, sizeof(thrdspec) * s->dense_alloc, sizeof(thrdspec) * next_alloc,
            s->dense)))
    return ERR_MEM;
  s->dense = next_dense;
  s->dense_size = 0;
  s->dense_alloc = next_alloc;
  return 0;
}

void sset_clear(sset *s) { s->dense_size = 0; }

void sset_init(re *r, sset *s)
{
  (void)(r);
  s->sparse = NULL;
  s->sparse_alloc = 0;
  s->dense = NULL;
  s->dense_alloc = s->dense_size = 0;
}

void sset_destroy(re *r, sset *s)
{
  re_ialloc(r, sizeof(u32) * s->sparse_alloc, 0, s->sparse);
  re_ialloc(r, sizeof(thrdspec) * s->dense_alloc, 0, s->dense);
}

int sset_memb(sset *s, u32 pc)
{
  assert(pc < s->dense_alloc);
  return s->sparse[pc] < s->dense_size && s->dense[s->sparse[pc]].pc == pc;
}

void sset_add(sset *s, thrdspec spec)
{
  assert(spec.pc < s->dense_alloc);
  assert(s->dense_size < s->dense_alloc);
  assert(spec.pc);
  if (sset_memb(s, spec.pc))
    return;
  s->dense[s->dense_size] = spec;
  s->sparse[spec.pc] = s->dense_size++;
}

typedef struct save_slots {
  size_t *slots, slots_size, slots_alloc, last_empty, per_thrd;
} save_slots;

void save_slots_init(re *r, save_slots *s)
{
  (void)r;
  s->slots = NULL;
  s->slots_size = s->slots_alloc = s->last_empty = s->per_thrd = 0;
}

void save_slots_destroy(re *r, save_slots *s)
{
  re_ialloc(r, sizeof(size_t) * s->slots_alloc, 0, s->slots);
}

void save_slots_clear(save_slots *s, size_t per_thrd)
{
  s->slots_size = 0, s->last_empty = 0,
  s->per_thrd = per_thrd + 2 /* for refcnt and setidx */;
}

int save_slots_new(re *r, save_slots *s, u32 *next)
{
  assert(s->per_thrd);
  if (s->last_empty) {
    /* reclaim */
    *next = s->last_empty;
    s->last_empty = s->slots[*next * s->per_thrd];
  } else {
    if ((s->slots_size + 1) * (s->per_thrd + 1) > s->slots_alloc) {
      /* initial alloc / realloc */
      size_t new_alloc =
          (s->slots_alloc ? s->slots_alloc * 2 : 16) * s->per_thrd;
      size_t *new_slots = re_ialloc(
          r, s->slots_alloc * sizeof(size_t), new_alloc * sizeof(size_t),
          s->slots);
      if (!new_slots)
        return ERR_MEM;
      s->slots = new_slots, s->slots_alloc = new_alloc;
    }
    if (!s->slots_size) {
      /* initial allocation */
      memset(s->slots + s->slots_size, 0, sizeof(*s->slots) * s->per_thrd);
      s->slots_size++;
    }
    *next = s->slots_size++;
    assert(s->slots_size * s->per_thrd <= s->slots_alloc);
  }
  memset(s->slots + *next * s->per_thrd, 0, sizeof(*s->slots) * s->per_thrd);
  s->slots[*next * s->per_thrd + s->per_thrd - 1] =
      1; /* initial refcount = 1 */
  return 0;
}

u32 save_slots_fork(save_slots *s, u32 ref)
{
  if (s->per_thrd)
    s->slots[ref * s->per_thrd + s->per_thrd - 1]++;
  return ref;
}

void save_slots_kill(save_slots *s, u32 ref)
{
  if (!s->per_thrd)
    return;
  if (!s->slots[ref * s->per_thrd + s->per_thrd - 1]--) {
    /* prepend to free list */
    s->slots[ref * s->per_thrd] = s->last_empty;
    s->last_empty = ref;
  }
}

int save_slots_set_internal(
    re *r, save_slots *s, u32 ref, u32 idx, size_t v, u32 *out)
{
  int err;
  *out = ref;
  assert(idx < s->per_thrd - 1);
  if (!s->per_thrd) {
    /* not saving anything */
    assert(0);
  } else if (v == s->slots[ref * s->per_thrd + idx]) {
    /* not changing anything */
  } else if (!s->slots[ref * s->per_thrd + s->per_thrd - 1]) {
    s->slots[ref * s->per_thrd + idx] = v;
  } else {
    if ((err = save_slots_new(r, s, out)))
      return err;
    save_slots_kill(s, ref); /* decrement refcount */
    assert(
        s->slots[*out * s->per_thrd + s->per_thrd - 1] ==
        1); /* new refcount is 1 */
    memcpy(
        s->slots + *out * s->per_thrd, s->slots + ref * s->per_thrd,
        sizeof(*s->slots) *
            (s->per_thrd - 1) /* leave refcount at 1 for new slot */);
    s->slots[*out * s->per_thrd + idx] = v; /* and update the requested value */
  }
  return 0;
}

u32 save_slots_perthrd(save_slots *s)
{
  return s->per_thrd ? s->per_thrd - 2 : s->per_thrd;
}

int save_slots_set(re *r, save_slots *s, u32 ref, u32 idx, size_t v, u32 *out)
{
  assert(idx < save_slots_perthrd(s));
  return save_slots_set_internal(r, s, ref, idx, v, out);
}

int save_slots_set_setidx(re *r, save_slots *s, u32 ref, u32 setidx, u32 *out)
{
  return save_slots_set_internal(r, s, ref, s->per_thrd - 2, (u32)setidx, out);
}

u32 save_slots_get(save_slots *s, u32 ref, u32 idx)
{
  assert(idx < save_slots_perthrd(s));
  return s->slots[ref * s->per_thrd + idx];
}

u32 save_slots_get_setidx(save_slots *s, u32 ref)
{
  return s->slots[ref * s->per_thrd + s->per_thrd - 2];
}

typedef struct exec_nfa {
  sset a, b, c;
  stk thrd_stk;
  save_slots slots;
  stk pri_stk, pri_bmp, pri_bmp_tmp;
  int reversed, track;
} exec_nfa;

void exec_nfa_init(re *r, exec_nfa *n)
{
  sset_init(r, &n->a), sset_init(r, &n->b), sset_init(r, &n->c);
  stk_init(r, &n->thrd_stk);
  save_slots_init(r, &n->slots);
  stk_init(r, &n->pri_stk), stk_init(r, &n->pri_bmp),
      stk_init(r, &n->pri_bmp_tmp);
  n->reversed = n->track = 0;
}

void exec_nfa_destroy(re *r, exec_nfa *n)
{
  sset_destroy(r, &n->a), sset_destroy(r, &n->b), sset_destroy(r, &n->c);
  stk_destroy(r, &n->thrd_stk);
  save_slots_destroy(r, &n->slots);
  stk_destroy(r, &n->pri_stk), stk_destroy(r, &n->pri_bmp),
      stk_destroy(r, &n->pri_bmp_tmp);
}

int thrdstk_push(re *r, stk *s, thrdspec t)
{
  int err = 0;
  assert(t.pc);
  (err = stk_push(r, s, t.pc)) || (err = stk_push(r, s, t.slot));
  return err;
}

thrdspec thrdstk_pop(re *r, stk *s)
{
  thrdspec out;
  out.slot = stk_pop(r, s);
  out.pc = stk_pop(r, s);
  return out;
}

#define BITS_PER_U32 (sizeof(u32) * CHAR_BIT)

int bmp_init(re *r, stk *s, u32 size)
{
  u32 i;
  int err = 0;
  s->size = 0;
  for (i = 0; i < (size + BITS_PER_U32) / BITS_PER_U32; i++)
    if ((err = stk_push(r, s, 0))) /* TODO: change this to a bulk allocation */
      return err;
  return err;
}

void bmp_clear(stk *s) { memset(s->ptr, 0, s->size * sizeof(u32)); }

void bmp_set(stk *s, u32 idx)
{
  /* TODO: assert idx < nsets */
  s->ptr[idx / BITS_PER_U32] |= (1 << (idx % BITS_PER_U32));
}

/* returns 0 or a positive value (not necessarily 1) */
u32 bmp_get(stk *s, u32 idx)
{
  return s->ptr[idx / BITS_PER_U32] & (1 << (idx % BITS_PER_U32));
}

int exec_nfa_start(
    re *r, exec_nfa *n, u32 pc, u32 noff, int reversed, int track)
{
  thrdspec initial_thrd;
  u32 i;
  int err = 0;
  if ((err = sset_reset(r, &n->a, r->prog.size)) ||
      (err = sset_reset(r, &n->b, r->prog.size)) ||
      (err = sset_reset(r, &n->c, r->prog.size)))
    return err;
  n->thrd_stk.size = 0, n->pri_stk.size = 0;
  save_slots_clear(&n->slots, noff);
  initial_thrd.pc = pc;
  if ((err = save_slots_new(r, &n->slots, &initial_thrd.slot)))
    return err;
  sset_add(&n->a, initial_thrd);
  initial_thrd.pc = initial_thrd.slot = 0;
  for (i = 0; i < r->ast_sets; i++)
    if ((err = stk_push(r, &n->pri_stk, 0)))
      return err;
  if ((err = bmp_init(r, &n->pri_bmp, r->ast_sets)) ||
      (err = bmp_init(r, &n->pri_bmp_tmp, r->ast_sets)))
    return err;
  n->reversed = reversed;
  n->track = track;
  return 0;
}

#define IMPLIES(subj, pred) (!(subj) || (pred))

int exec_nfa_eps(re *r, exec_nfa *n, size_t pos, assert_flag ass)
{
  int err;
  size_t i;
  sset_clear(&n->b);
  for (i = 0; i < n->a.dense_size; i++) {
    thrdspec thrd = n->a.dense[i];
    if ((err = thrdstk_push(r, &n->thrd_stk, thrd)))
      return err;
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
        if (INST_N(op)) {
          u32 idx = IMATCH_S(INST_P(op))
                        ? IMATCH_I(INST_P(op)) /* this is a save */
                        : n->reversed /* this is a set index marker */;
          if (!IMATCH_S(INST_P(op)) &&
              (err = save_slots_set_setidx(
                   r, &n->slots, top.slot, IMATCH_I(INST_P(op)), &top.slot)))
            return err;
          if (idx < save_slots_perthrd(&n->slots) &&
              (err =
                   save_slots_set(r, &n->slots, top.slot, idx, pos, &top.slot)))
            return err;
          top.pc = INST_N(op);
          if ((err = thrdstk_push(r, &n->thrd_stk, top)))
            return err;
          break;
        } /* else fall-through */
      case RANGE:
        sset_add(&n->b, top); /* this is a range or final match */
        break;
      case SPLIT: {
        thrdspec pri, sec;
        pri.pc = INST_N(op), pri.slot = top.slot;
        sec.pc = INST_P(op), sec.slot = save_slots_fork(&n->slots, top.slot);
        if ((err = thrdstk_push(r, &n->thrd_stk, sec)) ||
            (err = thrdstk_push(r, &n->thrd_stk, pri)))
          /* sec is pushed first because it needs to be processed after pri.
           * pri comes off the stack first because it's FIFO. */
          return err;
        break;
      }
      case ASSERT: {
        assert(!!(ass & WORD) ^ !!(ass & NOT_WORD));
        if ((INST_P(op) & ass) == INST_P(op)) {
          top.pc = INST_N(op);
          if ((err = thrdstk_push(r, &n->thrd_stk, top)))
            return err;
        } else
          save_slots_kill(&n->slots, top.slot);
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

int exec_nfa_matchend(
    re *r, exec_nfa *n, thrdspec thrd, size_t pos, unsigned int ch, int pri)
{
  int err = 0;
  u32 idx = save_slots_get_setidx(&n->slots, thrd.slot);
  u32 *memo = n->pri_stk.ptr + idx - 1;
  assert(idx > 0); /* save_slots_set_setidx() MUST have been called */
  assert(idx - 1 < n->pri_stk.size);
  if (!n->track && ch < 256)
    return err;
  if (n->slots.per_thrd) {
    u32 slot_idx = !n->reversed;
    if (*memo) {
      int older = 1, same = 0, better_pri = 0, same_pri = 0;
      if ((u32)n->reversed < save_slots_perthrd(&n->slots)) {
        size_t start = save_slots_get(
          &n->slots, thrd.slot,
          n->reversed /* TODO: should this actually be n->reversed or just 0 if we want leftmost matches */),
          other_start = save_slots_get(
          &n->slots, *memo,
          n->reversed /* TODO: should this actually be n->reversed or just 0 if we want leftmost matches */);

        older = start < other_start;
        same = start == other_start;
      }
      better_pri = !!bmp_get(&n->pri_bmp, idx) < pri;
      same_pri = !!bmp_get(&n->pri_bmp, idx) == pri;
      if (!older && !same)
        return 0;
      else if (older && !same) {
      } else if (!older && same) {
        if (better_pri || (same_pri && !pri)) {
        } else {
          return 0;
        }
      }
      save_slots_kill(&n->slots, *memo);
    }
    if (pri)
      bmp_set(&n->pri_bmp, idx);
    *memo = thrd.slot;
    if (slot_idx < save_slots_perthrd(&n->slots) &&
        (err = save_slots_set(r, &n->slots, thrd.slot, slot_idx, pos, memo)))
      return err;
  } else {
    *memo = 1; /* just mark that a set was matched */
  }
  return err;
}

int exec_nfa_chr(re *r, exec_nfa *n, unsigned int ch, size_t pos)
{
  int err;
  size_t i;
  bmp_clear(&n->pri_bmp_tmp);
  for (i = 0; i < n->b.dense_size; i++) {
    thrdspec thrd = n->b.dense[i];
    inst op = re_prog_get(r, thrd.pc);
    int pri =
        save_slots_perthrd(&n->slots)
            ? !bmp_get(
                  &n->pri_bmp_tmp, save_slots_get_setidx(&n->slots, thrd.slot))
            : 0;
    if (pri)
      bmp_set(&n->pri_bmp_tmp, save_slots_get_setidx(&n->slots, thrd.slot));
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
      assert(!INST_N(op));
      if ((err = exec_nfa_matchend(r, n, thrd, pos, ch, pri)))
        return err;
      break;
    }
    default:
      assert(0);
    }
  }
  return 0;
}

#define SENT_CH 256

int is_word_char(u32 ch)
{
  return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') ||
         (ch >= 'a' && ch <= 'z') || ch == '_';
}

assert_flag make_assert_flag(u32 prev_ch, u32 next_ch)
{
  return (prev_ch == SENT_CH) * TEXT_BEGIN | (next_ch == SENT_CH) * TEXT_END |
         (prev_ch == SENT_CH || prev_ch == '\n') * LINE_BEGIN |
         (next_ch == SENT_CH || next_ch == '\n') * LINE_END |
         ((is_word_char(prev_ch) == is_word_char(next_ch)) ? NOT_WORD : WORD);
}

/* return number of sets matched, -n otherwise */
/* 0th span is the full bounds, 1st is first group, etc. */
/* if max_set == 0 and max_span == 0 */
/* if max_set != 0 and max_span == 0 */
/* if max_set == 0 and max_span != 0 */
/* if max_set != 0 and max_span != 0 */
int exec_nfa_end(
    re *r, size_t pos, exec_nfa *n, u32 max_span, u32 max_set, span *out_span,
    u32 *out_set, u32 prev_ch)
{
  int err;
  size_t j, sets = 0, nset = 0;
  if ((err = exec_nfa_eps(r, n, pos, make_assert_flag(prev_ch, SENT_CH))) ||
      (err = exec_nfa_chr(r, n, 256, pos)))
    return err;
  for (sets = 0; sets < r->ast_sets && (max_set ? nset < max_set : nset < 1);
       sets++) {
    u32 slot = n->pri_stk.ptr[sets];
    if (!slot)
      continue; /* no match for this set */
    for (j = 0; (j < max_span) && out_span; j++) {
      out_span[nset * max_span + j].begin =
          save_slots_get(&n->slots, slot, j * 2);
      out_span[nset * max_span + j].end =
          save_slots_get(&n->slots, slot, j * 2 + 1);
    }
    if (out_set)
      out_set[nset] = sets;
    nset++;
  }
  return nset;
}

int exec_nfa_run(re *r, exec_nfa *n, u32 ch, size_t pos, u32 prev_ch)
{
  int err;
  (err = exec_nfa_eps(r, n, pos, make_assert_flag(prev_ch, ch))) ||
      (err = exec_nfa_chr(r, n, ch, pos));
  return err;
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

int re_match(
    re *r, const char *s, size_t n, u32 max_span, u32 max_set, span *out_span,
    u32 *out_set, anchor_type anchor)
{
  exec_nfa nfa;
  int err = 0;
  u32 entry = anchor == A_END          ? ENT_REV
              : anchor == A_UNANCHORED ? ENT_FWD | ENT_DOTSTAR
                                       : ENT_FWD;
  size_t i;
  u32 prev_ch = SENT_CH;
  if (!re_prog_size(r) && ((err = re_compile(r, r->ast_root, ENT_FWD)) ||
                           (err = re_compile(r, r->ast_root, ENT_REV))))
    return err;
  exec_nfa_init(r, &nfa);
  if ((err = exec_nfa_start(
           r, &nfa, r->entry[entry], max_span * 2, entry & ENT_REV,
           entry & ENT_DOTSTAR)))
    goto done;
  for (i = 0; i < n; i++) {
    if ((err = exec_nfa_run(r, &nfa, ((const u8 *)s)[i], i, prev_ch)))
      goto done;
    prev_ch = ((const u8 *)s)[i];
  }
  if ((err = exec_nfa_end(
           r, n, &nfa, max_span, max_set, out_span, out_set, prev_ch)))
    goto done;
done:
  exec_nfa_destroy(r, &nfa);
  return err;
}

#ifndef RE_COV

enum dumpformat { TERM, GRAPHVIZ };

char dump_hex(u8 d)
{
  d &= 0xF;
  if (d < 10)
    return '0' + d;
  else
    return 'A' + d - 10;
}

char *dump_chr(char *buf, u8 ch, int ascii)
{
  if (ch >= ' ' && ch < 0x7F)
    buf[0] = ch, buf[1] = 0;
  else if (
      (ch == '\a' && ch == 'a') || (ch == '\b' && ch == 'b') ||
      (ch == '\t' && ch == 't') || (ch == '\n' && ch == 'n') ||
      (ch == '\v' && ch == 'v') || (ch == '\f' && ch == 'f') ||
      (ch == '\r' && ch == 'r'))
    buf[0] = '\\', buf[1] = '\\', buf[2] = ch, buf[3] = 0;
  else if (ascii || (ch < 0x80))
    buf[0] = '\\', buf[1] = '\\', buf[2] = 'x', buf[3] = dump_hex(ch >> 4),
    buf[4] = dump_hex(ch), buf[5] = 0;
  else
    buf[0] = '\\', buf[1] = '\\', buf[2] = 'u', buf[3] = dump_hex(ch >> 20),
    buf[4] = dump_hex(ch >> 16), buf[5] = dump_hex(ch >> 12),
    buf[6] = dump_hex(ch >> 8), buf[7] = dump_hex(ch >> 4),
    buf[8] = dump_hex(ch), buf[9] = 0;
  return buf;
}

char *dump_chr_ascii(char *buf, u8 ch) { return dump_chr(buf, ch, 1); }

char *dump_chr_unicode(char *buf, u8 ch) { return dump_chr(buf, ch, 0); }

char *dump_assert(char *buf, assert_flag af)
{
  snprintf(
      buf, 32, "%s%s%s%s%s%s", af & LINE_BEGIN ? "^" : "",
      af & LINE_END ? "$" : "", af & TEXT_BEGIN ? "\\\\A" : "",
      af & TEXT_END ? "\\\\z" : "", af & WORD ? "\\\\b" : "",
      af & NOT_WORD ? "\\\\B" : "");
  return buf;
}

char *dump_group_flag(char *buf, group_flag gf)
{
  snprintf(
      buf, 32, "%s%s%s%s%s%s", gf & INSENSITIVE ? "i" : "",
      gf & MULTILINE ? "m" : "", gf & DOTNEWLINE ? "s" : "",
      gf & UNGREEDY ? "U" : "", gf & NONCAPTURING ? ":" : "",
      gf & SUBEXPRESSION ? "R" : "");
  return buf;
}

char *dump_quant(char *buf, u32 quantval)
{
  if (quantval >= INFTY)
    snprintf(buf, 32, "\xe2\x88\x9e"); /* infinity symbol */
  else
    snprintf(buf, 32, "%u", quantval);
  return buf;
}

void astdump_i(re *r, u32 root, u32 ilvl, enum dumpformat format)
{
  u32 i, first = root ? r->ast.ptr[root] : 0;
  u32 sub[2] = {0xFF, 0xFF};
  char buf[32] = {0}, buf2[32] = {0};
  const char *node_name = root == REF_NONE     ? "<eps>"
                          : (first == CHR)     ? "CHR"
                          : (first == CAT)     ? (sub[0] = 0, sub[1] = 1, "CAT")
                          : (first == ALT)     ? (sub[0] = 0, sub[1] = 1, "ALT")
                          : (first == QUANT)   ? (sub[0] = 0, "QUANT")
                          : (first == UQUANT)  ? (sub[0] = 0, "UQUANT")
                          : (first == GROUP)   ? (sub[0] = 0, "GROUP")
                          : (first == IGROUP)  ? (sub[0] = 0, "IGROUP")
                          : (first == CLS)     ? (sub[0] = 2, "CLS")
                          : (first == ICLS)    ? (sub[0] = 2, "ICLS")
                          : (first == ANYBYTE) ? "ANYBYTE"
                          : (first == AASSERT) ? "AASSERT"
                                               : NULL;
  if (format == TERM) {
    printf("%04u ", root);
    for (i = 0; i < ilvl; i++)
      printf(" ");
    printf("%s ", node_name);
  } else if (format == GRAPHVIZ) {
    if (!ilvl) {
      printf("digraph D {\n");
    }
    printf("A%04X [label=\"%s\\n", root, node_name);
  }
  if (first == CHR)
    printf("%s", dump_chr_unicode(buf, *re_astarg(r, root, 0)));
  else if (first == GROUP || first == IGROUP)
    printf("%s", dump_group_flag(buf, *re_astarg(r, root, 1)));
  else if (first == QUANT || first == UQUANT)
    printf(
        "%s-%s", dump_quant(buf, *re_astarg(r, root, 1)),
        dump_quant(buf2, *re_astarg(r, root, 2)));
  else if (first == CLS || first == ICLS)
    printf(
        "%s-%s", dump_chr_unicode(buf, *re_astarg(r, root, 0)),
        dump_chr_unicode(buf2, *re_astarg(r, root, 1)));
  if (format == GRAPHVIZ)
    printf("\"]\n");
  for (i = 0; i < sizeof(sub) / sizeof(*sub); i++)
    if (sub[i] != 0xFF) {
      u32 child = *re_astarg(r, root, sub[i]);
      astdump_i(r, child, ilvl + 1, format);
      if (format == GRAPHVIZ)
        printf(
            "A%04X -> A%04X [style=%s]\n", root, child, i ? "dashed" : "solid");
    }
  if (format == TERM) {
    printf("\n");
  } else if (format == GRAPHVIZ && !ilvl)
    printf("}\n");
}

void astdump(re *r, u32 root) { astdump_i(r, root, 0, TERM); }

void astdump_gv(re *r) { astdump_i(r, r->ast_root, 0, GRAPHVIZ); }

void progdump_range(re *r, u32 start, u32 end, enum dumpformat format)
{
  u32 j, k;
  assert(end <= re_prog_size(r));
  if (format == GRAPHVIZ)
    printf("digraph D {\nnode [colorscheme=pastel16]\n");
  for (start = 0; start < end; start++) {
    inst ins = re_prog_get(r, start);
    static const char *ops[] = {"RANGE", "ASSRT", "MATCH", "SPLIT"};
    static const char *labels[] = {"F  ", "R  ", "F.*", "R.*", "   ", "+  "};
    char start_buf[10] = {0}, end_buf[10] = {0}, assert_buf[32] = {0};
    k = 4;
    for (j = 0; j < 4; j++)
      if (start == r->entry[j])
        k = k == 4 ? j : 5;
    if (format == TERM) {
      static const int colors[] = {91, 92, 93, 94};
      printf(
          "%04X \x1b[%im%s\x1b[0m \x1b[%im%04X\x1b[0m %04X %s", start,
          colors[INST_OP(ins)], ops[INST_OP(ins)],
          INST_N(ins) ? (INST_N(ins) == start + 1 ? 90 : 0) : 91, INST_N(ins),
          INST_P(ins), labels[k]);
      if (INST_OP(ins) == MATCH)
        printf(
            " %c/%u", IMATCH_S(INST_P(ins)) ? 'G' : 'E', IMATCH_I(INST_P(ins)));
      printf("\n");
    } else {
      static const char *shapes[] = {"box", "diamond", "pentagon", "oval"};
      static const int colors[] = {1, 3, 6, 2};
      printf(
          "I%04X "
          "[shape=%s,fillcolor=%i,style=filled,regular=false,label=\"%s\\n",
          start, shapes[INST_OP(ins)], colors[INST_OP(ins)], ops[INST_OP(ins)]);
      if (INST_OP(ins) == RANGE)
        printf(
            "%s-%s", dump_chr_ascii(start_buf, u2br(INST_P(ins)).l),
            dump_chr_ascii(end_buf, u2br(INST_P(ins)).h));
      else if (INST_OP(ins) == MATCH)
        printf(
            "%s %u", IMATCH_S(INST_P(ins)) ? "slot" : "set",
            IMATCH_I(INST_P(ins)));
      else if (INST_OP(ins) == ASSERT)
        printf("%s", dump_assert(assert_buf, INST_P(ins)));
      printf("\"]\n");
      printf("I%04X -> I%04X\n", start, INST_N(ins));
      if (INST_OP(ins) == SPLIT)
        printf("I%04X -> I%04X [style=dashed]\n", start, INST_P(ins));
    }
  }
  if (format == GRAPHVIZ)
    printf("}\n");
}

void progdump(re *r) { progdump_range(r, 1, r->entry[ENT_REV], TERM); }

void progdump_r(re *r)
{
  progdump_range(r, r->entry[ENT_REV], re_prog_size(r), TERM);
}

void progdump_whole(re *r) { progdump_range(r, 0, re_prog_size(r), TERM); }

void progdump_gv(re *r) { progdump_range(r, 1, r->entry[ENT_REV], GRAPHVIZ); }

void cctreedump_i(stk *cc_tree, u32 ref, u32 lvl)
{
  u32 i;
  compcc_node *node = cc_treeref(cc_tree, ref);
  printf("%04X [%08X] ", ref, node->hash);
  for (i = 0; i < lvl; i++)
    printf("  ");
  printf("%02X-%02X\n", u2br(node->range).l, u2br(node->range).h);
  if (node->child_ref)
    cctreedump_i(cc_tree, node->child_ref, lvl + 1);
  if (node->sibling_ref)
    cctreedump_i(cc_tree, node->sibling_ref, lvl);
}

void cctreedump(stk *cc_tree, u32 ref) { cctreedump_i(cc_tree, ref, 0); }
#endif

/*T Generated by `unicode_data.py gen_casefold` */
static const s32 casefold_array_0[] = {
    -0x0040, +0x0000, -0x0022, -0x0022, +0x0022, +0x0022, -0x0040, -0x0040,
    +0x0040, +0x0040, -0x0027, -0x0027, +0x0027, +0x0027, -0x0028, -0x0028,
    +0x0028, +0x0028, -0x97D0, -0x97D0, -0x1C60, -0x1C60, -0x2A3F, -0x2A3F,
    -0x001A, -0x001A, +0x001A, +0x001A, -0x0010, -0x0010, +0x0010, +0x0010,
    -0x007E, -0x007E, -0x0080, -0x0080, -0x0070, -0x0070, -0x0064, -0x0064,
    -0x0056, -0x0056, -0x004A, -0x004A, +0x007E, +0x007E, +0x0070, +0x0070,
    +0x0080, +0x0080, +0x0064, +0x0064, +0x0056, +0x0056, +0x004A, +0x004A,
    -0x0BC0, -0x0BC0, -0x0008, -0x0008, +0x0008, +0x0008, +0x97D0, +0x97D0,
    +0x0BC0, +0x0BC0, +0x1C60, +0x1C60, -0x0030, -0x0030, +0x0030, +0x0030,
    -0x0050, -0x0050, +0x0050, +0x0050, -0x0082, -0x0082, -0x0025, -0x0025,
    +0x003F, +0x003F, +0x0025, +0x0025, +0x0082, +0x0082, -0x00D9, -0x00D9,
    -0x00CD, -0x00CD, +0x0001, +0x0001, -0x0020, -0x0020, +0x0020, +0x0020,
    +0x0000, +0x0000, -0x0027, +0x0000, -0x0027, +0x0027, +0x0000, -0x03A0,
    -0x8A38, +0x0001, -0x0030, -0xA543, -0xA515, +0x03A0, -0xA512, -0xA52A,
    -0xA544, +0x0000, -0xA54B, -0xA541, -0xA544, -0xA54F, -0x0001, -0xA528,
    -0x0001, -0x8A04, +0x0001, -0x89C3, +0x0000, -0x1C60, -0x2A1E, +0x0000,
    -0x29FD, -0x2A1F, -0x0001, -0x2A1C, -0x2A28, +0x0001, -0x29E7, -0x2A2B,
    -0x29F7, -0x0EE6, -0x001C, +0x0000, +0x001C, +0x0000, -0x20DF, -0x2066,
    -0x1D7D, +0x0000, -0x0007, +0x0000, +0x0007, +0x0000, -0x1C33, +0x0000,
    -0x1C43, -0x1C79, +0x0000, -0x0009, +0x0000, +0x0009, +0x0000, -0x0008,
    +0x0000, +0x0008, -0x1DBF, +0x0000, -0x003B, +0x0001, +0x003A, +0x8A38,
    +0x0000, +0x0EE6, +0x0000, +0x8A04, +0x0000, -0x0BC0, +0x0000, +0x89C2,
    +0x0000, -0x185C, -0x1825, +0x0001, -0x1863, -0x1864, -0x1862, -0x186E,
    -0x186D, +0x0000, +0x0BC0, +0x0000, +0x1C60, -0x0030, +0x0000, -0x0030,
    +0x0030, +0x0000, +0x0030, -0x0001, -0x000F, +0x000F, +0x0001, +0x1824,
    +0x183C, -0x0020, +0x1842, -0x0020, +0x1842, +0x1844, -0x0020, +0x184D,
    -0x0020, +0x184E, -0x0020, +0x0000, -0x0082, -0x0001, -0x0007, -0x005C,
    -0x0060, +0x0007, -0x0074, -0x0056, -0x0050, -0x0036, -0x0008, +0x0000,
    -0x002F, -0x003E, +0x0023, -0x003F, +0x0008, -0x0040, -0x003F, -0x0020,
    +0x1D5D, +0x000F, -0x0020, +0x0001, -0x0020, +0x0016, +0x0030, -0x0307,
    -0x0020, +0x0036, -0x0020, +0x0019, +0x1C05, -0x0020, +0x0040, +0x001E,
    -0x0020, +0x1C33, -0x0020, -0x0026, -0x0025, +0x0000, +0x001F, +0x1C43,
    +0x0020, +0x0040, +0x0000, +0x0025, +0x0000, +0x0026, +0x0000, +0x0074,
    +0x0000, +0x0082, +0x0000, +0x0054, +0xA512, +0x0000, +0xA515, -0x00DB,
    +0x0000, -0x0047, +0x0000, -0x00DA, -0x0045, +0x0000, +0xA52A, +0xA543,
    -0x00DA, +0x0000, +0x29E7, +0x0000, -0x00D6, -0x00D5, +0x0000, +0x29FD,
    +0x0000, -0x00D3, +0xA541, +0x0000, +0xA544, +0x29F7, -0x00D1, -0x00D3,
    +0xA544, +0x0000, +0xA528, +0x0000, -0x00CF, -0x00CD, +0xA54B, +0xA54F,
    +0x0000, -0x00CB, +0x0000, -0x00CA, -0x00CE, +0x0000, +0x2A1E, -0x00D2,
    +0x2A1F, +0x2A1C, +0x0045, +0x0047, -0x0001, -0x00C3, +0x2A3F, +0x0001,
    +0x2A28, +0x2A3F, -0x0001, -0x00A3, +0x2A2B, +0x0001, -0x0082, +0x0000,
    -0x0061, -0x0038, -0x0001, -0x004F, +0x0001, -0x0002, +0x0001, +0x0000,
    +0x0038, -0x0001, +0x00DB, +0x00D9, +0x0001, -0x0001, +0x00D9, -0x0001,
    +0x00DA, +0x0001, +0x0082, +0x00D6, +0x00D3, +0x00D5, +0x00A3, +0x0000,
    +0x00D3, +0x00D1, +0x00CF, +0x0061, +0x00CB, +0x0001, +0x004F, +0x00CA,
    +0x00CD, +0x0001, -0x0001, +0x00CD, +0x00CE, +0x0001, +0x00C3, +0x00D2,
    -0x0001, -0x012C, -0x0079, +0x0001, -0x0001, +0x0000, -0x0001, +0x0001,
    +0x0000, +0x0001, -0x0001, -0x0020, +0x0079, -0x0020, +0x2046, +0x0020,
    +0x1DBF, +0x0000, +0x02E7, -0x0020, +0x0000, -0x0020, +0x010C, -0x0020,
    +0x20BF, +0x0000, -0x0020, +0x0020, +0x0000, +0x0020};
static const u16 casefold_array_1[] = {
    0x002, 0x002, 0x060, 0x060, 0x004, 0x002, 0x002, 0x002, 0x002, 0x004, 0x004,
    0x004, 0x004, 0x006, 0x006, 0x006, 0x006, 0x008, 0x008, 0x008, 0x008, 0x00A,
    0x00A, 0x00A, 0x00A, 0x00C, 0x00C, 0x00C, 0x00C, 0x00E, 0x00E, 0x00E, 0x00E,
    0x010, 0x010, 0x010, 0x010, 0x012, 0x012, 0x012, 0x012, 0x014, 0x014, 0x014,
    0x014, 0x018, 0x018, 0x018, 0x018, 0x01A, 0x01A, 0x01A, 0x01A, 0x01C, 0x01C,
    0x01C, 0x01C, 0x01E, 0x01E, 0x01E, 0x01E, 0x09E, 0x09E, 0x09E, 0x09E, 0x0A0,
    0x0A0, 0x0A0, 0x0A0, 0x03A, 0x03A, 0x03A, 0x03A, 0x03C, 0x03C, 0x03C, 0x03C,
    0x038, 0x038, 0x038, 0x038, 0x03E, 0x03E, 0x03E, 0x03E, 0x040, 0x040, 0x040,
    0x040, 0x042, 0x042, 0x042, 0x042, 0x044, 0x044, 0x044, 0x044, 0x046, 0x046,
    0x046, 0x046, 0x048, 0x048, 0x048, 0x048, 0x04A, 0x04A, 0x04A, 0x04A, 0x176,
    0x176, 0x176, 0x176, 0x179, 0x179, 0x179, 0x179, 0x05C, 0x05C, 0x05C, 0x05C,
    0x05E, 0x05E, 0x05E, 0x05E, 0x060, 0x060, 0x060, 0x060, 0x179, 0x179, 0x0C0,
    0x179, 0x00A, 0x063, 0x00A, 0x00A, 0x060, 0x060, 0x07C, 0x060, 0x00C, 0x065,
    0x00C, 0x00C, 0x060, 0x060, 0x0BB, 0x060, 0x066, 0x060, 0x060, 0x179, 0x179,
    0x060, 0x179, 0x060, 0x060, 0x179, 0x060, 0x178, 0x076, 0x060, 0x179, 0x07A,
    0x179, 0x179, 0x060, 0x060, 0x10A, 0x060, 0x179, 0x060, 0x060, 0x119, 0x060,
    0x178, 0x174, 0x060, 0x08C, 0x060, 0x060, 0x05C, 0x05C, 0x17D, 0x05C, 0x060,
    0x08E, 0x060, 0x060, 0x181, 0x060, 0x09C, 0x060, 0x060, 0x038, 0x0AD, 0x0AC,
    0x038, 0x040, 0x0BA, 0x0B9, 0x040, 0x179, 0x0C6, 0x179, 0x179, 0x05C, 0x0C8,
    0x05C, 0x05C, 0x0D1, 0x0CF, 0x05C, 0x05E, 0x0FD, 0x05E, 0x05E, 0x060, 0x10F,
    0x060, 0x060, 0x05C, 0x185, 0x05C, 0x05C, 0x187, 0x05C, 0x05C, 0x006, 0x000,
    0x060, 0x060, 0x008, 0x101, 0x060, 0x060, 0x00A, 0x063, 0x062, 0x060, 0x00C,
    0x065, 0x00C, 0x063, 0x00E, 0x00E, 0x060, 0x060, 0x010, 0x010, 0x060, 0x060,
    0x178, 0x174, 0x176, 0x174, 0x060, 0x060, 0x179, 0x179, 0x06A, 0x068, 0x06E,
    0x06C, 0x179, 0x179, 0x074, 0x072, 0x070, 0x178, 0x176, 0x078, 0x179, 0x014,
    0x014, 0x014, 0x07C, 0x060, 0x178, 0x176, 0x174, 0x060, 0x060, 0x060, 0x016,
    0x07E, 0x179, 0x178, 0x174, 0x176, 0x176, 0x082, 0x080, 0x179, 0x088, 0x086,
    0x084, 0x018, 0x060, 0x060, 0x060, 0x01A, 0x060, 0x060, 0x060, 0x08A, 0x060,
    0x060, 0x060, 0x090, 0x022, 0x020, 0x09B, 0x060, 0x03A, 0x024, 0x092, 0x060,
    0x03C, 0x095, 0x093, 0x060, 0x03A, 0x026, 0x060, 0x060, 0x03C, 0x097, 0x060,
    0x060, 0x028, 0x028, 0x09B, 0x060, 0x03A, 0x02A, 0x09B, 0x099, 0x03C, 0x09C,
    0x060, 0x060, 0x030, 0x02E, 0x02C, 0x060, 0x036, 0x034, 0x034, 0x032, 0x060,
    0x0A3, 0x060, 0x0A2, 0x179, 0x179, 0x179, 0x060, 0x0A5, 0x179, 0x179, 0x179,
    0x060, 0x060, 0x060, 0x0A7, 0x0AA, 0x060, 0x0A8, 0x060, 0x0AF, 0x060, 0x060,
    0x060, 0x0B7, 0x0B5, 0x0B3, 0x0B1, 0x03A, 0x03A, 0x03A, 0x060, 0x03C, 0x03C,
    0x03C, 0x060, 0x042, 0x042, 0x042, 0x0BB, 0x044, 0x044, 0x044, 0x0BD, 0x0BE,
    0x044, 0x044, 0x044, 0x046, 0x046, 0x046, 0x0C0, 0x0C1, 0x046, 0x046, 0x046,
    0x176, 0x176, 0x176, 0x0C3, 0x0C5, 0x176, 0x176, 0x176, 0x179, 0x060, 0x060,
    0x060, 0x0CB, 0x0CA, 0x05C, 0x05C, 0x05C, 0x0CD, 0x0D5, 0x179, 0x0D3, 0x04C,
    0x0DB, 0x0D9, 0x0D7, 0x178, 0x0E1, 0x060, 0x0DF, 0x0DD, 0x0E7, 0x05C, 0x0E5,
    0x0E3, 0x0ED, 0x0EB, 0x05C, 0x0E9, 0x0F3, 0x0F1, 0x0EF, 0x05C, 0x0F9, 0x0F7,
    0x0F5, 0x05C, 0x05E, 0x05E, 0x0FB, 0x04E, 0x0FF, 0x05E, 0x05E, 0x05E, 0x052,
    0x103, 0x101, 0x050, 0x060, 0x060, 0x060, 0x105, 0x060, 0x108, 0x054, 0x106,
    0x060, 0x060, 0x10D, 0x10C, 0x113, 0x056, 0x111, 0x060, 0x118, 0x117, 0x060,
    0x115, 0x11E, 0x11D, 0x11B, 0x060, 0x126, 0x124, 0x122, 0x120, 0x12D, 0x12B,
    0x129, 0x128, 0x132, 0x130, 0x12F, 0x060, 0x138, 0x136, 0x134, 0x058, 0x13E,
    0x13C, 0x13A, 0x179, 0x060, 0x144, 0x142, 0x140, 0x179, 0x179, 0x060, 0x060,
    0x146, 0x179, 0x179, 0x179, 0x178, 0x14C, 0x179, 0x148, 0x176, 0x176, 0x14A,
    0x179, 0x14C, 0x05A, 0x14D, 0x176, 0x060, 0x060, 0x05A, 0x14D, 0x179, 0x060,
    0x179, 0x14F, 0x155, 0x153, 0x176, 0x151, 0x157, 0x060, 0x179, 0x158, 0x179,
    0x179, 0x179, 0x158, 0x179, 0x15E, 0x15C, 0x15A, 0x164, 0x16A, 0x162, 0x160,
    0x16A, 0x168, 0x174, 0x166, 0x16E, 0x179, 0x179, 0x16C, 0x172, 0x176, 0x176,
    0x170, 0x174, 0x179, 0x179, 0x179, 0x178, 0x176, 0x176, 0x176, 0x060, 0x179,
    0x179, 0x179, 0x05C, 0x05C, 0x05C, 0x17B, 0x05C, 0x05C, 0x05C, 0x183, 0x05E,
    0x05E, 0x05E, 0x17F, 0x05E, 0x05E, 0x05E, 0x18B, 0x05C, 0x183, 0x060, 0x060,
    0x189, 0x05C, 0x05C, 0x05C, 0x05E, 0x18B, 0x060, 0x060, 0x18C, 0x05E, 0x05E,
    0x05E};
static const u16 casefold_array_2[] = {
    0x000, 0x07D, 0x005, 0x005, 0x009, 0x009, 0x075, 0x075, 0x00D, 0x00D, 0x011,
    0x011, 0x01D, 0x01D, 0x021, 0x021, 0x025, 0x025, 0x029, 0x029, 0x02D, 0x02D,
    0x031, 0x031, 0x035, 0x035, 0x039, 0x039, 0x04D, 0x04D, 0x051, 0x051, 0x055,
    0x055, 0x059, 0x059, 0x05D, 0x05D, 0x061, 0x061, 0x065, 0x065, 0x069, 0x069,
    0x071, 0x071, 0x079, 0x079, 0x07D, 0x07D, 0x004, 0x005, 0x0E5, 0x07D, 0x0E9,
    0x07D, 0x085, 0x0ED, 0x085, 0x015, 0x0F1, 0x015, 0x019, 0x08D, 0x01D, 0x0F5,
    0x0F9, 0x01D, 0x021, 0x01D, 0x075, 0x259, 0x25D, 0x075, 0x094, 0x07D, 0x0FB,
    0x07D, 0x09B, 0x19F, 0x103, 0x0FF, 0x107, 0x071, 0x10A, 0x081, 0x071, 0x09F,
    0x07D, 0x10E, 0x245, 0x071, 0x201, 0x071, 0x163, 0x071, 0x0A3, 0x112, 0x089,
    0x0AA, 0x07D, 0x201, 0x116, 0x11E, 0x11A, 0x126, 0x122, 0x02D, 0x12A, 0x12B,
    0x031, 0x0AF, 0x07D, 0x12F, 0x0B2, 0x07D, 0x133, 0x0BA, 0x0BF, 0x137, 0x13F,
    0x13B, 0x147, 0x143, 0x0BF, 0x14B, 0x153, 0x14F, 0x15B, 0x157, 0x041, 0x03D,
    0x049, 0x045, 0x163, 0x15F, 0x167, 0x071, 0x07D, 0x16B, 0x07D, 0x16F, 0x04D,
    0x0C3, 0x177, 0x173, 0x17F, 0x17B, 0x055, 0x0C7, 0x183, 0x091, 0x187, 0x07D,
    0x18B, 0x05D, 0x18F, 0x07D, 0x193, 0x061, 0x19B, 0x197, 0x19F, 0x245, 0x0CB,
    0x071, 0x1A3, 0x0CF, 0x0D2, 0x1A5, 0x1AD, 0x1A9, 0x1B1, 0x071, 0x1B9, 0x1B5,
    0x1C1, 0x1BD, 0x0D6, 0x1C5, 0x1C9, 0x079, 0x1D1, 0x1CD, 0x098, 0x1D5, 0x0A7,
    0x07D, 0x0DA, 0x1D9, 0x1E1, 0x1DD, 0x1E5, 0x0AC, 0x1ED, 0x1E9, 0x1F5, 0x1F1,
    0x1F9, 0x071, 0x201, 0x1FD, 0x205, 0x071, 0x209, 0x071, 0x06D, 0x20D, 0x215,
    0x211, 0x21D, 0x219, 0x225, 0x221, 0x22D, 0x229, 0x235, 0x231, 0x071, 0x239,
    0x06D, 0x23D, 0x245, 0x241, 0x24D, 0x249, 0x0B6, 0x075, 0x255, 0x251, 0x0BC,
    0x07D, 0x0DE, 0x259, 0x25D, 0x0E1, 0x079, 0x261, 0x265, 0x079};
static const u8 casefold_array_3[] = {
    0x0E, 0x0E, 0x44, 0x0C, 0x0C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x0E,
    0x0E, 0x42, 0x0C, 0x40, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3E,
    0x3E, 0x3C, 0x3A, 0x38, 0x30, 0x30, 0x30, 0x30, 0x26, 0x26, 0x26, 0x24,
    0x24, 0x24, 0x69, 0x67, 0x2C, 0x2C, 0x2C, 0x2C, 0x2C, 0x2C, 0x65, 0x63,
    0x12, 0x12, 0x61, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x22, 0x22, 0x96, 0x20, 0x20, 0x94, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x4C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x6D, 0x16, 0x14, 0x6B, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0xEE, 0xEC, 0x48, 0x46, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x0A, 0x0A, 0x0A, 0x36, 0x08, 0x08,
    0x08, 0x34, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2E, 0x2E, 0x06, 0x06, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x04, 0x04, 0x32, 0x02, 0x00, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2E, 0x2E, 0x06, 0x06,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x4A, 0x30, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x74, 0x72, 0x70,
    0x30, 0x1A, 0x18, 0x6F, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x90, 0x1C, 0x1C, 0x8E, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x8C, 0x8A, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x5F, 0x2C, 0x5D, 0x30, 0x2C, 0x5B, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x5A, 0x5A, 0x2C, 0x2C, 0x2C, 0x58, 0x56, 0x55, 0x53, 0x52,
    0x50, 0x4E, 0x30, 0x4C, 0x2C, 0x2C, 0x2C, 0x2C, 0x2C, 0x2C, 0x88, 0x2C,
    0x2C, 0x86, 0x2C, 0x2C, 0x2C, 0x2C, 0x2C, 0x2C, 0x84, 0x92, 0x84, 0x84,
    0x92, 0x82, 0x84, 0x80, 0x84, 0x84, 0x84, 0x7E, 0x7C, 0x7A, 0x78, 0x76,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x1E, 0x1E, 0x1E, 0x1E, 0x1E, 0x92, 0x2A, 0x2E, 0x2E, 0xA8,
    0xA6, 0x28, 0xA4, 0x2C, 0xA2, 0x2C, 0x2C, 0x2C, 0xA0, 0x2C, 0x2C, 0x2C,
    0x2C, 0x2C, 0x2C, 0x9E, 0x26, 0x9C, 0x9A, 0x24, 0x98, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x2C, 0x2C, 0xCA, 0xC8, 0xC6, 0xC4, 0xC2, 0xC0,
    0xBE, 0xBC, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0xBA, 0x30, 0x30, 0xB8, 0xB6, 0xB4, 0xB2, 0xB0, 0xAE, 0xAC, 0x2C, 0xAA,
    0x30, 0x30, 0x30, 0x30, 0xEE, 0xEC, 0xEA, 0xE8, 0x30, 0x30, 0x30, 0xE6,
    0x2E, 0xE4, 0xE2, 0xE0, 0x2C, 0x2C, 0x2C, 0xDE, 0xDC, 0x2C, 0x2C, 0xDA,
    0xD8, 0xD6, 0xD4, 0xD2, 0xD0, 0xCE, 0x2C, 0xCC};
static const u16 casefold_array_4[] = {
    0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC,
    0x0CC, 0x0CC, 0x046, 0x0CC, 0x06A, 0x0F3, 0x0CC, 0x05B, 0x0CC, 0x0CC, 0x0CC,
    0x020, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x000,
    0x0CC, 0x0CC, 0x0CC, 0x082, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x098, 0x0CC,
    0x0CC, 0x0CC, 0x128, 0x0CC, 0x0D7, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC,
    0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0A8, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC,
    0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0C4,
    0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x1C8, 0x1A8, 0x188,
    0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x0CC, 0x036, 0x168, 0x0CC, 0x0CC, 0x0CC, 0x0CC,
    0x10C, 0x148};
static const u8 casefold_array_5[] = {
    0x55, 0x10, 0x3C, 0x3C, 0x3C, 0x2B, 0x3C, 0x00, 0x1E, 0x3C, 0x3C, 0x45,
    0x3C, 0x3C, 0x3C, 0x37, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C,
    0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C,
    0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C,
    0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C,
    0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C,
    0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C,
    0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C,
    0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C,
    0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C,
    0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C,
    0x3C, 0x3C, 0x3C, 0x3C};

s32 casefold_next(u32 rune)
{
  return casefold_array_0
      [casefold_array_1
           [casefold_array_2
                [casefold_array_3
                     [casefold_array_4
                          [casefold_array_5[((rune >> 13) & 0xFF)] +
                           ((rune >> 9) & 0x0F)] +
                      ((rune >> 4) & 0x1F)] +
                 ((rune >> 3) & 0x01)] +
            ((rune >> 1) & 0x03)] +
       (rune & 0x01)];
}

int casefold_fold_range(re *r, u32 begin, u32 end, stk *cc_out)
{
  int err = 0;
  s32 a0;
  u16 a1, a2, a4;
  u32 current, x0, x1, x2, x3, x4, x5;
  u8 a3, a5;
  assert(begin <= UTFMAX && end <= UTFMAX && begin <= end);
  for (x5 = ((begin >> 13) & 0xFF); x5 <= 0x87 && begin <= end; x5++) {
    if ((a5 = casefold_array_5[x5]) == 0x3C) {
      begin = ((begin >> 13) + 1) << 13;
      continue;
    }
    for (x4 = ((begin >> 9) & 0x0F); x4 <= 0xF && begin <= end; x4++) {
      if ((a4 = casefold_array_4[a5 + x4]) == 0xCC) {
        begin = ((begin >> 9) + 1) << 9;
        continue;
      }
      for (x3 = ((begin >> 4) & 0x1F); x3 <= 0x1F && begin <= end; x3++) {
        if ((a3 = casefold_array_3[a4 + x3]) == 0x30) {
          begin = ((begin >> 4) + 1) << 4;
          continue;
        }
        for (x2 = ((begin >> 3) & 0x01); x2 <= 0x1 && begin <= end; x2++) {
          if ((a2 = casefold_array_2[a3 + x2]) == 0x7D) {
            begin = ((begin >> 3) + 1) << 3;
            continue;
          }
          for (x1 = ((begin >> 1) & 0x03); x1 <= 0x3 && begin <= end; x1++) {
            if ((a1 = casefold_array_1[a2 + x1]) == 0x60) {
              begin = ((begin >> 1) + 1) << 1;
              continue;
            }
            for (x0 = (begin & 0x01); x0 <= 0x1 && begin <= end; x0++) {
              if ((a0 = casefold_array_0[a1 + x0]) == +0x0) {
                begin = ((begin >> 0) + 1) << 0;
                continue;
              }
              current = begin + a0;
              while (current != begin) {
                if ((err = ccpush(r, cc_out, current, current)))
                  return err;
                current = (u32)((s32)current + casefold_next(current));
              }
              begin++;
            }
          }
        }
      }
    }
  }
  return err;
}

/*t Generated by `unicode_data.py gen_casefold` */

/*T Generated by `unicode_data.py gen_ascii_charclasses impl` */
const ccdef builtin_cc[] = {
    {5, 3, "alnum", "\x30\x39\x41\x5A\x61\x7A"},
    {5, 2, "alpha", "\x41\x5A\x61\x7A"},
    {5, 1, "ascii", "\x00\x7F"},
    {5, 2, "blank", "\x09\x09\x20\x20"},
    {5, 2, "cntrl", "\x00\x1F\x7F\x7F"},
    {5, 2, "digit", "\x30\x30\x39\x39"},
    {5, 2, "graph", "\x21\x21\x7E\x7E"},
    {5, 2, "lower", "\x61\x61\x7A\x7A"},
    {5, 1, "print", "\x20\x7E"},
    {5, 4, "punct", "\x21\x2F\x3A\x40\x5B\x60\x7B\x7E"},
    {5, 2, "space", "\x09\x0D\x20\x20"},
    {10, 3, "perl_space", "\x09\x0A\x0C\x0D\x20\x20"},
    {5, 2, "upper", "\x41\x41\x5A\x5A"},
    {4, 3, "word", "\x30\x39\x41\x5A\x61\x7A"},
    {6, 3, "xdigit", "\x30\x39\x41\x46\x61\x66"},
    {0},
};
/*t Generated by `unicode_data.py gen_ascii_charclasses impl` */

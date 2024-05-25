#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "re.h"

#ifdef RE_CONFIG_HEADER_FILE
  #include RE_CONFIG_HEADER_FILE
#endif

#define REF_NONE 0
#define UTFMAX   0x10FFFF

/* A general-purpose growable buffer. */
typedef struct stk {
  u32 *ptr, size, alloc;
} stk;

/* A set of regular expressions. */
struct re {
  re_alloc alloc;
  stk ast;
  u32 ast_root, ast_sets;
  stk arg_stk, op_stk, comp_stk;
  stk prog, prog_set_idxs;
  stk cc_stk_a, cc_stk_b;
  u32 entry[4];
  const u8 *expr;
  size_t expr_pos, expr_size;
  const char *error;
  size_t error_pos;
};

/* Bit flags to identify program entry points in the `entry` field of `re`. */
typedef enum prog_entry {
  PROG_ENTRY_REVERSE = 1,
  PROG_ENTRY_DOTSTAR = 2,
  PROG_ENTRY_MAX = 4
} prog_entry;

/* Helper macro for assertions. */
#define IMPLIES(subj, pred) (!(subj) || (pred))

#ifndef RE_DEFAULT_ALLOC
/* Default allocation function. Hooks stdlib malloc. */
void *re_default_alloc(
    size_t prev, size_t next, void *ptr, const char *file, int line)
{
  if (next) {
    (void)prev, assert(IMPLIES(!prev, !ptr));
    return realloc(ptr, next);
  } else if (ptr) {
    free(ptr);
  }
  return NULL;
}

  #define RE_DEFAULT_ALLOC re_default_alloc
#endif

/* Allocate memory for an instance of `re`. */
#define re_ialloc(re, prev, next, ptr)                                         \
  (re)->alloc((prev), (next), (ptr), __FILE__, __LINE__)

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
  r = alloc(0, sizeof(re), NULL, __FILE__, __LINE__);
  *pr = r;
  if (!r)
    return (err = ERR_MEM);
  r->alloc = alloc;
  stk_init(r, &r->ast);
  r->ast_root = r->ast_sets = 0;
  stk_init(r, &r->arg_stk), stk_init(r, &r->op_stk), stk_init(r, &r->comp_stk);
  stk_init(r, &r->cc_stk_a), stk_init(r, &r->cc_stk_b);
  stk_init(r, &r->prog), stk_init(r, &r->prog_set_idxs);
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
  stk_destroy(r, &r->prog), stk_destroy(r, &r->prog_set_idxs);
  r->alloc(sizeof(*r), 0, r, __FILE__, __LINE__);
}

typedef enum ast_type {
  /* A single character: /a/ */
  CHR = 1,
  /* The concatenation of two regular expressions: /lr/
   *   Argument 0: left child tree (AST)
   *   Argument 1: right child tree (AST) */
  CAT,
  /* The alternation of two regular expressions: /l|r/
   *   Argument 0: primary alternation tree (AST)
   *   Argument 1: secondary alternation tree (AST) */
  ALT,
  /* A repeated regular expression: /a+/
   *   Argument 0: child tree (AST)
   *   Argument 1: lower bound, always <= upper bound (number)
   *   Argument 2: upper bound, might be the constant `INFTY` (number) */
  QUANT,
  /* Like `QUANT`, but not greedy: /(a*?)/
   *   Argument 0: child tree (AST)
   *   Argument 1: lower bound, always <= upper bound (number)
   *   Argument 2: upper bound, might be the constant `INFTY` (number) */
  UQUANT,
  /* A matching group: /(a)/
   *   Argument 0: child tree (AST)
   *   Argument 1: group flags, bitset of `enum group_flag` (number)
   *   Argument 2: scratch used by the parser to store old flags (number) */
  GROUP,
  /* An inline group: /(?i)a/
   *   Argument 0: child tree (AST)
   *   Argument 1: group flags, bitset of `enum group_flag` (number)
   *   Argument 2: scratch used by the parser to store old flags (number) */
  IGROUP,
  /* A character class: /[a-zA-Z]/
   *   Argument 0: REF_NONE or another CLS node in the charclass (AST)
   *   Argument 1: character range begin (number)
   *   Argument 2: character range end (number) */
  CLS,
  /* An inverted character class: /[^a-zA-Z]/
   *   Argument 0: REF_NONE or another CLS node in the charclass (AST)
   *   Argument 1: character range begin (number)
   *   Argument 2: character range end (number) */
  ICLS,
  /* Matches any byte: /\C/ */
  ANYBYTE,
  /* Empty assertion: /\b/
   *   Argument 0: assertion flags, bitset of `enum assert_flag` (number) */
  AASSERT
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
  LINE_BEGIN = 1, /* ^ */
  LINE_END = 2,   /* $ */
  TEXT_BEGIN = 4, /* \A */
  TEXT_END = 8,   /* \z */
  WORD = 16,      /* \w */
  NOT_WORD = 32   /* \W */
} assert_flag;

/* Represents an inclusive range of bytes. */
typedef struct byte_range {
  u8 l /* min ordinal */, h /* max ordinal */;
} byte_range;

/* Make a byte range inline. */
byte_range byte_range_make(u8 l, u8 h)
{
  byte_range out;
  out.l = l, out.h = h;
  return out;
}

/* Pack a byte range into a u32, low byte first. */
u32 byte_range_to_u32(byte_range br) { return ((u32)br.l) | ((u32)br.h) << 8; }

/* Unpack a byte range from a u32. */
byte_range u32_to_byte_range(u32 u)
{
  return byte_range_make(u & 0xFF, u >> 8 & 0xFF);
}

/* Check if two byte ranges intersect. */
int byte_range_is_intersecting(byte_range r, byte_range clip)
{
  return r.l <= clip.h && clip.l <= r.h;
}

/* Check if two byte ranges are adjacent (right directly supersedes left) */
int byte_range_is_adjacent(byte_range left, byte_range right)
{
  return ((u32)left.h) + 1 == ((u32)right.l);
}

/* Make a new AST node within the regular expression. */
int re_ast_make(re *re, ast_type type, u32 p0, u32 p1, u32 p2, u32 *out_node)
{
  u32 args[4];
  int err;
  args[0] = type, args[1] = p0, args[2] = p1, args[3] = p2;
  if (type && !re->ast.size &&
      (err = re_ast_make(re, 0, 0, 0, 0, out_node))) /* sentinel node */
    return err;
  *out_node = re->ast.size;
  return stk_pushn(re, &re->ast, args, (1 + ast_type_lens[type]) * sizeof(u32));
}

/* Decompose a given AST node, given its reference, into `out_args`. */
void re_ast_decompose(re *re, u32 node, u32 *out_args)
{
  u32 *in_args = stk_getn(&re->ast, node);
  memcpy(out_args, in_args + 1, ast_type_lens[*in_args] * sizeof(u32));
}

/* Get a pointer to the `n`'th parameter of the given AST node. */
u32 *re_ast_param(re *re, u32 node, u32 n)
{
  assert(ast_type_lens[re->ast.ptr[node]] > n);
  return re->ast.ptr + node + 1 + n;
}

/* Get the type of the given AST node. */
u32 *re_ast_type(re *re, u32 node) { return re->ast.ptr + node; }

/* Add another regular expression to the set of regular expressions matched by
 * this `re` instance. */
int re_union(re *r, const char *regex, size_t n)
{
  int err = 0;
  if (!r->ast_sets && (err = re_parse(r, (const u8 *)regex, n, &r->ast_root))) {
    return err;
  } else if (!r->ast_sets) {
    u32 next_reg, next_root;
    if ((err = re_parse(r, (const u8 *)regex, n, &next_reg)) ||
        (err = re_ast_make(r, ALT, r->ast_root, next_reg, 0, &next_root)))
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

/* Create and propagate a parsing error.
 * Returns `ERR_PARSE` unconditionally. */
int re_parse_err(re *r, const char *msg)
{
  r->error = msg, r->error_pos = r->expr_pos;
  return ERR_PARSE;
}

/* Check if we are at the end of the regex string. */
int re_parse_has_more(re *r) { return r->expr_pos != r->expr_size; }

/* Get the next input codepoint.
 * Returns `ERR_PARSE` if the parser encounters an invalid UTF-8 sequence. */
int re_parse_next(re *r, u32 *codep, const char *else_msg)
{
  u32 state = UTF8_ACCEPT;
  assert(IMPLIES(!else_msg, re_parse_has_more(r)));
  if (!re_parse_has_more(r))
    return re_parse_err(r, else_msg);
  while (utf8_decode(&state, codep, *(r->expr + r->expr_pos)),
         (++r->expr_pos != r->expr_size))
    if (!state)
      return 0;
  if (state != UTF8_ACCEPT)
    return re_parse_err(r, "invalid utf-8 sequence");
  return 0;
}

/* Without advancing the parser, check the next character.
 * Returns `ERR_PARSE` if the parser encounters an invalid UTF-8 sequence. */
int re_peek_next(re *r, u32 *first)
{
  size_t prev_pos = r->expr_pos;
  int err;
  assert(re_parse_has_more(r));
  if ((err = re_parse_next(r, first, NULL)))
    return err;
  r->expr_pos = prev_pos;
  return 0;
}

#define MAXREP 100000
#define INFTY  (MAXREP + 1)

/* Given nodes R_1i..R_N on the argument stack, fold them into a single CAT
 * node. If there are no nodes on the stack, create an epsilon node.
 * Returns `ERR_MEM` if out of memory. */
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
    if ((err = re_ast_make(r, CAT, left, right, 0, &rest)) ||
        (err = stk_push(r, &r->arg_stk, rest)))
      return err;
    /* arg_stk: | ... | R_N-1R_N | */
  }
  /* arg_stk: | R1R2...Rn | */
  return 0;
}

/* Given a node R on the argument stack and an arbitrary number of ALT nodes at
 * the end of the operator stack, fold and finish each ALT node into a single
 * resulting ALT node on the argument stack.
 * Returns `ERR_MEM` if out of memory. */
int re_fold_alts(re *r, u32 *flags)
{
  int err = 0;
  assert(r->arg_stk.size == 1);
  /* First pop all inline groups. */
  while (r->op_stk.size &&
         *re_ast_type(r, stk_peek(r, &r->op_stk, 0)) == IGROUP) {
    /* arg_stk: |  R  | */
    /* op_stk:  | ... | (S) | */
    u32 igrp = stk_pop(r, &r->op_stk), prev = *re_ast_param(r, igrp, 0), cat,
        old_flags = *re_ast_param(r, igrp, 2);
    *re_ast_param(r, igrp, 0) = stk_pop(r, &r->arg_stk);
    *flags = old_flags;
    if ((err = re_ast_make(r, CAT, prev, igrp, 0, &cat)) ||
        (err = stk_push(r, &r->arg_stk, cat)))
      return err;
    /* arg_stk: | S(R)| */
    /* op_stk:  | ... | */
  }
  assert(r->arg_stk.size == 1);
  /* arg_stk: |  R  | */
  /* op_stk:  | ... | */
  if (r->op_stk.size && *re_ast_type(r, stk_peek(r, &r->op_stk, 0)) == ALT) {
    /* op_stk:  | ... |  A  | */
    /* finish the last alt */
    *re_ast_param(r, stk_peek(r, &r->op_stk, 0), 1) = stk_pop(r, &r->arg_stk);
    /* arg_stk: | */
    /* op_stk:  | ... | */
  }
  while (r->op_stk.size > 1 &&
         *re_ast_type(r, stk_peek(r, &r->op_stk, 0)) == ALT &&
         *re_ast_type(r, stk_peek(r, &r->op_stk, 1)) == ALT) {
    /* op_stk:  | ... | A_1 | A_2 | */
    u32 right = stk_pop(r, &r->op_stk), left = stk_pop(r, &r->op_stk);
    *re_ast_param(r, left, 1) = right;
    if ((err = stk_push(r, &r->op_stk, left)))
      return err;
    /* op_stk:  | ... | A_1(|A_2) | */
  }
  if (r->op_stk.size &&
      *re_ast_type(r, r->op_stk.ptr[r->op_stk.size - 1]) == ALT) {
    /* op_stk:  | ... |  A  | */
    if ((err = stk_push(r, &r->arg_stk, stk_pop(r, &r->op_stk))))
      return err;
    /* arg_stk: |  A  | */
    /* op_stk:  | ... | */
  }
  return 0;
}

/* Add the CLS node `rest` to the CLS node `first`. */
u32 re_ast_cls_union(re *r, u32 rest, u32 first)
{
  u32 cur = first, *next;
  assert(first);
  assert(*re_ast_type(r, first) == CLS || *re_ast_type(r, first) == ICLS);
  assert(IMPLIES(rest, *re_ast_type(r, rest) == CLS));
  while (*(next = re_ast_param(r, cur, 0)))
    cur = *next;
  *next = rest;
  return first;
}

/* Helper function to add a character to the argument stack.
 * Returns `ERR_MEM` if out of memory. */
int re_parse_escape_addchr(re *r, u32 ch, u32 allowed_outputs)
{
  int err = 0;
  u32 res, args[1];
  (void)allowed_outputs, assert(allowed_outputs & (1 << CHR));
  args[0] = ch;
  if ((err = re_ast_make(r, CHR, ch, 0, 0, &res)) ||
      (err = stk_push(r, &r->arg_stk, res)))
    return err;
  return 0;
}

/* Convert a hexadecimal digit to a number.
 * Returns -1 on invalid hex digit.
 * TODO: convert this to an idiomatic error function */
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
    if (!invert && (err = re_ast_make(r, CLS, res, cur_min, cur_max, &res)))
      return err;
    else if (invert) {
      assert(cur_min >= max); /* builtin charclasses are ordered. */
      if (max != cur_min &&
          (err = re_ast_make(r, CLS, res, max, cur_min - 1, &res)))
        return err;
      else
        max = cur_max + 1;
    }
  }
  assert(cur_max < UTFMAX); /* builtin charclasses never reach UTFMAX */
  if (invert && i &&
      (err = re_ast_make(r, CLS, res, cur_max + 1, UTFMAX, &res)))
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
  if ((err = re_parse_next(r, &ch, "expected escape sequence")))
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
      (ch == '^') ||                /* caret */
      (ch == '$') ||                /* dolla */
      (ch == '-') ||                /* dash */
      (ch == '\\') /* escaped slash */) {
    return re_parse_escape_addchr(r, ch, allowed_outputs);
  } else if (ch >= '0' && ch <= '7') { /* octal escape */
    int digs = 1;
    u32 ord = ch - '0';
    while (digs++ < 3 && re_parse_has_more(r) &&
           !(err = re_peek_next(r, &ch)) && ch >= '0' && ch <= '7') {
      err = re_parse_next(r, &ch, NULL);
      assert(!err && ch >= '0' && ch <= '7');
      ord = ord * 8 + ch - '0';
    }
    if (err)
      return err; /* malformed */
    return re_parse_escape_addchr(r, ord, allowed_outputs);
  } else if (ch == 'x') { /* hex escape */
    u32 ord = 0;
    if ((err = re_parse_next(
             r, &ch, "expected two hex characters or a bracketed hex literal")))
      return err;
    if (ch == '{') { /* bracketed hex lit */
      u32 i;
      for (i = 0; i < 8; i++) {
        if ((i == 7) ||
            (err = re_parse_next(r, &ch, "expected up to six hex characters")))
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
      if ((err = re_parse_next(r, &ch, "expected two hex characters")))
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
    if ((err = re_ast_make(r, ANYBYTE, 0, 0, 0, &res)) ||
        (err = stk_push(r, &r->arg_stk, res)))
      return err;
  } else if (ch == 'Q') { /* quote string */
    u32 cat = REF_NONE, chr = REF_NONE;
    if (!(allowed_outputs & (1 << CAT)))
      return re_parse_err(r, "cannot use \\Q...\\E here");
    while (re_parse_has_more(r)) {
      if ((err = re_parse_next(r, &ch, NULL)))
        return err;
      if (ch == '\\' && re_parse_has_more(r)) {
        if ((err = re_peek_next(r, &ch)))
          return err;
        if (ch == 'E') {
          err = re_parse_next(r, &ch, NULL);
          assert(!err); /* we already read this in the peeknext */
          return stk_push(r, &r->arg_stk, cat);
        } else if (ch == '\\') {
          err = re_parse_next(r, &ch, NULL);
          assert(!err && ch == '\\');
        } else {
          ch = '\\';
        }
      }
      if ((err = re_ast_make(r, CHR, ch, 0, 0, &chr)))
        return err;
      if ((err = re_ast_make(r, CAT, cat, chr, 0, &cat)))
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
    if ((err = re_ast_make(
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
  if (!re_parse_has_more(r))
    return re_parse_err(r, "expected at least one decimal digit");
  while (re_parse_has_more(r) && !(err = re_peek_next(r, &ch)) && ch >= '0' &&
         ch <= '9' && (re_parse_next(r, &ch, NULL), ++ndigs < max_digits))
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
  while (re_parse_has_more(r)) {
    u32 ch, res = REF_NONE;
    if ((err = re_parse_next(r, &ch, NULL)))
      return err;
    if (ch == '*' || ch == '+' || ch == '?') {
      u32 q = ch, greedy = 1;
      /* arg_stk: | ... |  R  | */
      /* pop one from arg stk, create quant, push to arg stk */
      if (!r->arg_stk.size)
        return re_parse_err(r, "cannot apply quantifier to empty regex");
      if (re_parse_has_more(r)) {
        if ((err = re_peek_next(r, &ch)))
          return err;
        else if (ch == '?') {
          re_parse_next(r, &ch, NULL);
          greedy = 0;
        }
      }
      if ((err = re_ast_make(
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
      if ((err = re_ast_make(
               r, ALT, stk_pop(r, &r->arg_stk) /* left */, REF_NONE /* right */,
               0, &res)) ||
          (err = stk_push(r, &r->op_stk, res)))
        return err;
      /* arg_stk: | */
      /* op_stk:  | ... | R(|) | */
    } else if (ch == '(') {
      u32 old_flags = flags, inline_group = 0;
      if (!re_parse_has_more(r))
        return re_parse_err(r, "expected ')' to close group");
      if ((err = re_peek_next(r, &ch)))
        return err;
      if (ch == '?') { /* start of group flags */
        re_parse_next(r, &ch, NULL);
        if ((err = re_parse_next(
                 r, &ch,
                 "expected 'P', '<', or group flags after special "
                 "group opener \"(?\"")))
          return err;
        if (ch == 'P' || ch == '<') {
          if (ch == 'P' &&
              (err = re_parse_next(
                   r, &ch, "expected '<' after named group opener \"(?P\"")))
            return err;
          if (ch != '<')
            return re_parse_err(
                r, "expected '<' after named group opener \"(?P\"");
          /* parse group name */
          while (1) {
            if ((err = re_parse_next(
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
            if ((err = re_parse_next(
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
      if ((err = re_ast_make(
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
      prev = *re_ast_param(r, grp, 0);
      /* add it to the group */
      *(re_ast_param(r, grp, 0)) = stk_pop(r, &r->arg_stk);
      /* restore group flags */
      flags = *(re_ast_param(r, grp, 2));
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
           (err = re_ast_make(r, CLS, REF_NONE, 0, UTFMAX, &res))) ||
          (!(flags & DOTNEWLINE) &&
           ((err = re_ast_make(r, CLS, REF_NONE, 0, '\n' - 1, &res)) ||
            (err = re_ast_make(r, CLS, res, '\n' + 1, UTFMAX, &res)))) ||
          (err = stk_push(r, &r->arg_stk, res)))
        return err;
      /* arg_stk: | ... |  .  | */
    } else if (ch == '[') { /* charclass */
      size_t start = r->expr_pos;
      u32 inverted = 0, min, max;
      res = REF_NONE;
      while (1) {
        u32 next;
        if ((err = re_parse_next(r, &ch, "unclosed character class")))
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
          assert(*re_ast_type(r, next) == CHR || *re_ast_type(r, next) == CLS);
          if (*re_ast_type(r, next) == CHR)
            min = *re_ast_param(r, next, 0); /* single-character escape */
          else if (*re_ast_type(r, next) == CLS) {
            res = re_ast_cls_union(r, res, next);
            /* we parsed an entire class, so there's no ending character */
            continue;
          }
        } else if (
            ch == '[' && re_parse_has_more(r) && !re_peek_next(r, &ch) &&
            ch == ':') { /* named class */
          int named_inverted = 0;
          size_t name_start, name_end;
          err = re_parse_next(r, &ch, NULL); /* : */
          assert(!err && ch == ':');
          if (re_parse_has_more(r) && !re_peek_next(r, &ch) &&
              ch == '^') {                     /* inverted named class */
            err = re_parse_next(r, &ch, NULL); /* ^ */
            assert(!err && ch == '^');
            named_inverted = 1;
          }
          name_start = name_end = r->expr_pos;
          while (1) {
            if ((err = re_parse_next(r, &ch, "expected character class name")))
              return err;
            if (ch == ':')
              break;
            name_end = r->expr_pos;
          }
          if ((err = re_parse_next(
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
          assert(next && *re_ast_type(r, next) == CLS);
          res = re_ast_cls_union(r, res, next);
          continue;
        }
        max = min;
        if (re_parse_has_more(r) && !re_peek_next(r, &ch) && ch == '-') {
          /* range expression */
          err = re_parse_next(r, &ch, NULL);
          assert(!err && ch == '-');
          if ((err = re_parse_next(
                   r, &ch, "expected ending character for range expression")))
            return err;
          if (ch == '\\') { /* start of escape */
            if ((err = re_parse_escape(r, (1 << CHR))))
              return err;
            next = stk_pop(r, &r->arg_stk);
            assert(*re_ast_type(r, next) == CHR);
            max = *re_ast_param(r, next, 0);
          } else {
            max = ch; /* non-escaped character */
          }
        }
        if ((err = re_ast_make(r, CLS, res, min, max, &res)))
          return err;
      }
      assert(res);  /* charclass cannot be empty */
      if (inverted) /* inverted character class */
        *re_ast_type(r, res) = ICLS;
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
      if ((err = re_parse_next(
               r, &ch, "expected } to end repetition expression")))
        return err;
      if (ch == '}')
        max = min;
      else if (ch == ',') {
        if (!re_parse_has_more(r))
          return re_parse_err(
              r, "expected upper bound or } to end repetition expression");
        if ((err = re_peek_next(r, &ch)))
          return err;
        if (ch == '}')
          re_parse_next(r, &ch, NULL), max = INFTY;
        else {
          if ((err = re_parse_number(r, &max, 6)))
            return err;
          if ((err = re_parse_next(
                   r, &ch, "expected } to end repetition expression")))
            return err;
          if (ch != '}')
            return re_parse_err(r, "expected } to end repetition expression");
        }
      } else
        return re_parse_err(r, "expected } or , for repetition expression");
      if (!r->arg_stk.size)
        return re_parse_err(r, "cannot apply quantifier to empty regex");
      if ((err = re_ast_make(
               r, QUANT, stk_pop(r, &r->arg_stk), min, max, &res)) ||
          (err = stk_push(r, &r->arg_stk, res)))
        return err;
    } else if (ch == '^' || ch == '$') { /* beginning/end of text/line */
      if ((err = re_ast_make(
               r, AASSERT,
               ch == '^' ? (flags & MULTILINE ? LINE_BEGIN : TEXT_BEGIN)
                         : (flags & MULTILINE ? LINE_END : TEXT_END),
               0, 0, &res)) ||
          (err = stk_push(r, &r->arg_stk, res)))
        return err;
    } else { /* char: push to the arg stk */
      /* arg_stk: | ... | */
      if ((err = re_ast_make(r, CHR, ch, 0, 0, &res)) ||
          (err = stk_push(r, &r->arg_stk, res)))
        return err;
      /* arg_stk: | ... | chr | */
    }
  }
  if ((err = re_fold(r)) || (err = re_fold_alts(r, &flags)))
    return err;
  if (r->op_stk.size)
    return re_parse_err(r, "unmatched open parenthesis");
  if ((err = re_ast_make(
           r, GROUP, stk_pop(r, &r->arg_stk), SUBEXPRESSION, 0, root)))
    return err;
  return 0;
}

typedef struct inst {
  u32 l, h;
} inst;

#define OPCODE_BITS 2

typedef enum opcode { RANGE, ASSERT, MATCH, SPLIT } opcode;

opcode inst_opcode(inst i) { return i.l & (1 << OPCODE_BITS) - 1; }

u32 inst_next(inst i) { return i.l >> OPCODE_BITS; }

u32 inst_param(inst i) { return i.h; }

inst inst_make(opcode op, u32 next, u32 param)
{
  inst out;
  out.l = op | next << OPCODE_BITS, out.h = param;
  return out;
}

u32 inst_match_param_make(
    u32 slot_or_set, u32 begin_or_end, u32 slot_idx_or_set_idx)
{
  assert(slot_or_set == 0 || slot_or_set == 1);
  assert(begin_or_end == 0 || begin_or_end == 1);
  return slot_or_set | (begin_or_end << 1) | (slot_idx_or_set_idx << 2);
}

u32 inst_match_param_slot(u32 param) { return param & 1; }

u32 inst_match_param_end(u32 param) { return (param >> 1) & 1; }

u32 inst_match_param_idx(u32 param) { return param >> 2; }

void re_prog_set(re *r, u32 pc, inst i)
{
  r->prog.ptr[pc * 2 + 0] = i.l, r->prog.ptr[pc * 2 + 1] = i.h;
}

inst re_prog_get(re *r, u32 pc)
{
  inst out;
  out.l = r->prog.ptr[pc * 2 + 0], out.h = r->prog.ptr[pc * 2 + 1];
  return out;
}

u32 re_prog_size(re *r) { return r->prog.size >> 1; }

#define RE_PROG_MAX_INSTS 100000

typedef struct compframe {
  u32 root_ref, child_ref, idx, patch_head, patch_tail, pc, flags, set_idx;
} compframe;

int re_emit(re *r, inst i, compframe *frame)
{
  int err = 0;
  if (re_prog_size(r) == RE_PROG_MAX_INSTS)
    return ERR_LIMIT;
  if ((err = stk_push(r, &r->prog, 0)) || (err = stk_push(r, &r->prog, 0)) ||
      (err = stk_push(r, &r->prog_set_idxs, frame->set_idx)))
    return err;
  re_prog_set(r, re_prog_size(r) - 1, i);
  return err;
}

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

inst patch_set(re *r, u32 pc, u32 val)
{
  inst prev = re_prog_get(r, pc >> 1);
  assert(pc);
  re_prog_set(
      r, pc >> 1,
      inst_make(
          inst_opcode(prev), pc & 1 ? inst_next(prev) : val,
          pc & 1 ? val : inst_param(prev)));
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
    i = i & 1 ? inst_param(prev) : inst_next(prev);
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
  u32 range, child_ref, sibling_ref, aux;
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
  if (out)
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
             r, cc_out, byte_range_to_u32(byte_range_make(byte_min, byte_max)),
             parent, &next)))
      return err;
  } else {
    /* nonterminal */
    u32 x_min = min & x_mask, x_max = max & x_mask, brs[3], mins[3], maxs[3], n;
    if (y_min == y_max || (x_min == 0 && x_max == x_mask)) {
      /* Range can be split into either a single byte followed by a range,
       * _or_ one range followed by another maximal range */
      /* Output:
       * ---[Ymin-Ymax]---{tree for [Xmin-Xmax]} */
      brs[0] = byte_range_to_u32(byte_range_make(byte_min, byte_max));
      mins[0] = x_min, maxs[0] = x_max;
      n = 1;
    } else if (!x_min) {
      /* Range begins on zero, but has multiple starting bytes */
      /* Output:
       * ---[Ymin-(Ymax-1)]---{tree for [00-FF]}
       *           |
       *      [Ymax-Ymax]----{tree for [00-Xmax]} */
      brs[0] = byte_range_to_u32(byte_range_make(byte_min, byte_max - 1));
      mins[0] = 0, maxs[0] = x_mask;
      brs[1] = byte_range_to_u32(byte_range_make(byte_max, byte_max));
      mins[1] = 0, maxs[1] = x_max;
      n = 2;
    } else if (x_max == x_mask) {
      /* Range ends on all ones, but has multiple starting bytes */
      /* Output:
       * -----[Ymin-Ymin]----{tree for [Xmin-FF]}
       *           |
       *    [(Ymin+1)-Ymax]---{tree for [00-FF]} */
      brs[0] = byte_range_to_u32(byte_range_make(byte_min, byte_min));
      mins[0] = x_min, maxs[0] = x_mask;
      brs[1] = byte_range_to_u32(byte_range_make(byte_min + 1, byte_max));
      mins[1] = 0, maxs[1] = x_mask;
      n = 2;
    } else if (y_min == y_max - 1) {
      /* Range occupies exactly two starting bytes */
      /* Output:
       * -----[Ymin-Ymin]----{tree for [Xmin-FF]}
       *           |
       *      [Ymax-Ymax]----{tree for [00-Xmax]} */
      brs[0] = byte_range_to_u32(byte_range_make(byte_min, byte_min));
      mins[0] = x_min, maxs[0] = x_mask;
      brs[1] = byte_range_to_u32(byte_range_make(byte_min + 1, byte_max));
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
      brs[0] = byte_range_to_u32(byte_range_make(byte_min, byte_min));
      mins[0] = x_min, maxs[0] = x_mask;
      brs[1] = byte_range_to_u32(byte_range_make(byte_min + 1, byte_max - 1));
      mins[1] = 0, maxs[1] = x_mask;
      brs[2] = byte_range_to_u32(byte_range_make(byte_max, byte_max));
      mins[2] = 0, maxs[2] = x_max;
      n = 3;
    }
    for (i = 0; i < n; i++) {
      compcc_node *parent_node;
      u32 child_ref;
      /* check if previous child intersects and then compute intersection */
      assert(parent);
      parent_node = cc_treeref(cc_out, parent);
      if (parent_node->child_ref &&
          byte_range_is_intersecting(
              u32_to_byte_range(
                  cc_treeref(cc_out, parent_node->child_ref)->range),
              u32_to_byte_range(brs[i]))) {
        child_ref = parent_node->child_ref;
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
  size_t i = 0, j = 0, min_bound = 0;
  u32 root_ref;
  compcc_node root_node;
  int err = 0;
  root_node.child_ref = root_node.sibling_ref = root_node.aux =
      root_node.range = 0;
  /* clear output charclass */
  cc_out->size = 0;
  if ((err = cc_treenew(r, cc_out, root_node, &root_ref)))
    return err;
  for (i = 0, j = 0; i < ccsize(cc_in) && j < 4;) {
    static const u32 y_bits[4] = {7, 5, 4, 3};
    static const u32 x_bits[4] = {0, 6, 12, 18};
    u32 max_bound = (1 << (x_bits[j] + y_bits[j])) - 1, min, max;
    ccget(cc_in, i, &min, &max);
    if (min_bound <= max && min <= max_bound) {
      /* [min,max] intersects [min_bound,max_bound] */
      u32 clamped_min = min < min_bound ? min_bound : min, /* clamp range */
          clamped_max = max > max_bound ? max_bound : max;
      if ((err = re_compcc_buildtree_split(
               r, cc_out, root_ref, clamped_min, clamped_max, x_bits[j],
               y_bits[j])))
        return err;
    }
    if (max < max_bound)
      /* range is less than [min_bound,max_bound] */
      i++;
    else
      /* range is greater than [min_bound,max_bound] */
      j++, min_bound = max_bound + 1;
  }
  return err;
}

int re_compcc_treeeq(re *r, stk *cc_tree_in, u32 a_ref, u32 b_ref)
{
  while (a_ref && b_ref) {
    compcc_node *a = cc_treeref(cc_tree_in, a_ref),
                *b = cc_treeref(cc_tree_in, b_ref);
    if (!re_compcc_treeeq(r, cc_tree_in, a->child_ref, b->child_ref))
      return 0;
    if (a->range != b->range)
      return 0;
    a_ref = a->sibling_ref, b_ref = b->sibling_ref;
  }
  assert(a_ref == 0 || b_ref == 0);
  return a_ref == b_ref;
}

void re_compcc_merge_one(stk *cc_tree_in, u32 child_ref, u32 sibling_ref)
{
  compcc_node *child = cc_treeref(cc_tree_in, child_ref),
              *sibling = cc_treeref(cc_tree_in, sibling_ref);
  child->sibling_ref = sibling->sibling_ref;
  assert(byte_range_is_adjacent(
      u32_to_byte_range(child->range), u32_to_byte_range(sibling->range)));
  child->range = byte_range_to_u32(byte_range_make(
      u32_to_byte_range(child->range).l, u32_to_byte_range(sibling->range).h));
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
      if (byte_range_is_adjacent(
              u32_to_byte_range(child_node->range),
              u32_to_byte_range(sibling_node->range))) {
        if (!sibling_node->child_ref) {
          if (!child_node->child_ref) {
            re_compcc_merge_one(cc_tree_in, child_ref, sibling_ref);
          }
        } else {
          if (child_node->child_ref) {
            if (re_compcc_treeeq(
                    r, cc_tree_in, child_node->child_ref,
                    sibling_node->child_ref)) {
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
        hash_plain[1] = child_sibling_node->aux;
      }
      if (child_node->child_ref) {
        compcc_node *child_child_node =
            cc_treeref(cc_tree_in, child_node->child_ref);
        hash_plain[2] = child_child_node->aux;
      }
      child_node->aux = hashington(
          hashington(hashington(hash_plain[0]) + hash_plain[1]) +
          hash_plain[2]);
    }
    sibling_ref = child_ref;
    sibling_node = child_node;
    child_ref = next_child_ref;
  }
  parent_node->child_ref = sibling_ref;
}

void re_compcc_reducetree(
    re *r, stk *cc_tree_in, stk *cc_ht, u32 node_ref, u32 *my_out_ref)
{
  u32 prev_sibling_ref = 0;
  assert(node_ref);
  assert(!*my_out_ref);
  while (node_ref) {
    compcc_node *node = cc_treeref(cc_tree_in, node_ref);
    u32 probe, found, child_ref = 0;
    probe = node->aux << 1;
    node->aux = 0;
    /* check if child is in the hash table */
    while (1) {
      if (!((found = cc_ht->ptr[probe % cc_ht->size]) & 1))
        /* child is NOT in the cache */
        break;
      else {
        /* something is in the cache, but it might not be a child */
        if (re_compcc_treeeq(r, cc_tree_in, node_ref, found >> 1)) {
          if (prev_sibling_ref)
            cc_treeref(cc_tree_in, prev_sibling_ref)->sibling_ref = found >> 1;
          if (!*my_out_ref)
            *my_out_ref = found >> 1;
          return;
        }
      }
      probe += 1 << 1; /* linear probe */
    }
    cc_ht->ptr[(probe % cc_ht->size) + 0] = node_ref << 1 | 1;
    if (!*my_out_ref)
      *my_out_ref = node_ref;
    if (node->child_ref) {
      re_compcc_reducetree(r, cc_tree_in, cc_ht, node->child_ref, &child_ref);
      node->child_ref = child_ref;
    }
    prev_sibling_ref = node_ref;
    node_ref = node->sibling_ref;
  }
  assert(*my_out_ref);
  return;
}

int re_compcc_rendertree(
    re *r, stk *cc_tree_in, u32 node_ref, u32 *my_out_pc, compframe *frame)
{
  int err = 0;
  u32 split_from = 0, my_pc = 0, range_pc = 0;
  while (node_ref) {
    compcc_node *node = cc_treeref(cc_tree_in, node_ref);
    if (node->aux) {
      if (split_from) {
        inst i = re_prog_get(r, split_from);
        /* found our child, patch into it */
        i = inst_make(inst_opcode(i), inst_next(i), node->aux);
        re_prog_set(r, split_from, i);
      } else if (!*my_out_pc)
        *my_out_pc = node->aux;
      return 0;
    }
    my_pc = re_prog_size(r);
    if (split_from) {
      inst i = re_prog_get(r, split_from);
      /* patch into it */
      i = inst_make(inst_opcode(i), inst_next(i), my_pc);
      re_prog_set(r, split_from, i);
    }
    if (node->sibling_ref) {
      /* need a split */
      split_from = my_pc;
      if ((err = re_emit(r, inst_make(SPLIT, my_pc + 1, 0), frame)))
        return err;
    }
    if (!*my_out_pc)
      *my_out_pc = my_pc;
    range_pc = re_prog_size(r);
    if ((err = re_emit(
             r,
             inst_make(
                 RANGE, 0,
                 byte_range_to_u32(byte_range_make(
                     u32_to_byte_range(node->range).l,
                     u32_to_byte_range(node->range).h))),
             frame)))
      return err;
    if (node->child_ref) {
      /* need to down-compile */
      u32 their_pc = 0;
      inst i = re_prog_get(r, range_pc);
      if ((err = re_compcc_rendertree(
               r, cc_tree_in, node->child_ref, &their_pc, frame)))
        return err;
      i = inst_make(inst_opcode(i), their_pc, inst_param(i));
      re_prog_set(r, range_pc, i);
    } else {
      /* terminal: patch out */
      patch_add(r, frame, range_pc, 0);
    }
    node->aux = my_pc;
    node_ref = node->sibling_ref;
  }
  assert(*my_out_pc);
  return 0;
}

void re_compcc_xposetree(
    stk *cc_tree_in, stk *cc_tree_out, u32 node_ref, u32 root_ref)
{
  compcc_node *src_node, *dst_node, *parent_node;
  assert(node_ref != REF_NONE);
  assert(cc_treesize(cc_tree_out) == cc_treesize(cc_tree_in));
  while (node_ref) {
    u32 parent_ref = root_ref;
    src_node = cc_treeref(cc_tree_in, node_ref);
    dst_node = cc_treeref(cc_tree_out, node_ref);
    dst_node->sibling_ref = dst_node->child_ref = REF_NONE;
    if (src_node->child_ref != REF_NONE)
      re_compcc_xposetree(
          cc_tree_in, cc_tree_out, (parent_ref = src_node->child_ref),
          root_ref);
    parent_node = cc_treeref(cc_tree_out, parent_ref);
    dst_node->sibling_ref = parent_node->child_ref;
    parent_node->child_ref = node_ref;
    node_ref = src_node->sibling_ref;
  }
}

int casefold_fold_range(re *r, u32 begin, u32 end, stk *cc_out);

int re_compcc(re *r, u32 root, compframe *frame, int reversed)
{
  int err = 0, inverted = *re_ast_type(r, frame->root_ref) == ICLS,
      insensitive = !!(frame->flags & INSENSITIVE);
  u32 start_pc = 0;
  r->cc_stk_a.size = r->cc_stk_b.size = 0; /* clear stks */
  /* push ranges */
  while (root) {
    u32 args[3], min, max;
    re_ast_decompose(r, root, args);
    root = args[0], min = args[1], max = args[2];
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
    if ((err = re_emit(
             r, inst_make(ASSERT, 0, WORD | NOT_WORD),
             frame))) /* never matches */
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
  /* reduce tree */
  re_compcc_reducetree(r, &r->cc_stk_a, &r->cc_stk_b, 2, &start_pc);
  if (reversed) {
    u32 i;
    stk tmp;
    r->cc_stk_b.size = 0;
    for (i = 1 /* skip sentinel */; i < cc_treesize(&r->cc_stk_a); i++) {
      if ((err = cc_treenew(
               r, &r->cc_stk_b, *cc_treeref(&r->cc_stk_a, i), NULL)) == ERR_MEM)
        return err;
      assert(!err);
    }
    /* detach new root */
    cc_treeref(&r->cc_stk_b, 1)->child_ref = REF_NONE;
    re_compcc_xposetree(&r->cc_stk_a, &r->cc_stk_b, 2, 1);
    /* potench reverse the tree if needed */
    tmp = r->cc_stk_a;
    r->cc_stk_a = r->cc_stk_b;
    r->cc_stk_b = tmp;
  }
  if ((err = re_compcc_rendertree(r, &r->cc_stk_a, start_pc, &start_pc, frame)))
    return err;
  return err;
}

int re_compile(re *r, u32 root, u32 reverse)
{
  int err = 0;
  compframe initial_frame = {0}, returned_frame = {0}, child_frame = {0};
  u32 set_idx = 0, grp_idx = 1, tmp_cc_ast = REF_NONE;
  if (!r->prog.size &&
      ((err = stk_push(r, &r->prog, 0)) || (err = stk_push(r, &r->prog, 0))))
    return err;
  initial_frame.root_ref = root;
  initial_frame.child_ref = initial_frame.patch_head =
      initial_frame.patch_tail = REF_NONE;
  initial_frame.idx = 0;
  initial_frame.pc = re_prog_size(r);
  r->entry[reverse ? PROG_ENTRY_REVERSE : 0] = initial_frame.pc;
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
    type = *re_ast_type(r, frame.root_ref);
    if (frame.root_ref)
      re_ast_decompose(r, frame.root_ref, args);
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
                 r,
                 inst_make(
                     RANGE, 0,
                     byte_range_to_u32(byte_range_make(args[0], args[0]))),
                 &frame)))
          return err;
        patch_add(r, &frame, my_pc, 0);
      } else { /* unicode */
        /* create temp ast */
        if (!tmp_cc_ast &&
            (err = re_ast_make(r, CLS, REF_NONE, 0, 0, &tmp_cc_ast)))
          return err;
        *re_ast_param(r, tmp_cc_ast, 1) = *re_ast_param(r, tmp_cc_ast, 2) =
            args[0];
        if ((err = re_compcc(r, tmp_cc_ast, &frame, reverse)))
          return err;
      }
    } else if (type == ANYBYTE) {
      /*  in     out
       * ---> R ----> */
      patch(r, &frame, my_pc);
      if ((err = re_emit(
               r,
               inst_make(
                   RANGE, 0, byte_range_to_u32(byte_range_make(0x00, 0xFF))),
               &frame)))
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
        if ((err = re_emit(r, inst_make(SPLIT, 0, 0), &frame)))
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
      assert(IMPLIES((min == INFTY || max == INFTY), min != max));
      if (frame.idx < min) { /* before minimum bound */
        patch_xfer(&child_frame, frame.idx ? &returned_frame : &frame);
        frame.child_ref = child;
      } else if (max == INFTY && frame.idx == min) { /* before inf. bound */
        patch(r, frame.idx ? &returned_frame : &frame, my_pc);
        if ((err = re_emit(r, inst_make(SPLIT, 0, 0), &frame)))
          return err;
        frame.pc = my_pc;
        patch_add(r, &child_frame, my_pc, !is_greedy);
        patch_add(r, &frame, my_pc, is_greedy);
        frame.child_ref = child;
      } else if (max == INFTY && frame.idx == min + 1) { /* after inf. bound */
        patch(r, &returned_frame, frame.pc);
      } else if (frame.idx < max) { /* before maximum bound */
        patch(r, frame.idx ? &returned_frame : &frame, my_pc);
        if ((err = re_emit(r, inst_make(SPLIT, 0, 0), &frame)))
          return err;
        patch_add(r, &child_frame, my_pc, !is_greedy);
        patch_add(r, &frame, my_pc, is_greedy);
        frame.child_ref = child;
      } else if (frame.idx && frame.idx == max) { /* after maximum bound */
        patch_merge(r, &frame, &returned_frame);
      } else if (!frame.idx && frame.idx == max) {
        /* epsilon */
      } else {
        assert(0);
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
          if (flags & SUBEXPRESSION)
            grp_idx = 1, frame.set_idx = set_idx++;
          if ((err = re_emit(
                   r,
                   inst_make(
                       MATCH, 0,
                       inst_match_param_make(
                           !(flags & SUBEXPRESSION), reverse,
                           (flags & SUBEXPRESSION ? set_idx : grp_idx++))),
                   &frame)))
            return err;
          patch_add(r, &child_frame, my_pc, 0);
        } else
          patch_xfer(&child_frame, &frame);
        frame.child_ref = child, frame.idx++;
      } else if (frame.idx) { /* after child */
        if (!(flags & NONCAPTURING)) {
          patch(r, &returned_frame, my_pc);
          if ((err = re_emit(
                   r,
                   inst_make(
                       MATCH, 0,
                       inst_match_param_make(
                           !(flags & SUBEXPRESSION), !reverse,
                           inst_match_param_idx(
                               inst_param(re_prog_get(r, frame.pc))))),
                   &frame)))
            return err;
          if (!(flags & SUBEXPRESSION))
            patch_add(r, &frame, my_pc, 0);
        } else
          patch_merge(r, &frame, &returned_frame);
      }
    } else if (type == CLS || type == ICLS) {
      patch(r, &frame, my_pc);
      if ((err = re_compcc(r, frame.root_ref, &frame, reverse)))
        return err;
    } else if (type == AASSERT) {
      u32 assert_flag = args[0];
      patch(r, &frame, my_pc);
      if ((err = re_emit(r, inst_make(ASSERT, 0, assert_flag), &frame)))
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
      child_frame.set_idx = frame.set_idx;
      if ((err = compframe_push(r, child_frame)))
        return err;
    }
    returned_frame = frame;
  }
  assert(!r->comp_stk.size);
  assert(!returned_frame.patch_head && !returned_frame.patch_tail);
  {
    u32 dstar =
        r->entry[PROG_ENTRY_DOTSTAR | (reverse ? PROG_ENTRY_REVERSE : 0)] =
            re_prog_size(r);
    compframe frame = {0};
    if ((err = re_emit(
             r,
             inst_make(
                 SPLIT, r->entry[reverse ? PROG_ENTRY_REVERSE : 0], dstar + 1),
             &frame)))
      return err;
    if ((err = re_emit(
             r,
             inst_make(
                 RANGE, dstar, byte_range_to_u32(byte_range_make(0, 255))),
             &frame)))
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

int sset_reset(re *r, sset *s, size_t next_alloc)
{
  u32 *next_sparse;
  thrdspec *next_dense;
  if (!next_alloc)
    return 0;
  if (!(next_sparse = re_ialloc(
            r, sizeof(u32) * s->sparse_alloc, sizeof(u32) * next_alloc,
            s->sparse)))
    return ERR_MEM;
  s->sparse = next_sparse;
  s->sparse_alloc = next_alloc;
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

typedef struct nfa {
  sset a, b, c;
  stk thrd_stk;
  save_slots slots;
  stk pri_stk, pri_bmp_tmp;
  int reversed, pri;
} nfa;

void nfa_init(re *r, nfa *n)
{
  sset_init(r, &n->a), sset_init(r, &n->b), sset_init(r, &n->c);
  stk_init(r, &n->thrd_stk);
  save_slots_init(r, &n->slots);
  stk_init(r, &n->pri_stk), stk_init(r, &n->pri_bmp_tmp);
  n->reversed = 0;
}

void nfa_destroy(re *r, nfa *n)
{
  sset_destroy(r, &n->a), sset_destroy(r, &n->b), sset_destroy(r, &n->c);
  stk_destroy(r, &n->thrd_stk);
  save_slots_destroy(r, &n->slots);
  stk_destroy(r, &n->pri_stk), stk_destroy(r, &n->pri_bmp_tmp);
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

int nfa_start(re *r, nfa *n, u32 pc, u32 noff, int reversed, int pri)
{
  thrdspec initial_thrd;
  u32 i;
  int err = 0;
  if ((err = sset_reset(r, &n->a, re_prog_size(r))) ||
      (err = sset_reset(r, &n->b, re_prog_size(r))) ||
      (err = sset_reset(r, &n->c, re_prog_size(r))))
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
  if ((err = bmp_init(r, &n->pri_bmp_tmp, r->ast_sets)))
    return err;
  n->reversed = reversed;
  n->pri = pri;
  return 0;
}

int nfa_eps(re *r, nfa *n, size_t pos, assert_flag ass)
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
      switch (inst_opcode(re_prog_get(r, top.pc))) {
      case MATCH: {
        u32 idx =
            (inst_match_param_slot(inst_param(op))
                 ? inst_match_param_idx(inst_param(op)) /* this is a save */
                 : 0) *
                2 +
            inst_match_param_end(inst_param(op));
        if (!inst_match_param_slot(inst_param(op)) &&
            (err = save_slots_set_setidx(
                 r, &n->slots, top.slot, inst_match_param_idx(inst_param(op)),
                 &top.slot)))
          return err;
        if (idx < save_slots_perthrd(&n->slots) &&
            (err = save_slots_set(r, &n->slots, top.slot, idx, pos, &top.slot)))
          return err;
        if (inst_next(op)) {
          if (inst_match_param_slot(inst_param(op)) ||
              !n->pri_stk.ptr[inst_match_param_idx(inst_param(op)) - 1]) {
            top.pc = inst_next(op);
            if ((err = thrdstk_push(r, &n->thrd_stk, top)))
              return err;
          }
          break;
        } /* else fallthrough */
      }
      case RANGE:
        sset_add(&n->b, top); /* this is a range or final match */
        break;
      case SPLIT: {
        thrdspec pri, sec;
        pri.pc = inst_next(op), pri.slot = top.slot;
        sec.pc = inst_param(op),
        sec.slot = save_slots_fork(&n->slots, top.slot);
        if ((err = thrdstk_push(r, &n->thrd_stk, sec)) ||
            (err = thrdstk_push(r, &n->thrd_stk, pri)))
          /* sec is pushed first because it needs to be processed after pri.
           * pri comes off the stack first because it's FIFO. */
          return err;
        break;
      }
      case ASSERT: {
        assert(!!(ass & WORD) ^ !!(ass & NOT_WORD));
        if ((inst_param(op) & ass) == inst_param(op)) {
          top.pc = inst_next(op);
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

int nfa_matchend(re *r, nfa *n, thrdspec thrd, size_t pos, unsigned int ch)
{
  int err = 0;
  u32 idx = r->prog_set_idxs.ptr[thrd.pc] + 1;
  u32 *memo = n->pri_stk.ptr + idx - 1;
  assert(idx > 0); /* save_slots_set_setidx() MUST have been called */
  assert(idx - 1 < n->pri_stk.size);
  if (!n->pri && ch < 256)
    return err;
  if (n->slots.per_thrd) {
    u32 slot_idx = !n->reversed;
    if (*memo)
      save_slots_kill(&n->slots, *memo);
    *memo = thrd.slot;
    if (slot_idx < save_slots_perthrd(&n->slots) &&
        (err = save_slots_set(r, &n->slots, thrd.slot, slot_idx, pos, memo)))
      return err;
  } else {
    *memo = 1; /* just mark that a set was matched */
  }
  return err;
}

int nfa_chr(re *r, nfa *n, unsigned int ch, size_t pos)
{
  int err;
  size_t i;
  bmp_clear(&n->pri_bmp_tmp);
  for (i = 0; i < n->b.dense_size; i++) {
    thrdspec thrd = n->b.dense[i];
    inst op = re_prog_get(r, thrd.pc);
    int pri = save_slots_perthrd(&n->slots)
                  ? bmp_get(&n->pri_bmp_tmp, r->prog_set_idxs.ptr[thrd.pc])
                  : 0;
    if (pri && n->pri)
      continue; /* priority exhaustion: disregard this thread */
    switch (inst_opcode(op)) {
    case RANGE: {
      byte_range br = u32_to_byte_range(inst_param(op));
      if (ch >= br.l && ch <= br.h) {
        thrd.pc = inst_next(op);
        sset_add(&n->a, thrd);
      } else
        save_slots_kill(&n->slots, thrd.slot);
      break;
    }
    case MATCH: {
      assert(!inst_next(op));
      assert(!inst_match_param_slot(inst_param(op)));
      if ((err = nfa_matchend(r, n, thrd, pos, ch)))
        return err;
      if (save_slots_perthrd(&n->slots) && n->pri)
        bmp_set(&n->pri_bmp_tmp, r->prog_set_idxs.ptr[thrd.pc]);
      break;
    }
    default:
      assert(0);
    }
  }
  return 0;
}

#define SENT_CH 256

u32 is_word_char(u32 ch)
{
  return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') ||
         (ch >= 'a' && ch <= 'z') || ch == '_';
}

assert_flag make_assert_flag_raw(
    u32 prev_text_begin, u32 prev_line_begin, u32 prev_word, u32 next_ch)
{
  return prev_text_begin * TEXT_BEGIN | (next_ch == SENT_CH) * TEXT_END |
         prev_line_begin * LINE_BEGIN |
         (next_ch == SENT_CH || next_ch == '\n') * LINE_END |
         ((prev_word == is_word_char(next_ch)) ? NOT_WORD : WORD);
}

assert_flag make_assert_flag(u32 prev_ch, u32 next_ch)
{
  return make_assert_flag_raw(
      prev_ch == SENT_CH, (prev_ch == SENT_CH || prev_ch == '\n'),
      is_word_char(prev_ch), next_ch);
}

/* return number of sets matched, -n otherwise */
/* 0th span is the full bounds, 1st is first group, etc. */
/* if max_set == 0 and max_span == 0 */
/* if max_set != 0 and max_span == 0 */
/* if max_set == 0 and max_span != 0 */
/* if max_set != 0 and max_span != 0 */
int nfa_end(
    re *r, size_t pos, nfa *n, u32 max_span, u32 max_set, span *out_span,
    u32 *out_set, u32 prev_ch)
{
  int err;
  size_t j, sets = 0, nset = 0;
  if ((err = nfa_eps(r, n, pos, make_assert_flag(prev_ch, SENT_CH))) ||
      (err = nfa_chr(r, n, 256, pos)))
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

int nfa_run(re *r, nfa *n, u32 ch, size_t pos, u32 prev_ch)
{
  int err;
  (err = nfa_eps(r, n, pos, make_assert_flag(prev_ch, ch))) ||
      (err = nfa_chr(r, n, ch, pos));
  return err;
}

#define DFA_MAX_NUM_STATES 256

typedef enum dfa_state_flag {
  FROM_TEXT_BEGIN = 1,
  FROM_LINE_BEGIN = 2,
  FROM_WORD = 4,
  PRIORITY_EXHAUST = 8,
  DFA_STATE_FLAG_MAX = 16
} dfa_state_flag;

typedef struct dfa_state {
  struct dfa_state *ptrs[256 + 1];
  u32 flags, nstate, nset;
} dfa_state;

typedef struct dfa {
  dfa_state **states;
  size_t states_size, num_active_states;
  dfa_state *entry[PROG_ENTRY_MAX][DFA_STATE_FLAG_MAX]; /* program entry type *
                                                           dfa_state_flag */
  stk set_buf;
} dfa;

void dfa_init(re *r, dfa *d)
{
  d->states = NULL;
  d->states_size = d->num_active_states = 0;
  memset(d->entry, 0, sizeof(d->entry));
  stk_init(r, &d->set_buf);
}

void dfa_destroy(re *r, dfa *d)
{
  size_t i;
  for (i = 0; i < d->states_size; i++)
    if (d->states[i])
      re_ialloc(r, sizeof(dfa_state), 0, d->states[i]);
  re_ialloc(r, d->states_size * sizeof(dfa_state *), 0, d->states);
  stk_destroy(r, &d->set_buf);
}

size_t dfa_state_size(u32 nstate, u32 nset)
{
  return sizeof(dfa_state) + sizeof(u32) * (nstate + nset);
}

u32 *dfa_state_data(dfa_state *state) { return (u32 *)(state + 1); }

/* need: current state, but ALSO the previous state's matches */
int dfa_construct(
    re *r, dfa *d, dfa_state *prev_state, unsigned int ch, u32 prev_flag,
    nfa *n, dfa_state **out_next_state)
{
  size_t i;
  int err = 0;
  u32 hash, table_pos, *state_data;
  dfa_state *next_state;
  /* check threads in n, and look them up in the dfa cache */
  hash = hashington(prev_flag);
  hash = hashington(hash + n->a.dense_size);
  hash = hashington(hash + d->set_buf.size);
  for (i = 0; i < n->a.dense_size; i++)
    hash = hashington(hash + n->a.dense[i].pc);
  for (i = 0; i < d->set_buf.size; i++)
    hash = hashington(hash + d->set_buf.size);
  if (!d->states_size) {
    /* need to allocate initial cache */
    dfa_state **next_cache =
        re_ialloc(r, 0, sizeof(dfa_state *) * DFA_MAX_NUM_STATES, NULL);
    if (!next_cache)
      return ERR_MEM;
    memset(next_cache, 0, sizeof(dfa_state *) * DFA_MAX_NUM_STATES);
    d->states = next_cache, d->states_size = DFA_MAX_NUM_STATES;
  }
  table_pos = hash % d->states_size;
  while (1) {
    /* linear probe for next state */
    if (!d->states[table_pos]) {
      next_state = NULL;
      break;
    }
    next_state = d->states[table_pos];
    state_data = dfa_state_data(next_state);
    if (next_state->flags != prev_flag)
      goto not_found;
    if (next_state->nstate != n->a.dense_size)
      goto not_found;
    if (next_state->nset != d->set_buf.size)
      goto not_found;
    for (i = 0; i < n->a.dense_size; i++)
      if (state_data[i] != n->a.dense[i].pc)
        goto not_found;
    for (i = 0; i < d->set_buf.size; i++)
      if (state_data[n->a.dense_size + i] != d->set_buf.ptr[i])
        goto not_found;
    /* state found! */
    break;
  not_found:
    table_pos += 1;
    if (table_pos == d->states_size)
      table_pos = 0;
  }
  if (!next_state) {
    /* we need to construct a new state */
    if (d->num_active_states == DFA_MAX_NUM_STATES) {
      /* clear cache */
      for (i = 0; i < d->states_size; d++)
        if (d->states[i]) {
          re_ialloc(
              r, dfa_state_size(d->states[i]->nstate, d->states[i]->nset), 0,
              d->states[i]);
          d->states[i] = NULL;
        }
      d->num_active_states = 0;
      table_pos = hash % d->states_size;
      memset(d->entry, 0, sizeof(d->entry));
      prev_state = NULL;
    }
    /* allocate new state */
    next_state =
        re_ialloc(r, 0, dfa_state_size(n->a.dense_size, d->set_buf.size), NULL);
    if (!next_state)
      return ERR_MEM;
    memset(next_state, 0, dfa_state_size(n->a.dense_size, d->set_buf.size));
    next_state->flags = prev_flag;
    next_state->nstate = n->a.dense_size;
    next_state->nset = d->set_buf.size;
    state_data = dfa_state_data(next_state);
    for (i = 0; i < n->a.dense_size; i++)
      state_data[i] = n->a.dense[i].pc;
    for (i = 0; i < d->set_buf.size; i++)
      state_data[n->a.dense_size + i] = d->set_buf.ptr[i];
    d->states[table_pos] = next_state;
  }
  assert(next_state);
  if (prev_state)
    /* link the states */
    prev_state->ptrs[ch] = next_state;
  *out_next_state = next_state;
  return err;
}

int dfa_construct_start(
    re *r, dfa *d, nfa *n, u32 entry, u32 prev_flag, dfa_state **out_next_state)
{
  int err = 0;
  /* clear the set buffer so that it can be used to compare dfa states later */
  d->set_buf.size = 0;
  *out_next_state = d->entry[entry][prev_flag];
  if (!*out_next_state) {
    thrdspec spec;
    spec.pc = r->entry[entry];
    spec.slot = 0;
    sset_clear(&n->a);
    sset_add(&n->a, spec);
    err = dfa_construct(r, d, NULL, 0, prev_flag, n, out_next_state);
  }
  return err;
}

int dfa_construct_chr(
    re *r, dfa *d, nfa *n, dfa_state *prev_state, unsigned int ch,
    dfa_state **out_next_state)
{
  int err;
  size_t i;
  /* clear the set buffer so that it can be used to compare dfa states later */
  d->set_buf.size = 0;
  /* we only care about `ch` if `prev_state != NULL`. we only care about
   * `prev_flag` if `prev_state == NULL` */
  /* import prev_state into n */
  sset_clear(&n->a);
  for (i = 0; i < prev_state->nstate; i++) {
    thrdspec thrd;
    thrd.pc = dfa_state_data(prev_state)[i];
    thrd.slot = 0;
    sset_add(&n->a, thrd);
  }
  /* run eps on n */
  if ((err = nfa_eps(
           r, n, 0,
           make_assert_flag_raw(
               prev_state->flags & TEXT_BEGIN, prev_state->flags & LINE_BEGIN,
               prev_state->flags & FROM_WORD, ch))))
    return err;
  /* collect matches and match priorities into d->set_buf */
  bmp_clear(&n->pri_bmp_tmp);
  for (i = 0; i < n->b.dense_size; i++) {
    thrdspec thrd = n->b.dense[i];
    inst op = re_prog_get(r, thrd.pc);
    int pri = save_slots_perthrd(&n->slots)
                  ? bmp_get(&n->pri_bmp_tmp, r->prog_set_idxs.ptr[thrd.pc])
                  : 0;
    if (pri && n->pri)
      continue; /* priority exhaustion: disregard this thread */
    switch (inst_opcode(op)) {
    case RANGE: {
      byte_range br = u32_to_byte_range(inst_param(op));
      if (ch >= br.l && ch <= br.h) {
        thrd.pc = inst_next(op);
        sset_add(&n->a, thrd);
      } else
        save_slots_kill(&n->slots, thrd.slot);
      break;
    }
    case MATCH: {
      assert(!inst_next(op));
      assert(!inst_match_param_slot(inst_param(op)));
      /* NOTE: since there only exists one match instruction for a set n, we
       * don't need to check if we've already pushed the match instruction. */
      if ((err =
               stk_push(r, &d->set_buf, inst_match_param_idx(inst_param(op)))))
        return err;
      if (n->pri)
        bmp_set(&n->pri_bmp_tmp, inst_match_param_idx(inst_param(op)));
      break;
    }
    default:
      assert(0);
    }
  }
  /* feed ch to n -> this was accomplished by the above code */
  return dfa_construct(
      r, d, prev_state, ch,
      (ch == SENT_CH) * TEXT_BEGIN | (ch == SENT_CH || ch == '\n') * LINE_END |
          (is_word_char(ch) ? WORD : NOT_WORD),
      n, out_next_state);
}

int re_match_dfa(
    re *r, nfa *nfa, u8 *s, size_t n, u32 max_span, u32 max_set, span *out_span,
    u32 *out_set, anchor_type anchor)
{
  int err;
  dfa dfa;
  dfa_state *state = NULL;
  size_t i;
  u32 entry = anchor == A_END          ? PROG_ENTRY_REVERSE
              : anchor == A_UNANCHORED ? PROG_ENTRY_DOTSTAR
                                       : 0;
  u32 incoming_assert_flag = FROM_TEXT_BEGIN | FROM_LINE_BEGIN;
  assert(max_span == 0 || max_span == 1);
  assert(anchor == A_BOTH);
  if ((err = nfa_start(
           r, nfa, r->entry[entry], 0, entry & PROG_ENTRY_REVERSE,
           entry & PROG_ENTRY_DOTSTAR)))
    return err;
  dfa_init(r, &dfa);
  if (!(state = dfa.entry[entry][incoming_assert_flag]) &&
      (err = dfa_construct_start(
           r, &dfa, nfa, entry, FROM_TEXT_BEGIN | FROM_LINE_BEGIN, &state)))
    goto done;
  for (i = 0; i < n; i++) {
    if (!state->ptrs[s[i]]) {
      if ((err = dfa_construct_chr(r, &dfa, nfa, state, s[i], &state)))
        goto done;
    } else
      state = state->ptrs[s[i]];
  }
  if (!state->ptrs[SENT_CH]) {
    if ((err = dfa_construct_chr(r, &dfa, nfa, state, SENT_CH, &state)))
      goto done;
  } else
    state = state->ptrs[s[i]];
  for (i = 0; i < state->nset; i++) {
    if (max_span)
      out_span[i].begin = 0, out_span[i].end = n;
    if (i < max_set)
      out_set[i] = dfa_state_data(state)[state->nstate + i];
  }
  err = state->nset;
done:
  dfa_destroy(r, &dfa);
  return err;
}

/* go to next state: run eps, dump previous state's matching state into new
 * state */
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
  nfa nfa;
  int err = 0;
  u32 entry = anchor == A_END          ? PROG_ENTRY_REVERSE
              : anchor == A_UNANCHORED ? PROG_ENTRY_DOTSTAR
                                       : 0;
  size_t i;
  u32 prev_ch = SENT_CH;
  if (!re_prog_size(r) && ((err = re_compile(r, r->ast_root, 0)) ||
                           (err = re_compile(r, r->ast_root, 1))))
    return err;
  nfa_init(r, &nfa);
  if (0 && anchor == A_BOTH && (max_span == 0 || max_span == 1)) {
    err = re_match_dfa(
        r, &nfa, (u8 *)s, n, max_span, max_set, out_span, out_set, anchor);
    goto done;
  }
  if ((err = nfa_start(
           r, &nfa, r->entry[entry], max_span * 2, entry & PROG_ENTRY_REVERSE,
           entry & PROG_ENTRY_DOTSTAR)))
    goto done;
  if (entry & PROG_ENTRY_REVERSE) {
    for (i = n; i > 0; i--) {
      if ((err = nfa_run(r, &nfa, ((const u8 *)s)[i - 1], i, prev_ch)))
        goto done;
      prev_ch = ((const u8 *)s)[i - 1];
    }
    if ((err = nfa_end(
             r, 0, &nfa, max_span, max_set, out_span, out_set, prev_ch)))
      goto done;
  } else {
    for (i = 0; i < n; i++) {
      if ((err = nfa_run(r, &nfa, ((const u8 *)s)[i], i, prev_ch)))
        goto done;
      prev_ch = ((const u8 *)s)[i];
    }
    if ((err = nfa_end(
             r, n, &nfa, max_span, max_set, out_span, out_set, prev_ch)))
      goto done;
  }
done:
  nfa_destroy(r, &nfa);
  return err;
}

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

/*T The rest of this file contains functions that aid debugging. */
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

char *dump_chr(char *buf, u32 ch, int ascii)
{
  if ((ch == '\a' && ch == 'a') || (ch == '\b' && ch == 'b') ||
      (ch == '\t' && ch == 't') || (ch == '\n' && ch == 'n') ||
      (ch == '\v' && ch == 'v') || (ch == '\f' && ch == 'f') ||
      (ch == '\r' && ch == 'r'))
    buf[0] = '\\', buf[1] = '\\', buf[2] = ch, buf[3] = 0;
  else if (ch == '"')
    buf[0] = '\\', buf[1] = '"';
  else if (ch >= ' ' && ch < 0x7F)
    buf[0] = ch, buf[1] = 0;
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

char *dump_chr_ascii(char *buf, u32 ch) { return dump_chr(buf, ch, 1); }

char *dump_chr_unicode(char *buf, u32 ch) { return dump_chr(buf, ch, 0); }

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

void astdump_i(re *r, u32 root, u32 ilvl, int format)
{
  const char *colors[] = {"1", "2", "3", "4"};
  u32 i, first = root ? r->ast.ptr[root] : 0;
  u32 sub[2] = {0xFF, 0xFF};
  char buf[32] = {0}, buf2[32] = {0};
  const char *node_name = root == REF_NONE     ? "\xc9\x9b" /* epsilon */
                          : (first == CHR)     ? "CHR"
                          : (first == CAT)     ? (sub[0] = 0, sub[1] = 1, "CAT")
                          : (first == ALT)     ? (sub[0] = 0, sub[1] = 1, "ALT")
                          : (first == QUANT)   ? (sub[0] = 0, "QUANT")
                          : (first == UQUANT)  ? (sub[0] = 0, "UQUANT")
                          : (first == GROUP)   ? (sub[0] = 0, "GROUP")
                          : (first == IGROUP)  ? (sub[0] = 0, "IGROUP")
                          : (first == CLS)     ? (sub[0] = 0, "CLS")
                          : (first == ICLS)    ? (sub[0] = 0, "ICLS")
                          : (first == ANYBYTE) ? "ANYBYTE"
                          : (first == AASSERT) ? "AASSERT"
                                               : NULL;
  if (format == TERM) {
    printf("%04u ", root);
    for (i = 0; i < ilvl; i++)
      printf(" ");
    printf("%s ", node_name);
  } else if (format == GRAPHVIZ) {
    printf("A%04X [label=\"%s\\n", root, node_name);
  }
  if (first == CHR)
    printf("%s", dump_chr_unicode(buf, *re_ast_param(r, root, 0)));
  else if (first == GROUP || first == IGROUP)
    printf("%s", dump_group_flag(buf, *re_ast_param(r, root, 1)));
  else if (first == QUANT || first == UQUANT)
    printf(
        "%s-%s", dump_quant(buf, *re_ast_param(r, root, 1)),
        dump_quant(buf2, *re_ast_param(r, root, 2)));
  else if (first == CLS || first == ICLS)
    printf(
        "%s-%s", dump_chr_unicode(buf, *re_ast_param(r, root, 1)),
        dump_chr_unicode(buf2, *re_ast_param(r, root, 2)));
  if (format == GRAPHVIZ)
    printf(
        "\"]\nsubgraph cluster_%04X { "
        "label=\"\";style=filled;colorscheme=greys7;fillcolor=%s;",
        root, colors[ilvl % (sizeof(colors) / sizeof(*colors))]);
  if (format == TERM)
    printf("\n");
  for (i = 0; i < sizeof(sub) / sizeof(*sub); i++)
    if (sub[i] != 0xFF) {
      u32 child = *re_ast_param(r, root, sub[i]);
      astdump_i(r, child, ilvl + 1, format);
      if (format == GRAPHVIZ)
        printf(
            "A%04X -> A%04X [style=%s]\n", root, child, i ? "dashed" : "solid");
    }
  if (format == GRAPHVIZ)
    printf("}\n");
}

void astdump(re *r, u32 root) { astdump_i(r, root, 0, TERM); }

void astdump_gv(re *r) { astdump_i(r, r->ast_root, 0, GRAPHVIZ); }

void ssetdump(sset *s)
{
  u32 i;
  for (i = 0; i < s->dense_size; i++)
    printf("%04X pc: %04X slot: %04X\n", i, s->dense[i].pc, s->dense[i].slot);
}

void progdump_range(re *r, u32 start, u32 end, int format)
{
  u32 j, k;
  assert(end <= re_prog_size(r));
  if (format == GRAPHVIZ)
    printf("node [colorscheme=pastel16]\n");
  for (; start < end; start++) {
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
          colors[inst_opcode(ins)], ops[inst_opcode(ins)],
          inst_next(ins) ? (inst_next(ins) == start + 1 ? 90 : 0) : 91,
          inst_next(ins), inst_param(ins), labels[k]);
      if (inst_opcode(ins) == MATCH)
        printf(
            " %s %u %s",
            inst_match_param_slot(inst_param(ins)) ? "slot" : "set",
            inst_match_param_idx(inst_param(ins)),
            inst_match_param_end(inst_param(ins)) ? "end" : "begin");
      printf("\n");
    } else {
      static const char *shapes[] = {"box", "diamond", "pentagon", "oval"};
      static const int colors[] = {1, 3, 6, 2};
      printf(
          "I%04X "
          "[shape=%s,fillcolor=%i,style=filled,regular=false,forcelabels=true,"
          "xlabel=\"%u\","
          "label=\"%s\\n",
          start, shapes[inst_opcode(ins)], colors[inst_opcode(ins)], start,
          ops[inst_opcode(ins)]);
      if (inst_opcode(ins) == RANGE)
        printf(
            "%s-%s",
            dump_chr_ascii(start_buf, u32_to_byte_range(inst_param(ins)).l),
            dump_chr_ascii(end_buf, u32_to_byte_range(inst_param(ins)).h));
      else if (inst_opcode(ins) == MATCH)
        printf(
            " %s %u %s",
            inst_match_param_slot(inst_param(ins)) ? "slot" : "set",
            inst_match_param_idx(inst_param(ins)),
            inst_match_param_end(inst_param(ins)) ? "end" : "begin");
      else if (inst_opcode(ins) == ASSERT)
        printf("%s", dump_assert(assert_buf, inst_param(ins)));
      printf("\"]\n");
      if (!(inst_opcode(ins) == MATCH &&
            inst_match_param_slot(inst_param(ins)) && !inst_next(ins))) {
        printf("I%04X -> I%04X\n", start, inst_next(ins));
        if (inst_opcode(ins) == SPLIT)
          printf("I%04X -> I%04X [style=dashed]\n", start, inst_param(ins));
      }
    }
  }
}

void progdump(re *r)
{
  progdump_range(r, 1, r->entry[PROG_ENTRY_REVERSE], TERM);
}

void progdump_r(re *r)
{
  progdump_range(r, r->entry[PROG_ENTRY_REVERSE], re_prog_size(r), TERM);
}

void progdump_whole(re *r) { progdump_range(r, 0, re_prog_size(r), TERM); }

void progdump_gv(re *r)
{
  progdump_range(r, 1, r->entry[PROG_ENTRY_DOTSTAR], GRAPHVIZ);
}

void cctreedump_i(stk *cc_tree, u32 ref, u32 lvl)
{
  u32 i;
  compcc_node *node = cc_treeref(cc_tree, ref);
  printf("%04X [%08X] ", ref, node->aux);
  for (i = 0; i < lvl; i++)
    printf("  ");
  printf(
      "%02X-%02X\n", u32_to_byte_range(node->range).l,
      u32_to_byte_range(node->range).h);
  if (node->child_ref)
    cctreedump_i(cc_tree, node->child_ref, lvl + 1);
  if (node->sibling_ref)
    cctreedump_i(cc_tree, node->sibling_ref, lvl);
}

void cctreedump(stk *cc_tree, u32 ref) { cctreedump_i(cc_tree, ref, 0); }
#endif

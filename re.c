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

#define RE_REF_NONE 0
#define RE_UTF_MAX  0x10FFFF

/* A general-purpose growable, generic buffer. */
typedef struct re_buf {
  char *ptr;
  size_t size, alloc;
} re_buf;

#define re_buf2(x) x *

typedef struct re_compframe {
  u32 root_ref, child_ref, idx, patch_head, patch_tail, pc, flags, set_idx;
} re_compframe;

/* A set of regular expressions. */
struct re {
  re_alloc alloc;
  re_buf2(u32) ast;
  u32 ast_root, ast_sets;
  re_buf2(u32) arg_stk;
  re_buf2(u32) op_stk;
  re_buf2(re_compframe) comp_stk;
  re_buf prog;
  re_buf2(u32) prog_set_idxs;
  re_buf cc_stk_a, cc_stk_b;
  u32 entry[4];
  const u8 *expr;
  size_t expr_pos, expr_size;
  const char *error;
  size_t error_pos;
};

/* Bit flags to identify program entry points in the `entry` field of `re`. */
typedef enum re_prog_entry {
  RE_PROG_ENTRY_REVERSE = 1,
  RE_PROG_ENTRY_DOTSTAR = 2,
  RE_PROG_ENTRY_MAX = 4
} re_prog_entry;

/* Helper macro for assertions. */
#define RE_IMPLIES(subj, pred) (!(subj) || (pred))

#ifndef RE_DEFAULT_ALLOC
/* Default allocation function. Hooks stdlib malloc. */
static void *re_default_alloc(
    size_t prev, size_t next, void *ptr, const char *file, int line)
{
  (void)file, (void)line;
  if (next) {
    (void)prev, assert(RE_IMPLIES(!prev, !ptr));
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

/* new buf:
 * initialize: set to NULL */

typedef struct re_buf2_hdr {
  size_t size, alloc;
} re_buf2_hdr;

re_buf2_hdr *re_buf2_get_hdr(void *buf) { return ((re_buf2_hdr *)buf) - 1; }

size_t re_buf2_size_t(void *buf)
{
  return buf ? re_buf2_get_hdr(buf)->size : 0;
}

static int re_buf2_reserve_t(re *r, void **buf, size_t size)
{
  re_buf2_hdr *hdr = NULL;
  assert(buf);
  if (!*buf) {
    hdr = re_ialloc(r, 0, sizeof(re_buf2_hdr) + size, NULL);
    if (!hdr)
      return ERR_MEM;
    hdr->alloc = hdr->size = size;
    *buf = hdr + 1;
  } else {
    size_t next_alloc;
    void *next_ptr;
    hdr = re_buf2_get_hdr(*buf);
    next_alloc = hdr->alloc;
    if (size <= hdr->alloc) {
      hdr->size = size;
      return 0;
    }
    while (next_alloc < size)
      next_alloc *= 2;
    next_ptr = re_ialloc(
        r, sizeof(re_buf2_hdr) + hdr->alloc, sizeof(re_buf2_hdr) + next_alloc,
        hdr);
    if (!next_ptr)
      return ERR_MEM;
    hdr = next_ptr;
    hdr->alloc = next_alloc;
    hdr->size = size;
    *buf = hdr + 1;
  }
  return 0;
}

static void re_buf2_destroy_t(re *r, void **buf)
{
  re_buf2_hdr *hdr;
  assert(buf);
  if (!*buf)
    return;
  hdr = re_buf2_get_hdr(*buf);
  re_ialloc(r, sizeof(*hdr) + hdr->alloc, 0, hdr);
}

static int re_buf2_grow_t(re *r, void **buf, size_t incr)
{
  assert(buf);
  return re_buf2_reserve_t(r, buf, re_buf2_size_t(*buf) + incr);
}

static size_t re_buf2_tail_t(void *buf, size_t decr)
{
  return re_buf2_get_hdr(buf)->size - decr;
}

size_t re_buf2_pop_t(void *buf, size_t decr)
{
  size_t out;
  re_buf2_hdr *hdr;
  assert(buf);
  out = re_buf2_tail_t(buf, decr);
  hdr = re_buf2_get_hdr(buf);
  assert(hdr->size >= decr);
  hdr->size -= decr;
  return out;
}

void re_buf2_clear(void *buf)
{
  if (!buf)
    return;
  re_buf2_get_hdr(buf)->size = 0;
}

#define re_buf2_esz(b) sizeof(**(b))
#define re_buf2_push(r, b, e)                                                  \
  (re_buf2_grow_t((r), (void **)(b), re_buf2_esz(b))                           \
       ? ERR_MEM                                                               \
       : (((*b)                                                                \
               [re_buf2_tail_t((void *)(*b), re_buf2_esz(b)) /                 \
                re_buf2_esz(b)]) = (e),                                        \
          0))
#define re_buf2_reserve(r, b, n)                                               \
  (re_buf_reserven(r, (void **)(b), re_buf2_esz(b) * (n)))
#define re_buf2_pop(b)                                                         \
  ((*b)[re_buf2_pop_t((void *)(*b), re_buf2_esz(b)) / re_buf2_esz(b)])
#define re_buf2_peek(b, n)                                                     \
  ((*b) + re_buf2_tail_t((void *)(*b), re_buf2_esz(b)) / re_buf2_esz(b) - (n))
#define re_buf2_size(b)       (re_buf2_size_t((void *)(b)) / sizeof(*(b)))
#define re_buf2_destroy(r, b) (re_buf2_destroy_t((r), (void **)(b)))

/* For a library like this, you really need a convenient way to represent
 * dynamically-sized arrays of many different types. There's a million ways to
 * do this in C, but they usually boil down to capturing the size of each
 * element, and then plugging that size into an array allocation routine.
 * Originally, this library used a non-generic dynamic array only capable of
 * holding u32 (machine words), and simply represented all relevant types in
 * terms of u32. This actually worked very well for the AST and parser, but the
 * more complex structures used to execute regular expressions really benefit
 * from having a properly typed dynamic array implementation. */
/* I avoided implementing this generically for a while because I didn't want to
 * spend the brainpower on finding an elegant way to do this. The main problems
 * with making this kind of generic data structure in C are (1) the free-for-all
 * that comes into play once you start fiddling with macros, and (2) the lack of
 * type safety. Problem 1 cannot easily be fixed, as macros are a requirement,
 * but problem 2 can. The issue with type safety, however, is that one must
 * declare all generic functions they want to use beforehand (essentially manual
 * template instantiation). This leads to lots of unreadable, irrelevant code.
 * These declarations could be rolled into a macro, but that just makes Problem
 * 1 worse. */
static void re_buf_init(re_buf *b)
{
  b->ptr = NULL;
  b->size = b->alloc = 0;
}

static void re_buf_destroy(const re *r, re_buf *b)
{
  re_ialloc(r, b->alloc, 0, b->ptr);
}

static int re_buf_reserven(const re *r, re_buf *b, size_t size)
{
  size_t next_alloc = b->alloc ? b->alloc : 1 /* initial allocation */;
  void *next_ptr;
  if (size <= b->alloc) {
    b->size = size;
    return 0;
  }
  while (next_alloc < size)
    next_alloc *= 2;
  next_ptr = re_ialloc(r, b->alloc, next_alloc, b->ptr);
  if (!next_ptr)
    return ERR_MEM;
  b->alloc = next_alloc;
  b->ptr = next_ptr;
  b->size = size;
  return 0;
}

static int re_buf_grown(const re *r, re_buf *b, size_t incr)
{
  return re_buf_reserven(r, b, b->size + incr);
}

static char *re_buf_tailn(re_buf *b, size_t elem_size)
{
  return b->ptr + b->size - elem_size;
}

static char *re_buf_popn(re_buf *b, size_t elem_size)
{
  void *out = re_buf_tailn(b, elem_size);
  assert(b->size >= elem_size);
  b->size -= elem_size;
  return out;
}

#define re_buf_ptr(T, ptr) ((T *)(ptr))
#define re_buf_push(r, b, T, e)                                                \
  (re_buf_grown((r), (b), sizeof(T))                                           \
       ? ERR_MEM                                                               \
       : (*re_buf_ptr(T, re_buf_tailn((b), sizeof(T))) = (e), 0))
#define re_buf_reserve(r, b, T, n) (re_buf_reserven(r, b, sizeof(T) * (n)))
#define re_buf_pop(b, T)           (*re_buf_ptr(T, re_buf_popn((b), sizeof(T))))
#define re_buf_peek(b, T, n)       ((re_buf_ptr(T, re_buf_tailn((b), sizeof(T)))) - n)
#define re_buf_at(b, T, i)         (re_buf_ptr(T, (b)->ptr)[(i)])
#define re_buf_size(b, T)          ((b).size / sizeof(T))
#define re_buf_clear(b)            ((b)->size = 0)

static int re_parse(re *r, const u8 *s, size_t sz, u32 *root);

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
  r->ast = NULL;
  r->ast_root = r->ast_sets = 0;
  r->arg_stk = r->op_stk = NULL, r->comp_stk = NULL;
  re_buf_init(&r->cc_stk_a), re_buf_init(&r->cc_stk_b);
  re_buf_init(&r->prog);
  r->prog_set_idxs = NULL;
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
  re_buf2_destroy(r, (void **)&r->ast);
  re_buf2_destroy(r, &r->op_stk), re_buf2_destroy(r, &r->arg_stk),
      re_buf2_destroy(r, &r->comp_stk);
  re_buf_destroy(r, &r->cc_stk_a), re_buf_destroy(r, &r->cc_stk_b);
  re_buf_destroy(r, &r->prog);
  re_buf2_destroy(r, (void **)&r->prog_set_idxs);
  r->alloc(sizeof(*r), 0, r, __FILE__, __LINE__);
}

typedef enum re_ast_type {
  /* A single character: /a/ */
  RE_AST_TYPE_CHR = 1,
  /* The concatenation of two regular expressions: /lr/
   *   Argument 0: left child tree (AST)
   *   Argument 1: right child tree (AST) */
  RE_AST_TYPE_CAT,
  /* The alternation of two regular expressions: /l|r/
   *   Argument 0: primary alternation tree (AST)
   *   Argument 1: secondary alternation tree (AST) */
  RE_AST_TYPE_ALT,
  /* A repeated regular expression: /a+/
   *   Argument 0: child tree (AST)
   *   Argument 1: lower bound, always <= upper bound (number)
   *   Argument 2: upper bound, might be the constant `RE_INFTY` (number) */
  RE_AST_TYPE_QUANT,
  /* Like `QUANT`, but not greedy: /(a*?)/
   *   Argument 0: child tree (AST)
   *   Argument 1: lower bound, always <= upper bound (number)
   *   Argument 2: upper bound, might be the constant `RE_INFTY` (number) */
  RE_AST_TYPE_UQUANT,
  /* A matching group: /(a)/
   *   Argument 0: child tree (AST)
   *   Argument 1: group flags, bitset of `enum group_flag` (number)
   *   Argument 2: scratch used by the parser to store old flags (number) */
  RE_AST_TYPE_GROUP,
  /* An inline group: /(?i)a/
   *   Argument 0: child tree (AST)
   *   Argument 1: group flags, bitset of `enum group_flag` (number)
   *   Argument 2: scratch used by the parser to store old flags (number) */
  RE_AST_TYPE_IGROUP,
  /* A character class: /[a-zA-Z]/
   *   Argument 0: RE_REF_NONE or another CLS node in the charclass (AST)
   *   Argument 1: character range begin (number)
   *   Argument 2: character range end (number) */
  RE_AST_TYPE_CC,
  /* An inverted character class: /[^a-zA-Z]/
   *   Argument 0: RE_REF_NONE or another CLS node in the charclass (AST)
   *   Argument 1: character range begin (number)
   *   Argument 2: character range end (number) */
  RE_AST_TYPE_ICC,
  /* Matches any byte: /\C/ */
  RE_AST_TYPE_ANYBYTE,
  /* Empty assertion: /\b/
   *   Argument 0: assertion flags, bitset of `enum assert_flag` (number) */
  RE_AST_TYPE_ASSERT
} re_ast_type;

static const unsigned int re_ast_type_lens[] = {
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

typedef enum re_group_flag {
  RE_GROUP_FLAG_INSENSITIVE = 1,   /* case-insensitive matching */
  RE_GROUP_FLAG_MULTILINE = 2,     /* ^$ match beginning/end of each line */
  RE_GROUP_FLAG_DOTNEWLINE = 4,    /* . matches \n */
  RE_GROUP_FLAG_UNGREEDY = 8,      /* ungreedy quantifiers */
  RE_GROUP_FLAG_NONCAPTURING = 16, /* non-capturing group (?:...) */
  RE_GROUP_FLAG_SUBEXPRESSION = 32 /* set-match component */
} re_group_flag;

typedef enum re_assert_flag {
  RE_ASSERT_LINE_BEGIN = 1, /* ^ */
  RE_ASSERT_LINE_END = 2,   /* $ */
  RE_ASSERT_TEXT_BEGIN = 4, /* \A */
  RE_ASSERT_TEXT_END = 8,   /* \z */
  RE_ASSERT_WORD = 16,      /* \w */
  RE_ASSERT_NOT_WORD = 32   /* \W */
} re_assert_flag;

/* Represents an inclusive range of bytes. */
typedef struct re_byte_range {
  u8 l /* min ordinal */, h /* max ordinal */;
} re_byte_range;

/* Make a byte range inline. */
static re_byte_range re_byte_range_make(u8 l, u8 h)
{
  re_byte_range out;
  out.l = l, out.h = h;
  return out;
}

/* Pack a byte range into a u32, low byte first. */
static u32 re_byte_range_to_u32(re_byte_range br)
{
  return ((u32)br.l) | ((u32)br.h) << 8;
}

/* Unpack a byte range from a u32. */
static re_byte_range re_u32_to_byte_range(u32 u)
{
  return re_byte_range_make(u & 0xFF, u >> 8 & 0xFF);
}

/* Check if two byte ranges are adjacent (right directly supersedes left) */
static int re_byte_range_is_adjacent(re_byte_range left, re_byte_range right)
{
  return ((u32)left.h) + 1 == ((u32)right.l);
}

/* Represents an inclusive range of runes. */
typedef struct re_rune_range {
  u32 l, h;
} re_rune_range;

/* Make a rune range inline. */
static re_rune_range re_rune_range_make(u32 l, u32 h)
{
  re_rune_range out;
  out.l = l, out.h = h;
  return out;
}

/* Make a new AST node within the regular expression. */
static int
re_ast_make(re *r, re_ast_type type, u32 p0, u32 p1, u32 p2, u32 *out_node)
{
  u32 args[4], i;
  int err;
  args[0] = type, args[1] = p0, args[2] = p1, args[3] = p2;
  if (type && !re_buf2_size(r->ast) &&
      (err = re_ast_make(r, 0, 0, 0, 0, out_node))) /* sentinel node */
    return err;
  *out_node = re_buf2_size(r->ast);
  for (i = 0; i < 1 + re_ast_type_lens[type]; i++)
    if ((err = re_buf2_push(r, &r->ast, args[i])))
      return err;
  return 0;
}

/* Decompose a given AST node, given its reference, into `out_args`. */
static void re_ast_decompose(re *r, u32 node, u32 *out_args)
{
  u32 *in_args = r->ast + node;
  memcpy(out_args, in_args + 1, re_ast_type_lens[*in_args] * sizeof(u32));
}

/* Get the type of the given AST node. */
static u32 *re_ast_type_ref(re *r, u32 node) { return r->ast + node; }

/* Get a pointer to the `n`'th parameter of the given AST node. */
static u32 *re_ast_param_ref(re *r, u32 node, u32 n)
{
  assert(re_ast_type_lens[*re_ast_type_ref(r, node)] > n);
  return r->ast + node + 1 + n;
}

/* Add another regular expression to the set of regular expressions matched by
 * this `re` instance. */
int re_union(re *r, const char *regex, size_t n)
{
  int err = 0;
  u32 next_reg, next_root;
  if (!r->ast_sets) {
    r->ast_sets++;
    return re_parse(r, (const u8 *)regex, n, &r->ast_root);
  }
  if ((err = re_parse(r, (const u8 *)regex, n, &next_reg)) ||
      (err = re_ast_make(
           r, RE_AST_TYPE_ALT, r->ast_root, next_reg, 0, &next_root)))
    return err;
  r->ast_root = next_root;
  r->ast_sets++;
  return err;
}

#define RE_UTF8_ACCEPT 0
#define RE_UTF8_REJECT 1

static const uint8_t re_utf8_dfa[] = {
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

static u32 re_utf8_decode(u32 *state, u32 *codep, u32 byte)
{
  u32 type = re_utf8_dfa[byte];
  *codep = (*state != RE_UTF8_ACCEPT) ? (byte & 0x3fu) | (*codep << 6)
                                      : (0xff >> type) & (byte);

  *state = re_utf8_dfa[256 + *state * 16 + type];
  return *state;
}

/* Create and propagate a parsing error.
 * Returns `ERR_PARSE` unconditionally. */
static int re_parse_err(re *r, const char *msg)
{
  r->error = msg, r->error_pos = r->expr_pos;
  return ERR_PARSE;
}

/* Check if we are at the end of the regex string. */
static int re_parse_has_more(re *r) { return r->expr_pos != r->expr_size; }

static u32 re_parse_next(re *r)
{
  u32 state = RE_UTF8_ACCEPT, codep;
  assert(re_parse_has_more(r));
  while (re_utf8_decode(&state, &codep, r->expr[r->expr_pos++]) !=
         RE_UTF8_ACCEPT)
    assert(r->expr_pos < r->expr_size);
  assert(state == RE_UTF8_ACCEPT);
  return codep;
}

/* Get the next input codepoint. */
static int re_parse_next_or(re *r, u32 *codep, const char *else_msg)
{
  assert(else_msg);
  if (!re_parse_has_more(r))
    return re_parse_err(r, else_msg);
  *codep = re_parse_next(r);
  return 0;
}

static int re_parse_checkutf8(re *r)
{
  u32 state = RE_UTF8_ACCEPT, codep;
  while (r->expr_pos < r->expr_size &&
         re_utf8_decode(&state, &codep, r->expr[r->expr_pos]) != RE_UTF8_REJECT)
    r->expr_pos++;
  if (state != RE_UTF8_ACCEPT)
    return re_parse_err(r, "invalid utf-8 sequence");
  r->expr_pos = 0;
  return 0;
}

/* Without advancing the parser, check the next character. */
static u32 re_peek_next_new(re *r)
{
  size_t prev_pos = r->expr_pos;
  u32 out = re_parse_next(r);
  r->expr_pos = prev_pos;
  return out;
}

#define RE_LIMIT_REPETITION_COUNT 100000
#define RE_INFTY                  (RE_LIMIT_REPETITION_COUNT + 1)

/* Given nodes R_1i..R_N on the argument stack, fold them into a single CAT
 * node. If there are no nodes on the stack, create an epsilon node.
 * Returns `ERR_MEM` if out of memory. */
static int re_fold(re *r)
{
  int err = 0;
  if (!re_buf2_size(r->arg_stk)) {
    /* arg_stk: | */
    return re_buf2_push(r, &r->arg_stk, RE_REF_NONE);
    /* arg_stk: | eps |*/
  }
  while (re_buf2_size(r->arg_stk) > 1) {
    /* arg_stk: | ... | R_N-1 | R_N | */
    u32 right, left, rest;
    right = re_buf2_pop(&r->arg_stk);
    left = *re_buf2_peek(&r->arg_stk, 0);
    if ((err = re_ast_make(r, RE_AST_TYPE_CAT, left, right, 0, &rest)))
      return err;
    *re_buf2_peek(&r->arg_stk, 0) = rest;
    /* arg_stk: | ... | R_N-1R_N | */
  }
  /* arg_stk: | R1R2...Rn | */
  return 0;
}

/* Given a node R on the argument stack and an arbitrary number of ALT nodes at
 * the end of the operator stack, fold and finish each ALT node into a single
 * resulting ALT node on the argument stack.
 * Returns `ERR_MEM` if out of memory. */
static void re_fold_alts(re *r, u32 *flags)
{
  assert(re_buf2_size(r->arg_stk) == 1);
  /* First pop all inline groups. */
  while (re_buf2_size(r->op_stk) &&
         *re_ast_type_ref(r, *re_buf2_peek(&r->op_stk, 0)) ==
             RE_AST_TYPE_IGROUP) {
    /* arg_stk: |  R  | */
    /* op_stk:  | ... | (S) | */
    u32 igrp = re_buf2_pop(&r->op_stk), cat = *re_ast_param_ref(r, igrp, 0),
        old_flags = *re_ast_param_ref(r, igrp, 2);
    *re_ast_param_ref(r, igrp, 0) = *re_buf2_peek(&r->arg_stk, 0);
    *flags = old_flags;
    *re_ast_param_ref(r, cat, 1) = igrp;
    *re_buf2_peek(&r->arg_stk, 0) = cat;
    /* arg_stk: | S(R)| */
    /* op_stk:  | ... | */
  }
  assert(re_buf2_size(r->arg_stk) == 1);
  /* arg_stk: |  R  | */
  /* op_stk:  | ... | */
  if (re_buf2_size(r->op_stk) &&
      *re_ast_type_ref(r, *re_buf2_peek(&r->op_stk, 0)) == RE_AST_TYPE_ALT) {
    /* op_stk:  | ... |  A  | */
    /* finish the last alt */
    *re_ast_param_ref(r, *re_buf2_peek(&r->op_stk, 0), 1) =
        *re_buf2_peek(&r->arg_stk, 0);
    /* arg_stk: | */
    /* op_stk:  | ... | */
    while (re_buf2_size(r->op_stk) > 1 &&
           *re_ast_type_ref(r, *re_buf2_peek(&r->op_stk, 1)) ==
               RE_AST_TYPE_ALT) {
      /* op_stk:  | ... | A_1 | A_2 | */
      u32 right = re_buf2_pop(&r->op_stk), left = *re_buf2_peek(&r->op_stk, 0);
      *re_ast_param_ref(r, left, 1) = right;
      *re_buf2_peek(&r->op_stk, 0) = left;
      /* op_stk:  | ... | A_1(|A_2) | */
    }
    /* op_stk:  | ... |  A  | */
    assert(re_buf2_size(r->arg_stk) == 1);
    *re_buf2_peek(&r->arg_stk, 0) = re_buf2_pop(&r->op_stk);
    /* arg_stk: |  A  | */
    /* op_stk:  | ... | */
  }
  assert(re_buf2_size(r->arg_stk) == 1);
}

/* Add the CLS node `rest` to the CLS node `first`. */
static u32 re_ast_cls_union(re *r, u32 rest, u32 first)
{
  u32 cur = first, *next;
  assert(first);
  assert(
      *re_ast_type_ref(r, first) == RE_AST_TYPE_CC ||
      *re_ast_type_ref(r, first) == RE_AST_TYPE_ICC);
  assert(RE_IMPLIES(rest, *re_ast_type_ref(r, rest) == RE_AST_TYPE_CC));
  while (*(next = re_ast_param_ref(r, cur, 0)))
    cur = *next;
  *next = rest;
  return first;
}

/* Helper function to add a character to the argument stack.
 * Returns `ERR_MEM` if out of memory. */
static int re_parse_escape_addchr(re *r, u32 ch, u32 allowed_outputs)
{
  int err = 0;
  u32 res, args[1];
  (void)allowed_outputs, assert(allowed_outputs & (1 << RE_AST_TYPE_CHR));
  args[0] = ch;
  if ((err = re_ast_make(r, RE_AST_TYPE_CHR, ch, 0, 0, &res)) ||
      (err = re_buf2_push(r, &r->arg_stk, res)))
    return err;
  return 0;
}

/* Convert a hexadecimal digit to a number.
 * Returns -1 on invalid hex digit.
 * TODO: convert this to an idiomatic error function */
static int re_parse_hexdig(u32 ch)
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

static int re_parse_octdig(u32 ch)
{
  if (ch >= '0' && ch <= '7')
    return ch - '0';
  return -1;
}

typedef struct re_parse_builtin_cc {
  u8 name_len, cc_len;
  const char *name;
  const char *chars;
} re_parse_builtin_cc;

static const re_parse_builtin_cc re_parse_builtin_ccs[];

static const re_parse_builtin_cc *re_parse_named_cc(const u8 *s, size_t sz)
{
  const re_parse_builtin_cc *p = re_parse_builtin_ccs;
  while (p->name_len) {
    if ((size_t)p->name_len == sz && !memcmp(s, (const u8 *)p->name, sz))
      return p;
    p++;
  }
  return NULL;
}

static int re_parse_add_namedcc(re *r, const u8 *s, size_t sz, int invert)
{
  int err = 0;
  const re_parse_builtin_cc *named = re_parse_named_cc(s, sz);
  u32 res = RE_REF_NONE, i, max = 0, cur_min, cur_max;
  if (!named)
    return re_parse_err(r, "unknown builtin character class name");
  for (i = 0; i < named->cc_len; i++) {
    cur_min = named->chars[i * 2], cur_max = named->chars[i * 2 + 1];
    if (!invert &&
        (err = re_ast_make(r, RE_AST_TYPE_CC, res, cur_min, cur_max, &res)))
      return err;
    else if (invert) {
      assert(cur_min >= max); /* builtin charclasses are ordered. */
      if (max != cur_min &&
          (err = re_ast_make(r, RE_AST_TYPE_CC, res, max, cur_min - 1, &res)))
        return err;
      else
        max = cur_max + 1;
    }
  }
  assert(cur_max < RE_UTF_MAX); /* builtin charclasses never reach RE_UTF_MAX */
  assert(i);                    /* builtin charclasses are not length zero */
  if (invert && (err = re_ast_make(
                     r, RE_AST_TYPE_CC, res, cur_max + 1, RE_UTF_MAX, &res)))
    return err;
  if ((err = re_buf2_push(r, &r->arg_stk, res)))
    return err;
  return 0;
}

/* after a \ */
static int re_parse_escape(re *r, u32 allowed_outputs)
{
  u32 ch;
  int err = 0;
  if ((err = re_parse_next_or(r, &ch, "expected escape sequence")))
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
  } else if (re_parse_octdig(ch) >= 0) { /* octal escape */
    int digs = 1;
    u32 ord = ch - '0';
    while (digs++ < 3 && re_parse_has_more(r) &&
           re_parse_octdig(ch = re_peek_next_new(r)) >= 0) {
      ch = re_parse_next(r);
      assert(!err && re_parse_octdig(ch) >= 0);
      ord = ord * 8 + re_parse_octdig(ch);
    }
    return re_parse_escape_addchr(r, ord, allowed_outputs);
  } else if (ch == 'x') { /* hex escape */
    u32 ord = 0;
    if ((err = re_parse_next_or(
             r, &ch, "expected two hex characters or a bracketed hex literal")))
      return err;
    if (ch == '{') { /* bracketed hex lit */
      u32 i = 0;
      while (1) {
        if ((i == 7) || (err = re_parse_next_or(
                             r, &ch, "expected up to six hex characters")))
          return re_parse_err(r, "expected up to six hex characters");
        if (ch == '}')
          break;
        if ((err = re_parse_hexdig(ch)) == -1)
          return re_parse_err(r, "invalid hex digit");
        ord = ord * 16 + err;
        i++;
      }
      if (!i)
        return re_parse_err(r, "expected at least one hex character");
    } else if ((err = re_parse_hexdig(ch)) == -1) {
      return re_parse_err(r, "invalid hex digit");
    } else {
      ord = err;
      if ((err = re_parse_next_or(r, &ch, "expected two hex characters")))
        return err;
      else if ((err = re_parse_hexdig(ch)) == -1)
        return re_parse_err(r, "invalid hex digit");
      ord = ord * 16 + err;
    }
    if (ord > RE_UTF_MAX)
      return re_parse_err(r, "ordinal value out of range [0, 0x10FFFF]");
    return re_parse_escape_addchr(r, ord, allowed_outputs);
  } else if (ch == 'C') { /* any byte: \C */
    u32 res;
    if (!(allowed_outputs & (1 << RE_AST_TYPE_ANYBYTE)))
      return re_parse_err(r, "cannot use \\C here");
    if ((err = re_ast_make(r, RE_AST_TYPE_ANYBYTE, 0, 0, 0, &res)) ||
        (err = re_buf2_push(r, &r->arg_stk, res)))
      return err;
  } else if (ch == 'Q') { /* quote string */
    u32 cat = RE_REF_NONE, chr = RE_REF_NONE;
    if (!(allowed_outputs & (1 << RE_AST_TYPE_CAT)))
      return re_parse_err(r, "cannot use \\Q...\\E here");
    while (re_parse_has_more(r)) {
      ch = re_parse_next(r);
      if (ch == '\\' && re_parse_has_more(r)) {
        ch = re_peek_next_new(r);
        if (ch == 'E') {
          ch = re_parse_next(r);
          assert(ch == 'E');
          return re_buf2_push(r, &r->arg_stk, cat);
        } else if (ch == '\\') {
          ch = re_parse_next(r);
          assert(ch == '\\');
        } else {
          ch = '\\';
        }
      }
      if ((err = re_ast_make(r, RE_AST_TYPE_CHR, ch, 0, 0, &chr)))
        return err;
      if ((err = re_ast_make(r, RE_AST_TYPE_CAT, cat, chr, 0, &cat)))
        return err;
    }
    if ((err = re_buf2_push(r, &r->arg_stk, cat)))
      return err;
  } else if (
      ch == 'D' || ch == 'd' || ch == 'S' || ch == 's' || ch == 'W' ||
      ch == 'w') {
    /* Perl builtin character classes */
    const char *cc_name;
    int inverted =
        ch == 'D' || ch == 'S' || ch == 'W'; /* uppercase are inverted */
    ch = inverted ? ch - 'A' + 'a' : ch;     /* convert to lowercase */
    cc_name = ch == 'd' ? "digit" : ch == 's' ? "perl_space" : "word";
    if (!(allowed_outputs & (1 << RE_AST_TYPE_CC)))
      return re_parse_err(r, "cannot use a character class here");
    if ((err = re_parse_add_namedcc(
             r, (const u8 *)cc_name, strlen(cc_name), inverted)))
      return err;
  } else if (ch == 'A' || ch == 'z' || ch == 'B' || ch == 'b') { /* empty
                                                                    asserts */
    u32 res;
    if (!(allowed_outputs & (1 << RE_AST_TYPE_ASSERT)))
      return re_parse_err(r, "cannot use an epsilon assertion here");
    if ((err = re_ast_make(
             r, RE_AST_TYPE_ASSERT,
             ch == 'A'   ? RE_ASSERT_TEXT_BEGIN
             : ch == 'z' ? RE_ASSERT_TEXT_END
             : ch == 'B' ? RE_ASSERT_NOT_WORD
                         : RE_ASSERT_WORD,
             0, 0, &res)) ||
        (err = re_buf2_push(r, &r->arg_stk, res)))
      return err;
  } else {
    return re_parse_err(r, "invalid escape sequence");
  }
  return 0;
}

static int re_parse_number(re *r, u32 *out, u32 max_digits)
{
  int err = 0;
  u32 ch, acc = 0, ndigs = 0;
  if (!re_parse_has_more(r))
    return re_parse_err(r, "expected at least one decimal digit");
  while (ndigs < max_digits && re_parse_has_more(r) &&
         (ch = re_peek_next_new(r)) >= '0' && ch <= '9')
    acc = acc * 10 + (re_parse_next(r) - '0'), ndigs++;
  if (!ndigs)
    return re_parse_err(r, "expected at least one decimal digit");
  if (ndigs == max_digits)
    return re_parse_err(r, "too many digits for decimal number");
  *out = acc;
  return err;
}

static int re_parse(re *r, const u8 *ts, size_t tsz, u32 *root)
{
  int err;
  u32 flags = 0;
  r->expr = ts;
  r->expr_size = tsz, r->expr_pos = 0;
  if ((err = re_parse_checkutf8(r)))
    return err;
  while (re_parse_has_more(r)) {
    u32 ch = re_parse_next(r), res = RE_REF_NONE;
    if (ch == '*' || ch == '+' || ch == '?') {
      u32 q = ch, greedy = 1;
      /* arg_stk: | ... |  R  | */
      /* pop one from arg stk, create quant, push to arg stk */
      if (!re_buf2_size(r->arg_stk))
        return re_parse_err(r, "cannot apply quantifier to empty regex");
      if (re_parse_has_more(r) && re_peek_next_new(r) == '?')
        re_parse_next(r), greedy = 0;
      if ((err = re_ast_make(
               r, greedy ? RE_AST_TYPE_QUANT : RE_AST_TYPE_UQUANT,
               *re_buf2_peek(&r->arg_stk, 0) /* child */, q == '+' /* min */,
               q == '?' ? 1 : RE_INFTY /* max */, &res)))
        return err;
      *re_buf2_peek(&r->arg_stk, 0) = res;
      /* arg_stk: | ... | *(R) | */
    } else if (ch == '|') {
      /* fold the arg stk into a concat, create alt, push it to the arg stk */
      /* op_stk:  | ... | */
      /* arg_stk: | R_1 | R_2 | ... | R_N | */
      if ((err = re_fold(r)))
        return err;
      /* arg_stk: |  R  | */
      if ((err = re_ast_make(
               r, RE_AST_TYPE_ALT, re_buf2_pop(&r->arg_stk) /* left */,
               RE_REF_NONE /* right */, 0, &res)) ||
          (err = re_buf2_push(r, &r->op_stk, res)))
        return err;
      /* arg_stk: | */
      /* op_stk:  | ... | R(|) | */
    } else if (ch == '(') {
      u32 old_flags = flags, inline_group = 0, child;
      if (!re_parse_has_more(r))
        return re_parse_err(r, "expected ')' to close group");
      ch = re_peek_next_new(r);
      if (ch == '?') { /* start of group flags */
        ch = re_parse_next(r);
        assert(ch == '?');
        if ((err = re_parse_next_or(
                 r, &ch,
                 "expected 'P', '<', or group flags after special "
                 "group opener \"(?\"")))
          return err;
        if (ch == 'P' || ch == '<') {
          if (ch == 'P' &&
              (err = re_parse_next_or(
                   r, &ch, "expected '<' after named group opener \"(?P\"")))
            return err;
          if (ch != '<')
            return re_parse_err(
                r, "expected '<' after named group opener \"(?P\"");
          /* parse group name */
          while (1) {
            if ((err = re_parse_next_or(
                     r, &ch, "expected name followed by '>' for named group")))
              return err;
            if (ch == '>')
              break;
          }
        } else {
          u32 neg = 0, flag = RE_GROUP_FLAG_UNGREEDY;
          while (1) {
            if (ch == ':' || ch == ')')
              break;
            else if (ch == '-') {
              if (neg)
                return re_parse_err(r, "cannot apply flag negation '-' twice");
              neg = 1;
            } else if (
                (ch == 'i' && (flag = RE_GROUP_FLAG_INSENSITIVE)) ||
                (ch == 'm' && (flag = RE_GROUP_FLAG_MULTILINE)) ||
                (ch == 's' && (flag = RE_GROUP_FLAG_DOTNEWLINE)) ||
                (ch == 'u')) {
              flags = neg ? flags & ~flag : flags | flag;
            } else {
              return re_parse_err(
                  r, "expected ':', ')', or group flags for special group");
            }
            if ((err = re_parse_next_or(
                     r, &ch,
                     "expected ':', ')', or group flags for special group")))
              return err;
          }
          flags |= RE_GROUP_FLAG_NONCAPTURING;
          if (ch == ')')
            inline_group = 1;
        }
      }
      /* op_stk:  | ... | */
      /* arg_stk: | R_1 | R_2 | ... | R_N | */
      if ((err = re_fold(r)))
        return err;
      child = re_buf2_pop(&r->arg_stk);
      if (inline_group &&
          (err = re_ast_make(r, RE_AST_TYPE_CAT, child, 0, 0, &child)))
        return err;
      /* arg_stk: |  R  | */
      if ((err = re_ast_make(
               r, inline_group ? RE_AST_TYPE_IGROUP : RE_AST_TYPE_GROUP, child,
               flags, old_flags, &res)) ||
          (err = re_buf2_push(r, &r->op_stk, res)))
        return err;
      /* op_stk:  | ... | (R) | */
    } else if (ch == ')') {
      u32 grp, prev;
      /* arg_stk: | S_1 | S_2 | ... | S_N | */
      /* op_stk:  | ... | (R) | ... | */
      /* fold the arg stk into a concat, fold remaining alts, create group,
       * push it to the arg stk */
      if ((err = re_fold(r)))
        return err;
      re_fold_alts(r, &flags);
      /* arg_stk has one value */
      assert(re_buf2_size(r->arg_stk) == 1);
      if (!re_buf2_size(r->op_stk))
        return re_parse_err(r, "extra close parenthesis");
      /* arg_stk: |  S  | */
      /* op_stk:  | ... | (R) | */
      grp = *re_buf2_peek(&r->op_stk, 0);
      /* retrieve the previous contents of arg_stk */
      prev = *re_ast_param_ref(r, grp, 0);
      /* add it to the group */
      *(re_ast_param_ref(r, grp, 0)) = *re_buf2_peek(&r->arg_stk, 0);
      /* restore group flags */
      flags = *(re_ast_param_ref(r, grp, 2));
      /* push the saved contents of arg_stk */
      *re_buf2_peek(&r->arg_stk, 0) = prev;
      /* pop the group frame into arg_stk */
      if ((err = re_buf2_push(r, &r->arg_stk, re_buf2_pop(&r->op_stk))))
        return err;
      /* arg_stk: |  R  | (S) | */
      /* op_stk:  | ... | */
    } else if (ch == '.') { /* any char */
      /* arg_stk: | ... | */
      if (((flags & RE_GROUP_FLAG_DOTNEWLINE) &&
           (err = re_ast_make(
                r, RE_AST_TYPE_CC, RE_REF_NONE, 0, RE_UTF_MAX, &res))) ||
          (!(flags & RE_GROUP_FLAG_DOTNEWLINE) &&
           ((err = re_ast_make(
                 r, RE_AST_TYPE_CC, RE_REF_NONE, 0, '\n' - 1, &res)) ||
            (err = re_ast_make(
                 r, RE_AST_TYPE_CC, res, '\n' + 1, RE_UTF_MAX, &res)))) ||
          (err = re_buf2_push(r, &r->arg_stk, res)))
        return err;
      /* arg_stk: | ... |  .  | */
    } else if (ch == '[') { /* charclass */
      size_t start = r->expr_pos;
      u32 inverted = 0, min, max;
      res = RE_REF_NONE;
      while (1) {
        u32 next;
        if ((err = re_parse_next_or(r, &ch, "unclosed character class")))
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
          if ((err = re_parse_escape(
                   r, (1 << RE_AST_TYPE_CHR) | (1 << RE_AST_TYPE_CC))))
            return err;
          next = re_buf2_pop(&r->arg_stk);
          assert(
              *re_ast_type_ref(r, next) == RE_AST_TYPE_CHR ||
              *re_ast_type_ref(r, next) == RE_AST_TYPE_CC);
          if (*re_ast_type_ref(r, next) == RE_AST_TYPE_CHR)
            min = *re_ast_param_ref(r, next, 0); /* single-character escape */
          else {
            assert(*re_ast_type_ref(r, next) == RE_AST_TYPE_CC);
            res = re_ast_cls_union(r, res, next);
            /* we parsed an entire class, so there's no ending character */
            continue;
          }
        } else if (
            ch == '[' && re_parse_has_more(r) &&
            re_peek_next_new(r) == ':') { /* named class */
          int named_inverted = 0;
          size_t name_start, name_end;
          ch = re_parse_next(r); /* : */
          assert(!err && ch == ':');
          if (re_parse_has_more(r) &&
              (ch = re_peek_next_new(r)) == '^') { /* inverted named class */
            ch = re_parse_next(r);
            assert(ch == '^');
            named_inverted = 1;
          }
          name_start = name_end = r->expr_pos;
          while (1) {
            if ((err =
                     re_parse_next_or(r, &ch, "expected character class name")))
              return err;
            if (ch == ':')
              break;
            name_end = r->expr_pos;
          }
          if ((err = re_parse_next_or(
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
          next = re_buf2_pop(&r->arg_stk);
          assert(next && *re_ast_type_ref(r, next) == RE_AST_TYPE_CC);
          res = re_ast_cls_union(r, res, next);
          continue;
        }
        max = min;
        if (re_parse_has_more(r) && re_peek_next_new(r) == '-') {
          /* range expression */
          ch = re_parse_next(r);
          assert(ch == '-');
          ch = re_parse_next(r);
          if (ch == '\\') { /* start of escape */
            if ((err = re_parse_escape(r, (1 << RE_AST_TYPE_CHR))))
              return err;
            next = re_buf2_pop(&r->arg_stk);
            assert(*re_ast_type_ref(r, next) == RE_AST_TYPE_CHR);
            max = *re_ast_param_ref(r, next, 0);
          } else {
            max = ch; /* non-escaped character */
          }
        }
        if ((err = re_ast_make(r, RE_AST_TYPE_CC, res, min, max, &res)))
          return err;
      }
      assert(res);  /* charclass cannot be empty */
      if (inverted) /* inverted character class */
        *re_ast_type_ref(r, res) = RE_AST_TYPE_ICC;
      if ((err = re_buf2_push(r, &r->arg_stk, res)))
        return err;
    } else if (ch == '\\') { /* escape */
      if ((err = re_parse_escape(
               r, 1 << RE_AST_TYPE_CHR | 1 << RE_AST_TYPE_CC |
                      1 << RE_AST_TYPE_ANYBYTE | 1 << RE_AST_TYPE_CAT |
                      1 << RE_AST_TYPE_ASSERT)))
        return err;
    } else if (ch == '{') { /* repetition */
      u32 min = 0, max = 0;
      if ((err = re_parse_number(r, &min, 6)))
        return err;
      if ((err = re_parse_next_or(
               r, &ch, "expected } to end repetition expression")))
        return err;
      if (ch == '}')
        max = min;
      else if (ch == ',') {
        if (!re_parse_has_more(r))
          return re_parse_err(
              r, "expected upper bound or } to end repetition expression");
        ch = re_peek_next_new(r);
        if (ch == '}')
          ch = re_parse_next(r), assert(ch == '}'), max = RE_INFTY;
        else {
          if ((err = re_parse_number(r, &max, 6)))
            return err;
          if ((err = re_parse_next_or(
                   r, &ch, "expected } to end repetition expression")))
            return err;
          if (ch != '}')
            return re_parse_err(r, "expected } to end repetition expression");
        }
      } else
        return re_parse_err(r, "expected } or , for repetition expression");
      if (!re_buf2_size(r->arg_stk))
        return re_parse_err(r, "cannot apply quantifier to empty regex");
      if ((err = re_ast_make(
               r, RE_AST_TYPE_QUANT, *re_buf2_peek(&r->arg_stk, 0), min, max,
               &res)))
        return err;
      *re_buf2_peek(&r->arg_stk, 0) = res;
    } else if (ch == '^' || ch == '$') { /* beginning/end of text/line */
      if ((err = re_ast_make(
               r, RE_AST_TYPE_ASSERT,
               ch == '^'
                   ? (flags & RE_GROUP_FLAG_MULTILINE ? RE_ASSERT_LINE_BEGIN
                                                      : RE_ASSERT_TEXT_BEGIN)
                   : (flags & RE_GROUP_FLAG_MULTILINE ? RE_ASSERT_LINE_END
                                                      : RE_ASSERT_TEXT_END),
               0, 0, &res)) ||
          (err = re_buf2_push(r, &r->arg_stk, res)))
        return err;
    } else { /* char: push to the arg stk */
      /* arg_stk: | ... | */
      if ((err = re_ast_make(r, RE_AST_TYPE_CHR, ch, 0, 0, &res)) ||
          (err = re_buf2_push(r, &r->arg_stk, res)))
        return err;
      /* arg_stk: | ... | chr | */
    }
  }
  if ((err = re_fold(r)))
    return err;
  re_fold_alts(r, &flags);
  if (re_buf2_size(r->op_stk))
    return re_parse_err(r, "unmatched open parenthesis");
  if ((err = re_ast_make(
           r, RE_AST_TYPE_GROUP, re_buf2_pop(&r->arg_stk),
           RE_GROUP_FLAG_SUBEXPRESSION, 0, root)))
    return err;
  return 0;
}

typedef struct re_inst {
  u32 l, h;
} re_inst;

#define RE_INST_OPCODE_BITS 2

typedef enum re_opcode {
  RE_OPCODE_RANGE,
  RE_OPCODE_ASSERT,
  RE_OPCODE_MATCH,
  RE_OPCODE_SPLIT
} re_opcode;

static re_opcode re_inst_opcode(re_inst i)
{
  return i.l & (1 << RE_INST_OPCODE_BITS) - 1;
}

static u32 re_inst_next(re_inst i) { return i.l >> RE_INST_OPCODE_BITS; }

static u32 re_inst_param(re_inst i) { return i.h; }

static re_inst re_inst_make(re_opcode op, u32 next, u32 param)
{
  re_inst out;
  out.l = op | next << RE_INST_OPCODE_BITS, out.h = param;
  return out;
}

static u32 re_inst_match_param_make(u32 begin_or_end, u32 slot_idx_or_set_idx)
{
  assert(begin_or_end == 0 || begin_or_end == 1);
  return begin_or_end | (slot_idx_or_set_idx << 1);
}

static u32 re_inst_match_param_end(u32 param) { return param & 1; }

static u32 re_inst_match_param_idx(u32 param) { return param >> 1; }

static void re_prog_set(re *r, u32 pc, re_inst i)
{
  re_buf_at(&r->prog, re_inst, pc) = i;
}

static re_inst re_prog_get(const re *r, u32 pc)
{
  return re_buf_at(&r->prog, re_inst, pc);
}

static u32 re_prog_size(const re *r) { return re_buf_size(r->prog, re_inst); }

#define RE_PROG_MAX_INSTS 100000

static int re_inst_emit(re *r, re_inst i, re_compframe *frame)
{
  int err = 0;
  if (re_prog_size(r) == RE_PROG_MAX_INSTS)
    return ERR_LIMIT;
  if ((err = re_buf_push(r, &r->prog, re_inst, i)) ||
      (err = re_buf2_push(r, &r->prog_set_idxs, frame->set_idx)))
    return err;
  return err;
}

static re_inst re_patch_set(re *r, u32 pc, u32 val)
{
  re_inst prev = re_prog_get(r, pc >> 1);
  assert(pc);
  re_prog_set(
      r, pc >> 1,
      re_inst_make(
          re_inst_opcode(prev), pc & 1 ? re_inst_next(prev) : val,
          pc & 1 ? val : re_inst_param(prev)));
  return prev;
}

static void re_patch_add(re *r, re_compframe *f, u32 dest_pc, int p)
{
  u32 out_val = dest_pc << 1 | !!p;
  assert(dest_pc);
  if (!f->patch_head)
    f->patch_head = f->patch_tail = out_val;
  else {
    re_patch_set(r, f->patch_tail, out_val);
    f->patch_tail = out_val;
  }
}

static void re_patch_merge(re *r, re_compframe *p, re_compframe *q)
{
  if (!p->patch_head) {
    p->patch_head = q->patch_head;
    p->patch_tail = q->patch_tail;
    return;
  }
  re_patch_set(r, p->patch_tail, q->patch_head);
  p->patch_tail = q->patch_tail;
}

static void re_patch_xfer(re_compframe *dst, re_compframe *src)
{
  dst->patch_head = src->patch_head;
  dst->patch_tail = src->patch_tail;
  src->patch_head = src->patch_tail = RE_REF_NONE;
}

static void re_patch_apply(re *r, re_compframe *p, u32 dest_pc)
{
  u32 i = p->patch_head;
  while (i) {
    re_inst prev = re_patch_set(r, i, dest_pc);
    i = i & 1 ? re_inst_param(prev) : re_inst_next(prev);
  }
  p->patch_head = p->patch_tail = RE_REF_NONE;
}

static u32 re_compcc_array_key(re_buf *cc, size_t idx)
{
  return re_buf_at(cc, re_rune_range, idx).l;
}

static void re_compcc_array_swap(re_buf *cc, size_t a, size_t b)
{
  re_rune_range tmp = re_buf_at(cc, re_rune_range, a);
  re_buf_at(cc, re_rune_range, a) = re_buf_at(cc, re_rune_range, b);
  re_buf_at(cc, re_rune_range, b) = tmp;
}

static void re_compcc_hsort(re_buf *cc, size_t n)
{
  size_t start = n >> 1, end = n, root, child;
  while (end > 1) {
    if (start)
      start--;
    else
      re_compcc_array_swap(cc, --end, 0);
    root = start;
    while ((child = 2 * root + 1) < end) {
      if (child + 1 < end &&
          re_compcc_array_key(cc, child) < re_compcc_array_key(cc, child + 1))
        child++;
      if (re_compcc_array_key(cc, root) < re_compcc_array_key(cc, child)) {
        re_compcc_array_swap(cc, root, child);
        root = child;
      } else
        break;
    }
  }
}

typedef struct re_compcc_node {
  u32 range, child_ref, sibling_ref, aux;
} re_compcc_node;

static int
re_compcc_tree_new(re *r, re_buf *cc_out, re_compcc_node node, u32 *out)
{
  int err = 0;
  if (!re_buf_size(*cc_out, re_compcc_node)) {
    re_compcc_node sentinel = {0};
    /* need to create sentinel node */
    if ((err = re_buf_push(r, cc_out, re_compcc_node, sentinel)))
      return err;
  }
  if (out)
    *out = re_buf_size(*cc_out, re_compcc_node);
  if ((err = re_buf_push(r, cc_out, re_compcc_node, node)))
    return err;
  return 0;
}

static int
re_compcc_tree_append(re *r, re_buf *cc, u32 range, u32 parent, u32 *out)
{
  re_compcc_node *parent_node, child_node = {0};
  u32 child_ref;
  int err;
  parent_node = &re_buf_at(cc, re_compcc_node, parent);
  child_node.sibling_ref = parent_node->child_ref, child_node.range = range;
  if ((err = re_compcc_tree_new(r, cc, child_node, &child_ref)))
    return err;
  parent_node = &re_buf_at(cc, re_compcc_node, parent); /* ref could be stale */
  parent_node->child_ref = child_ref;
  assert(parent_node->child_ref != parent);
  assert(parent_node->sibling_ref != parent);
  assert(child_node.child_ref != parent_node->child_ref);
  assert(child_node.sibling_ref != parent_node->child_ref);
  *out = parent_node->child_ref;
  return 0;
}

static int re_compcc_tree_build_one(
    re *r, re_buf *cc_out, u32 parent, u32 min, u32 max, u32 x_bits, u32 y_bits)
{
  u32 x_mask = (1 << x_bits) - 1, y_min = min >> x_bits, y_max = max >> x_bits,
      u_mask = (0xFE << y_bits) & 0xFF, byte_min = (y_min & 0xFF) | u_mask,
      byte_max = (y_max & 0xFF) | u_mask, i, next;
  int err = 0;
  assert(y_bits <= 7);
  if (x_bits == 0) {
    if ((err = re_compcc_tree_append(
             r, cc_out,
             re_byte_range_to_u32(re_byte_range_make(byte_min, byte_max)),
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
      brs[0] = re_byte_range_to_u32(re_byte_range_make(byte_min, byte_max));
      mins[0] = x_min, maxs[0] = x_max;
      n = 1;
    } else if (!x_min) {
      /* Range begins on zero, but has multiple starting bytes */
      /* Output:
       * ---[Ymin-(Ymax-1)]---{tree for [00-FF]}
       *           |
       *      [Ymax-Ymax]----{tree for [00-Xmax]} */
      brs[0] = re_byte_range_to_u32(re_byte_range_make(byte_min, byte_max - 1));
      mins[0] = 0, maxs[0] = x_mask;
      brs[1] = re_byte_range_to_u32(re_byte_range_make(byte_max, byte_max));
      mins[1] = 0, maxs[1] = x_max;
      n = 2;
    } else if (x_max == x_mask) {
      /* Range ends on all ones, but has multiple starting bytes */
      /* Output:
       * -----[Ymin-Ymin]----{tree for [Xmin-FF]}
       *           |
       *    [(Ymin+1)-Ymax]---{tree for [00-FF]} */
      brs[0] = re_byte_range_to_u32(re_byte_range_make(byte_min, byte_min));
      mins[0] = x_min, maxs[0] = x_mask;
      brs[1] = re_byte_range_to_u32(re_byte_range_make(byte_min + 1, byte_max));
      mins[1] = 0, maxs[1] = x_mask;
      n = 2;
    } else if (y_min == y_max - 1) {
      /* Range occupies exactly two starting bytes */
      /* Output:
       * -----[Ymin-Ymin]----{tree for [Xmin-FF]}
       *           |
       *      [Ymax-Ymax]----{tree for [00-Xmax]} */
      brs[0] = re_byte_range_to_u32(re_byte_range_make(byte_min, byte_min));
      mins[0] = x_min, maxs[0] = x_mask;
      brs[1] = re_byte_range_to_u32(re_byte_range_make(byte_min + 1, byte_max));
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
      brs[0] = re_byte_range_to_u32(re_byte_range_make(byte_min, byte_min));
      mins[0] = x_min, maxs[0] = x_mask;
      brs[1] =
          re_byte_range_to_u32(re_byte_range_make(byte_min + 1, byte_max - 1));
      mins[1] = 0, maxs[1] = x_mask;
      brs[2] = re_byte_range_to_u32(re_byte_range_make(byte_max, byte_max));
      mins[2] = 0, maxs[2] = x_max;
      n = 3;
    }
    for (i = 0; i < n; i++) {
      re_compcc_node *parent_node;
      u32 child_ref;
      /* check if previous child intersects and then compute intersection */
      assert(parent);
      parent_node = &re_buf_at(cc_out, re_compcc_node, parent);
      if (parent_node->child_ref &&
          re_u32_to_byte_range(brs[i]).l <=
              re_u32_to_byte_range(
                  (&re_buf_at(cc_out, re_compcc_node, parent_node->child_ref))
                      ->range)
                  .h) {
        child_ref = parent_node->child_ref;
      } else {
        if ((err =
                 re_compcc_tree_append(r, cc_out, brs[i], parent, &child_ref)))
          return err;
      }
      if ((err = re_compcc_tree_build_one(
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
static int re_compcc_tree_build(re *r, re_buf *cc_in, re_buf *cc_out)
{
  size_t i = 0, j = 0, min_bound = 0;
  u32 root_ref;
  re_compcc_node root_node;
  int err = 0;
  root_node.child_ref = root_node.sibling_ref = root_node.aux =
      root_node.range = 0;
  /* clear output charclass */
  re_buf_clear(cc_out);
  if ((err = re_compcc_tree_new(r, cc_out, root_node, &root_ref)))
    return err;
  for (i = 0, j = 0; i < re_buf_size(*cc_in, re_rune_range) && j < 4;) {
    static const u32 y_bits[4] = {7, 5, 4, 3};
    static const u32 x_bits[4] = {0, 6, 12, 18};
    u32 max_bound = (1 << (x_bits[j] + y_bits[j])) - 1;
    re_rune_range rr = re_buf_at(cc_in, re_rune_range, i);
    if (min_bound <= rr.h && rr.l <= max_bound) {
      /* [min,max] intersects [min_bound,max_bound] */
      u32 clamped_min = rr.l < min_bound ? min_bound : rr.l, /* clamp range */
          clamped_max = rr.h > max_bound ? max_bound : rr.h;
      if ((err = re_compcc_tree_build_one(
               r, cc_out, root_ref, clamped_min, clamped_max, x_bits[j],
               y_bits[j])))
        return err;
    }
    if (rr.h < max_bound)
      /* range is less than [min_bound,max_bound] */
      i++;
    else
      /* range is greater than [min_bound,max_bound] */
      j++, min_bound = max_bound + 1;
  }
  return err;
}

static int re_compcc_tree_eq(re *r, re_buf *cc_tree_in, u32 a_ref, u32 b_ref)
{
  while (a_ref && b_ref) {
    re_compcc_node *a = &re_buf_at(cc_tree_in, re_compcc_node, a_ref),
                   *b = &re_buf_at(cc_tree_in, re_compcc_node, b_ref);
    if (!re_compcc_tree_eq(r, cc_tree_in, a->child_ref, b->child_ref))
      return 0;
    if (a->range != b->range)
      return 0;
    a_ref = a->sibling_ref, b_ref = b->sibling_ref;
  }
  assert(a_ref == 0 || b_ref == 0);
  return a_ref == b_ref;
}

static void
re_compcc_tree_merge_one(re_buf *cc_tree_in, u32 child_ref, u32 sibling_ref)
{
  re_compcc_node *child = &re_buf_at(cc_tree_in, re_compcc_node, child_ref),
                 *sibling = &re_buf_at(cc_tree_in, re_compcc_node, sibling_ref);
  child->sibling_ref = sibling->sibling_ref;
  assert(re_byte_range_is_adjacent(
      re_u32_to_byte_range(child->range),
      re_u32_to_byte_range(sibling->range)));
  child->range = re_byte_range_to_u32(re_byte_range_make(
      re_u32_to_byte_range(child->range).l,
      re_u32_to_byte_range(sibling->range).h));
}

/*https://nullprogram.com/blog/2018/07/31/*/
static u32 re_hashington(u32 x)
{
  x ^= x >> 16;
  x *= 0x7feb352dU;
  x ^= x >> 15;
  x *= 0x846ca68bU;
  x ^= x >> 16;
  return x;
}

/* hash table */
static int re_compcc_hash_init(re *r, re_buf *cc_tree_in, re_buf *cc_ht_out)
{
  int err = 0;
  if ((err = re_buf_reserve(
           r, cc_ht_out, u32,
           (re_buf_size(*cc_tree_in, re_compcc_node) +
            (re_buf_size(*cc_tree_in, re_compcc_node) >> 1)))))
    return err;
  memset(cc_ht_out->ptr, 0, cc_ht_out->alloc);
  return 0;
}

static void re_compcc_tree_hash(
    re *r, re_buf *cc_tree_in, re_buf *cc_ht_out, u32 parent_ref)
{
  /* flip links and hash everything */
  re_compcc_node *parent_node =
      &re_buf_at(cc_tree_in, re_compcc_node, parent_ref);
  u32 child_ref, next_child_ref, sibling_ref = 0;
  child_ref = parent_node->child_ref;
  while (child_ref) {
    re_compcc_node *child_node =
                       &re_buf_at(cc_tree_in, re_compcc_node, child_ref),
                   *sibling_node;
    next_child_ref = child_node->sibling_ref;
    child_node->sibling_ref = sibling_ref;
    re_compcc_tree_hash(r, cc_tree_in, cc_ht_out, child_ref);
    if (sibling_ref) {
      sibling_node = &re_buf_at(cc_tree_in, re_compcc_node, sibling_ref);
      if (re_byte_range_is_adjacent(
              re_u32_to_byte_range(child_node->range),
              re_u32_to_byte_range(sibling_node->range))) {
        /* Since the input ranges are normalized, terminal nodes (nodes with no
         * concatenation) are NOT adjacent. */
        assert(sibling_node->child_ref && child_node->child_ref);
        if (re_compcc_tree_eq(
                r, cc_tree_in, child_node->child_ref, sibling_node->child_ref))
          re_compcc_tree_merge_one(cc_tree_in, child_ref, sibling_ref);
      }
    }
    {
      u32 hash_plain[3] = {0x6D99232E, 0xC281FF0B, 0x54978D96};
      memset(hash_plain, 0, sizeof(hash_plain));
      hash_plain[0] ^= child_node->range;
      if (child_node->sibling_ref) {
        re_compcc_node *child_sibling_node =
            &re_buf_at(cc_tree_in, re_compcc_node, child_node->sibling_ref);
        hash_plain[1] = child_sibling_node->aux;
      }
      if (child_node->child_ref) {
        re_compcc_node *child_child_node =
            &re_buf_at(cc_tree_in, re_compcc_node, child_node->child_ref);
        hash_plain[2] = child_child_node->aux;
      }
      child_node->aux = re_hashington(
          re_hashington(re_hashington(hash_plain[0]) + hash_plain[1]) +
          hash_plain[2]);
    }
    sibling_ref = child_ref;
    sibling_node = child_node;
    child_ref = next_child_ref;
  }
  parent_node->child_ref = sibling_ref;
}

static void re_compcc_tree_reduce(
    re *r, re_buf *cc_tree_in, re_buf *cc_ht, u32 node_ref, u32 *my_out_ref)
{
  u32 prev_sibling_ref = 0;
  assert(node_ref);
  assert(!*my_out_ref);
  while (node_ref) {
    re_compcc_node *node = &re_buf_at(cc_tree_in, re_compcc_node, node_ref);
    u32 probe, found, child_ref = 0;
    probe = node->aux;
    node->aux = 0;
    /* check if child is in the hash table */
    while (1) {
      if (!((found = re_buf_at(cc_ht, u32, probe % re_buf_size(*cc_ht, u32))) &
            1))
        /* child is NOT in the cache */
        break;
      else {
        /* something is in the cache, but it might not be a child */
        if (re_compcc_tree_eq(r, cc_tree_in, node_ref, found >> 1)) {
          if (prev_sibling_ref)
            (&re_buf_at(cc_tree_in, re_compcc_node, prev_sibling_ref))
                ->sibling_ref = found >> 1;
          if (!*my_out_ref)
            *my_out_ref = found >> 1;
          return;
        }
      }
      probe += 1; /* linear probe */
    }
    re_buf_at(cc_ht, u32, (probe % re_buf_size(*cc_ht, u32))) =
        node_ref << 1 | 1;
    if (!*my_out_ref)
      *my_out_ref = node_ref;
    if (node->child_ref) {
      re_compcc_tree_reduce(r, cc_tree_in, cc_ht, node->child_ref, &child_ref);
      node->child_ref = child_ref;
    }
    prev_sibling_ref = node_ref;
    node_ref = node->sibling_ref;
  }
  assert(*my_out_ref);
  return;
}

static int re_compcc_tree_render(
    re *r, re_buf *cc_tree_in, u32 node_ref, u32 *my_out_pc,
    re_compframe *frame)
{
  int err = 0;
  u32 split_from = 0, my_pc = 0, range_pc = 0;
  while (node_ref) {
    re_compcc_node *node = &re_buf_at(cc_tree_in, re_compcc_node, node_ref);
    if (node->aux) {
      if (split_from) {
        re_inst i = re_prog_get(r, split_from);
        /* found our child, patch into it */
        i = re_inst_make(re_inst_opcode(i), re_inst_next(i), node->aux);
        re_prog_set(r, split_from, i);
      } else
        assert(!*my_out_pc), *my_out_pc = node->aux;
      return 0;
    }
    my_pc = re_prog_size(r);
    if (split_from) {
      re_inst i = re_prog_get(r, split_from);
      /* patch into it */
      i = re_inst_make(re_inst_opcode(i), re_inst_next(i), my_pc);
      re_prog_set(r, split_from, i);
    }
    if (node->sibling_ref) {
      /* need a split */
      split_from = my_pc;
      if ((err = re_inst_emit(
               r, re_inst_make(RE_OPCODE_SPLIT, my_pc + 1, 0), frame)))
        return err;
    }
    if (!*my_out_pc)
      *my_out_pc = my_pc;
    range_pc = re_prog_size(r);
    if ((err = re_inst_emit(
             r,
             re_inst_make(
                 RE_OPCODE_RANGE, 0,
                 re_byte_range_to_u32(re_byte_range_make(
                     re_u32_to_byte_range(node->range).l,
                     re_u32_to_byte_range(node->range).h))),
             frame)))
      return err;
    if (node->child_ref) {
      /* need to down-compile */
      u32 their_pc = 0;
      re_inst i = re_prog_get(r, range_pc);
      if ((err = re_compcc_tree_render(
               r, cc_tree_in, node->child_ref, &their_pc, frame)))
        return err;
      i = re_inst_make(re_inst_opcode(i), their_pc, re_inst_param(i));
      re_prog_set(r, range_pc, i);
    } else {
      /* terminal: patch out */
      re_patch_add(r, frame, range_pc, 0);
    }
    node->aux = my_pc;
    node_ref = node->sibling_ref;
  }
  assert(*my_out_pc);
  return 0;
}

static void re_compcc_tree_xpose(
    re_buf *cc_tree_in, re_buf *cc_tree_out, u32 node_ref, u32 root_ref)
{
  re_compcc_node *src_node, *dst_node, *parent_node;
  assert(node_ref != RE_REF_NONE);
  assert(
      re_buf_size(*cc_tree_out, re_compcc_node) ==
      re_buf_size(*cc_tree_in, re_compcc_node));
  while (node_ref) {
    u32 parent_ref = root_ref;
    src_node = &re_buf_at(cc_tree_in, re_compcc_node, node_ref);
    dst_node = &re_buf_at(cc_tree_out, re_compcc_node, node_ref);
    dst_node->sibling_ref = dst_node->child_ref = RE_REF_NONE;
    if (src_node->child_ref != RE_REF_NONE)
      re_compcc_tree_xpose(
          cc_tree_in, cc_tree_out, (parent_ref = src_node->child_ref),
          root_ref);
    parent_node = &re_buf_at(cc_tree_out, re_compcc_node, parent_ref);
    dst_node->sibling_ref = parent_node->child_ref;
    parent_node->child_ref = node_ref;
    node_ref = src_node->sibling_ref;
  }
}

static int re_compcc_fold_range(re *r, u32 begin, u32 end, re_buf *cc_out);

static int re_compcc(re *r, u32 root, re_compframe *frame, int reversed)
{
  int err = 0,
      inverted = *re_ast_type_ref(r, frame->root_ref) == RE_AST_TYPE_ICC,
      insensitive = !!(frame->flags & RE_GROUP_FLAG_INSENSITIVE);
  u32 start_pc = 0;
  re_buf_clear(&r->cc_stk_a), re_buf_clear(&r->cc_stk_b);
  /* push ranges */
  while (root) {
    u32 args[3], min, max;
    re_ast_decompose(r, root, args);
    root = args[0], min = args[1], max = args[2];
    /* handle out-of-order ranges (min > max) */
    if ((err = re_buf_push(
             r, &r->cc_stk_a, re_rune_range,
             re_rune_range_make(min > max ? max : min, min > max ? min : max))))
      return err;
  }
  assert(re_buf_size(r->cc_stk_a, re_rune_range));
  do {
    /* sort ranges */
    re_compcc_hsort(&r->cc_stk_a, re_buf_size(r->cc_stk_a, re_rune_range));
    /* normalize ranges */
    {
      size_t i;
      re_rune_range cur, next;
      for (i = 0; i < re_buf_size(r->cc_stk_a, re_rune_range); i++) {
        cur = re_buf_at(&r->cc_stk_a, re_rune_range, i);
        assert(cur.l <= cur.h);
        if (!i)
          next = re_rune_range_make(cur.l, cur.h); /* first range */
        else if (cur.l <= next.h + 1) {
          next.h = cur.h > next.h ? cur.h : next.h; /* intersection */
        } else {
          /* disjoint */
          if ((err = re_buf_push(r, &r->cc_stk_b, re_rune_range, next)))
            return err;
          next.l = cur.l, next.h = cur.h;
        }
      }
      assert(i); /* the charclass is never empty here */
      if ((err = re_buf_push(r, &r->cc_stk_b, re_rune_range, next)))
        return err;
      if (insensitive) {
        /* casefold normalized ranges */
        re_buf_clear(&r->cc_stk_a);
        for (i = 0; i < re_buf_size(r->cc_stk_b, re_rune_range); i++) {
          cur = re_buf_at(&r->cc_stk_b, re_rune_range, i);
          if ((err = re_buf_push(r, &r->cc_stk_a, re_rune_range, cur)))
            return err;
          if ((err = re_compcc_fold_range(r, cur.l, cur.h, &r->cc_stk_a)))
            return err;
        }
        re_buf_clear(&r->cc_stk_b);
      }
    }
  } while (insensitive && insensitive-- /* re-normalize by looping again */);
  /* invert ranges */
  if (inverted) {
    u32 max = 0, i, write = 0,
        old_size = re_buf_size(r->cc_stk_b, re_rune_range);
    re_rune_range cur;
    for (i = 0; i < old_size; i++) {
      cur = re_buf_at(&r->cc_stk_b, re_rune_range, i);
      assert(write <= i);
      if (cur.l > max) {
        re_buf_at(&r->cc_stk_b, re_rune_range, write++) =
            re_rune_range_make(max, cur.l - 1);
        max = cur.h + 1;
      }
    }
    if ((err = re_buf_reserve(
             r, &r->cc_stk_b, re_rune_range, write += (cur.h < RE_UTF_MAX))))
      return err;
    if (cur.h < RE_UTF_MAX)
      re_buf_at(&r->cc_stk_b, re_rune_range, write - 1) =
          re_rune_range_make(cur.h + 1, RE_UTF_MAX);
  }
  if (!re_buf_size(r->cc_stk_b, re_rune_range)) {
    /* empty charclass */
    if ((err = re_inst_emit(
             r,
             re_inst_make(
                 RE_OPCODE_ASSERT, 0, RE_ASSERT_WORD | RE_ASSERT_NOT_WORD),
             frame))) /* never matches */
      return err;
    re_patch_add(r, frame, re_prog_size(r) - 1, 0);
    return err;
  }
  /* build tree */
  re_buf_clear(&r->cc_stk_a);
  if ((err = re_compcc_tree_build(r, &r->cc_stk_b, &r->cc_stk_a)))
    return err;
  /* hash tree */
  if ((err = re_compcc_hash_init(r, &r->cc_stk_a, &r->cc_stk_b)))
    return err;
  re_compcc_tree_hash(r, &r->cc_stk_a, &r->cc_stk_b, 1);
  /* reduce tree */
  re_compcc_tree_reduce(r, &r->cc_stk_a, &r->cc_stk_b, 2, &start_pc);
  if (reversed) {
    u32 i;
    re_buf tmp;
    re_buf_clear(&r->cc_stk_b);
    for (i = 1 /* skip sentinel */;
         i < re_buf_size(r->cc_stk_a, re_compcc_node); i++) {
      if ((err = re_compcc_tree_new(
               r, &r->cc_stk_b, re_buf_at(&r->cc_stk_a, re_compcc_node, i),
               NULL)) == ERR_MEM)
        return err;
      assert(!err);
    }
    /* detach new root */
    re_buf_at(&r->cc_stk_b, re_compcc_node, 1).child_ref = RE_REF_NONE;
    re_compcc_tree_xpose(&r->cc_stk_a, &r->cc_stk_b, 2, 1);
    /* potench reverse the tree if needed */
    tmp = r->cc_stk_a;
    r->cc_stk_a = r->cc_stk_b;
    r->cc_stk_b = tmp;
  }
  if ((err =
           re_compcc_tree_render(r, &r->cc_stk_a, start_pc, &start_pc, frame)))
    return err;
  return err;
}

static int re_compile_internal(re *r, u32 root, u32 reverse)
{
  int err = 0;
  re_compframe initial_frame = {0}, returned_frame = {0}, child_frame = {0};
  u32 set_idx = 0, grp_idx = 1, tmp_cc_ast = RE_REF_NONE;
  if (!re_prog_size(r) &&
      ((err = re_buf_push(
            r, &r->prog, re_inst, re_inst_make(RE_OPCODE_RANGE, 0, 0))) ||
       (err = re_buf2_push(r, &r->prog_set_idxs, 0))))
    return err;
  assert(re_prog_size(r) > 0);
  initial_frame.root_ref = root;
  initial_frame.child_ref = initial_frame.patch_head =
      initial_frame.patch_tail = RE_REF_NONE;
  initial_frame.idx = 0;
  initial_frame.pc = re_prog_size(r);
  r->entry[reverse ? RE_PROG_ENTRY_REVERSE : 0] = initial_frame.pc;
  if ((err = re_buf2_push(r, &r->comp_stk, initial_frame)))
    return err;
  while (re_buf2_size(r->comp_stk)) {
    re_compframe frame = *re_buf2_peek(&r->comp_stk, 0);
    re_ast_type type;
    u32 args[4], my_pc = re_prog_size(r);
    frame.child_ref = frame.root_ref;
    child_frame.child_ref = child_frame.root_ref = child_frame.patch_head =
        child_frame.patch_tail = RE_REF_NONE;
    child_frame.idx = child_frame.pc = 0;
    type = *re_ast_type_ref(r, frame.root_ref);
    if (frame.root_ref)
      re_ast_decompose(r, frame.root_ref, args);
    if (type == RE_AST_TYPE_CHR) {
      re_patch_apply(r, &frame, my_pc);
      if (args[0] < 128 &&
          !(frame.flags & RE_GROUP_FLAG_INSENSITIVE)) { /* ascii */
        /*  in     out
         * ---> R ----> */
        if ((err = re_inst_emit(
                 r,
                 re_inst_make(
                     RE_OPCODE_RANGE, 0,
                     re_byte_range_to_u32(
                         re_byte_range_make(args[0], args[0]))),
                 &frame)))
          return err;
        re_patch_add(r, &frame, my_pc, 0);
      } else { /* unicode */
        /* create temp ast */
        if (!tmp_cc_ast &&
            (err = re_ast_make(
                 r, RE_AST_TYPE_CC, RE_REF_NONE, 0, 0, &tmp_cc_ast)))
          return err;
        *re_ast_param_ref(r, tmp_cc_ast, 1) =
            *re_ast_param_ref(r, tmp_cc_ast, 2) = args[0];
        if ((err = re_compcc(r, tmp_cc_ast, &frame, reverse)))
          return err;
      }
    } else if (type == RE_AST_TYPE_ANYBYTE) {
      /*  in     out
       * ---> R ----> */
      re_patch_apply(r, &frame, my_pc);
      if ((err = re_inst_emit(
               r,
               re_inst_make(
                   RE_OPCODE_RANGE, 0,
                   re_byte_range_to_u32(re_byte_range_make(0x00, 0xFF))),
               &frame)))
        return err;
      re_patch_add(r, &frame, my_pc, 0);
    } else if (type == RE_AST_TYPE_CAT) {
      /*  in              out
       * ---> [A] -> [B] ----> */
      assert(frame.idx >= 0 && frame.idx <= 2);
      if (frame.idx == 0) {              /* before left child */
        frame.child_ref = args[reverse]; /* push left child */
        re_patch_xfer(&child_frame, &frame);
        frame.idx++;
      } else if (frame.idx == 1) {        /* after left child */
        frame.child_ref = args[!reverse]; /* push right child */
        re_patch_xfer(&child_frame, &returned_frame);
        frame.idx++;
      } else /* if (frame.idx == 2) */ { /* after right child */
        re_patch_xfer(&frame, &returned_frame);
      }
    } else if (type == RE_AST_TYPE_ALT) {
      /*  in             out
       * ---> S --> [A] ---->
       *       \         out
       *        --> [B] ----> */
      assert(frame.idx >= 0 && frame.idx <= 2);
      if (frame.idx == 0) { /* before left child */
        re_patch_apply(r, &frame, frame.pc);
        if ((err =
                 re_inst_emit(r, re_inst_make(RE_OPCODE_SPLIT, 0, 0), &frame)))
          return err;
        re_patch_add(r, &child_frame, frame.pc, 0);
        frame.child_ref = args[0], frame.idx++;
      } else if (frame.idx == 1) { /* after left child */
        re_patch_merge(r, &frame, &returned_frame);
        re_patch_add(r, &child_frame, frame.pc, 1);
        frame.child_ref = args[1], frame.idx++;
      } else /* if (frame.idx == 2) */ { /* after right child */
        re_patch_merge(r, &frame, &returned_frame);
      }
    } else if (type == RE_AST_TYPE_QUANT || type == RE_AST_TYPE_UQUANT) {
      /*        +-------+
       *  in   /         \
       * ---> S -> [A] ---+
       *       \             out
       *        +-----------------> */
      u32 child = args[0], min = args[1], max = args[2],
          is_greedy = !(frame.flags & RE_GROUP_FLAG_UNGREEDY) ^
                      (type == RE_AST_TYPE_UQUANT);
      assert(min <= max);
      assert(RE_IMPLIES((min == RE_INFTY || max == RE_INFTY), min != max));
      assert(RE_IMPLIES(max == RE_INFTY, frame.idx <= min + 1));
      if (frame.idx < min) { /* before minimum bound */
        re_patch_xfer(&child_frame, frame.idx ? &returned_frame : &frame);
        frame.child_ref = child;
      } else if (max == RE_INFTY && frame.idx == min) { /* before inf. bound */
        re_patch_apply(r, frame.idx ? &returned_frame : &frame, my_pc);
        if ((err =
                 re_inst_emit(r, re_inst_make(RE_OPCODE_SPLIT, 0, 0), &frame)))
          return err;
        frame.pc = my_pc;
        re_patch_add(r, &child_frame, my_pc, !is_greedy);
        re_patch_add(r, &frame, my_pc, is_greedy);
        frame.child_ref = child;
      } else if (max == RE_INFTY) { /* after inf. bound */
        assert(frame.idx == min + 1);
        re_patch_apply(r, &returned_frame, frame.pc);
      } else if (frame.idx < max) { /* before maximum bound */
        re_patch_apply(r, frame.idx ? &returned_frame : &frame, my_pc);
        if ((err =
                 re_inst_emit(r, re_inst_make(RE_OPCODE_SPLIT, 0, 0), &frame)))
          return err;
        re_patch_add(r, &child_frame, my_pc, !is_greedy);
        re_patch_add(r, &frame, my_pc, is_greedy);
        frame.child_ref = child;
      } else if (frame.idx) { /* after maximum bound */
        assert(frame.idx == max);
        re_patch_merge(r, &frame, &returned_frame);
      } else {
        assert(!frame.idx);
        assert(frame.idx == max);
        /* epsilon */
      }
      frame.idx++;
    } else if (type == RE_AST_TYPE_GROUP || type == RE_AST_TYPE_IGROUP) {
      /*  in                 out
       * ---> M -> [A] -> M ----> */
      u32 child = args[0], flags = args[1];
      frame.flags =
          flags &
          ~RE_GROUP_FLAG_SUBEXPRESSION; /* we shouldn't propagate this */
      if (!frame.idx) {                 /* before child */
        if (!(flags & RE_GROUP_FLAG_NONCAPTURING)) {
          re_patch_apply(r, &frame, my_pc);
          if (flags & RE_GROUP_FLAG_SUBEXPRESSION)
            grp_idx = 0, frame.set_idx = ++set_idx;
          if ((err = re_inst_emit(
                   r,
                   re_inst_make(
                       RE_OPCODE_MATCH, 0,
                       re_inst_match_param_make(reverse, grp_idx++)),
                   &frame)))
            return err;
          re_patch_add(r, &child_frame, my_pc, 0);
        } else
          re_patch_xfer(&child_frame, &frame);
        frame.child_ref = child, frame.idx++;
      } else { /* after child */
        if (!(flags & RE_GROUP_FLAG_NONCAPTURING)) {
          re_patch_apply(r, &returned_frame, my_pc);
          if ((err = re_inst_emit(
                   r,
                   re_inst_make(
                       RE_OPCODE_MATCH, 0,
                       re_inst_match_param_make(
                           !reverse, re_inst_match_param_idx(re_inst_param(
                                         re_prog_get(r, frame.pc))))),
                   &frame)))
            return err;
          if (!(flags & RE_GROUP_FLAG_SUBEXPRESSION))
            re_patch_add(r, &frame, my_pc, 0);
        } else
          re_patch_merge(r, &frame, &returned_frame);
      }
    } else if (type == RE_AST_TYPE_CC || type == RE_AST_TYPE_ICC) {
      re_patch_apply(r, &frame, my_pc);
      if ((err = re_compcc(r, frame.root_ref, &frame, reverse)))
        return err;
    } else if (type == RE_AST_TYPE_ASSERT) {
      u32 assert_flag = args[0];
      re_patch_apply(r, &frame, my_pc);
      if ((err = re_inst_emit(
               r, re_inst_make(RE_OPCODE_ASSERT, 0, assert_flag), &frame)))
        return err;
      re_patch_add(r, &frame, my_pc, 0);
    } else {
      /* epsilon */
      /*  in  out  */
      /* --------> */
      assert(!frame.root_ref);
      assert(type == 0);
    }
    if (frame.child_ref != frame.root_ref) {
      /* should we push a child? */
      *re_buf2_peek(&r->comp_stk, 0) = frame;
      child_frame.root_ref = frame.child_ref;
      child_frame.idx = 0;
      child_frame.pc = re_prog_size(r);
      child_frame.flags = frame.flags;
      child_frame.set_idx = frame.set_idx;
      if ((err = re_buf2_push(r, &r->comp_stk, child_frame)))
        return err;
    } else {
      re_buf2_pop(&r->comp_stk);
    }
    returned_frame = frame;
  }
  assert(!re_buf2_size(r->comp_stk));
  assert(!returned_frame.patch_head && !returned_frame.patch_tail);
  {
    u32 dstar =
        r->entry
            [RE_PROG_ENTRY_DOTSTAR | (reverse ? RE_PROG_ENTRY_REVERSE : 0)] =
            re_prog_size(r);
    re_compframe frame = {0};
    if ((err = re_inst_emit(
             r,
             re_inst_make(
                 RE_OPCODE_SPLIT, r->entry[reverse ? RE_PROG_ENTRY_REVERSE : 0],
                 dstar + 1),
             &frame)))
      return err;
    if ((err = re_inst_emit(
             r,
             re_inst_make(
                 RE_OPCODE_RANGE, dstar,
                 re_byte_range_to_u32(re_byte_range_make(0, 255))),
             &frame)))
      return err;
  }
  return 0;
}

typedef struct re_nfa_thrd {
  u32 pc, slot;
} re_nfa_thrd;

typedef struct re_sset {
  u32 *sparse, sparse_alloc;
  re_nfa_thrd *dense;
  u32 dense_size, dense_alloc;
} re_sset;

static int re_sset_reset(const re *r, re_sset *s, size_t next_alloc)
{
  u32 *next_sparse;
  re_nfa_thrd *next_dense;
  /* next_alloc is equal to the program size, so it should never be 0. */
  assert(next_alloc);
  if (!(next_sparse = re_ialloc(
            r, sizeof(u32) * s->sparse_alloc, sizeof(u32) * next_alloc,
            s->sparse)))
    return ERR_MEM;
  s->sparse = next_sparse;
  s->sparse_alloc = next_alloc;
  if (!(next_dense = re_ialloc(
            r, sizeof(re_nfa_thrd) * s->dense_alloc,
            sizeof(re_nfa_thrd) * next_alloc, s->dense)))
    return ERR_MEM;
  s->dense = next_dense;
  s->dense_size = 0;
  s->dense_alloc = next_alloc;
  return 0;
}

static void re_sset_clear(re_sset *s) { s->dense_size = 0; }

static void re_sset_init(re_sset *s)
{
  s->sparse = NULL;
  s->sparse_alloc = 0;
  s->dense = NULL;
  s->dense_alloc = s->dense_size = 0;
}

static void re_sset_destroy(const re *r, re_sset *s)
{
  re_ialloc(r, sizeof(u32) * s->sparse_alloc, 0, s->sparse);
  re_ialloc(r, sizeof(re_nfa_thrd) * s->dense_alloc, 0, s->dense);
}

static int re_sset_is_memb(re_sset *s, u32 pc)
{
  assert(pc < s->dense_alloc);
  return s->sparse[pc] < s->dense_size && s->dense[s->sparse[pc]].pc == pc;
}

static void re_sset_add(re_sset *s, re_nfa_thrd spec)
{
  assert(spec.pc < s->dense_alloc);
  assert(s->dense_size < s->dense_alloc);
  assert(spec.pc);
  if (re_sset_is_memb(s, spec.pc))
    return;
  s->dense[s->dense_size] = spec;
  s->sparse[spec.pc] = s->dense_size++;
}

typedef struct re_save_slots {
  size_t *slots, slots_size, slots_alloc, last_empty, per_thrd;
} re_save_slots;

static void re_save_slots_init(re_save_slots *s)
{
  s->slots = NULL;
  s->slots_size = s->slots_alloc = s->last_empty = s->per_thrd = 0;
}

static void re_save_slots_destroy(const re *r, re_save_slots *s)
{
  re_ialloc(r, sizeof(size_t) * s->slots_alloc, 0, s->slots);
}

static void re_save_slots_clear(re_save_slots *s, size_t per_thrd)
{
  s->slots_size = 0, s->last_empty = 0,
  s->per_thrd = per_thrd + 1 /* for refcnt */;
}

static int re_save_slots_new(const re *r, re_save_slots *s, u32 *next)
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

static u32 re_save_slots_fork(re_save_slots *s, u32 ref)
{
  if (s->per_thrd)
    s->slots[ref * s->per_thrd + s->per_thrd - 1]++;
  return ref;
}

static void re_save_slots_kill(re_save_slots *s, u32 ref)
{
  if (!s->per_thrd)
    return;
  if (!s->slots[ref * s->per_thrd + s->per_thrd - 1]--) {
    /* prepend to free list */
    s->slots[ref * s->per_thrd] = s->last_empty;
    s->last_empty = ref;
  }
}

static int re_save_slots_set_internal(
    const re *r, re_save_slots *s, u32 ref, u32 idx, size_t v, u32 *out)
{
  int err;
  *out = ref;
  assert(s->per_thrd);
  assert(idx < s->per_thrd);
  assert(s->slots[ref * s->per_thrd + s->per_thrd - 1]);
  if (v == s->slots[ref * s->per_thrd + idx]) {
    /* not changing anything */
  } else {
    if ((err = re_save_slots_new(r, s, out)))
      return err;
    re_save_slots_kill(s, ref); /* decrement refcount */
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

static u32 re_save_slots_per_thrd(re_save_slots *s)
{
  return s->per_thrd ? s->per_thrd - 1 : s->per_thrd;
}

static int re_save_slots_set(
    const re *r, re_save_slots *s, u32 ref, u32 idx, size_t v, u32 *out)
{
  assert(idx < re_save_slots_per_thrd(s));
  return re_save_slots_set_internal(r, s, ref, idx, v, out);
}

static u32 re_save_slots_get(re_save_slots *s, u32 ref, u32 idx)
{
  assert(idx < re_save_slots_per_thrd(s));
  return s->slots[ref * s->per_thrd + idx];
}

typedef struct re_nfa {
  re_sset a, b, c;
  re_buf thrd_stk;
  re_save_slots slots;
  re_buf pri_stk, pri_bmp_tmp;
  int reversed, pri;
} re_nfa;

#define RE_DFA_MAX_NUM_STATES 256

typedef enum re_dfa_state_flag {
  RE_DFA_STATE_FLAG_FROM_TEXT_BEGIN = 1,
  RE_DFA_STATE_FLAG_FROM_LINE_BEGIN = 2,
  RE_DFA_STATE_FLAG_FROM_WORD = 4,
  RE_DFA_STATE_FLAG_PRIORITY_EXHAUST = 8,
  RE_DFA_STATE_FLAG_MAX = 16,
  RE_DFA_STATE_FLAG_DIRTY = 16
} re_dfa_state_flag;

typedef struct re_dfa_state {
  struct re_dfa_state *ptrs[256 + 1];
  u32 flags, nstate, nset;
} re_dfa_state;

typedef struct re_dfa {
  re_dfa_state **states;
  size_t states_size, num_active_states;
  re_dfa_state
      *entry[RE_PROG_ENTRY_MAX][RE_DFA_STATE_FLAG_MAX]; /* program entry type
                                                         * dfa_state_flag */
  re_buf set_buf;
  re_buf loc_buf;
  re_buf set_bmp;
} re_dfa;

struct re_exec {
  const re *r;
  re_nfa nfa;
  re_dfa dfa;
};

static void re_nfa_init(re_nfa *n)
{
  re_sset_init(&n->a), re_sset_init(&n->b), re_sset_init(&n->c);
  re_buf_init(&n->thrd_stk);
  re_save_slots_init(&n->slots);
  re_buf_init(&n->pri_stk), re_buf_init(&n->pri_bmp_tmp);
  n->reversed = 0;
}

static void re_nfa_destroy(const re *r, re_nfa *n)
{
  re_sset_destroy(r, &n->a), re_sset_destroy(r, &n->b),
      re_sset_destroy(r, &n->c);
  re_buf_destroy(r, &n->thrd_stk);
  re_save_slots_destroy(r, &n->slots);
  re_buf_destroy(r, &n->pri_stk), re_buf_destroy(r, &n->pri_bmp_tmp);
}

#define RE_BITS_PER_U32 (sizeof(u32) * CHAR_BIT)

static int re_bmp_init(const re *r, re_buf *b, u32 size)
{
  u32 i;
  int err = 0;
  re_buf_clear(b);
  for (i = 0; i < (size + RE_BITS_PER_U32) / RE_BITS_PER_U32; i++)
    if ((err = re_buf_push(
             r, b, u32, 0))) /* TODO: change this to a bulk allocation */
      return err;
  return err;
}

static void re_bmp_clear(re_buf *b) { memset(b->ptr, 0, b->alloc); }

static void re_bmp_set(re_buf *b, u32 idx)
{
  /* TODO: assert idx < nsets */
  re_buf_at(b, u32, idx / RE_BITS_PER_U32) |= (1 << (idx % RE_BITS_PER_U32));
}

/* returns 0 or a positive value (not necessarily 1) */
static u32 re_bmp_get(re_buf *b, u32 idx)
{
  return re_buf_at(b, u32, idx / RE_BITS_PER_U32) &
         (1 << (idx % RE_BITS_PER_U32));
}

static int
re_nfa_start(const re *r, re_nfa *n, u32 pc, u32 noff, int reversed, int pri)
{
  re_nfa_thrd initial_thrd;
  u32 i;
  int err = 0;
  if ((err = re_sset_reset(r, &n->a, re_prog_size(r))) ||
      (err = re_sset_reset(r, &n->b, re_prog_size(r))) ||
      (err = re_sset_reset(r, &n->c, re_prog_size(r))))
    return err;
  re_buf_clear(&n->thrd_stk), re_buf_clear(&n->pri_stk);
  re_save_slots_clear(&n->slots, noff);
  initial_thrd.pc = pc;
  if ((err = re_save_slots_new(r, &n->slots, &initial_thrd.slot)))
    return err;
  re_sset_add(&n->a, initial_thrd);
  initial_thrd.pc = initial_thrd.slot = 0;
  for (i = 0; i < r->ast_sets; i++)
    if ((err = re_buf_push(r, &n->pri_stk, u32, 0)))
      return err;
  if ((err = re_bmp_init(r, &n->pri_bmp_tmp, r->ast_sets)))
    return err;
  n->reversed = reversed;
  n->pri = pri;
  return 0;
}

static int re_nfa_eps(const re *r, re_nfa *n, size_t pos, re_assert_flag ass)
{
  int err;
  size_t i;
  re_sset_clear(&n->b);
  for (i = 0; i < n->a.dense_size; i++) {
    re_nfa_thrd dense_thrd = n->a.dense[i];
    if ((err = re_buf_push(r, &n->thrd_stk, re_nfa_thrd, dense_thrd)))
      return err;
    re_sset_clear(&n->c);
    while (re_buf_size(n->thrd_stk, re_nfa_thrd)) {
      re_nfa_thrd thrd = *re_buf_peek(&n->thrd_stk, re_nfa_thrd, 0);
      re_inst op = re_prog_get(r, thrd.pc);
      assert(thrd.pc);
      if (re_sset_is_memb(&n->c, thrd.pc)) {
        /* we already processed this thread */
        re_buf_pop(&n->thrd_stk, re_nfa_thrd);
        continue;
      }
      re_sset_add(&n->c, thrd);
      switch (re_inst_opcode(re_prog_get(r, thrd.pc))) {
      case RE_OPCODE_MATCH: {
        u32 idx = re_inst_match_param_idx(re_inst_param(op)) * 2 +
                  re_inst_match_param_end(re_inst_param(op));
        if (idx < re_save_slots_per_thrd(&n->slots) &&
            (err = re_save_slots_set(
                 r, &n->slots, thrd.slot, idx, pos, &thrd.slot)))
          return err;
        if (re_inst_next(op)) {
          if (re_inst_match_param_idx(re_inst_param(op)) > 0 ||
              !re_buf_at(&n->pri_stk, u32, r->prog_set_idxs[thrd.pc - 1])) {
            thrd.pc = re_inst_next(op);
            *re_buf_peek(&n->thrd_stk, re_nfa_thrd, 0) = thrd;
          } else
            re_buf_pop(&n->thrd_stk, re_nfa_thrd);
          break;
        } /* else fallthrough */
      }
      case RE_OPCODE_RANGE:
        re_buf_pop(&n->thrd_stk, re_nfa_thrd);
        re_sset_add(&n->b, thrd); /* this is a range or final match */
        break;
      case RE_OPCODE_SPLIT: {
        re_nfa_thrd pri, sec;
        pri.pc = re_inst_next(op), pri.slot = thrd.slot;
        sec.pc = re_inst_param(op),
        sec.slot = re_save_slots_fork(&n->slots, thrd.slot);
        *re_buf_peek(&n->thrd_stk, re_nfa_thrd, 0) = sec;
        if ((err = re_buf_push(r, &n->thrd_stk, re_nfa_thrd, pri)))
          /* sec is pushed first because it needs to be processed after pri.
           * pri comes off the stack first because it's FIFO. */
          return err;
        break;
      }
      default: /* ASSERT */ {
        assert(re_inst_opcode(re_prog_get(r, thrd.pc)) == RE_OPCODE_ASSERT);
        assert(!!(ass & RE_ASSERT_WORD) ^ !!(ass & RE_ASSERT_NOT_WORD));
        if ((re_inst_param(op) & ass) == re_inst_param(op)) {
          thrd.pc = re_inst_next(op);
          *re_buf_peek(&n->thrd_stk, re_nfa_thrd, 0) = thrd;
        } else {
          re_save_slots_kill(&n->slots, thrd.slot);
          re_buf_pop(&n->thrd_stk, re_nfa_thrd);
        }
        break;
      }
      }
    }
  }
  re_sset_clear(&n->a);
  return 0;
}

static int re_nfa_match_end(
    const re *r, re_nfa *n, re_nfa_thrd thrd, size_t pos, unsigned int ch)
{
  int err = 0;
  u32 idx = r->prog_set_idxs[thrd.pc];
  u32 *memo = &re_buf_at(&n->pri_stk, u32, idx - 1);
  assert(idx > 0);
  assert(idx - 1 < re_buf_size(n->pri_stk, u32));
  if (!n->pri && ch < 256)
    goto out_kill;
  if (n->slots.per_thrd) {
    u32 slot_idx = !n->reversed;
    if (*memo)
      re_save_slots_kill(&n->slots, *memo);
    *memo = thrd.slot;
    if (slot_idx < re_save_slots_per_thrd(&n->slots) &&
        (err = re_save_slots_set(r, &n->slots, thrd.slot, slot_idx, pos, memo)))
      return err;
    goto out_survive;
  } else {
    *memo = 1; /* just mark that a set was matched */
    goto out_kill;
  }
out_survive:
  return err;
out_kill:
  re_save_slots_kill(&n->slots, thrd.slot);
  return err;
}

static int re_nfa_chr(const re *r, re_nfa *n, unsigned int ch, size_t pos)
{
  int err;
  size_t i;
  re_bmp_clear(&n->pri_bmp_tmp);
  for (i = 0; i < n->b.dense_size; i++) {
    re_nfa_thrd thrd = n->b.dense[i];
    re_inst op = re_prog_get(r, thrd.pc);
    u32 pri = re_bmp_get(&n->pri_bmp_tmp, r->prog_set_idxs[thrd.pc]),
        opcode = re_inst_opcode(op);
    if (pri && n->pri)
      continue; /* priority exhaustion: disregard this thread */
    assert(opcode == RE_OPCODE_RANGE || opcode == RE_OPCODE_MATCH);
    if (opcode == RE_OPCODE_RANGE) {
      re_byte_range br = re_u32_to_byte_range(re_inst_param(op));
      if (ch >= br.l && ch <= br.h) {
        thrd.pc = re_inst_next(op);
        re_sset_add(&n->a, thrd);
      } else
        re_save_slots_kill(&n->slots, thrd.slot);
    } else /* if opcode == MATCH */ {
      assert(!re_inst_next(op));
      if ((err = re_nfa_match_end(r, n, thrd, pos, ch)))
        return err;
      if (n->pri)
        re_bmp_set(&n->pri_bmp_tmp, r->prog_set_idxs[thrd.pc]);
      re_save_slots_kill(&n->slots, thrd.slot);
    }
  }
  return 0;
}

#define RE_SENTINEL_CH 256

static u32 re_is_word_char(u32 ch)
{
  return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') ||
         (ch >= 'a' && ch <= 'z') || ch == '_';
}

static re_assert_flag re_make_assert_flag_raw(
    u32 prev_text_begin, u32 prev_line_begin, u32 prev_word, u32 next_ch)
{
  return !!prev_text_begin * RE_ASSERT_TEXT_BEGIN |
         (next_ch == RE_SENTINEL_CH) * RE_ASSERT_TEXT_END |
         !!prev_line_begin * RE_ASSERT_LINE_BEGIN |
         (next_ch == RE_SENTINEL_CH || next_ch == '\n') * RE_ASSERT_LINE_END |
         ((!!prev_word == re_is_word_char(next_ch)) ? RE_ASSERT_NOT_WORD
                                                    : RE_ASSERT_WORD);
}

static re_assert_flag re_make_assert_flag(u32 prev_ch, u32 next_ch)
{
  return re_make_assert_flag_raw(
      prev_ch == RE_SENTINEL_CH, (prev_ch == RE_SENTINEL_CH || prev_ch == '\n'),
      re_is_word_char(prev_ch), next_ch);
}

/* return number of sets matched, -n otherwise */
/* 0th span is the full bounds, 1st is first group, etc. */
/* if max_set == 0 and max_span == 0 */
/* if max_set != 0 and max_span == 0 */
/* if max_set == 0 and max_span != 0 */
/* if max_set != 0 and max_span != 0 */
static int re_nfa_end(
    const re *r, size_t pos, re_nfa *n, u32 max_span, u32 max_set,
    span *out_span, u32 *out_set, u32 prev_ch)
{
  int err;
  size_t j, sets = 0, nset = 0;
  if ((err = re_nfa_eps(
           r, n, pos, re_make_assert_flag(prev_ch, RE_SENTINEL_CH))) ||
      (err = re_nfa_chr(r, n, 256, pos)))
    return err;
  for (sets = 0; sets < r->ast_sets && (max_set ? nset < max_set : nset < 1);
       sets++) {
    u32 slot = re_buf_at(&n->pri_stk, u32, sets);
    if (!slot)
      continue; /* no match for this set */
    for (j = 0; (j < max_span) && out_span; j++) {
      out_span[nset * max_span + j].begin =
          re_save_slots_get(&n->slots, slot, j * 2);
      out_span[nset * max_span + j].end =
          re_save_slots_get(&n->slots, slot, j * 2 + 1);
    }
    if (out_set)
      out_set[nset] = sets;
    nset++;
  }
  return nset;
}

static int re_nfa_run(const re *r, re_nfa *n, u32 ch, size_t pos, u32 prev_ch)
{
  int err;
  (err = re_nfa_eps(r, n, pos, re_make_assert_flag(prev_ch, ch))) ||
      (err = re_nfa_chr(r, n, ch, pos));
  return err;
}

static void re_dfa_init(re_dfa *d)
{
  d->states = NULL;
  d->states_size = d->num_active_states = 0;
  memset(d->entry, 0, sizeof(d->entry));
  re_buf_init(&d->set_buf), re_buf_init(&d->loc_buf), re_buf_init(&d->set_bmp);
}

static size_t re_dfa_state_size(u32 nstate, u32 nset)
{
  return sizeof(re_dfa_state) + sizeof(u32) * (nstate + nset);
}

static void re_dfa_reset(const re *r, re_dfa *d)
{
  size_t i;
  for (i = 0; i < d->states_size; i++)
    if (d->states[i]) {
      re_ialloc(
          r, re_dfa_state_size(d->states[i]->nstate, d->states[i]->nset), 0,
          d->states[i]);
      d->states[i] = NULL;
    }
  d->num_active_states = 0;
  re_buf_clear(&d->set_buf), re_buf_clear(&d->loc_buf),
      re_buf_clear(&d->set_bmp);
  memset(d->entry, 0, sizeof(d->entry));
}

static void re_dfa_destroy(const re *r, re_dfa *d)
{
  re_dfa_reset(r, d);
  re_ialloc(r, d->states_size * sizeof(re_dfa_state *), 0, d->states);
  re_buf_destroy(r, &d->set_buf), re_buf_destroy(r, &d->loc_buf),
      re_buf_destroy(r, &d->set_bmp);
}

static u32 *re_dfa_state_data(re_dfa_state *state)
{
  return (u32 *)(state + 1);
}

/* need: current state, but ALSO the previous state's matches */
static int re_dfa_construct(
    const re *r, re_dfa *d, re_dfa_state *prev_state, unsigned int ch,
    u32 prev_flag, re_nfa *n, re_dfa_state **out_next_state)
{
  size_t i;
  int err = 0;
  u32 hash, table_pos, num_checked, *state_data;
  re_dfa_state *next_state;
  /* check threads in n, and look them up in the dfa cache */
  hash = re_hashington(prev_flag);
  hash = re_hashington(hash + n->a.dense_size);
  hash = re_hashington(hash + re_buf_size(d->set_buf, u32));
  for (i = 0; i < n->a.dense_size; i++)
    hash = re_hashington(hash + n->a.dense[i].pc);
  for (i = 0; i < re_buf_size(d->set_buf, u32); i++)
    hash = re_hashington(hash + re_buf_at(&d->set_buf, u32, i));
  if (!d->states_size) {
    /* need to allocate initial cache */
    re_dfa_state **next_cache =
        re_ialloc(r, 0, sizeof(re_dfa_state *) * RE_DFA_MAX_NUM_STATES, NULL);
    if (!next_cache)
      return ERR_MEM;
    memset(next_cache, 0, sizeof(re_dfa_state *) * RE_DFA_MAX_NUM_STATES);
    assert(!d->states);
    d->states = next_cache, d->states_size = RE_DFA_MAX_NUM_STATES;
  }
  table_pos = hash % d->states_size, num_checked = 0;
  while (1) {
    /* linear probe for next state */
    if (!d->states[table_pos]) {
      next_state = NULL;
      break;
    }
    next_state = d->states[table_pos];
    state_data = re_dfa_state_data(next_state);
    if (next_state->flags != prev_flag)
      goto not_found;
    if (next_state->nstate != n->a.dense_size)
      goto not_found;
    if (next_state->nset != re_buf_size(d->set_buf, u32))
      goto not_found;
    for (i = 0; i < n->a.dense_size; i++)
      if (state_data[i] != n->a.dense[i].pc)
        goto not_found;
    for (i = 0; i < re_buf_size(d->set_buf, u32); i++)
      if (state_data[n->a.dense_size + i] != re_buf_at(&d->set_buf, u32, i))
        goto not_found;
    /* state found! */
    break;
  not_found:
    table_pos += 1, num_checked += 1;
    if (table_pos == d->states_size)
      table_pos = 0;
    if (num_checked == d->states_size) {
      next_state = NULL;
      break;
    }
  }
  if (!next_state) {
    /* we need to construct a new state */
    if (d->num_active_states == RE_DFA_MAX_NUM_STATES) {
      /* clear cache */
      for (i = 0; i < d->states_size; i++)
        if (d->states[i]) {
          re_ialloc(
              r, re_dfa_state_size(d->states[i]->nstate, d->states[i]->nset), 0,
              d->states[i]);
          d->states[i] = NULL;
        }
      d->num_active_states = 0;
      table_pos = hash % d->states_size;
      memset(d->entry, 0, sizeof(d->entry));
      prev_state = NULL;
    }
    /* allocate new state */
    next_state = re_ialloc(
        r, 0, re_dfa_state_size(n->a.dense_size, re_buf_size(d->set_buf, u32)),
        NULL);
    if (!next_state)
      return ERR_MEM;
    memset(
        next_state, 0,
        re_dfa_state_size(n->a.dense_size, re_buf_size(d->set_buf, u32)));
    next_state->flags = prev_flag;
    next_state->nstate = n->a.dense_size;
    next_state->nset = re_buf_size(d->set_buf, u32);
    state_data = re_dfa_state_data(next_state);
    for (i = 0; i < n->a.dense_size; i++)
      state_data[i] = n->a.dense[i].pc;
    for (i = 0; i < re_buf_size(d->set_buf, u32); i++)
      state_data[n->a.dense_size + i] = re_buf_at(&d->set_buf, u32, i);
    assert(!d->states[table_pos]);
    d->states[table_pos] = next_state;
    d->num_active_states++;
  }
  assert(next_state);
  if (prev_state)
    /* link the states */
    assert(!prev_state->ptrs[ch]), prev_state->ptrs[ch] = next_state;
  *out_next_state = next_state;
  return err;
}

static int re_dfa_construct_start(
    const re *r, re_dfa *d, re_nfa *n, u32 entry, u32 prev_flag,
    re_dfa_state **out_next_state)
{
  int err = 0;
  /* clear the set buffer so that it can be used to compare dfa states later */
  re_buf_clear(&d->set_buf);
  *out_next_state = d->entry[entry][prev_flag];
  if (!*out_next_state) {
    re_nfa_thrd spec;
    spec.pc = r->entry[entry];
    spec.slot = 0;
    re_sset_clear(&n->a);
    re_sset_add(&n->a, spec);
    if ((err = re_dfa_construct(r, d, NULL, 0, prev_flag, n, out_next_state)))
      return err;
    d->entry[entry][prev_flag] = *out_next_state;
  }
  return err;
}

static int re_dfa_construct_chr(
    const re *r, re_dfa *d, re_nfa *n, re_dfa_state *prev_state,
    unsigned int ch, re_dfa_state **out_next_state)
{
  int err;
  size_t i;
  /* clear the set buffer so that it can be used to compare dfa states later */
  re_buf_clear(&d->set_buf);
  /* we only care about `ch` if `prev_state != NULL`. we only care about
   * `prev_flag` if `prev_state == NULL` */
  /* import prev_state into n */
  re_sset_clear(&n->a);
  for (i = 0; i < prev_state->nstate; i++) {
    re_nfa_thrd thrd;
    thrd.pc = re_dfa_state_data(prev_state)[i];
    thrd.slot = 0;
    re_sset_add(&n->a, thrd);
  }
  /* run eps on n */
  if ((err = re_nfa_eps(
           r, n, 0,
           re_make_assert_flag_raw(
               prev_state->flags & RE_DFA_STATE_FLAG_FROM_TEXT_BEGIN,
               prev_state->flags & RE_DFA_STATE_FLAG_FROM_LINE_BEGIN,
               prev_state->flags & RE_DFA_STATE_FLAG_FROM_WORD, ch))))
    return err;
  /* collect matches and match priorities into d->set_buf */
  re_bmp_clear(&n->pri_bmp_tmp);
  for (i = 0; i < n->b.dense_size; i++) {
    re_nfa_thrd thrd = n->b.dense[i];
    re_inst op = re_prog_get(r, thrd.pc);
    int pri = re_bmp_get(&n->pri_bmp_tmp, r->prog_set_idxs[thrd.pc]);
    if (pri && n->pri)
      continue; /* priority exhaustion: disregard this thread */
    switch (re_inst_opcode(op)) {
    case RE_OPCODE_RANGE: {
      re_byte_range br = re_u32_to_byte_range(re_inst_param(op));
      if (ch >= br.l && ch <= br.h) {
        thrd.pc = re_inst_next(op);
        re_sset_add(&n->a, thrd);
      } else
        re_save_slots_kill(&n->slots, thrd.slot);
      break;
    }
    case RE_OPCODE_MATCH: {
      assert(!re_inst_next(op));
      /* NOTE: since there only exists one match instruction for a set n, we
       * don't need to check if we've already pushed the match instruction. */
      if ((err =
               re_buf_push(r, &d->set_buf, u32, r->prog_set_idxs[thrd.pc] - 1)))
        return err;
      if (n->pri)
        re_bmp_set(&n->pri_bmp_tmp, r->prog_set_idxs[thrd.pc]);
      break;
    }
    default:
      assert(0);
    }
  }
  /* feed ch to n -> this was accomplished by the above code */
  return re_dfa_construct(
      r, d, prev_state, ch,
      (ch == RE_SENTINEL_CH) * RE_DFA_STATE_FLAG_FROM_TEXT_BEGIN |
          (ch == RE_SENTINEL_CH || ch == '\n') *
              RE_DFA_STATE_FLAG_FROM_LINE_BEGIN |
          (re_is_word_char(ch) ? RE_DFA_STATE_FLAG_FROM_WORD : 0),
      n, out_next_state);
}

static void re_dfa_save_matches(re_dfa *dfa, re_dfa_state *state, size_t pos)
{
  u32 i;
  for (i = 0; i < state->nset; i++) {
    re_buf_at(
        &dfa->loc_buf, size_t, re_dfa_state_data(state)[state->nstate + i]) =
        pos;
    re_bmp_set(&dfa->set_bmp, i);
  }
}

static int re_dfa_match(
    re_exec *exec, re_nfa *nfa, u8 *s, size_t n, u32 max_span, u32 max_set,
    span *out_span, u32 *out_set, anchor_type anchor)
{
  int err;
  re_dfa_state *state = NULL;
  size_t i;
  u32 entry = anchor == A_END          ? RE_PROG_ENTRY_REVERSE
              : anchor == A_UNANCHORED ? RE_PROG_ENTRY_DOTSTAR
                                       : 0;
  u32 incoming_assert_flag =
          RE_DFA_STATE_FLAG_FROM_TEXT_BEGIN | RE_DFA_STATE_FLAG_FROM_LINE_BEGIN,
      reversed = !!(entry & RE_PROG_ENTRY_REVERSE);
  int pri = anchor != A_BOTH;
  assert(max_span == 0 || max_span == 1);
  assert(anchor == A_BOTH || anchor == A_START || anchor == A_END);
  re_dfa_reset(exec->r, &exec->dfa);
  if ((err = re_nfa_start(
           exec->r, &exec->nfa, exec->r->entry[entry], 0, reversed, pri)))
    return err;
  if (pri) {
    re_buf_clear(&exec->dfa.loc_buf);
    if ((err = re_bmp_init(exec->r, &exec->dfa.set_bmp, exec->r->ast_sets)))
      return err;
    for (i = 0; i < exec->r->ast_sets; i++) {
      size_t p = 0;
      if ((err = re_buf_push(exec->r, &exec->dfa.loc_buf, size_t, p)))
        return err;
    }
  }
  i = reversed ? n : 0;
  if (!(state = exec->dfa.entry[entry][incoming_assert_flag]) &&
      (err = re_dfa_construct_start(
           exec->r, &exec->dfa, nfa, entry, incoming_assert_flag, &state)))
    return err;
  if (pri)
    re_dfa_save_matches(&exec->dfa, state, i);
  {
    /* This is a *very* hot loop. Don't change this without profiling first. */
    /* Originally this loop used an index on the `s` variable. It was determined
     * through profiling that it was faster to just keep a pointer and
     * dereference+increment it every iteration of the character loop. So, we
     * compute the start and end pointers of the span of the string, and then
     * rip through the string until start == end. */
    const u8 *start = reversed ? s + n - 1 : s, *end = reversed ? s - 1 : s + n;
    /* The amount to increment each iteration of the loop. */
    int increment = reversed ? -1 : 1;
    while (start != end) {
      u8 ch = *start;
      re_dfa_state *next = state->ptrs[ch];
      if (!next) {
        if ((err = re_dfa_construct_chr(
                 exec->r, &exec->dfa, nfa, state, ch, &next)))
          return err;
      }
      state = next;
      start += increment;
      if (pri)
        re_dfa_save_matches(&exec->dfa, state, start - s);
    }
  }
  if (!state->ptrs[RE_SENTINEL_CH]) {
    if ((err = re_dfa_construct_chr(
             exec->r, &exec->dfa, nfa, state, RE_SENTINEL_CH, &state)))
      return err;
  } else
    state = state->ptrs[s[i]];
  if (pri) {
    re_dfa_save_matches(&exec->dfa, state, i);
    assert(!err);
    for (i = 0; i < exec->r->ast_sets; i++) {
      assert(err >= 0 && err <= (signed)i);
      if (!re_bmp_get(&exec->dfa.set_bmp, i))
        continue;
      if ((unsigned)err == max_set && max_set)
        break;
      if (max_span) {
        size_t spos = re_buf_at(&exec->dfa.loc_buf, size_t, i);
        out_span[i].begin = reversed ? spos : 0;
        out_span[i].end = reversed ? n : spos;
      }
      if (!max_set) {
        err = 1;
        break;
      } else if ((unsigned)err < max_set)
        out_set[err] = i;
      err++;
    }
  } else {
    assert(state);
    for (i = 0; i < state->nset; i++) {
      if (max_span) {
        out_span[i].begin = 0, out_span[i].end = n;
      }
      if (i < max_set)
        out_set[i] = re_dfa_state_data(state)[state->nstate + i];
    }
    err = max_set ? (state->nset > max_set ? max_set : state->nset)
                  : !!state->nset;
  }
  return err;
}

int re_exec_init(const re *r, re_exec **pexec)
{
  int err = 0;
  re_exec *exec = r->alloc(0, sizeof(re_exec), NULL, __FILE__, __LINE__);
  *pexec = exec;
  assert(re_prog_size(r));
  if (!exec)
    return ERR_MEM;
  memset(exec, 0, sizeof(re_exec));
  exec->r = r;
  re_nfa_init(&exec->nfa);
  re_dfa_init(&exec->dfa);
  return err;
}

void re_exec_destroy(re_exec *exec)
{
  if (!exec)
    return;
  re_nfa_destroy(exec->r, &exec->nfa);
  re_dfa_destroy(exec->r, &exec->dfa);
  exec->r->alloc(sizeof(re_exec), 0, exec, __FILE__, __LINE__);
}

int re_compile(re *r)
{
  int err;
  assert(!re_prog_size(r));
  ((err = re_compile_internal(r, r->ast_root, 0)) ||
   (err = re_compile_internal(r, r->ast_root, 1)));
  return err;
}

int re_exec_match(
    re_exec *exec, const char *s, size_t n, u32 max_span, u32 max_set,
    span *out_span, u32 *out_set, anchor_type anchor)
{
  int err = 0;
  u32 entry = anchor == A_END          ? RE_PROG_ENTRY_REVERSE
              : anchor == A_UNANCHORED ? RE_PROG_ENTRY_DOTSTAR
                                       : 0;
  size_t i;
  u32 prev_ch = RE_SENTINEL_CH;
  if (!(entry & RE_PROG_ENTRY_DOTSTAR) && (max_span == 0 || max_span == 1)) {
    err = re_dfa_match(
        exec, &exec->nfa, (u8 *)s, n, max_span, max_set, out_span, out_set,
        anchor);
    return err;
  }
  if ((err = re_nfa_start(
           exec->r, &exec->nfa, exec->r->entry[entry], max_span * 2,
           entry & RE_PROG_ENTRY_REVERSE, entry != A_BOTH)))
    return err;
  if (entry & RE_PROG_ENTRY_REVERSE) {
    for (i = n; i > 0; i--) {
      if ((err = re_nfa_run(
               exec->r, &exec->nfa, ((const u8 *)s)[i - 1], i, prev_ch)))
        return err;
      prev_ch = ((const u8 *)s)[i - 1];
    }
    if ((err = re_nfa_end(
             exec->r, 0, &exec->nfa, max_span, max_set, out_span, out_set,
             prev_ch)))
      return err;
  } else {
    for (i = 0; i < n; i++) {
      if ((err =
               re_nfa_run(exec->r, &exec->nfa, ((const u8 *)s)[i], i, prev_ch)))
        return err;
      prev_ch = ((const u8 *)s)[i];
    }
    if ((err = re_nfa_end(
             exec->r, n, &exec->nfa, max_span, max_set, out_span, out_set,
             prev_ch)))
      return err;
  }
  return err;
}

int re_match(
    const re *r, const char *s, size_t n, u32 max_span, u32 max_set,
    span *out_span, u32 *out_set, anchor_type anchor)
{
  re_exec *exec = NULL;
  int err;
  if ((err = re_exec_init(r, &exec)))
    goto done;
  if ((err = re_exec_match(
           exec, s, n, max_span, max_set, out_span, out_set, anchor)))
    goto done;
done:
  re_exec_destroy(exec);
  return err;
}

/*T Generated by `unicode_data.py gen_casefold` */
static const s32 re_compcc_fold_array_0[] = {
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
static const u16 re_compcc_fold_array_1[] = {
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
static const u16 re_compcc_fold_array_2[] = {
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
static const u8 re_compcc_fold_array_3[] = {
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
static const u16 re_compcc_fold_array_4[] = {
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
static const u8 re_compcc_fold_array_5[] = {
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

static s32 re_compcc_fold_next(u32 rune)
{
  return re_compcc_fold_array_0
      [re_compcc_fold_array_1
           [re_compcc_fold_array_2
                [re_compcc_fold_array_3
                     [re_compcc_fold_array_4
                          [re_compcc_fold_array_5[((rune >> 13) & 0xFF)] +
                           ((rune >> 9) & 0x0F)] +
                      ((rune >> 4) & 0x1F)] +
                 ((rune >> 3) & 0x01)] +
            ((rune >> 1) & 0x03)] +
       (rune & 0x01)];
}

static int re_compcc_fold_range(re *r, u32 begin, u32 end, re_buf *cc_out)
{
  int err = 0;
  s32 a0;
  u16 a1, a2, a4;
  u32 current, x0, x1, x2, x3, x4, x5;
  u8 a3, a5;
  assert(begin <= RE_UTF_MAX && end <= RE_UTF_MAX && begin <= end);
  for (x5 = ((begin >> 13) & 0xFF); x5 <= 0x87 && begin <= end; x5++) {
    if ((a5 = re_compcc_fold_array_5[x5]) == 0x3C) {
      begin = ((begin >> 13) + 1) << 13;
      continue;
    }
    for (x4 = ((begin >> 9) & 0x0F); x4 <= 0xF && begin <= end; x4++) {
      if ((a4 = re_compcc_fold_array_4[a5 + x4]) == 0xCC) {
        begin = ((begin >> 9) + 1) << 9;
        continue;
      }
      for (x3 = ((begin >> 4) & 0x1F); x3 <= 0x1F && begin <= end; x3++) {
        if ((a3 = re_compcc_fold_array_3[a4 + x3]) == 0x30) {
          begin = ((begin >> 4) + 1) << 4;
          continue;
        }
        for (x2 = ((begin >> 3) & 0x01); x2 <= 0x1 && begin <= end; x2++) {
          if ((a2 = re_compcc_fold_array_2[a3 + x2]) == 0x7D) {
            begin = ((begin >> 3) + 1) << 3;
            continue;
          }
          for (x1 = ((begin >> 1) & 0x03); x1 <= 0x3 && begin <= end; x1++) {
            if ((a1 = re_compcc_fold_array_1[a2 + x1]) == 0x60) {
              begin = ((begin >> 1) + 1) << 1;
              continue;
            }
            for (x0 = (begin & 0x01); x0 <= 0x1 && begin <= end; x0++) {
              if ((a0 = re_compcc_fold_array_0[a1 + x0]) == +0x0) {
                begin = ((begin >> 0) + 1) << 0;
                continue;
              }
              current = begin + a0;
              while (current != begin) {
                if ((err = re_buf_push(
                         r, cc_out, re_rune_range,
                         re_rune_range_make(current, current))))
                  return err;
                current = (u32)((s32)current + re_compcc_fold_next(current));
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
static const re_parse_builtin_cc re_parse_builtin_ccs[] = {
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

static char d_hex(u8 d)
{
  d &= 0xF;
  if (d < 10)
    return '0' + d;
  else
    return 'A' + d - 10;
}

static char *d_chr(char *buf, u32 ch, int ascii)
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
    buf[0] = '\\', buf[1] = '\\', buf[2] = 'x', buf[3] = d_hex(ch >> 4),
    buf[4] = d_hex(ch), buf[5] = 0;
  else
    buf[0] = '\\', buf[1] = '\\', buf[2] = 'u', buf[3] = d_hex(ch >> 20),
    buf[4] = d_hex(ch >> 16), buf[5] = d_hex(ch >> 12), buf[6] = d_hex(ch >> 8),
    buf[7] = d_hex(ch >> 4), buf[8] = d_hex(ch), buf[9] = 0;
  return buf;
}

static char *d_chr_ascii(char *buf, u32 ch) { return d_chr(buf, ch, 1); }

static char *d_chr_unicode(char *buf, u32 ch) { return d_chr(buf, ch, 0); }

static char *d_assert(char *buf, re_assert_flag af)
{
  snprintf(
      buf, 32, "%s%s%s%s%s%s", af & RE_ASSERT_LINE_BEGIN ? "^" : "",
      af & RE_ASSERT_LINE_END ? "$" : "",
      af & RE_ASSERT_TEXT_BEGIN ? "\\\\A" : "",
      af & RE_ASSERT_TEXT_END ? "\\\\z" : "",
      af & RE_ASSERT_WORD ? "\\\\b" : "",
      af & RE_ASSERT_NOT_WORD ? "\\\\B" : "");
  return buf;
}

static char *d_group_flag(char *buf, re_group_flag gf)
{
  snprintf(
      buf, 32, "%s%s%s%s%s%s", gf & RE_GROUP_FLAG_INSENSITIVE ? "i" : "",
      gf & RE_GROUP_FLAG_MULTILINE ? "m" : "",
      gf & RE_GROUP_FLAG_DOTNEWLINE ? "s" : "",
      gf & RE_GROUP_FLAG_UNGREEDY ? "U" : "",
      gf & RE_GROUP_FLAG_NONCAPTURING ? ":" : "",
      gf & RE_GROUP_FLAG_SUBEXPRESSION ? "R" : "");
  return buf;
}

static char *d_quant(char *buf, u32 quantval)
{
  if (quantval >= RE_INFTY)
    snprintf(buf, 32, "\xe2\x88\x9e"); /* infinity symbol */
  else
    snprintf(buf, 32, "%u", quantval);
  return buf;
}

void d_ast_i(re *r, u32 root, u32 ilvl, int format)
{
  const char *colors[] = {"1", "2", "3", "4"};
  u32 i, first = root ? *re_ast_type_ref(r, root) : 0;
  u32 sub[2] = {0xFF, 0xFF};
  char buf[32] = {0}, buf2[32] = {0};
  const char *node_name =
      root == RE_REF_NONE              ? "\xc9\x9b" /* epsilon */
      : (first == RE_AST_TYPE_CHR)     ? "CHR"
      : (first == RE_AST_TYPE_CAT)     ? (sub[0] = 0, sub[1] = 1, "CAT")
      : (first == RE_AST_TYPE_ALT)     ? (sub[0] = 0, sub[1] = 1, "ALT")
      : (first == RE_AST_TYPE_QUANT)   ? (sub[0] = 0, "QUANT")
      : (first == RE_AST_TYPE_UQUANT)  ? (sub[0] = 0, "UQUANT")
      : (first == RE_AST_TYPE_GROUP)   ? (sub[0] = 0, "GROUP")
      : (first == RE_AST_TYPE_IGROUP)  ? (sub[0] = 0, "IGROUP")
      : (first == RE_AST_TYPE_CC)      ? (sub[0] = 0, "CLS")
      : (first == RE_AST_TYPE_ICC)     ? (sub[0] = 0, "ICLS")
      : (first == RE_AST_TYPE_ANYBYTE) ? "ANYBYTE"
      : (first == RE_AST_TYPE_ASSERT)  ? "ASSERT"
                                       : NULL;
  if (format == TERM) {
    printf("%04u ", root);
    for (i = 0; i < ilvl; i++)
      printf(" ");
    printf("%s ", node_name);
  } else if (format == GRAPHVIZ) {
    printf("A%04X [label=\"%s\\n", root, node_name);
  }
  if (first == RE_AST_TYPE_CHR)
    printf("%s", d_chr_unicode(buf, *re_ast_param_ref(r, root, 0)));
  else if (first == RE_AST_TYPE_GROUP || first == RE_AST_TYPE_IGROUP)
    printf("%s", d_group_flag(buf, *re_ast_param_ref(r, root, 1)));
  else if (first == RE_AST_TYPE_QUANT || first == RE_AST_TYPE_UQUANT)
    printf(
        "%s-%s", d_quant(buf, *re_ast_param_ref(r, root, 1)),
        d_quant(buf2, *re_ast_param_ref(r, root, 2)));
  else if (first == RE_AST_TYPE_CC || first == RE_AST_TYPE_ICC)
    printf(
        "%s-%s", d_chr_unicode(buf, *re_ast_param_ref(r, root, 1)),
        d_chr_unicode(buf2, *re_ast_param_ref(r, root, 2)));
  if (format == GRAPHVIZ)
    printf(
        "\"]\nsubgraph cluster_%04X { "
        "label=\"\";style=filled;colorscheme=greys7;fillcolor=%s;",
        root, colors[ilvl % (sizeof(colors) / sizeof(*colors))]);
  if (format == TERM)
    printf("\n");
  for (i = 0; i < sizeof(sub) / sizeof(*sub); i++)
    if (sub[i] != 0xFF) {
      u32 child = *re_ast_param_ref(r, root, sub[i]);
      d_ast_i(r, child, ilvl + 1, format);
      if (format == GRAPHVIZ)
        printf(
            "A%04X -> A%04X [style=%s]\n", root, child, i ? "dashed" : "solid");
    }
  if (format == GRAPHVIZ)
    printf("}\n");
}

void d_ast(re *r, u32 root) { d_ast_i(r, root, 0, TERM); }

void d_ast_gv(re *r) { d_ast_i(r, r->ast_root, 0, GRAPHVIZ); }

void d_sset(re_sset *s)
{
  u32 i;
  for (i = 0; i < s->dense_size; i++)
    printf("%04X pc: %04X slot: %04X\n", i, s->dense[i].pc, s->dense[i].slot);
}

void d_prog_range(re *r, u32 start, u32 end, int format)
{
  u32 j, k;
  assert(end <= re_prog_size(r));
  if (format == GRAPHVIZ)
    printf("node [colorscheme=pastel16]\n");
  for (; start < end; start++) {
    re_inst ins = re_prog_get(r, start);
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
          "%04X %01X \x1b[%im%s\x1b[0m \x1b[%im%04X\x1b[0m %04X %s", start,
          r->prog_set_idxs[start], colors[re_inst_opcode(ins)],
          ops[re_inst_opcode(ins)],
          re_inst_next(ins) ? (re_inst_next(ins) == start + 1 ? 90 : 0) : 91,
          re_inst_next(ins), re_inst_param(ins), labels[k]);
      if (re_inst_opcode(ins) == RE_OPCODE_MATCH)
        printf(
            " %u %s", re_inst_match_param_idx(re_inst_param(ins)),
            re_inst_match_param_end(re_inst_param(ins)) ? "end" : "begin");
      printf("\n");
    } else {
      static const char *shapes[] = {"box", "diamond", "pentagon", "oval"};
      static const int colors[] = {1, 3, 6, 2};
      printf(
          "I%04X "
          "[shape=%s,fillcolor=%i,style=filled,regular=false,forcelabels=true,"
          "xlabel=\"%u\","
          "label=\"%s\\n",
          start, shapes[re_inst_opcode(ins)], colors[re_inst_opcode(ins)],
          start, ops[re_inst_opcode(ins)]);
      if (re_inst_opcode(ins) == RE_OPCODE_RANGE)
        printf(
            "%s-%s",
            d_chr_ascii(start_buf, re_u32_to_byte_range(re_inst_param(ins)).l),
            d_chr_ascii(end_buf, re_u32_to_byte_range(re_inst_param(ins)).h));
      else if (re_inst_opcode(ins) == RE_OPCODE_MATCH)
        printf(
            "%u %s", re_inst_match_param_idx(re_inst_param(ins)),
            re_inst_match_param_end(re_inst_param(ins)) ? "end" : "begin");
      else if (re_inst_opcode(ins) == RE_OPCODE_ASSERT)
        printf("%s", d_assert(assert_buf, re_inst_param(ins)));
      printf("\"]\n");
      if (!(re_inst_opcode(ins) == RE_OPCODE_MATCH && !re_inst_next(ins))) {
        printf("I%04X -> I%04X\n", start, re_inst_next(ins));
        if (re_inst_opcode(ins) == RE_OPCODE_SPLIT)
          printf("I%04X -> I%04X [style=dashed]\n", start, re_inst_param(ins));
      }
    }
  }
}

void d_prog(re *r)
{
  d_prog_range(r, 1, r->entry[RE_PROG_ENTRY_REVERSE], TERM);
}

void d_prog_r(re *r)
{
  d_prog_range(r, r->entry[RE_PROG_ENTRY_REVERSE], re_prog_size(r), TERM);
}

void d_prog_whole(re *r) { d_prog_range(r, 0, re_prog_size(r), TERM); }

void d_prog_gv(re *r)
{
  d_prog_range(r, 1, r->entry[RE_PROG_ENTRY_DOTSTAR], GRAPHVIZ);
}

void d_cctree_i(re_buf *cc_tree, u32 ref, u32 lvl)
{
  u32 i;
  re_compcc_node *node = &re_buf_at(cc_tree, re_compcc_node, ref);
  printf("%04X [%08X] ", ref, node->aux);
  for (i = 0; i < lvl; i++)
    printf("  ");
  printf(
      "%02X-%02X\n", re_u32_to_byte_range(node->range).l,
      re_u32_to_byte_range(node->range).h);
  if (node->child_ref)
    d_cctree_i(cc_tree, node->child_ref, lvl + 1);
  if (node->sibling_ref)
    d_cctree_i(cc_tree, node->sibling_ref, lvl);
}

void d_cctree(re_buf *cc_tree, u32 ref) { d_cctree_i(cc_tree, ref, 0); }
#endif

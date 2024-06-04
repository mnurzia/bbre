#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "re.h"

#ifdef RE_CONFIG_HEADER_FILE
  #include RE_CONFIG_HEADER_FILE
#endif

#define RE_REF_NONE 0
#define RE_UTF_MAX  0x10FFFF

/* Macro for declaring a buffer. Serves mostly for readability. */
#define re_buf(x) x *

/* Enumeration of AST types. */
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

/* Length (number of arguments) for each AST type. */
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

/* Stack frame for the compiler, used to keep track of a single AST node being
 * compiled. */
typedef struct re_compframe {
  re_u32 root_ref, /* reference to the AST node being compiled */
      child_ref,   /* reference to the child AST node to be compiled next */
      idx,         /* used keep track of repetition index */
      patch_head,  /* head of the outgoing patch linked list */
      patch_tail,  /* tail of the outgoing patch linked list */
      pc,          /* location of first instruction compiled for this node */
      flags,       /* group flags in effect (INSENSITIVE, etc.) */
      set_idx;     /* index of the current pattern being compiled */
} re_compframe;

typedef enum re_assert_flag {
  RE_ASSERT_LINE_BEGIN = 1, /* ^ */
  RE_ASSERT_LINE_END = 2,   /* $ */
  RE_ASSERT_TEXT_BEGIN = 4, /* \A */
  RE_ASSERT_TEXT_END = 8,   /* \z */
  RE_ASSERT_WORD = 16,      /* \w */
  RE_ASSERT_NOT_WORD = 32   /* \W */
} re_assert_flag;

#define RE_INST_OPCODE_BITS 2

typedef enum re_opcode {
  RE_OPCODE_RANGE, /* matches a range of bytes */
  RE_OPCODE_SPLIT, /* forks execution into two paths */
  RE_OPCODE_MATCH, /* writes the current string position into a submatch */
  RE_OPCODE_ASSERT /* continue execution if zero-width assertion */
} re_opcode;

/* Compiled program instruction. */
typedef struct re_inst {
  /* opcode_next is the opcode and the next program counter (primary branch
   * target), and param is opcode-specific data */
  /*                     3   2   2   2   1   1   0   0   0  */
  /*                      2   8   4   0   6   2   8   4   0 */
  re_u32 opcode_next, /* / nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnoo */
                      /* \          n = next PC, o = opcode */
      param;          /* / 0000000000000000hhhhhhhhllllllll (RANGE) */
                      /* \      h = high byte, l = low byte (RANGE) */
                      /* / NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN (SPLIT) */
                      /* \            N = secondary next PC (SPLIT) */
                      /* / iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiie (MATCH) */
                      /* \     i = group idx, e = start/end (MATCH) */
                      /* / 00000000000000000000000000aaaaaa (ASSERT) */
                      /* \                  a = assert_flag (ASSERT) */
} re_inst;

/* Represents an inclusive range of bytes. */
typedef struct re_byte_range {
  re_u8 l, /* min ordinal */
      h;   /* max ordinal */
} re_byte_range;

/* Represents an inclusive range of runes. */
typedef struct re_rune_range {
  re_u32 l, /* min ordinal */
      h;    /* max ordinal */
} re_rune_range;

/* Auxiliary data for tree nodes used for accelerating compilation. */
typedef union re_compcc_tree_aux {
  re_u32 hash, /* node hash, used for tree reduction */
      pc; /* compiled location, nonzero if this node was compiled already */
} re_compcc_tree_aux;

/* Tree node for the character class compiler. */
typedef struct re_compcc_tree {
  re_u32 range,           /* range of bytes this node matches */
      child_ref,          /* concatenation */
      sibling_ref;        /* alternation */
  re_compcc_tree_aux aux; /* node hash OR cached PC TODO: replace with union */
} re_compcc_tree;

/* Bit flags to identify program entry points in the `entry` field of `re`. */
typedef enum re_prog_entry {
  RE_PROG_ENTRY_REVERSE = 1, /* reverse execution */
  RE_PROG_ENTRY_DOTSTAR = 2, /* .* before execution (unanchored match) */
  RE_PROG_ENTRY_MAX = 4
} re_prog_entry;

/* A set of regular expressions. */
struct re {
  re_alloc alloc;                /* allocator function */
  re_buf(re_u32) ast;            /* AST arena */
  re_u32 ast_root,               /* AST root node reference */
      ast_sets;                  /* number of subpatterns */
  re_buf(re_u32) arg_stk;        /* parser argument stack */
  re_buf(re_u32) op_stk;         /* parser operator stack */
  re_buf(re_compframe) comp_stk; /* compiler frame stack (see re_compframe) */
  re_buf(re_inst) prog;          /* compiled program */
  re_buf(re_u32) prog_set_idxs;  /* pattern index for each instruction */
  re_buf(re_rune_range) compcc_ranges;
  re_buf(re_rune_range) compcc_ranges_2;
  re_buf(re_compcc_tree) compcc_tree;
  re_buf(re_compcc_tree) compcc_tree_2;
  re_buf(re_u32) compcc_hash;
  re_u32 entry[RE_PROG_ENTRY_MAX]; /* program entrypoints (see RE_PROG_ENTRY) */
  const re_u8 *expr;               /* input parser expression */
  size_t expr_pos,                 /* current position in expr */
      expr_size;                   /* number of bytes in expr */
  const char *error;               /* error message, if any */
  size_t error_pos; /* position the error was encountered in expr */
};

/* Helper macro for assertions. */
#define RE_IMPLIES(subject, predicate) (!(subject) || (predicate))

/* Allocate memory for an instance of `re`. */
static void *re_ialloc(const re *r, size_t prev, size_t next, void *ptr)
{
  return r->alloc(prev, next, ptr);
}

#ifndef RE_DEFAULT_ALLOC
/* Default allocation function. Hooks stdlib malloc. */
static void *re_default_alloc(size_t prev, size_t next, void *ptr)
{
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

/* For a library like this, you really need a convenient way to represent
 * dynamically-sized arrays of many different types. There's a million ways to
 * do this in C, but they usually boil down to capturing the size of each
 * element, and then plugging that size into an array allocation routine.
 * Originally, this library used a non-generic dynamic array only capable of
 * holding u32 (machine words), and simply represented all relevant types in
 * terms of u32. This actually worked very well for the AST and parser, but the
 * more complex structures used to execute regular expressions really benefit
 * from having a properly typed dynamic array implementation. */
/* I avoided implementing a solid dynamic array in this library for a while,
 * becuase I didn't feel like spending the brainpower on finding a good and safe
 * solution. I've implemented dynamic arrays in C before, and I've never been
 * fully satisfied with them. I think that the main problems with these data
 * structures result from (1) type unsafety, (2) macro overuse, and (3)
 * ergonomics, in order of importance. */
/* Any generic dynamic array implementation in C worth its salt *must* have a
 * measure of type safety. When the language itself provides next to nothing in
 * terms of safety checks, you have to take everything you can get.
 * Many dynamic array implementations rely on the user carrying the type
 * information around with them. Consider these two ways of defining push:
 * [a] dynamic_array_T_push(arr, elem)
 * [b] dynamic_array_push(arr, T, elem)
 * Option (a) requires the function dynamic_array_T_push to be predefined,
 * usually through a lengthy macro. This increases macro use, and decreases
 * ergonomics, since you end up wasting lines on declaring these functions in
 * what is essentially manual template instantiation:
 *   DYNAMIC_ARRAY_INIT_DECL(T);
 *   DYNAMIC_ARRAY_PUSH_DECL(T);
 *   DYNAMIC_ARRAY_POP_DECL(T);
 *   ...
 * Option (b) does not require this manual template instantiation, but suffers
 * from a worse problem: it's easy to accidentally use the wrong T, which is
 * very hard to check for, especially at compile-time. */
/* In essence, we want a dynamic array implementation that does not require us
 * to carry around a T for each call:
 *   dynamic_array_push(arr, elem)
 * This means that the dynamic_array_push macro must determine the generic type
 * of arr purely through properties of arr. But this presents another problem. A
 * dynamic array needs to remember its size and allocated reserve, so it will
 * look something like this:
 *   struct dynamic_array_struct_T {
 *     T* ptr;
 *     size_t size, alloc;
 *   };
 * ...which means that the `arr` in dynamic_array_push(arr, elem) must be such a
 * generic struct. We now have a familiar problem: foreach T we use in our
 * program, we must declare some `struct dynamic_array_struct_T` to be able to
 * use the dynamic array. */
/* So now we have another constraint on our implementation: we must not be
 * required to declare a new dynamic array type for each distinct T used in our
 * program. The only way to do this, to my knowledge, is to just represent the
 * dynamic array as a bare T*, and use the ages-old trick of storing metadata in
 * a header *before the pointer.*
 * We get type safety and ergonomics (array accesses can simply use p[i]!) and
 * the macro side can be made relatively simple. This proved to be a good fit
 * for this library. */

/* Dynamic array header, stored before the data pointer in memory. */
typedef struct re_buf_hdr {
  size_t size, alloc;
} re_buf_hdr;

/* Since we store the dynamic array as a raw T*, a natural implementaion might
 * represent an empty array as NULL. However, this complicates things-- size
 * checks must always have a branch to check for NULL, the grow routine has more
 * scary codepaths, etc. To make code simpler, there exists a special sentinel
 * value that contains the empty array. */
static re_buf_hdr re_buf_sentinel = {0};

/* Given a dynamic array, get its header. */
static re_buf_hdr *re_buf_get_hdr(void *buf) { return ((re_buf_hdr *)buf) - 1; }

/* Given a dynamic array, get its size. */
static size_t re_buf_size_t(void *buf) { return re_buf_get_hdr(buf)->size; }

/* Reserve enough memory to set the array's size to `size`. Note that this is
 * different from C++'s std::vector::reserve() in that it actually sets the used
 * size of the dynamic array. The caller must initialize the newly available
 * elements. */
static int re_buf_reserve_t(const re *r, void **buf, size_t size)
{
  re_buf_hdr *hdr = NULL;
  size_t next_alloc;
  void *next_ptr;
  assert(buf && *buf);
  hdr = re_buf_get_hdr(*buf);
  next_alloc = hdr->alloc ? hdr->alloc : /* sentinel */ 1;
  if (size <= hdr->alloc) {
    hdr->size = size;
    return 0;
  }
  while (next_alloc < size)
    next_alloc *= 2;
  next_ptr = re_ialloc(
      r, hdr->alloc ? sizeof(re_buf_hdr) + hdr->alloc : /* sentinel */ 0,
      sizeof(re_buf_hdr) + next_alloc, hdr->alloc ? hdr : /* sentinel */ NULL);
  if (!next_ptr)
    return RE_ERR_MEM;
  hdr = next_ptr;
  hdr->alloc = next_alloc;
  hdr->size = size;
  *buf = hdr + 1;
  return 0;
}

/* Initialize an empty dynamic array. */
static void re_buf_init_t(void **b) { *b = &re_buf_sentinel + 1; }

/* Destroy a dynamic array. */
static void re_buf_destroy_t(const re *r, void **buf)
{
  re_buf_hdr *hdr;
  assert(buf && *buf);
  hdr = re_buf_get_hdr(*buf);
  if (hdr->alloc)
    re_ialloc(r, sizeof(*hdr) + hdr->alloc, 0, hdr);
}

/* Increase size by `incr`. */
static int re_buf_grow_t(const re *r, void **buf, size_t incr)
{
  assert(buf);
  return re_buf_reserve_t(r, buf, re_buf_size_t(*buf) + incr);
}

/* Get the last element index of the dynamic array. */
static size_t re_buf_tail_t(void *buf, size_t decr)
{
  return re_buf_get_hdr(buf)->size - decr;
}

/* Pop the last element of the array, returning its index in storage units. */
size_t re_buf_pop_t(void *buf, size_t decr)
{
  size_t out;
  re_buf_hdr *hdr;
  assert(buf);
  out = re_buf_tail_t(buf, decr);
  hdr = re_buf_get_hdr(buf);
  assert(hdr->size >= decr);
  hdr->size -= decr;
  return out;
}

/* Clear the buffer, without freeing its backing memory */
void re_buf_clear(void *buf)
{
  void *sbuf;
  assert(buf);
  sbuf = *(void **)buf;
  if (!sbuf)
    return;
  re_buf_get_hdr(sbuf)->size = 0;
}

/* Initialize a dynamic array. */
#define re_buf_init(b) re_buf_init_t((void **)b)

/* Get the element size of a dynamic array. */
#define re_buf_esz(b) sizeof(**(b))

/* Push an element. */
#define re_buf_push(r, b, e)                                                   \
  (re_buf_grow_t((r), (void **)(b), re_buf_esz(b))                             \
       ? RE_ERR_MEM                                                            \
       : (((*b)[re_buf_tail_t((void *)(*b), re_buf_esz(b)) / re_buf_esz(b)]) = \
              (e),                                                             \
          0))

/* Set the size to `n`. */
#define re_buf_reserve(r, b, n)                                                \
  (re_buf_reserve_t(r, (void **)(b), re_buf_esz(b) * (n)))

/* Pop an element. */
#define re_buf_pop(b)                                                          \
  ((*(b))[re_buf_pop_t((void *)(*b), re_buf_esz(b)) / re_buf_esz(b)])

/* Get a pointer to `n` elements from the end. */
#define re_buf_peek(b, n)                                                      \
  ((*b) + re_buf_tail_t((void *)(*b), re_buf_esz(b)) / re_buf_esz(b) - (n))

/* Get the size. */
#define re_buf_size(b) (re_buf_size_t((void *)(b)) / sizeof(*(b)))

/* Destroy a dynamic array. */
#define re_buf_destroy(r, b) (re_buf_destroy_t((r), (void **)(b)))

static int re_parse(re *r, const re_u8 *s, size_t sz, re_u32 *root);

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
    return (err = RE_ERR_MEM);
  r->alloc = alloc;
  re_buf_init(&r->ast);
  r->ast_root = r->ast_sets = 0;
  re_buf_init(&r->arg_stk), re_buf_init(&r->op_stk), re_buf_init(&r->comp_stk);
  re_buf_init(&r->compcc_ranges), re_buf_init(&r->compcc_tree),
      re_buf_init(&r->compcc_ranges_2), re_buf_init(&r->compcc_tree_2),
      re_buf_init(&r->compcc_hash);
  re_buf_init(&r->prog), re_buf_init(&r->prog_set_idxs);
  memset(r->entry, 0, sizeof(r->entry));
  if (regex) {
    if ((err = re_parse(r, (const re_u8 *)regex, n, &r->ast_root))) {
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
  re_buf_destroy(r, (void **)&r->ast);
  re_buf_destroy(r, &r->op_stk), re_buf_destroy(r, &r->arg_stk),
      re_buf_destroy(r, &r->comp_stk);
  re_buf_destroy(r, &r->compcc_ranges), re_buf_destroy(r, &r->compcc_ranges_2),
      re_buf_destroy(r, &r->compcc_tree), re_buf_destroy(r, &r->compcc_tree_2),
      re_buf_destroy(r, &r->compcc_hash);
  re_buf_destroy(r, &r->prog);
  re_buf_destroy(r, (void **)&r->prog_set_idxs);
  r->alloc(sizeof(*r), 0, r);
}

/* Make a byte range inline; more convenient than initializing a struct. */
static re_byte_range re_byte_range_make(re_u8 l, re_u8 h)
{
  re_byte_range out;
  out.l = l, out.h = h;
  return out;
}

/* Pack a byte range into a u32, low byte first. */
static re_u32 re_byte_range_to_u32(re_byte_range br)
{
  return ((re_u32)br.l) | ((re_u32)br.h) << 8;
}

/* Unpack a byte range from a u32. */
static re_byte_range re_u32_to_byte_range(re_u32 u)
{
  return re_byte_range_make(u & 0xFF, u >> 8 & 0xFF);
}

/* Check if two byte ranges are adjacent (right directly supersedes left) */
static int re_byte_range_is_adjacent(re_byte_range left, re_byte_range right)
{
  return ((re_u32)left.h) + 1 == ((re_u32)right.l);
}

/* Make a rune range inline. */
static re_rune_range re_rune_range_make(re_u32 l, re_u32 h)
{
  re_rune_range out;
  out.l = l, out.h = h;
  return out;
}

/* Make a new AST node within the regular expression. */
static int re_ast_make(
    re *r, re_ast_type type, re_u32 p0, re_u32 p1, re_u32 p2, re_u32 *out_node)
{
  re_u32 args[4], i;
  int err;
  args[0] = type, args[1] = p0, args[2] = p1, args[3] = p2;
  if (type && !re_buf_size(r->ast) &&
      (err = re_ast_make(r, 0, 0, 0, 0, out_node))) /* sentinel node */
    return err;
  *out_node = re_buf_size(r->ast);
  for (i = 0; i < 1 + re_ast_type_lens[type]; i++)
    if ((err = re_buf_push(r, &r->ast, args[i])))
      return err;
  return 0;
}

/* Decompose a given AST node, given its reference, into `out_args`. */
static void re_ast_decompose(re *r, re_u32 node, re_u32 *out_args)
{
  re_u32 *in_args = r->ast + node;
  memcpy(out_args, in_args + 1, re_ast_type_lens[*in_args] * sizeof(re_u32));
}

/* Get the type of the given AST node. */
static re_u32 *re_ast_type_ref(re *r, re_u32 node) { return r->ast + node; }

/* Get a pointer to the `n`'th parameter of the given AST node. */
static re_u32 *re_ast_param_ref(re *r, re_u32 node, re_u32 n)
{
  assert(re_ast_type_lens[*re_ast_type_ref(r, node)] > n);
  return r->ast + node + 1 + n;
}

/* Add another regular expression to the set of regular expressions matched by
 * this `re` instance. */
int re_union(re *r, const char *regex, size_t n)
{
  int err = 0;
  re_u32 next_reg, next_root;
  if (!r->ast_sets) {
    r->ast_sets++;
    return re_parse(r, (const re_u8 *)regex, n, &r->ast_root);
  }
  if ((err = re_parse(r, (const re_u8 *)regex, n, &next_reg)) ||
      (err = re_ast_make(
           r, RE_AST_TYPE_ALT, r->ast_root, next_reg, 0, &next_root)))
    return err;
  r->ast_root = next_root;
  r->ast_sets++;
  return err;
}

/*T Generated by `charclass_tree.py dfa` */
static const re_u32 re_utf8_dfa_num_range = 13;
static const re_u32 re_utf8_dfa_num_state = 9;
static const re_u8 re_utf8_dfa_trans[] = {
    0, 8, 8, 8, 8, 3, 7, 2, 6, 2, 5, 4, 1, 8, 2, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 3, 3, 3, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 0, 0,
    0, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 2, 2, 2, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 2, 2, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 3, 3, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 3, 8, 8, 8, 8, 8, 8, 8, 8, 8};
static const re_u8 re_utf8_dfa_class[] = {
    0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,  0,  0,  0,  0,  0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2,  2,  2,  2,  2,  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3,
    3,  3,  3,  3,  3,  3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    4,  4,  5,  5,  5,  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5,  5,  5,  5,  5,  5, 5, 5, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 9, 9,
    10, 11, 11, 11, 12, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4};
static const re_u8 re_utf8_dfa_shift[] = {0, 0, 0, 0, 2, 2, 3,
                                          3, 3, 3, 4, 4, 4};

/*t Generated by `charclass_tree.py dfa` */

static re_u32 re_utf8_decode(re_u32 *state, re_u32 *codep, re_u32 byte)
{
  re_u32 type = re_utf8_dfa_class[byte];
  *codep = *state ? (byte & 0x3F) | (*codep << 6)
                  : (0xFF >> re_utf8_dfa_shift[type]) & (byte);
  *state = re_utf8_dfa_trans[*state * re_utf8_dfa_num_range + type];
  return *state;
}

/* Create and propagate a parsing error.
 * Returns `RE_ERR_PARSE` unconditionally. */
static int re_parse_err(re *r, const char *msg)
{
  r->error = msg, r->error_pos = r->expr_pos;
  return RE_ERR_PARSE;
}

/* Check if we are at the end of the regex string. */
static int re_parse_has_more(re *r) { return r->expr_pos != r->expr_size; }

static re_u32 re_parse_next(re *r)
{
  re_u32 state = 0, codep;
  assert(re_parse_has_more(r));
  while (re_utf8_decode(&state, &codep, r->expr[r->expr_pos++]) != 0)
    assert(r->expr_pos < r->expr_size);
  assert(state == 0);
  return codep;
}

/* Get the next input codepoint, or raise a parse error with the given error
 * message if there is no more input. */
static int re_parse_next_or(re *r, re_u32 *codep, const char *else_msg)
{
  assert(else_msg);
  if (!re_parse_has_more(r))
    return re_parse_err(r, else_msg);
  *codep = re_parse_next(r);
  return 0;
}

/* Check that the input string is well-formed UTF-8. */
static int re_parse_checkutf8(re *r)
{
  re_u32 state = 0, codep;
  while (r->expr_pos < r->expr_size &&
         re_utf8_decode(&state, &codep, r->expr[r->expr_pos]) !=
             re_utf8_dfa_num_state - 1)
    r->expr_pos++;
  if (state != 0)
    return re_parse_err(r, "invalid utf-8 sequence");
  r->expr_pos = 0;
  return 0;
}

/* Without advancing the parser, check the next character. */
static re_u32 re_peek_next_new(re *r)
{
  size_t prev_pos = r->expr_pos;
  re_u32 out = re_parse_next(r);
  r->expr_pos = prev_pos;
  return out;
}

/* Maximum repetition count for quantifiers. */
#define RE_LIMIT_REPETITION_COUNT 100000

/* Sentinel value to represent an infinite repetition. */
#define RE_INFTY (RE_LIMIT_REPETITION_COUNT + 1)

/* Given nodes R_1..R_N on the argument stack, fold them into a single CAT
 * node. If there are no nodes on the stack, create an epsilon node.
 * Returns `RE_ERR_MEM` if out of memory. */
static int re_fold(re *r)
{
  int err = 0;
  if (!re_buf_size(r->arg_stk)) {
    /* arg_stk: | */
    return re_buf_push(r, &r->arg_stk, /* epsilon */ RE_REF_NONE);
    /* arg_stk: | eps |*/
  }
  while (re_buf_size(r->arg_stk) > 1) {
    /* arg_stk: | ... | R_N-1 | R_N | */
    re_u32 right, left, rest;
    right = re_buf_pop(&r->arg_stk);
    left = *re_buf_peek(&r->arg_stk, 0);
    if ((err = re_ast_make(r, RE_AST_TYPE_CAT, left, right, 0, &rest)))
      return err;
    *re_buf_peek(&r->arg_stk, 0) = rest;
    /* arg_stk: | ... | R_N-1R_N | */
  }
  /* arg_stk: | R1R2...Rn | */
  return 0;
}

/* Given a node R on the argument stack and an arbitrary number of ALT nodes at
 * the end of the operator stack, fold and finish each ALT node into a single
 * resulting ALT node on the argument stack.
 * Returns `RE_ERR_MEM` if out of memory. */
static void re_fold_alts(re *r, re_u32 *flags)
{
  assert(re_buf_size(r->arg_stk) == 1);
  /* First pop all inline groups. */
  while (re_buf_size(r->op_stk) &&
         *re_ast_type_ref(r, *re_buf_peek(&r->op_stk, 0)) ==
             RE_AST_TYPE_IGROUP) {
    /* arg_stk: |  R  | */
    /* op_stk:  | ... | (S) | */
    re_u32 igrp = re_buf_pop(&r->op_stk), cat = *re_ast_param_ref(r, igrp, 0),
           old_flags = *re_ast_param_ref(r, igrp, 2);
    *re_ast_param_ref(r, igrp, 0) = *re_buf_peek(&r->arg_stk, 0);
    *flags = old_flags;
    *re_ast_param_ref(r, cat, 1) = igrp;
    *re_buf_peek(&r->arg_stk, 0) = cat;
    /* arg_stk: | S(R)| */
    /* op_stk:  | ... | */
  }
  assert(re_buf_size(r->arg_stk) == 1);
  /* arg_stk: |  R  | */
  /* op_stk:  | ... | */
  if (re_buf_size(r->op_stk) &&
      *re_ast_type_ref(r, *re_buf_peek(&r->op_stk, 0)) == RE_AST_TYPE_ALT) {
    /* op_stk:  | ... |  A  | */
    /* finish the last alt */
    *re_ast_param_ref(r, *re_buf_peek(&r->op_stk, 0), 1) =
        *re_buf_peek(&r->arg_stk, 0);
    /* arg_stk: | */
    /* op_stk:  | ... | */
    while (re_buf_size(r->op_stk) > 1 &&
           *re_ast_type_ref(r, *re_buf_peek(&r->op_stk, 1)) ==
               RE_AST_TYPE_ALT) {
      /* op_stk:  | ... | A_1 | A_2 | */
      re_u32 right = re_buf_pop(&r->op_stk), left = *re_buf_peek(&r->op_stk, 0);
      *re_ast_param_ref(r, left, 1) = right;
      *re_buf_peek(&r->op_stk, 0) = left;
      /* op_stk:  | ... | A_1(|A_2) | */
    }
    /* op_stk:  | ... |  A  | */
    assert(re_buf_size(r->arg_stk) == 1);
    *re_buf_peek(&r->arg_stk, 0) = re_buf_pop(&r->op_stk);
    /* arg_stk: |  A  | */
    /* op_stk:  | ... | */
  }
  assert(re_buf_size(r->arg_stk) == 1);
}

/* Add the CC node `rest` to the CC node `first`. */
static re_u32 re_ast_cls_union(re *r, re_u32 rest, re_u32 first)
{
  re_u32 cur = first, *next;
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
 * Returns `RE_ERR_MEM` if out of memory. */
static int re_parse_escape_addchr(re *r, re_u32 ch, re_u32 allowed_outputs)
{
  int err = 0;
  re_u32 res;
  (void)allowed_outputs, assert(allowed_outputs & (1 << RE_AST_TYPE_CHR));
  if ((err = re_ast_make(r, RE_AST_TYPE_CHR, ch, 0, 0, &res)) ||
      (err = re_buf_push(r, &r->arg_stk, res)))
    return err;
  return 0;
}

/* Convert a hexadecimal digit to a number.
 * Returns -1 on invalid hex digit.
 * TODO: convert this to an idiomatic error function */
static int re_parse_hexdig(re_u32 ch)
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

static int re_parse_octdig(re_u32 ch)
{
  if (ch >= '0' && ch <= '7')
    return ch - '0';
  return -1;
}

typedef struct re_parse_builtin_cc {
  re_u8 name_len, cc_len;
  const char *name;
  const char *chars;
} re_parse_builtin_cc;

/*T Generated by `unicode_data.py gen_ascii_charclasses impl` */
static const re_parse_builtin_cc re_parse_builtin_ccs[15] = {
    {5,  3, "alnum",      "\x30\x39\x41\x5A\x61\x7A"        },
    {5,  2, "alpha",      "\x41\x5A\x61\x7A"                },
    {5,  1, "ascii",      "\x00\x7F"                        },
    {5,  2, "blank",      "\x09\x09\x20\x20"                },
    {5,  2, "cntrl",      "\x00\x1F\x7F\x7F"                },
    {5,  2, "digit",      "\x30\x30\x39\x39"                },
    {5,  2, "graph",      "\x21\x21\x7E\x7E"                },
    {5,  2, "lower",      "\x61\x61\x7A\x7A"                },
    {5,  1, "print",      "\x20\x7E"                        },
    {5,  4, "punct",      "\x21\x2F\x3A\x40\x5B\x60\x7B\x7E"},
    {5,  2, "space",      "\x09\x0D\x20\x20"                },
    {10, 3, "perl_space", "\x09\x0A\x0C\x0D\x20\x20"        },
    {5,  2, "upper",      "\x41\x41\x5A\x5A"                },
    {4,  3, "word",       "\x30\x39\x41\x5A\x61\x7A"        },
    {6,  3, "xdigit",     "\x30\x39\x41\x46\x61\x66"        },
};

/*t Generated by `unicode_data.py gen_ascii_charclasses impl` */

static const re_parse_builtin_cc *re_parse_named_cc(const re_u8 *s, size_t sz)
{
  const re_parse_builtin_cc *p = re_parse_builtin_ccs;
  while (p < re_parse_builtin_ccs + (sizeof(re_parse_builtin_ccs) /
                                     sizeof(*re_parse_builtin_ccs))) {
    if ((size_t)p->name_len == sz && !memcmp(s, (const re_u8 *)p->name, sz))
      return p;
    p++;
  }
  return NULL;
}

static int re_parse_add_namedcc(re *r, const re_u8 *s, size_t sz, int invert)
{
  int err = 0;
  const re_parse_builtin_cc *named = re_parse_named_cc(s, sz);
  re_u32 res = RE_REF_NONE, i, max = 0, cur_min = 0, cur_max = 0;
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
  if ((err = re_buf_push(r, &r->arg_stk, res)))
    return err;
  return 0;
}

static int re_utf8_prop_decode(re *r, const re_u8 *name, size_t name_len);

/* after a \ */
static int re_parse_escape(re *r, re_u32 allowed_outputs)
{
  re_u32 ch;
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
    re_u32 ord = ch - '0';
    while (digs++ < 3 && re_parse_has_more(r) &&
           re_parse_octdig(ch = re_peek_next_new(r)) >= 0) {
      ch = re_parse_next(r);
      assert(!err && re_parse_octdig(ch) >= 0);
      ord = ord * 8 + re_parse_octdig(ch);
    }
    return re_parse_escape_addchr(r, ord, allowed_outputs);
  } else if (ch == 'x') { /* hex escape */
    re_u32 ord = 0;
    if ((err = re_parse_next_or(
             r, &ch, "expected two hex characters or a bracketed hex literal")))
      return err;
    if (ch == '{') { /* bracketed hex lit */
      re_u32 i = 0;
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
    re_u32 res;
    if (!(allowed_outputs & (1 << RE_AST_TYPE_ANYBYTE)))
      return re_parse_err(r, "cannot use \\C here");
    if ((err = re_ast_make(r, RE_AST_TYPE_ANYBYTE, 0, 0, 0, &res)) ||
        (err = re_buf_push(r, &r->arg_stk, res)))
      return err;
  } else if (ch == 'Q') { /* quote string */
    re_u32 cat = RE_REF_NONE, chr = RE_REF_NONE;
    if (!(allowed_outputs & (1 << RE_AST_TYPE_CAT)))
      return re_parse_err(r, "cannot use \\Q...\\E here");
    while (re_parse_has_more(r)) {
      ch = re_parse_next(r);
      if (ch == '\\' && re_parse_has_more(r)) {
        ch = re_peek_next_new(r);
        if (ch == 'E') {
          ch = re_parse_next(r);
          assert(ch == 'E');
          return re_buf_push(r, &r->arg_stk, cat);
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
    if ((err = re_buf_push(r, &r->arg_stk, cat)))
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
             r, (const re_u8 *)cc_name, strlen(cc_name), inverted)))
      return err;
  } else if (ch == 'P' || ch == 'p') { /* Unicode properties */
    size_t name_start = r->expr_pos, name_end;
    const char *err_msg =
        "expected one-character property name or bracketed property name "
        "for Unicode property escape";
    if ((err = re_parse_next_or(r, &ch, err_msg)))
      return err;
    if (ch == '{') { /* bracketed property */
      name_start = r->expr_pos;
      while (ch != '}')
        if ((err = re_parse_next_or(
                 r, &ch, "expected '}' to close bracketed property name")))
          return err;
      name_end = r->expr_pos - 1;
    } else
      name_end = r->expr_pos;
    if (!(allowed_outputs & (1 << RE_AST_TYPE_CC)))
      return re_parse_err(r, "cannot use a character class here");
    assert(name_end >= name_start);
    if ((err = re_utf8_prop_decode(
             r, r->expr + name_start, name_end - name_start)))
      return err;
  } else if (ch == 'A' || ch == 'z' || ch == 'B' || ch == 'b') { /* empty
                                                                    asserts */
    re_u32 res;
    if (!(allowed_outputs & (1 << RE_AST_TYPE_ASSERT)))
      return re_parse_err(r, "cannot use an epsilon assertion here");
    if ((err = re_ast_make(
             r, RE_AST_TYPE_ASSERT,
             ch == 'A'   ? RE_ASSERT_TEXT_BEGIN
             : ch == 'z' ? RE_ASSERT_TEXT_END
             : ch == 'B' ? RE_ASSERT_NOT_WORD
                         : RE_ASSERT_WORD,
             0, 0, &res)) ||
        (err = re_buf_push(r, &r->arg_stk, res)))
      return err;
  } else {
    return re_parse_err(r, "invalid escape sequence");
  }
  return 0;
}

static int re_parse_number(re *r, re_u32 *out, re_u32 max_digits)
{
  int err = 0;
  re_u32 ch, acc = 0, ndigs = 0;
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

static int re_parse(re *r, const re_u8 *ts, size_t tsz, re_u32 *root)
{
  int err;
  re_u32 flags = 0;
  r->expr = ts;
  r->expr_size = tsz, r->expr_pos = 0;
  if ((err = re_parse_checkutf8(r)))
    return err;
  while (re_parse_has_more(r)) {
    re_u32 ch = re_parse_next(r), res = RE_REF_NONE;
    if (ch == '*' || ch == '+' || ch == '?') {
      re_u32 q = ch, greedy = 1;
      /* arg_stk: | ... |  R  | */
      /* pop one from arg stk, create quant, push to arg stk */
      if (!re_buf_size(r->arg_stk))
        return re_parse_err(r, "cannot apply quantifier to empty regex");
      if (re_parse_has_more(r) && re_peek_next_new(r) == '?')
        re_parse_next(r), greedy = 0;
      if ((err = re_ast_make(
               r, greedy ? RE_AST_TYPE_QUANT : RE_AST_TYPE_UQUANT,
               *re_buf_peek(&r->arg_stk, 0) /* child */, q == '+' /* min */,
               q == '?' ? 1 : RE_INFTY /* max */, &res)))
        return err;
      *re_buf_peek(&r->arg_stk, 0) = res;
      /* arg_stk: | ... | *(R) | */
    } else if (ch == '|') {
      /* fold the arg stk into a concat, create alt, push it to the arg stk */
      /* op_stk:  | ... | */
      /* arg_stk: | R_1 | R_2 | ... | R_N | */
      if ((err = re_fold(r)))
        return err;
      /* arg_stk: |  R  | */
      if ((err = re_ast_make(
               r, RE_AST_TYPE_ALT, re_buf_pop(&r->arg_stk) /* left */,
               RE_REF_NONE /* right */, 0, &res)) ||
          (err = re_buf_push(r, &r->op_stk, res)))
        return err;
      /* arg_stk: | */
      /* op_stk:  | ... | R(|) | */
    } else if (ch == '(') {
      re_u32 old_flags = flags, inline_group = 0, child;
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
          re_u32 neg = 0, flag = RE_GROUP_FLAG_UNGREEDY;
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
      child = re_buf_pop(&r->arg_stk);
      if (inline_group &&
          (err = re_ast_make(r, RE_AST_TYPE_CAT, child, 0, 0, &child)))
        return err;
      /* arg_stk: |  R  | */
      if ((err = re_ast_make(
               r, inline_group ? RE_AST_TYPE_IGROUP : RE_AST_TYPE_GROUP, child,
               flags, old_flags, &res)) ||
          (err = re_buf_push(r, &r->op_stk, res)))
        return err;
      /* op_stk:  | ... | (R) | */
    } else if (ch == ')') {
      re_u32 grp, prev;
      /* arg_stk: | S_1 | S_2 | ... | S_N | */
      /* op_stk:  | ... | (R) | ... | */
      /* fold the arg stk into a concat, fold remaining alts, create group,
       * push it to the arg stk */
      if ((err = re_fold(r)))
        return err;
      re_fold_alts(r, &flags);
      /* arg_stk has one value */
      assert(re_buf_size(r->arg_stk) == 1);
      if (!re_buf_size(r->op_stk))
        return re_parse_err(r, "extra close parenthesis");
      /* arg_stk: |  S  | */
      /* op_stk:  | ... | (R) | */
      grp = *re_buf_peek(&r->op_stk, 0);
      /* retrieve the previous contents of arg_stk */
      prev = *re_ast_param_ref(r, grp, 0);
      /* add it to the group */
      *(re_ast_param_ref(r, grp, 0)) = *re_buf_peek(&r->arg_stk, 0);
      /* restore group flags */
      flags = *(re_ast_param_ref(r, grp, 2));
      /* push the saved contents of arg_stk */
      *re_buf_peek(&r->arg_stk, 0) = prev;
      /* pop the group frame into arg_stk */
      if ((err = re_buf_push(r, &r->arg_stk, re_buf_pop(&r->op_stk))))
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
          (err = re_buf_push(r, &r->arg_stk, res)))
        return err;
      /* arg_stk: | ... |  .  | */
    } else if (ch == '[') { /* charclass */
      size_t start = r->expr_pos;
      re_u32 inverted = 0, min, max;
      res = RE_REF_NONE;
      while (1) {
        re_u32 next;
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
          next = re_buf_pop(&r->arg_stk);
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
          next = re_buf_pop(&r->arg_stk);
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
            next = re_buf_pop(&r->arg_stk);
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
      if ((err = re_buf_push(r, &r->arg_stk, res)))
        return err;
    } else if (ch == '\\') { /* escape */
      if ((err = re_parse_escape(
               r, 1 << RE_AST_TYPE_CHR | 1 << RE_AST_TYPE_CC |
                      1 << RE_AST_TYPE_ANYBYTE | 1 << RE_AST_TYPE_CAT |
                      1 << RE_AST_TYPE_ASSERT)))
        return err;
    } else if (ch == '{') { /* repetition */
      re_u32 min = 0, max = 0;
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
      if (!re_buf_size(r->arg_stk))
        return re_parse_err(r, "cannot apply quantifier to empty regex");
      if ((err = re_ast_make(
               r, RE_AST_TYPE_QUANT, *re_buf_peek(&r->arg_stk, 0), min, max,
               &res)))
        return err;
      *re_buf_peek(&r->arg_stk, 0) = res;
    } else if (ch == '^' || ch == '$') { /* beginning/end of text/line */
      if ((err = re_ast_make(
               r, RE_AST_TYPE_ASSERT,
               ch == '^'
                   ? (flags & RE_GROUP_FLAG_MULTILINE ? RE_ASSERT_LINE_BEGIN
                                                      : RE_ASSERT_TEXT_BEGIN)
                   : (flags & RE_GROUP_FLAG_MULTILINE ? RE_ASSERT_LINE_END
                                                      : RE_ASSERT_TEXT_END),
               0, 0, &res)) ||
          (err = re_buf_push(r, &r->arg_stk, res)))
        return err;
    } else { /* char: push to the arg stk */
      /* arg_stk: | ... | */
      if ((err = re_ast_make(r, RE_AST_TYPE_CHR, ch, 0, 0, &res)) ||
          (err = re_buf_push(r, &r->arg_stk, res)))
        return err;
      /* arg_stk: | ... | chr | */
    }
  }
  if ((err = re_fold(r)))
    return err;
  re_fold_alts(r, &flags);
  if (re_buf_size(r->op_stk))
    return re_parse_err(r, "unmatched open parenthesis");
  if ((err = re_ast_make(
           r, RE_AST_TYPE_GROUP, re_buf_pop(&r->arg_stk),
           RE_GROUP_FLAG_SUBEXPRESSION, 0, root)))
    return err;
  return 0;
}

static re_opcode re_inst_opcode(re_inst i)
{
  return i.opcode_next & ((1 << RE_INST_OPCODE_BITS) - 1);
}

static re_u32 re_inst_next(re_inst i)
{
  return i.opcode_next >> RE_INST_OPCODE_BITS;
}

static re_u32 re_inst_param(re_inst i) { return i.param; }

static re_inst re_inst_make(re_opcode op, re_u32 next, re_u32 param)
{
  re_inst out;
  out.opcode_next = op | next << RE_INST_OPCODE_BITS, out.param = param;
  return out;
}

static re_u32
re_inst_match_param_make(re_u32 begin_or_end, re_u32 slot_idx_or_set_idx)
{
  assert(begin_or_end == 0 || begin_or_end == 1);
  return begin_or_end | (slot_idx_or_set_idx << 1);
}

static re_u32 re_inst_match_param_end(re_u32 param) { return param & 1; }

static re_u32 re_inst_match_param_idx(re_u32 param) { return param >> 1; }

static void re_prog_set(re *r, re_u32 pc, re_inst i) { r->prog[pc] = i; }

static re_inst re_prog_get(const re *r, re_u32 pc) { return r->prog[pc]; }

static re_u32 re_prog_size(const re *r) { return re_buf_size(r->prog); }

#define RE_PROG_MAX_INSTS 100000

static int re_inst_emit(re *r, re_inst i, re_compframe *frame)
{
  int err = 0;
  if (re_prog_size(r) == RE_PROG_MAX_INSTS)
    return RE_ERR_LIMIT;
  if ((err = re_buf_push(r, &r->prog, i)) ||
      (err = re_buf_push(r, &r->prog_set_idxs, frame->set_idx)))
    return err;
  return err;
}

static re_inst re_patch_set(re *r, re_u32 pc, re_u32 val)
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

static void re_patch_add(re *r, re_compframe *f, re_u32 dest_pc, int p)
{
  re_u32 out_val = dest_pc << 1 | !!p;
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

static void re_patch_apply(re *r, re_compframe *p, re_u32 dest_pc)
{
  re_u32 i = p->patch_head;
  while (i) {
    re_inst prev = re_patch_set(r, i, dest_pc);
    i = i & 1 ? re_inst_param(prev) : re_inst_next(prev);
  }
  p->patch_head = p->patch_tail = RE_REF_NONE;
}

static re_u32 re_compcc_array_key(re_buf(re_rune_range) cc, size_t idx)
{
  return cc[idx].l;
}

static void re_compcc_array_swap(re_buf(re_rune_range) cc, size_t a, size_t b)
{
  re_rune_range tmp = cc[a];
  cc[a] = cc[b];
  cc[b] = tmp;
}

static void re_compcc_hsort(re_buf(re_rune_range) cc)
{
  size_t end = re_buf_size(cc), start = end >> 1, root, child;
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

static int re_compcc_tree_new(
    re *r, re_buf(re_compcc_tree) * cc_out, re_compcc_tree node, re_u32 *out)
{
  int err = 0;
  if (!re_buf_size(*cc_out)) {
    re_compcc_tree sentinel = {0};
    /* need to create sentinel node */
    if ((err = re_buf_push(r, cc_out, sentinel)))
      return err;
  }
  if (out)
    *out = re_buf_size(*cc_out);
  if ((err = re_buf_push(r, cc_out, node)))
    return err;
  return 0;
}

static int re_compcc_tree_append(
    re *r, re_buf(re_compcc_tree) * cc, re_u32 range, re_u32 parent,
    re_u32 *out)
{
  re_compcc_tree *parent_node, child_node = {0};
  re_u32 child_ref;
  int err;
  parent_node = (*cc) + parent;
  child_node.sibling_ref = parent_node->child_ref, child_node.range = range;
  if ((err = re_compcc_tree_new(r, cc, child_node, &child_ref)))
    return err;
  parent_node = (*cc) + parent;
  parent_node->child_ref = child_ref;
  assert(parent_node->child_ref != parent);
  assert(parent_node->sibling_ref != parent);
  assert(child_node.child_ref != parent_node->child_ref);
  assert(child_node.sibling_ref != parent_node->child_ref);
  *out = parent_node->child_ref;
  return 0;
}

static int re_compcc_tree_build_one(
    re *r, re_buf(re_compcc_tree) * cc_out, re_u32 parent, re_u32 min,
    re_u32 max, re_u32 x_bits, re_u32 y_bits)
{
  re_u32 x_mask = (1 << x_bits) - 1, y_min = min >> x_bits,
         y_max = max >> x_bits, u_mask = (0xFE << y_bits) & 0xFF,
         byte_min = (y_min & 0xFF) | u_mask, byte_max = (y_max & 0xFF) | u_mask,
         i, next;
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
    re_u32 x_min = min & x_mask, x_max = max & x_mask, brs[3], mins[3], maxs[3],
           n;
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
      re_compcc_tree *parent_node;
      re_u32 child_ref;
      /* check if previous child intersects and then compute intersection */
      assert(parent);
      parent_node = (*cc_out) + parent;
      if (parent_node->child_ref &&
          re_u32_to_byte_range(brs[i]).l <=
              re_u32_to_byte_range(((*cc_out) + parent_node->child_ref)->range)
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
static int re_compcc_tree_build(
    re *r, const re_buf(re_rune_range) cc_in, re_buf(re_compcc_tree) * cc_out)
{
  size_t i = 0, j = 0, min_bound = 0;
  re_u32 root_ref;
  re_compcc_tree root_node;
  int err = 0;
  root_node.child_ref = root_node.sibling_ref = root_node.aux.hash =
      root_node.range = 0;
  /* clear output charclass */
  re_buf_clear(cc_out);
  if ((err = re_compcc_tree_new(r, cc_out, root_node, &root_ref)))
    return err;
  for (i = 0, j = 0; i < re_buf_size(cc_in) && j < 4;) {
    static const re_u32 y_bits[4] = {7, 5, 4, 3};
    static const re_u32 x_bits[4] = {0, 6, 12, 18};
    re_u32 max_bound = (1 << (x_bits[j] + y_bits[j])) - 1;
    re_rune_range rr = cc_in[i];
    if (min_bound <= rr.h && rr.l <= max_bound) {
      /* [min,max] intersects [min_bound,max_bound] */
      re_u32 clamped_min =
                 rr.l < min_bound ? min_bound : rr.l, /* clamp range */
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

static int re_compcc_tree_eq(
    re *r, const re_buf(re_compcc_tree) cc_tree_in, re_u32 a_ref, re_u32 b_ref)
{
  while (a_ref && b_ref) {
    const re_compcc_tree *a = cc_tree_in + a_ref, *b = cc_tree_in + b_ref;
    if (!re_compcc_tree_eq(r, cc_tree_in, a->child_ref, b->child_ref))
      return 0;
    if (a->range != b->range)
      return 0;
    a_ref = a->sibling_ref, b_ref = b->sibling_ref;
  }
  assert(a_ref == 0 || b_ref == 0);
  return a_ref == b_ref;
}

static void re_compcc_tree_merge_one(
    re_buf(re_compcc_tree) cc_tree_in, re_u32 child_ref, re_u32 sibling_ref)
{
  re_compcc_tree *child = cc_tree_in + child_ref,
                 *sibling = cc_tree_in + sibling_ref;
  child->sibling_ref = sibling->sibling_ref;
  assert(re_byte_range_is_adjacent(
      re_u32_to_byte_range(child->range),
      re_u32_to_byte_range(sibling->range)));
  child->range = re_byte_range_to_u32(re_byte_range_make(
      re_u32_to_byte_range(child->range).l,
      re_u32_to_byte_range(sibling->range).h));
}

/*https://nullprogram.com/blog/2018/07/31/*/
static re_u32 re_hashington(re_u32 x)
{
  x ^= x >> 16;
  x *= 0x7feb352dU;
  x ^= x >> 15;
  x *= 0x846ca68bU;
  x ^= x >> 16;
  return x;
}

/* hash table */
static int re_compcc_hash_init(
    re *r, const re_buf(re_compcc_tree) cc_tree_in, re_buf(re_u32) * cc_ht_out)
{
  int err = 0;
  if ((err = re_buf_reserve(
           r, cc_ht_out,
           (re_buf_size(cc_tree_in) + (re_buf_size(cc_tree_in) >> 1)))))
    return err;
  memset(*cc_ht_out, 0, re_buf_size(*cc_ht_out) * sizeof(**cc_ht_out));
  return 0;
}

static void
re_compcc_tree_hash(re *r, re_buf(re_compcc_tree) cc_tree_in, re_u32 parent_ref)
{
  /* flip links and hash everything */
  re_compcc_tree *parent_node = cc_tree_in + parent_ref;
  re_u32 child_ref, next_child_ref, sibling_ref = 0;
  child_ref = parent_node->child_ref;
  while (child_ref) {
    re_compcc_tree *child_node = cc_tree_in + child_ref, *sibling_node;
    next_child_ref = child_node->sibling_ref;
    child_node->sibling_ref = sibling_ref;
    re_compcc_tree_hash(r, cc_tree_in, child_ref);
    if (sibling_ref) {
      sibling_node = cc_tree_in + sibling_ref;
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
      re_u32 hash_plain[3] = {0x6D99232E, 0xC281FF0B, 0x54978D96};
      memset(hash_plain, 0, sizeof(hash_plain));
      hash_plain[0] ^= child_node->range;
      if (child_node->sibling_ref) {
        re_compcc_tree *child_sibling_node =
            cc_tree_in + child_node->sibling_ref;
        hash_plain[1] = child_sibling_node->aux.hash;
      }
      if (child_node->child_ref) {
        re_compcc_tree *child_child_node = cc_tree_in + child_node->child_ref;
        hash_plain[2] = child_child_node->aux.hash;
      }
      child_node->aux.hash = re_hashington(
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
    re *r, re_buf(re_compcc_tree) cc_tree_in, re_buf(re_u32) cc_ht,
    re_u32 node_ref, re_u32 *my_out_ref)
{
  re_u32 prev_sibling_ref = 0;
  assert(node_ref);
  assert(!*my_out_ref);
  while (node_ref) {
    re_compcc_tree *node = cc_tree_in + node_ref;
    re_u32 probe, found, child_ref = 0;
    probe = node->aux.hash;
    node->aux.pc = 0;
    /* check if child is in the hash table */
    while (1) {
      if (!((found = cc_ht[probe % re_buf_size(cc_ht)]) & 1))
        /* child is NOT in the cache */
        break;
      else {
        /* something is in the cache, but it might not be a child */
        if (re_compcc_tree_eq(r, cc_tree_in, node_ref, found >> 1)) {
          if (prev_sibling_ref)
            cc_tree_in[prev_sibling_ref].sibling_ref = found >> 1;
          if (!*my_out_ref)
            *my_out_ref = found >> 1;
          return;
        }
      }
      probe += 1; /* linear probe */
    }
    cc_ht[probe % re_buf_size(cc_ht)] = node_ref << 1 | 1;
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
    re *r, re_buf(re_compcc_tree) cc_tree_in, re_u32 node_ref,
    re_u32 *my_out_pc, re_compframe *frame)
{
  int err = 0;
  re_u32 split_from = 0, my_pc = 0, range_pc = 0;
  while (node_ref) {
    re_compcc_tree *node = cc_tree_in + node_ref;
    if (node->aux.pc) {
      if (split_from) {
        re_inst i = re_prog_get(r, split_from);
        /* found our child, patch into it */
        i = re_inst_make(re_inst_opcode(i), re_inst_next(i), node->aux.pc);
        re_prog_set(r, split_from, i);
      } else
        assert(!*my_out_pc), *my_out_pc = node->aux.pc;
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
      re_u32 their_pc = 0;
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
    node->aux.pc = my_pc;
    node_ref = node->sibling_ref;
  }
  assert(*my_out_pc);
  return 0;
}

static void re_compcc_tree_xpose(
    const re_buf(re_compcc_tree) cc_tree_in, re_buf(re_compcc_tree) cc_tree_out,
    re_u32 node_ref, re_u32 root_ref)
{
  const re_compcc_tree *src_node;
  re_compcc_tree *dst_node, *parent_node;
  assert(node_ref != RE_REF_NONE);
  assert(re_buf_size(cc_tree_out) == re_buf_size(cc_tree_in));
  while (node_ref) {
    re_u32 parent_ref = root_ref;
    src_node = cc_tree_in + node_ref;
    dst_node = cc_tree_out + node_ref;
    dst_node->sibling_ref = dst_node->child_ref = RE_REF_NONE;
    if (src_node->child_ref != RE_REF_NONE)
      re_compcc_tree_xpose(
          cc_tree_in, cc_tree_out, (parent_ref = src_node->child_ref),
          root_ref);
    parent_node = cc_tree_out + parent_ref;
    dst_node->sibling_ref = parent_node->child_ref;
    parent_node->child_ref = node_ref;
    node_ref = src_node->sibling_ref;
  }
}

static int re_compcc_fold_range(
    re *r, re_u32 begin, re_u32 end, re_buf(re_rune_range) * cc_out);

static int re_compcc(re *r, re_u32 root, re_compframe *frame, int reversed)
{
  int err = 0,
      inverted = *re_ast_type_ref(r, frame->root_ref) == RE_AST_TYPE_ICC,
      insensitive = !!(frame->flags & RE_GROUP_FLAG_INSENSITIVE);
  re_u32 start_pc = 0;
  re_buf_clear(&r->compcc_ranges), re_buf_clear(&r->compcc_ranges_2),
      re_buf_clear(&r->compcc_tree), re_buf_clear(&r->compcc_tree_2),
      re_buf_clear(&r->compcc_hash);
  /* push ranges */
  while (root) {
    re_u32 args[3], min, max;
    re_ast_decompose(r, root, args);
    root = args[0], min = args[1], max = args[2];
    /* handle out-of-order ranges (min > max) */
    if ((err = re_buf_push(
             r, &r->compcc_ranges,
             re_rune_range_make(min > max ? max : min, min > max ? min : max))))
      return err;
  }
  assert(re_buf_size(r->compcc_ranges));
  do {
    /* sort ranges */
    re_compcc_hsort(r->compcc_ranges);
    /* normalize ranges */
    {
      size_t i;
      re_rune_range cur, next;
      for (i = 0; i < re_buf_size(r->compcc_ranges); i++) {
        cur = r->compcc_ranges[i];
        assert(cur.l <= cur.h);
        if (!i)
          next = re_rune_range_make(cur.l, cur.h); /* first range */
        else if (cur.l <= next.h + 1) {
          next.h = cur.h > next.h ? cur.h : next.h; /* intersection */
        } else {
          /* disjoint */
          if ((err = re_buf_push(r, &r->compcc_ranges_2, next)))
            return err;
          next.l = cur.l, next.h = cur.h;
        }
      }
      assert(i); /* the charclass is never empty here */
      if ((err = re_buf_push(r, &r->compcc_ranges_2, next)))
        return err;
      if (insensitive) {
        /* casefold normalized ranges */
        re_buf_clear(&r->compcc_ranges);
        for (i = 0; i < re_buf_size(r->compcc_ranges_2); i++) {
          cur = r->compcc_ranges_2[i];
          if ((err = re_buf_push(r, &r->compcc_ranges, cur)))
            return err;
          if ((err = re_compcc_fold_range(r, cur.l, cur.h, &r->compcc_ranges)))
            return err;
        }
        re_buf_clear(&r->compcc_ranges_2);
      }
    }
  } while (insensitive && insensitive-- /* re-normalize by looping again */);
  /* invert ranges */
  if (inverted) {
    re_u32 max = 0, i, write = 0, old_size = re_buf_size(r->compcc_ranges_2);
    re_rune_range cur = re_rune_range_make(0, 0);
    for (i = 0; i < old_size; i++) {
      cur = r->compcc_ranges_2[i];
      assert(write <= i);
      if (cur.l > max) {
        r->compcc_ranges_2[write++] = re_rune_range_make(max, cur.l - 1);
        max = cur.h + 1;
      }
    }
    if ((err = re_buf_reserve(
             r, &r->compcc_ranges_2, write += (cur.h < RE_UTF_MAX))))
      return err;
    if (cur.h < RE_UTF_MAX)
      r->compcc_ranges_2[write - 1] = re_rune_range_make(cur.h + 1, RE_UTF_MAX);
  }
  if (!re_buf_size(r->compcc_ranges_2)) {
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
  if ((err = re_compcc_tree_build(r, r->compcc_ranges_2, &r->compcc_tree)))
    return err;
  /* hash tree */
  if ((err = re_compcc_hash_init(r, r->compcc_tree, &r->compcc_hash)))
    return err;
  re_compcc_tree_hash(r, r->compcc_tree, 1);
  /* reduce tree */
  re_compcc_tree_reduce(r, r->compcc_tree, r->compcc_hash, 2, &start_pc);
  if (reversed) {
    re_u32 i;
    re_buf(re_compcc_tree) tmp;
    re_buf_clear(&r->compcc_tree_2);
    for (i = 1 /* skip sentinel */; i < re_buf_size(r->compcc_tree); i++) {
      if ((err = re_compcc_tree_new(
               r, &r->compcc_tree_2, r->compcc_tree[i], NULL)) == RE_ERR_MEM)
        return err;
      assert(!err);
    }
    /* detach new root */
    r->compcc_tree_2[1].child_ref = RE_REF_NONE;
    re_compcc_tree_xpose(r->compcc_tree, r->compcc_tree_2, 2, 1);
    /* potench reverse the tree if needed */

    tmp = r->compcc_tree;
    r->compcc_tree = r->compcc_tree_2;
    r->compcc_tree_2 = tmp;
  }
  if ((err = re_compcc_tree_render(
           r, r->compcc_tree, start_pc, &start_pc, frame)))
    return err;
  return err;
}

static int re_compile_internal(re *r, re_u32 root, re_u32 reverse)
{
  int err = 0;
  re_compframe initial_frame = {0}, returned_frame = {0}, child_frame = {0};
  re_u32 set_idx = 0, grp_idx = 1, tmp_cc_ast = RE_REF_NONE;
  if (!re_prog_size(r) &&
      ((err = re_buf_push(r, &r->prog, re_inst_make(RE_OPCODE_RANGE, 0, 0))) ||
       (err = re_buf_push(r, &r->prog_set_idxs, 0))))
    return err;
  assert(re_prog_size(r) > 0);
  initial_frame.root_ref = root;
  initial_frame.child_ref = initial_frame.patch_head =
      initial_frame.patch_tail = RE_REF_NONE;
  initial_frame.idx = 0;
  initial_frame.pc = re_prog_size(r);
  r->entry[reverse ? RE_PROG_ENTRY_REVERSE : 0] = initial_frame.pc;
  if ((err = re_buf_push(r, &r->comp_stk, initial_frame)))
    return err;
  while (re_buf_size(r->comp_stk)) {
    re_compframe frame = *re_buf_peek(&r->comp_stk, 0);
    re_ast_type type;
    re_u32 args[4], my_pc = re_prog_size(r);
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
      assert(/* frame.idx >= 0 && */ frame.idx <= 2);
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
      assert(/* frame.idx >= 0 && */ frame.idx <= 2);
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
      re_u32 child = args[0], min = args[1], max = args[2],
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
      re_u32 child = args[0], flags = args[1];
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
      re_u32 assert_flag = args[0];
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
      *re_buf_peek(&r->comp_stk, 0) = frame;
      child_frame.root_ref = frame.child_ref;
      child_frame.idx = 0;
      child_frame.pc = re_prog_size(r);
      child_frame.flags = frame.flags;
      child_frame.set_idx = frame.set_idx;
      if ((err = re_buf_push(r, &r->comp_stk, child_frame)))
        return err;
    } else {
      (void)re_buf_pop(&r->comp_stk);
    }
    returned_frame = frame;
  }
  assert(!re_buf_size(r->comp_stk));
  assert(!returned_frame.patch_head && !returned_frame.patch_tail);
  {
    re_u32 dstar =
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
  re_u32 pc, slot;
} re_nfa_thrd;

typedef struct re_sset {
  re_u32 size, dense_size;
  re_buf(re_u32) sparse;
  re_buf(re_nfa_thrd) dense;
} re_sset;

static int re_sset_reset(const re *r, re_sset *s, size_t next_size)
{
  int err;
  assert(next_size); /* programs are never of size 0 */
  if ((err = re_buf_reserve(r, &s->sparse, next_size)))
    return err;
  if ((err = re_buf_reserve(r, &s->dense, next_size)))
    return err;
  s->size = next_size, s->dense_size = 0;
  return 0;
}

static void re_sset_clear(re_sset *s) { s->dense_size = 0; }

static void re_sset_init(re_sset *s)
{
  re_buf_init(&s->sparse), re_buf_init(&s->dense);
  s->size = s->dense_size = 0;
}

static void re_sset_destroy(const re *r, re_sset *s)
{
  re_buf_destroy(r, &s->sparse), re_buf_destroy(r, &s->dense);
}

static int re_sset_is_memb(re_sset *s, re_u32 pc)
{
  assert(pc < s->size);
  return s->sparse[pc] < s->dense_size && s->dense[s->sparse[pc]].pc == pc;
}

static void re_sset_add(re_sset *s, re_nfa_thrd spec)
{
  assert(spec.pc < s->size);
  assert(s->dense_size < s->size);
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

static int re_save_slots_new(const re *r, re_save_slots *s, re_u32 *next)
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
        return RE_ERR_MEM;
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

static re_u32 re_save_slots_fork(re_save_slots *s, re_u32 ref)
{
  if (s->per_thrd)
    s->slots[ref * s->per_thrd + s->per_thrd - 1]++;
  return ref;
}

static void re_save_slots_kill(re_save_slots *s, re_u32 ref)
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
    const re *r, re_save_slots *s, re_u32 ref, re_u32 idx, size_t v,
    re_u32 *out)
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

static re_u32 re_save_slots_per_thrd(re_save_slots *s)
{
  return s->per_thrd ? s->per_thrd - 1 : s->per_thrd;
}

static int re_save_slots_set(
    const re *r, re_save_slots *s, re_u32 ref, re_u32 idx, size_t v,
    re_u32 *out)
{
  assert(idx < re_save_slots_per_thrd(s));
  return re_save_slots_set_internal(r, s, ref, idx, v, out);
}

static re_u32 re_save_slots_get(re_save_slots *s, re_u32 ref, re_u32 idx)
{
  assert(idx < re_save_slots_per_thrd(s));
  return s->slots[ref * s->per_thrd + idx];
}

typedef struct re_nfa {
  re_sset a, b, c;
  re_buf(re_nfa_thrd) thrd_stk;
  re_save_slots slots;
  re_buf(re_u32) pri_stk;
  re_buf(re_u32) pri_bmp_tmp;
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
  re_u32 flags, nstate, nset, alloc;
} re_dfa_state;

typedef struct re_dfa {
  re_dfa_state **states;
  size_t states_size, num_active_states;
  re_dfa_state
      *entry[RE_PROG_ENTRY_MAX][RE_DFA_STATE_FLAG_MAX]; /* program entry type
                                                         * dfa_state_flag */
  re_buf(re_u32) set_buf;
  re_buf(size_t) loc_buf;
  re_buf(re_u32) set_bmp;
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
  re_buf_init(&n->pri_stk);
  re_buf_init(&n->pri_bmp_tmp);
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

#define RE_BITS_PER_U32 (sizeof(re_u32) * CHAR_BIT)

static int re_bmp_init(const re *r, re_buf(re_u32) * b, re_u32 size)
{
  re_u32 i;
  int err = 0;
  re_buf_clear(b);
  for (i = 0; i < (size + RE_BITS_PER_U32) / RE_BITS_PER_U32; i++)
    if ((err =
             re_buf_push(r, b, 0))) /* TODO: change this to a bulk allocation */
      return err;
  return err;
}

static void re_bmp_clear(re_buf(re_u32) * b) { memset(*b, 0, re_buf_size(*b)); }

static void re_bmp_set(re_buf(re_u32) b, re_u32 idx)
{
  /* TODO: assert idx < nsets */
  b[idx / RE_BITS_PER_U32] |= (1 << (idx % RE_BITS_PER_U32));
}

/* returns 0 or a positive value (not necessarily 1) */
static re_u32 re_bmp_get(re_buf(re_u32) b, re_u32 idx)
{
  return b[idx / RE_BITS_PER_U32] & (1 << (idx % RE_BITS_PER_U32));
}

static int re_nfa_start(
    const re *r, re_nfa *n, re_u32 pc, re_u32 noff, int reversed, int pri)
{
  re_nfa_thrd initial_thrd;
  re_u32 i;
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
    if ((err = re_buf_push(r, &n->pri_stk, 0)))
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
    if ((err = re_buf_push(r, &n->thrd_stk, dense_thrd)))
      return err;
    re_sset_clear(&n->c);
    while (re_buf_size(n->thrd_stk)) {
      re_nfa_thrd thrd = *re_buf_peek(&n->thrd_stk, 0);
      re_inst op = re_prog_get(r, thrd.pc);
      assert(thrd.pc);
      if (re_sset_is_memb(&n->c, thrd.pc)) {
        /* we already processed this thread */
        (void)re_buf_pop(&n->thrd_stk);
        continue;
      }
      re_sset_add(&n->c, thrd);
      switch (re_inst_opcode(re_prog_get(r, thrd.pc))) {
      case RE_OPCODE_MATCH: {
        re_u32 idx = re_inst_match_param_idx(re_inst_param(op)) * 2 +
                     re_inst_match_param_end(re_inst_param(op));
        if (idx < re_save_slots_per_thrd(&n->slots) &&
            (err = re_save_slots_set(
                 r, &n->slots, thrd.slot, idx, pos, &thrd.slot)))
          return err;
        if (re_inst_next(op)) {
          if (re_inst_match_param_idx(re_inst_param(op)) > 0 ||
              !n->pri_stk[r->prog_set_idxs[thrd.pc - 1]]) {
            thrd.pc = re_inst_next(op);
            *re_buf_peek(&n->thrd_stk, 0) = thrd;
          } else
            (void)re_buf_pop(&n->thrd_stk);
          break;
        }
      }
        /* fall through */
      case RE_OPCODE_RANGE:
        (void)re_buf_pop(&n->thrd_stk);
        re_sset_add(&n->b, thrd); /* this is a range or final match */
        break;
      case RE_OPCODE_SPLIT: {
        re_nfa_thrd pri, sec;
        pri.pc = re_inst_next(op), pri.slot = thrd.slot;
        sec.pc = re_inst_param(op),
        sec.slot = re_save_slots_fork(&n->slots, thrd.slot);
        *re_buf_peek(&n->thrd_stk, 0) = sec;
        if ((err = re_buf_push(r, &n->thrd_stk, pri)))
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
          *re_buf_peek(&n->thrd_stk, 0) = thrd;
        } else {
          re_save_slots_kill(&n->slots, thrd.slot);
          (void)re_buf_pop(&n->thrd_stk);
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
  re_u32 idx = r->prog_set_idxs[thrd.pc];
  re_u32 *memo = n->pri_stk + idx - 1;
  assert(idx > 0);
  assert(idx - 1 < re_buf_size(n->pri_stk));
  if (!n->pri && ch < 256)
    goto out_kill;
  if (n->slots.per_thrd) {
    re_u32 slot_idx = !n->reversed;
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
    re_u32 pri = re_bmp_get(n->pri_bmp_tmp, r->prog_set_idxs[thrd.pc]),
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
        re_bmp_set(n->pri_bmp_tmp, r->prog_set_idxs[thrd.pc]);
      re_save_slots_kill(&n->slots, thrd.slot);
    }
  }
  return 0;
}

#define RE_SENTINEL_CH 256

static re_u32 re_is_word_char(re_u32 ch)
{
  return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') ||
         (ch >= 'a' && ch <= 'z') || ch == '_';
}

static re_assert_flag re_make_assert_flag_raw(
    re_u32 prev_text_begin, re_u32 prev_line_begin, re_u32 prev_word,
    re_u32 next_ch)
{
  return !!prev_text_begin * RE_ASSERT_TEXT_BEGIN |
         (next_ch == RE_SENTINEL_CH) * RE_ASSERT_TEXT_END |
         !!prev_line_begin * RE_ASSERT_LINE_BEGIN |
         (next_ch == RE_SENTINEL_CH || next_ch == '\n') * RE_ASSERT_LINE_END |
         ((!!prev_word == re_is_word_char(next_ch)) ? RE_ASSERT_NOT_WORD
                                                    : RE_ASSERT_WORD);
}

static re_assert_flag re_make_assert_flag(re_u32 prev_ch, re_u32 next_ch)
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
    const re *r, size_t pos, re_nfa *n, re_u32 max_span, re_u32 max_set,
    span *out_span, re_u32 *out_set, re_u32 prev_ch)
{
  int err;
  size_t j, sets = 0, nset = 0;
  if ((err = re_nfa_eps(
           r, n, pos, re_make_assert_flag(prev_ch, RE_SENTINEL_CH))) ||
      (err = re_nfa_chr(r, n, 256, pos)))
    return err;
  for (sets = 0; sets < r->ast_sets && (max_set ? nset < max_set : nset < 1);
       sets++) {
    re_u32 slot = n->pri_stk[sets];
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

static int
re_nfa_run(const re *r, re_nfa *n, re_u32 ch, size_t pos, re_u32 prev_ch)
{
  int err;
  if ((err = re_nfa_eps(r, n, pos, re_make_assert_flag(prev_ch, ch))))
    return err;
  if ((err = re_nfa_chr(r, n, ch, pos)))
    return err;
  return err;
}

static void re_dfa_init(re_dfa *d)
{
  d->states = NULL;
  d->states_size = d->num_active_states = 0;
  memset(d->entry, 0, sizeof(d->entry));
  re_buf_init(&d->set_buf), re_buf_init(&d->loc_buf), re_buf_init(&d->set_bmp);
}

static void re_dfa_reset(re_dfa *d)
{
  size_t i;
  for (i = 0; i < d->states_size; i++)
    if (d->states[i])
      d->states[i]->flags |= RE_DFA_STATE_FLAG_DIRTY;
  d->num_active_states = 0;
  re_buf_clear(&d->set_buf), re_buf_clear(&d->loc_buf),
      re_buf_clear(&d->set_bmp);
  memset(d->entry, 0, sizeof(d->entry));
}

static void re_dfa_destroy(const re *r, re_dfa *d)
{
  size_t i;
  for (i = 0; i < d->states_size; i++)
    if (d->states[i])
      re_ialloc(r, d->states[i]->alloc, 0, d->states[i]);
  re_ialloc(r, d->states_size * sizeof(re_dfa_state *), 0, d->states);
  re_buf_destroy(r, &d->set_buf), re_buf_destroy(r, &d->loc_buf),
      re_buf_destroy(r, &d->set_bmp);
}

static re_u32 re_dfa_state_alloc(re_u32 nstate, re_u32 nset)
{
  re_u32 minsz = sizeof(re_dfa_state) + (nstate + nset) * sizeof(re_u32);
  re_u32 alloc = sizeof(re_dfa_state) & 0x800;
  while (alloc < minsz)
    alloc *= 2;
  return alloc;
}

static re_u32 *re_dfa_state_data(re_dfa_state *state)
{
  return (re_u32 *)(state + 1);
}

/* need: current state, but ALSO the previous state's matches */
static int re_dfa_construct(
    const re *r, re_dfa *d, re_dfa_state *prev_state, unsigned int ch,
    re_u32 prev_flag, re_nfa *n, re_dfa_state **out_next_state)
{
  size_t i;
  int err = 0;
  re_u32 hash, table_pos, num_checked, *state_data, next_alloc;
  re_dfa_state *next_state;
  assert(!(prev_flag & RE_DFA_STATE_FLAG_DIRTY));
  /* check threads in n, and look them up in the dfa cache */
  hash = re_hashington(prev_flag);
  hash = re_hashington(hash + n->a.dense_size);
  hash = re_hashington(hash + re_buf_size(d->set_buf));
  for (i = 0; i < n->a.dense_size; i++)
    hash = re_hashington(hash + n->a.dense[i].pc);
  for (i = 0; i < re_buf_size(d->set_buf); i++)
    hash = re_hashington(hash + d->set_buf[i]);
  if (!d->states_size) {
    /* need to allocate initial cache */
    re_dfa_state **next_cache =
        re_ialloc(r, 0, sizeof(re_dfa_state *) * RE_DFA_MAX_NUM_STATES, NULL);
    if (!next_cache)
      return RE_ERR_MEM;
    memset(next_cache, 0, sizeof(re_dfa_state *) * RE_DFA_MAX_NUM_STATES);
    assert(!d->states);
    d->states = next_cache, d->states_size = RE_DFA_MAX_NUM_STATES;
  }
  table_pos = hash % d->states_size, num_checked = 0;
  while (1) {
    /* linear probe for next state */
    if (!d->states[table_pos] ||
        d->states[table_pos]->flags & RE_DFA_STATE_FLAG_DIRTY) {
      next_state = NULL;
      break;
    }
    next_state = d->states[table_pos];
    assert(!(next_state->flags & RE_DFA_STATE_FLAG_DIRTY));
    state_data = re_dfa_state_data(next_state);
    if (next_state->flags != prev_flag)
      goto not_found;
    if (next_state->nstate != n->a.dense_size)
      goto not_found;
    if (next_state->nset != re_buf_size(d->set_buf))
      goto not_found;
    for (i = 0; i < n->a.dense_size; i++)
      if (state_data[i] != n->a.dense[i].pc)
        goto not_found;
    for (i = 0; i < re_buf_size(d->set_buf); i++)
      if (state_data[n->a.dense_size + i] != d->set_buf[i])
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
        if (d->states[i])
          d->states[i]->flags |= RE_DFA_STATE_FLAG_DIRTY;
      d->num_active_states = 0;
      table_pos = hash % d->states_size;
      memset(d->entry, 0, sizeof(d->entry));
      prev_state = NULL;
    }
    /* can we reuse the previous state? */
    assert(RE_IMPLIES(
        d->states[table_pos],
        d->states[table_pos]->flags & RE_DFA_STATE_FLAG_DIRTY));
    {
      re_u32 prev_alloc =
          d->states[table_pos] ? d->states[table_pos]->alloc : 0;
      next_alloc = re_dfa_state_alloc(n->a.dense_size, re_buf_size(d->set_buf));
      if (prev_alloc < next_alloc) {
        next_state = re_ialloc(r, prev_alloc, next_alloc, d->states[table_pos]);
        if (!next_state)
          return RE_ERR_MEM;
        d->states[table_pos] = next_state;
      } else {
        next_state = d->states[table_pos];
        next_alloc = prev_alloc;
      }
    }
    memset(next_state, 0, next_alloc);
    next_state->alloc = next_alloc;
    next_state->flags = prev_flag;
    next_state->nstate = n->a.dense_size;
    next_state->nset = re_buf_size(d->set_buf);
    state_data = re_dfa_state_data(next_state);
    for (i = 0; i < n->a.dense_size; i++)
      state_data[i] = n->a.dense[i].pc;
    for (i = 0; i < re_buf_size(d->set_buf); i++)
      state_data[n->a.dense_size + i] = d->set_buf[i];
    assert(d->states[table_pos] == next_state);
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
    const re *r, re_dfa *d, re_nfa *n, re_u32 entry, re_u32 prev_flag,
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
    int pri = re_bmp_get(n->pri_bmp_tmp, r->prog_set_idxs[thrd.pc]);
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
      if ((err = re_buf_push(r, &d->set_buf, r->prog_set_idxs[thrd.pc] - 1)))
        return err;
      if (n->pri)
        re_bmp_set(n->pri_bmp_tmp, r->prog_set_idxs[thrd.pc]);
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
  re_u32 i;
  for (i = 0; i < state->nset; i++) {
    dfa->loc_buf[re_dfa_state_data(state)[state->nstate + i]] = pos;
    re_bmp_set(dfa->set_bmp, i);
  }
}

static int re_dfa_match(
    re_exec *exec, re_nfa *nfa, re_u8 *s, size_t n, re_u32 max_span,
    re_u32 max_set, span *out_span, re_u32 *out_set, anchor_type anchor)
{
  int err;
  re_dfa_state *state = NULL;
  size_t i;
  re_u32 entry = anchor == RE_ANCHOR_END   ? RE_PROG_ENTRY_REVERSE
                 : anchor == RE_UNANCHORED ? RE_PROG_ENTRY_DOTSTAR
                                           : 0;
  re_u32 incoming_assert_flag = RE_DFA_STATE_FLAG_FROM_TEXT_BEGIN |
                                RE_DFA_STATE_FLAG_FROM_LINE_BEGIN,
         reversed = !!(entry & RE_PROG_ENTRY_REVERSE);
  int pri = anchor != RE_ANCHOR_BOTH;
  assert(max_span == 0 || max_span == 1);
  assert(
      anchor == RE_ANCHOR_BOTH || anchor == RE_ANCHOR_START ||
      anchor == RE_ANCHOR_END);
  re_dfa_reset(&exec->dfa);
  if ((err = re_nfa_start(
           exec->r, &exec->nfa, exec->r->entry[entry], 0, reversed, pri)))
    return err;
  if (pri) {
    re_buf_clear(&exec->dfa.loc_buf);
    if ((err = re_bmp_init(exec->r, &exec->dfa.set_bmp, exec->r->ast_sets)))
      return err;
    for (i = 0; i < exec->r->ast_sets; i++) {
      size_t p = 0;
      if ((err = re_buf_push(exec->r, &exec->dfa.loc_buf, p)))
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
    const re_u8 *start = reversed ? s + n - 1 : s,
                *end = reversed ? s - 1 : s + n;
    /* The amount to increment each iteration of the loop. */
    int increment = reversed ? -1 : 1;
    while (start != end) {
      re_u8 ch = *start;
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
      if (!re_bmp_get(exec->dfa.set_bmp, i))
        continue;
      if ((unsigned)err == max_set && max_set)
        break;
      if (max_span) {
        size_t spos = exec->dfa.loc_buf[i];
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
  re_exec *exec = re_ialloc(r, 0, sizeof(re_exec), NULL);
  *pexec = exec;
  assert(re_prog_size(r));
  if (!exec)
    return RE_ERR_MEM;
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
  re_ialloc(exec->r, sizeof(re_exec), 0, exec);
}

int re_compile(re *r)
{
  int err;
  assert(!re_prog_size(r));
  if ((err = re_compile_internal(r, r->ast_root, 0)) ||
      (err = re_compile_internal(r, r->ast_root, 1))) {
    return err;
  }
  return err;
}

int re_exec_match(
    re_exec *exec, const char *s, size_t n, re_u32 max_span, re_u32 max_set,
    span *out_span, re_u32 *out_set, anchor_type anchor)
{
  int err = 0;
  re_u32 entry = anchor == RE_ANCHOR_END   ? RE_PROG_ENTRY_REVERSE
                 : anchor == RE_UNANCHORED ? RE_PROG_ENTRY_DOTSTAR
                                           : 0;
  size_t i;
  re_u32 prev_ch = RE_SENTINEL_CH;
  if (!(entry & RE_PROG_ENTRY_DOTSTAR) && (max_span == 0 || max_span == 1)) {
    err = re_dfa_match(
        exec, &exec->nfa, (re_u8 *)s, n, max_span, max_set, out_span, out_set,
        anchor);
    return err;
  }
  if ((err = re_nfa_start(
           exec->r, &exec->nfa, exec->r->entry[entry], max_span * 2,
           entry & RE_PROG_ENTRY_REVERSE, entry != RE_ANCHOR_BOTH)))
    return err;
  if (entry & RE_PROG_ENTRY_REVERSE) {
    for (i = n; i > 0; i--) {
      if ((err = re_nfa_run(
               exec->r, &exec->nfa, ((const re_u8 *)s)[i - 1], i, prev_ch)))
        return err;
      prev_ch = ((const re_u8 *)s)[i - 1];
    }
    if ((err = re_nfa_end(
             exec->r, 0, &exec->nfa, max_span, max_set, out_span, out_set,
             prev_ch)))
      return err;
  } else {
    for (i = 0; i < n; i++) {
      if ((err = re_nfa_run(
               exec->r, &exec->nfa, ((const re_u8 *)s)[i], i, prev_ch)))
        return err;
      prev_ch = ((const re_u8 *)s)[i];
    }
    if ((err = re_nfa_end(
             exec->r, n, &exec->nfa, max_span, max_set, out_span, out_set,
             prev_ch)))
      return err;
  }
  return err;
}

int re_match(
    const re *r, const char *s, size_t n, re_u32 max_span, re_u32 max_set,
    span *out_span, re_u32 *out_set, anchor_type anchor)
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
static const re_s32 re_compcc_fold_array_0[] = {
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
static const re_u16 re_compcc_fold_array_1[] = {
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
static const re_u16 re_compcc_fold_array_2[] = {
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
static const re_u8 re_compcc_fold_array_3[] = {
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
static const re_u16 re_compcc_fold_array_4[] = {
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
static const re_u8 re_compcc_fold_array_5[] = {
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

static re_s32 re_compcc_fold_next(re_u32 rune)
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

static int re_compcc_fold_range(
    re *r, re_u32 begin, re_u32 end, re_buf(re_rune_range) * cc_out)
{
  int err = 0;
  re_s32 a0;
  re_u16 a1, a2, a4;
  re_u32 current, x0, x1, x2, x3, x4, x5;
  re_u8 a3, a5;
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
                         r, cc_out, re_rune_range_make(current, current))))
                  return err;
                current =
                    (re_u32)((re_s32)current + re_compcc_fold_next(current));
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

typedef struct re_utf8_prop {
  re_u16 name_len, num_range, start;
  const char *name;
} re_utf8_prop;

/* re_utf8_prop_data is a bitstream representing compressed rune ranges. Raw
 * ranges are flattened into an array of integers so that even indices are range
 * minimums, and odd indices are range maximums. Then the the array is derived
 * into an array of deltas between adjacent integers. For compression
 * optimality, 1s and 2s are swapped. Then each integer (of which all are
 * positive, since the ranges always increase) becomes:
 *
 *  0         if integer == 0
 *  0         if integer == 1 && previous_integer == 0
 *  1 <var>   if integer  > 1 && previous_integer == 0
 *  1 0       if integer == 1 && previous_integer != 0
 *  1 1 <var> if integer  > 1 && previous_integer != 0
 *
 * where <var> is the variable-length encoding of the integer - 2, split into
 * 3-bit chunks. For example:
 *
 *  1   -> 1 0 0 0
 *  8   -> 0 0 0 1 1 0 0 0
 *  127 -> 1 1 1 1 1 1 1 1 1 1 0 0
 *
 * This was the best compression scheme I could come up with. For property data,
 * each integer uses about 5.1 bits on average (~0.63 bytes). This represents
 * about an 84% reduction in size compared to just storing each range as two
 * 32-bit integers. */

/*T Generated by `unicode_data.py gen_props` */
/* 3321 ranges, 6642 integers, 4236 bytes */
const re_u32 re_utf8_prop_data[1059] = {
    0xFB3ECD7A, 0x00000000, 0x4ADA9B6B, 0x9FEA5ADB, 0x30DFF60B, 0xA2D9F9F3,
    0xD3B2DBFF, 0x37D2C2F2, 0xFE8F2BF7, 0x208E8CD0, 0x349DCA8F, 0x7EC98CD7,
    0x73CEACD3, 0x58AFA8ED, 0x005ECD7A, 0xC8FFFF73, 0xA27A5FE9, 0xFFFC9FFB,
    0xFFFC926F, 0x0000006F, 0xC8FFFB73, 0x5FCC35FD, 0x005FFCC3, 0x3F7ADFB3,
    0x5756B0D9, 0x00000000, 0x10C00000, 0x00043000, 0x00000000, 0x29213412,
    0x4D2926C3, 0x490C4812, 0x7530D20A, 0xC0001249, 0x30C00010, 0x000000A1,
    0x00000000, 0x90D24C70, 0xB4A33006, 0xA2808EC3, 0x272E92B4, 0x00052C34,
    0xD2492C00, 0x015DCAF0, 0xC8000000, 0x00000000, 0x12000000, 0x00010C00,
    0x00000000, 0x00000000, 0x9DF60000, 0x0DCE3773, 0x6DEFB353, 0xF33D22A7,
    0xCCFF4DCE, 0x16737ED2, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x013C0000, 0x00000000, 0x00000000, 0x3C000000, 0xF5D336DF, 0xD336DF5D,
    0x6CDF5DF5, 0xDF5DF5D3, 0x970D2DF5, 0x4D37C352, 0x54CD77C3, 0x0CA4A9C3,
    0x269A2E8B, 0xB9B4DF0D, 0x5DCB6B61, 0x31A04329, 0x00001DB4, 0x00000000,
    0x00000000, 0x0F0C0000, 0x65A76C9A, 0x002A99F8, 0x00000000, 0x00000AA0,
    0x000E2A00, 0x00000014, 0x00000000, 0xA0048570, 0x00005121, 0xA0000618,
    0xA6E80161, 0xC371B9C8, 0xD7333CF1, 0xCC77F9F9, 0xB0D8ACB6, 0x671CEADE,
    0xAD2778AD, 0x4734332E, 0x289EC347, 0xB1CFDC2F, 0xB7FDADD7, 0xB4EBABD7,
    0xF3474EDE, 0x4EDEB4ED, 0xB0CD1C53, 0xAD3B7AD3, 0x3B7AD3B7, 0x7AD3B7AD,
    0xD3B7AD3B, 0xB7AD3B7A, 0xADBB4ED3, 0x3AD3B6D3, 0xD3AD3B6D, 0x6D3AD3B6,
    0x96D3AD3B, 0x2B5F6B9E, 0x3BF9DB5D, 0x000001FB, 0xB7CCF6B3, 0xF2D734CD,
    0xBE1862A0, 0xA6A59E97, 0xB0C7270D, 0xA28323E9, 0xAA39A9FA, 0x323FC9AB,
    0x24EEE86E, 0xE29CC8B7, 0xD76B6DF3, 0x7498731F, 0x720BACCA, 0xFDCB37C8,
    0xA0BEC33E, 0xB61AF8FE, 0x309C872C, 0x9FBD1ECC, 0x6D27AA5A, 0xA4BC9727,
    0x3C3F30DB, 0x723A9F33, 0x6BF0CB43, 0xC832A5A8, 0x730C6A6D, 0xAD8334CE,
    0xB0C76588, 0x79D6DFBF, 0xC62F2F3D, 0x2CCF32B4, 0x88990DFF, 0xC347536C,
    0xDBF0B88E, 0xDBCC70CE, 0x000FB2A1, 0xFA3C836B, 0x7CED369F, 0xB0ECBE72,
    0xD5EC774D, 0x9CD0CA77, 0x4CC37A90, 0xDBB1F24D, 0x2CCEB31E, 0xC6B3EDEA,
    0xF3AD376A, 0xD5AC70CC, 0xBF39C2B6, 0xE4A8B6BC, 0xB1CDF37C, 0xAD30D35D,
    0x2D3291D6, 0xD431C9F2, 0xDE4CC35C, 0x6AD30DB6, 0x0D0D0D1D, 0xD2A94CFB,
    0x5AB54F7C, 0xA2CB4347, 0x3AC33C92, 0x30D35CB2, 0xD0D1D6AD, 0xD435E8B2,
    0x2DB02A3C, 0x0C432D35, 0xCCB4B0CB, 0x576B96B4, 0x2D7346B5, 0xC349353A,
    0xAD55DA5E, 0xE8B2D7D1, 0x33CC3433, 0xE754F0AC, 0x7D19F24C, 0xF31DB7AD,
    0x24F56B2D, 0xD5DD3F1D, 0xCBF6DB30, 0xC56B4B10, 0xB48330D7, 0xE7ED33AC,
    0xBB49D5CF, 0x0DCAF32C, 0x6DB7C9AB, 0x4F0CA2D3, 0xC9B32CDB, 0xD34E370B,
    0x9D34C474, 0xD3ED34D3, 0x4D311D34, 0xD34EF473, 0x319C2334, 0x7330BCD7,
    0xEB4F34D3, 0x75C3331D, 0xB1CDF33D, 0xCDF35CC2, 0xF3CD4B35, 0xCA3279D2,
    0x2CF2BD09, 0x33197ED3, 0xBC7B4CDA, 0xCCB4DBB0, 0xDEB6D372, 0xF0CC6B5B,
    0xC777DACA, 0xBB5BD70A, 0x74CC31CD, 0xDD274ED3, 0xCDBB4CD0, 0xC35B530B,
    0x74D3E2A2, 0xEB5BCEFF, 0xD1C331AD, 0xD1D1D1D1, 0x6331D1D1, 0xACDA1B8E,
    0x6DEB31F6, 0x6ECD0DC6, 0xDF75EC2B, 0x9C9FFF5C, 0x8D9FE5FB, 0x2B5AB5FF,
    0x6728CC6F, 0x36D3277D, 0x8CC34CD7, 0xB68CC2E4, 0xCA39C836, 0xB1AD4D51,
    0xDD734BC7, 0x30B6D7F7, 0x4CD3B2CC, 0xCBB0EC6B, 0xCB1DC773, 0x74B4CCF4,
    0xAD753ACE, 0xA2DB5736, 0x4C3297DC, 0xC37A84CB, 0xD723C332, 0x36D36D36,
    0x2AB1D1C3, 0xDA87B09C, 0x1ADB249B, 0x262B3DDB, 0xCD36DDDA, 0x5F0A3379,
    0xD0C4B4B3, 0xC274DCD0, 0x5FD2B0DD, 0xCDE76BD3, 0xAD2DAF34, 0xD7C37318,
    0xCB1ED32D, 0x36D36D36, 0xAD4CCA75, 0xCD0D0AD7, 0xD276CD31, 0xEC62F0FC,
    0xCF73DCB2, 0xD4AC735E, 0xD3369D75, 0xDB49D36E, 0x6CCDFF35, 0xDF59D273,
    0xB9DBAB4B, 0x336AC331, 0x36DEAB5D, 0x22C35371, 0x1AD331AD, 0x2331EC33,
    0xD330D0AC, 0x37AD336A, 0x0D75BD63, 0x5533C9FF, 0xCBB4DCBB, 0x5729CBB2,
    0xDAF2ED3B, 0xB4CDAB4C, 0xCDF31CC2, 0xBACE335D, 0x76EDD273, 0x5CCC35DE,
    0xADE4CCBB, 0x777CD376, 0x1ACBB2AD, 0xC3F2BDB3, 0xCB71C930, 0x74ECEB7E,
    0x77921ED2, 0x5DDB22C2, 0x606B4D73, 0xB3AD7CCA, 0x11CFF0CA, 0x3DF47353,
    0x4D759C77, 0x475AB4C3, 0x92A2CB43, 0xF5EACB6C, 0x6AD34ACA, 0x6AD775ED,
    0x1DDEEA43, 0xDDA74C37, 0x372F9AB5, 0xECE321CC, 0x3EB1C670, 0x5CABB4DC,
    0xB4357493, 0x5EC83CD6, 0x7CC674D7, 0x59D326E8, 0xDCB21A8F, 0x334A8AB6,
    0x74F389CE, 0xEC2E0ACA, 0x0D1DF736, 0x0E86B69D, 0xCD7B435B, 0x30ACE365,
    0xDFB4B30F, 0xCCF326FC, 0xED67B7AB, 0xCDB33748, 0xD8ACF33E, 0xEFF6C2B5,
    0x2B18CCC3, 0x3B8CC3EE, 0xCC2B1ECF, 0xB6EC2B1C, 0xACAF5DD2, 0x7730AC72,
    0xA870CCDF, 0x96FFB23D, 0x4DDABAB7, 0x73BECA8E, 0x47A3CC26, 0xF7D35C93,
    0x36899D32, 0x2CB31C37, 0xCCADF3CF, 0x2DC6FE7D, 0xBB08D827, 0x9FD374AD,
    0x1BECC3B6, 0x73435347, 0xF9ACA3B4, 0x4343B532, 0x58535F12, 0x1243501A,
    0xD4D24300, 0x5F14D4D1, 0x34B51CF3, 0x268D8CCF, 0x7E97BBAB, 0xA59EE232,
    0xF3B249BB, 0x66F25C9F, 0xB7323C8F, 0xA3349B99, 0x3249FADB, 0x23218337,
    0x0000017B, 0x99249A3F, 0x5C6AEF25, 0xB35DF5DF, 0x000F63C9, 0x6737ADFF,
    0x0271D1AC, 0x00000000, 0x01200000, 0x00001200, 0x30000000, 0x50C43284,
    0xCB50D4D3, 0x490C10D0, 0xE2C3150C, 0x00049248, 0x92000048, 0x00000144,
    0x00000000, 0xC4C34338, 0xA0266014, 0xD0C51678, 0x48A73D3C, 0x8000002D,
    0x2F4C3121, 0x000007DC, 0x00032000, 0x00000000, 0x80043000, 0x00000004,
    0x00000000, 0x00000000, 0xCDDDA748, 0xEC865A70, 0xA9DAB34A, 0x9D4C374E,
    0x0000007F, 0x00000000, 0x00000000, 0x00000000, 0x20000000, 0x00000003,
    0x00000000, 0x00000000, 0xB7D70C80, 0xD77D74CD, 0x7802CDB7, 0xCD378CD7,
    0xCD36CD36, 0x9D32CCB6, 0xD4D29A58, 0x30172CA4, 0xC34CD34D, 0x6FCD87E1,
    0x1347DD77, 0x05792530, 0x00000000, 0x00000000, 0xE0000000, 0x1CD9F9A1,
    0x00000000, 0x000AA000, 0x0E2A0000, 0x00002800, 0x00000000, 0x0C132000,
    0x0A121A01, 0x2D2C0000, 0x96530001, 0x67B66E81, 0x63AB7ACB, 0x9DE2B59C,
    0xD0CDBAB4, 0xBB0D1D1C, 0x7F70BD37, 0xF6B75EC7, 0xAEAF5EDF, 0xAD3B7ADF,
    0x3B7AD3B7, 0x30D24C31, 0xAD3B5D4D, 0x34D0D3B7, 0x0CBB1D5D, 0xC7292D4D,
    0xB4EDEB2E, 0xEDEB4EDE, 0xEB4EDEB4, 0x5EDEB4ED, 0xCEB09CEB, 0xB09CEB09,
    0x9CEB09CE, 0xEC6E6320, 0x00000007, 0x23B92267, 0x2F0D4DF5, 0x0D753F0D,
    0x2D9330D3, 0xF923353E, 0xC6F0C7D4, 0x30D613F0, 0x59C9330D, 0xCD52C343,
    0x4C7F4364, 0xB13F0C7F, 0x0CC3434C, 0x0D726EC3, 0x3354753F, 0x2CCC34D9,
    0xC34AD75D, 0xA3FC34CD, 0x259B0CB6, 0x330C3B0D, 0x0C6B1D35, 0xD4C936D3,
    0xA97A7BCE, 0x70D5CE08, 0xDB534D3B, 0x0DFBB6D0, 0xC303213F, 0xF60AADB7,
    0x7F0D2C19, 0x930DA5E8, 0xC329526F, 0xAC37D77D, 0x9CC86A2D, 0xBFEFC35B,
    0xDEB24C32, 0x2B5CD2F0, 0x7D8F70D7, 0xCD4C36C3, 0xAC34C35D, 0x87720767,
    0xC77A1C34, 0xAB90D0D0, 0x63FC82A8, 0xAF30DB47, 0x62FC37A8, 0x730C335F,
    0x432D1EC8, 0x0CFB536A, 0xD34D0D3F, 0x4C833530, 0x37D0AEC3, 0x1753722C,
    0x7477A4D3, 0xD0BC934D, 0x30772437, 0xB0C3725C, 0xA0CD1899, 0x9B0D6CEF,
    0x37D5CA84, 0x1E9AB26D, 0x8EAE5FC3, 0x2393725C, 0x36CB1AE9, 0xB30D7B64,
    0x437C37D9, 0x1BCF2236, 0x62F0DE73, 0x06D70CAF, 0xB30CE2AB, 0x5E8E9AE3,
    0xCBA8CD53, 0x00000012, 0x5DCCFFB3, 0x3272CAA7, 0x434312DC, 0xF70CDE32,
    0x9C9F32AD, 0x34DB4C71, 0xD7A29D34, 0x0CCBB30E, 0xA8333D3F, 0xCB54F537,
    0xDD76FD2D, 0xBD7B56B4, 0xCA6D7683, 0x87B0D331, 0xA9F4DA4F, 0x0D24EC36,
    0x36C3683F, 0x0D7A2D4C, 0x0FC32C8B, 0xA9B0D2DA, 0xE5B5AC36, 0x39F4C493,
    0x5EC32CC3, 0x92E6C87E, 0x351D0EE2, 0xC32CC33D, 0x96493E1E, 0xEC36AC31,
    0x6C30FC36, 0xB0DAA7D3, 0x94E78C87, 0xB31D24EC, 0xF492735D, 0x0CCC72CC,
    0xCEE02EC3, 0xC70D2D6C, 0x83349D0C, 0x35B5359C, 0xC30EC34C, 0x1CD37CD6,
    0x23C970D2, 0x2EF34FEB, 0xD7B0C7B5, 0xDFF0D7B0, 0x3349F1D0, 0xC94760CC,
    0xF249C31B, 0x8330DB56, 0x4C32EED5, 0x7484713E, 0xDF64DF5D, 0xC2F5CD6C,
    0x864B1F74, 0xC36CCF79, 0xD434D37E, 0xFD0B0C7B, 0xAAC34D74, 0x6C74B357,
    0x58EC3296, 0x37CECD7F, 0x74CCA6CB, 0x872B57FF, 0x8CD7B7EC, 0x32DCD34D,
    0xDA6AFAFC, 0xF330DFB7, 0xA29F270D, 0xAA1C30E9, 0x7CD3B0CE, 0xED759873,
    0xDD5DC330, 0x70D34D27, 0x4DB28C8E, 0xE6CC34C3, 0x4D0AE3D9, 0xD36431C3,
    0x925DE9F0, 0xC9F67E66, 0x7CD7309E, 0xA1CFCD73, 0xCB1AA927, 0x1C3558AE,
    0x6A6D79D3, 0xC7E330C6, 0x330CA2F4, 0x0CD6335F, 0x8BF34C2F, 0x20DC735B,
    0xC2F5330D, 0x1F8F0D34, 0xFD74B69D, 0xDAF0DB25, 0xC934D333, 0x970C4D3E,
    0xD7287AA4, 0xC30FC31A, 0x2CB1C662, 0x9535CA3B, 0x96DAB23A, 0x5DEC3436,
    0xEC3435D3, 0xD71ACC32, 0x213730C4, 0x4D19C96D, 0xF289CB53, 0x437FEC34,
    0x4D37CA9A, 0x77DFA6C3, 0x9F4D36DE, 0x5DD4DB0C, 0x5ABC34B3, 0xD2B25B47,
    0xD0D1D36A, 0x0B6D3F30, 0xDE324743, 0x0CBB60B0, 0x2DAF0CB3, 0x87FAB207,
    0xEAEEC735, 0xAC72FCB4, 0x34CFE7A8, 0x7BAB982B, 0x709CCCC3, 0x8CC6B4DB,
    0x4D70AD7E, 0xAAD35EC7, 0x6F2FBED6, 0x727DF76C, 0xC734B5A9, 0xF3477CDA,
    0xCB43474C, 0x1DFAA69C, 0xD31F8EF7, 0xEFCD36FF, 0xC71DCC77, 0xB1BBEC8E,
    0x00000177, 0x663B7CF7, 0xB7D62B7D, 0xDBAF7D63, 0xF37D6F37, 0x7D6F37D6,
    0x6F37D6F3, 0x37D6F37D, 0xD6F37D6F, 0xB37D6F37, 0x7D6F37DF, 0x6A77D633,
    0xB7D6337D, 0xD677D637, 0xF37DB677, 0x7D66B7DF, 0x7D6EB7D7, 0x62B7D6B3,
    0x6337D77D, 0x6B37D63E, 0xB7D677D6, 0x7D6B7D63, 0x6AF7D6B3, 0xD6A7377D,
    0x77D62EB7, 0x6737D62A, 0x7DFF37DB, 0xDF2B7DBF, 0xB77D6A77, 0x7D6F37D6,
    0x6737D6F7, 0xF7D6737D, 0xD6737D66, 0xB7D6FB37, 0xD6337D6F, 0x677D66F7,
    0x6B37D627, 0xF7D62B7D, 0x77DDAF2E, 0x66F7DFE6, 0xB7D6FF7D, 0xB337D6B2,
    0x00007D6A, 0x37477BB3, 0x4D309CF7, 0xF0E97F3F, 0xDAEFD5CC, 0x7CCDDDF2,
    0x9E6CFCAF, 0x88ACB58A, 0x0007734D, 0x4870C2EB, 0xDDB1B99D, 0xD7BCDB7B,
    0x0EEC718A, 0xBBCF0AC7, 0xB1B8ADF0, 0xDF2BCAD2, 0x86ABA7EF, 0x8EDF5DB2,
    0xB20DD735, 0x7334FD6B, 0xD6F336AD, 0xA8376B6E, 0x4CAD36AA, 0x73575EDF,
    0x339DF7EC, 0xB7DDAFC7, 0xB70AE9DD, 0x0AD308CC, 0xC3B1ADC3, 0x6B9AD369,
    0x39C70ED7, 0xACB2CCCF, 0xC37EADB5, 0xDB74D734, 0xC36BCF7F, 0xCB2CCD5E,
    0x77AD779C, 0x4CDC70DD, 0xC7B7EDDB, 0x34DDF5EA, 0x8AC77DCD, 0xB2FDD2B5,
    0xC318DAD2, 0x9DCCF5DB, 0x2ADCC2B3, 0x58BD9CAB, 0x6B5E9CC7, 0x2B0D8ABC,
    0xDCD2B6CD, 0xCDACCEB6, 0xF09BCCF5, 0x6CCD3543, 0xFCC734B7, 0x0000B348,
    0xEFFC97B3, 0xF722AC33, 0x5EB0D7BE, 0x00000F7B, 0xE6EDA9B7, 0x2A08CF8A,
    0xB0C89862, 0xE92088FD, 0xB9BA6C33, 0x3DC8AA5F, 0x0DF2EE72, 0x36A4C867,
    0x0003EBF8, 0x8FA2B9E7, 0xEDE81FAF, 0x3B836E65, 0x84FCC8F2, 0x017E2A5E,
    0x1FA7CC80, 0x0006AB80, 0x8261FE00, 0x6D80198A, 0xA006DB80, 0xE730D200,
    0xA0EE97A6, 0xA8A00007, 0x2B936A00, 0x001248FA, 0xEDFC93EB, 0x3EE6E8A1,
    0x8F249A1E, 0x00000002, 0xDDFC936B, 0x0E930D26, 0x49A1E3EE, 0x000028F2,
    0x0C1355FB, 0xB0CB0D33, 0xC8668C8B, 0x7EB23C35, 0x76D2BE79, 0x64925B83,
    0xD0DAB0DB, 0x4CCD0730, 0xCB659CD3, 0x6F437B6C, 0x898FB1CD, 0xB2A4CC31,
    0x83F27BC9, 0xDD9B258B, 0x34C93B23, 0x247379AC, 0xCB4CC9F7, 0xDB3DCC36,
    0xDA7322DA, 0xFC862733, 0xAC338CD6, 0x5B19D51E, 0xEC30F9D3, 0x77FCC37A,
    0xC76DADB4, 0x31FCC36E, 0x35FCB2FD, 0x22CD77FC, 0x5DF0D237, 0x534D33DF,
    0xBDF10CCB, 0xCC3534EA, 0xB0CF2A7D, 0x434F4935, 0xD2D330D2, 0xCB314D37,
    0x0FD6DBD4, 0x88AF87EA, 0xCD1C9C34, 0x2BC93229, 0xCD36FDDB, 0xE579C35A,
    0x9C8F70C2, 0xC37CCB30, 0x5FCD36FC, 0xFEC37CC3, 0x1DA63360, 0x0DAA5A93,
    0xF4D4B4D3, 0x1AAC3174, 0x4CC304D5, 0x62EC32C3, 0x4EBC349A, 0x9F66EACD,
    0x8E7B25EB, 0xC98FA38E, 0xF7259CF7, 0x31D2331D, 0xEEF34C3B, 0xEB4DB72D,
    0x0C7731C7, 0x74D7F34D, 0x4CF330DF, 0xEB341C9B, 0x9B8B736D, 0x2434CCB0,
    0x6B4FE9E7, 0x36ED0DCC, 0x22A6CCCB, 0x7899BFB5, 0xDBB22EAD, 0x32D4AB35,
    0xCEE77C7B, 0x2B30D372, 0xCD3330C6, 0xDCA8F6B2, 0x36FDDCB7, 0xC32FCDEC,
    0x2C23218A, 0xD34ADC9F, 0xBEAE638D, 0xCB39FBC9, 0x00034AEF, 0x8FA4B8E7,
    0xEDE85FAF, 0x6297F665, 0xC8F23B96, 0x2A5E84FC, 0xCC80017E, 0xAB801FA7,
    0xFE000006, 0x198A8261, 0x012A0E80, 0x02801B6E, 0x266E7248, 0x007A3AE8,
    0xA00A8A00, 0x8FA4B936, 0x00000122, 0xD31FC8A7, 0x8BF20DEA, 0x4BFC34BF,
    0x986FA3C3, 0x98633238, 0xDA3A62EB, 0xEF7A333E, 0x7228FAD8, 0xBBA4EA9B,
    0xFF30CB0C, 0x72734D6F, 0x07DB997A, 0x8E3207B3, 0x323229A5, 0x76CDB34C,
    0xBCCF311C, 0x26B0D721, 0x46B9EC92, 0x734734B3, 0xA330C734, 0x73BF0DBA,
    0x0C331ACA, 0x3F30CE73, 0x8DC35C9F, 0xDCCF358C, 0xF249A82F, 0x002CEA2B,
    0x1FD7C937, 0xA199A1D8, 0x325FEC8F, 0xBE3734F2, 0x734E61C8, 0xB398B2B4,
    0x72DA325C, 0x39249B0C, 0xFA130CFA, 0x0DFB4C9C, 0xEB5E93B3, 0x1AFDB79C,
    0xCD75B832, 0x32DF363D, 0x5CD331ED, 0xB08ADFFB, 0x5EDB1FD6, 0xDF77FED3,
    0xE736D32A, 0x7B9C9BBF, 0xD7C9A6B4, 0xD628A81F, 0x9ABBB734, 0xA0E8FA0E,
    0xE8FA0E8F, 0xB20E8FA0, 0x0000DB67, 0x21A4866B, 0x34C982BF, 0xCEC33FCC,
    0xC32A9325, 0x8A2323BE, 0x6D22A1BD, 0x8F3A68A9, 0xF34E2E0D, 0x06ADB4D0,
    0xD6D5C62A, 0xC63B4C70, 0x37DF7B30, 0x4AEC8ABB, 0x777EC7AA, 0xB3C337C2,
    0xD4D0CA2E, 0xB5C31330, 0xC32C9A05, 0x34F90C5C, 0x534CB0CC, 0x7B474343,
    0x71EC434C, 0x4ADB5DB2, 0x3CCD31D3, 0x59C3B6ED, 0xC3B28CD7, 0xCCC2B30C,
    0xD1BAD6B6, 0xDCDF6BD3, 0xDB75BED1, 0x5FEDFF4D, 0x6B5DDFFF, 0xD319D70C,
    0x7B39CD5E, 0x0C6776C6, 0xACD7AD77, 0xB6AEDB33, 0x1C9B5CD3, 0x0C6A6CC3,
    0x0DF370D7, 0x49DFB7DB, 0xC7B7C8B3, 0xF27DBB2C, 0x19D335EC, 0x735F9CF3,
    0xB75FDFEE, 0x731BDF2B, 0x0D334C27, 0xCDD1F8C9, 0xFCD7358E, 0x9A7F4763,
    0x0C730DA2, 0xC3F3C3E7, 0xB2CD533C, 0xCECB73D8, 0x3CCCC34F, 0xAA996F2E,
    0x9CF36D71, 0x61D34CDD, 0xACC96B63, 0x6FD2F32B, 0x674CDAFB, 0xAD1D3F4C,
    0x6DBB3C35, 0xDFF1ACBF, 0x1ACD3EA2, 0x5FFC36AB, 0x5D2F4CEF, 0x3BB0D6CD,
    0x2A6EDD9E, 0x370AEC82, 0x6CD2736D, 0x34734C73, 0xB3ACA747, 0xCBB7BCFA,
    0xCF6D371C, 0xADB5CC33, 0x31C3FB4E, 0xCF36D6BB, 0x6F32CB32, 0x35C7B36C,
    0x4CCF26D3, 0x77DF5BDB, 0x36EDF59D, 0xADD7330D, 0xD36CDB34, 0xDCF3CB2C,
    0xB6CDF1D6, 0xACF3CF3D, 0x0001BD0A, 0x000E622B, 0x001E622B, 0xB23FC8FB,
    0x3FD98FBE, 0x8F669C33, 0x00007EBF};
const re_utf8_prop re_utf8_props[29] = {
    {2, 2,   0,    "Cc"},
    {2, 21,  2,    "Cf"},
    {2, 6,   15,   "Co"},
    {2, 4,   20,   "Cs"},
    {2, 658, 23,   "Ll"},
    {2, 71,  118,  "Lm"},
    {2, 524, 153,  "Lo"},
    {2, 10,  379,  "Lt"},
    {2, 646, 383,  "Lu"},
    {2, 182, 471,  "Mc"},
    {2, 5,   538,  "Me"},
    {2, 346, 542,  "Mn"},
    {2, 64,  679,  "Nd"},
    {2, 12,  721,  "Nl"},
    {2, 72,  729,  "No"},
    {2, 6,   774,  "Pc"},
    {2, 19,  778,  "Pd"},
    {2, 76,  787,  "Pe"},
    {2, 10,  802,  "Pf"},
    {2, 11,  806,  "Pi"},
    {2, 187, 810,  "Po"},
    {2, 79,  893,  "Ps"},
    {2, 21,  909,  "Sc"},
    {2, 31,  921,  "Sk"},
    {2, 64,  936,  "Sm"},
    {2, 185, 963,  "So"},
    {2, 1,   1053, "Zl"},
    {2, 1,   1054, "Zp"},
    {2, 7,   1055, "Zs"},
};

/*t Generated by `unicode_data.py gen_props` */

/* Read a single bit from the compressed bit stream. Update the pointer and the
 * bit index variables appropriately. */
static int re_utf8_prop_next_bit(const re_u32 **p, re_u32 *idx)
{
  re_u32 out = ((**p) & ((re_u32)1 << (*idx)++));
  if (*idx == 32)
    *idx = 0, (*p)++;
  return (int)!!out;
}

static int re_utf8_prop_decode(re *r, const re_u8 *name, size_t name_len)
{
  const re_utf8_prop *p = NULL, *found = NULL;
  const re_u32 *read; /* pointer to compressed data */
  re_u32 i, bit_idx, prev = RE_UTF_MAX + 1, accum = 0, res = RE_REF_NONE;
  int err;
  /* Find the property with the matching name. */
  for (p = re_utf8_props;
       p < re_utf8_props + sizeof(re_utf8_props) / sizeof(*re_utf8_props); p++)
    if (p->name_len == name_len && !memcmp(p->name, name, name_len)) {
      found = p;
      break;
    }
  if (!found)
    return re_parse_err(r, "invalid Unicode property name");
  /* Start reading from the p->start offset in the compressed bit stream. */
  read = re_utf8_prop_data + p->start, bit_idx = 0;
  for (i = 0; i < p->num_range; i++) {
    re_u32 range[2] = {0}, *number, k;
    /* Read two integers per range. */
    for (number = range; number < &(range[2]); number++) {
      /* If the previous number was zero, we *know* that the next number is
       * nonzero. So, we don't read the 'is zero' bit if we don't need to. */
      int not_zero = prev == 0 ? 1 : re_utf8_prop_next_bit(&read, &bit_idx);
      if (!not_zero)
        *number = 0;
      else {
        /* The 'not one' bit is always necessary. */
        int not_one = re_utf8_prop_next_bit(&read, &bit_idx);
        if (!not_one)
          *number = 1;
        else {
          do
            for (k = 0; k < 3; k++)
              *number = (*number << 1) | re_utf8_prop_next_bit(&read, &bit_idx);
          while (re_utf8_prop_next_bit(&read, &bit_idx));
          *number += 2;
        }
      }
      /* Swap 1s and 2s. */
      *number = *number == 1 ? 2 : *number == 2 ? 1 : *number;
      /* Add the accumulated delta, and then update the accumulator itself. */
      *number = accum + *number, accum = *number;
      prev = *number;
    }
    if ((err = re_ast_make(r, RE_AST_TYPE_CC, res, range[0], range[1], &res)))
      return err;
  }
  return re_buf_push(r, &r->arg_stk, res);
}

/*T The rest of this file contains functions that aid debugging. */
#ifndef RE_COV

  #include <stdio.h>

enum dumpformat { TERM, GRAPHVIZ };

static char d_hex(re_u8 d)
{
  d &= 0xF;
  if (d < 10)
    return '0' + d;
  else
    return 'A' + d - 10;
}

static char *d_chr(char *buf, re_u32 ch, int ascii)
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

static char *d_chr_ascii(char *buf, re_u32 ch) { return d_chr(buf, ch, 1); }

static char *d_chr_unicode(char *buf, re_u32 ch) { return d_chr(buf, ch, 0); }

static char *d_assert(char *buf, re_assert_flag af)
{
  buf = strcat(buf, af & RE_ASSERT_LINE_BEGIN ? "^" : "");
  buf = strcat(buf, af & RE_ASSERT_LINE_END ? "$" : "");
  buf = strcat(buf, af & RE_ASSERT_TEXT_BEGIN ? "\\\\A" : "");
  buf = strcat(buf, af & RE_ASSERT_TEXT_END ? "\\\\z" : "");
  buf = strcat(buf, af & RE_ASSERT_WORD ? "\\\\b" : "");
  buf = strcat(buf, af & RE_ASSERT_NOT_WORD ? "\\\\B" : "");
  return buf;
}

static char *d_group_flag(char *buf, re_group_flag gf)
{
  buf = strcat(buf, gf & RE_GROUP_FLAG_INSENSITIVE ? "i" : "");
  buf = strcat(buf, gf & RE_GROUP_FLAG_MULTILINE ? "m" : "");
  buf = strcat(buf, gf & RE_GROUP_FLAG_DOTNEWLINE ? "s" : "");
  buf = strcat(buf, gf & RE_GROUP_FLAG_UNGREEDY ? "U" : "");
  buf = strcat(buf, gf & RE_GROUP_FLAG_NONCAPTURING ? ":" : "");
  buf = strcat(buf, gf & RE_GROUP_FLAG_SUBEXPRESSION ? "R" : "");
  return buf;
}

static char *d_quant(char *buf, re_u32 quantval)
{
  if (quantval >= RE_INFTY)
    strcat(buf, "\xe2\x88\x9e"); /* infinity symbol */
  else {
    /* macos doesn't have sprintf(), gcc --std=c89 doesn't have snprintf() */
    /* nice! */
    char buf_reverse[32] = {0}, buf_fwd[32] = {0};
    int i = 0, j = 0;
    do {
      buf_reverse[i++] = quantval % 10 + '0';
      quantval /= 10;
    } while (quantval);
    while (i)
      buf_fwd[j++] = buf_reverse[--i];
    strcat(buf, buf_fwd);
  }
  return buf;
}

void d_ast_i(re *r, re_u32 root, re_u32 ilvl, int format)
{
  const char *colors[] = {"1", "2", "3", "4"};
  re_u32 i, first = root ? *re_ast_type_ref(r, root) : 0;
  re_u32 sub[2] = {0xFF, 0xFF};
  char buf[32] = {0}, buf2[32] = {0};
  const char *node_name =
      root == RE_REF_NONE             ? "\xc9\x9b" /* epsilon */
      : (first == RE_AST_TYPE_CHR)    ? "CHR"
      : (first == RE_AST_TYPE_CAT)    ? (sub[0] = 0, sub[1] = 1, "CAT")
      : (first == RE_AST_TYPE_ALT)    ? (sub[0] = 0, sub[1] = 1, "ALT")
      : (first == RE_AST_TYPE_QUANT)  ? (sub[0] = 0, "QUANT")
      : (first == RE_AST_TYPE_UQUANT) ? (sub[0] = 0, "UQUANT")
      : (first == RE_AST_TYPE_GROUP)  ? (sub[0] = 0, "GROUP")
      : (first == RE_AST_TYPE_IGROUP) ? (sub[0] = 0, "IGROUP")
      : (first == RE_AST_TYPE_CC)     ? (sub[0] = 0, "CLS")
      : (first == RE_AST_TYPE_ICC)    ? (sub[0] = 0, "ICLS")
      : (first == RE_AST_TYPE_ANYBYTE)
          ? "ANYBYTE"
          : /* (first == RE_AST_TYPE_ASSERT) */ "ASSERT";
  assert(node_name != NULL);
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
      re_u32 child = *re_ast_param_ref(r, root, sub[i]);
      d_ast_i(r, child, ilvl + 1, format);
      if (format == GRAPHVIZ)
        printf(
            "A%04X -> A%04X [style=%s]\n", root, child, i ? "dashed" : "solid");
    }
  if (format == GRAPHVIZ)
    printf("}\n");
}

void d_ast(re *r, re_u32 root) { d_ast_i(r, root, 0, TERM); }

void d_ast_gv(re *r) { d_ast_i(r, r->ast_root, 0, GRAPHVIZ); }

void d_sset(re_sset *s)
{
  re_u32 i;
  for (i = 0; i < s->dense_size; i++)
    printf("%04X pc: %04X slot: %04X\n", i, s->dense[i].pc, s->dense[i].slot);
}

void d_prog_range(const re *r, re_u32 start, re_u32 end, int format)
{
  re_u32 j, k;
  assert(end <= re_prog_size(r));
  if (format == GRAPHVIZ)
    printf("node [colorscheme=pastel16]\n");
  for (; start < end; start++) {
    re_inst ins = re_prog_get(r, start);
    static const char *ops[] = {"RANGE", "SPLIT", "MATCH", "ASSRT"};
    static const char *labels[] = {"F  ", "R  ", "F.*", "R.*", "   ", "+  "};
    char start_buf[10] = {0}, end_buf[10] = {0}, assert_buf[32] = {0};
    k = 4;
    for (j = 0; j < 4; j++)
      if (start == r->entry[j])
        k = k == 4 ? j : 5;
    if (format == TERM) {
      static const int colors[] = {91, 94, 93, 92};
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
      static const char *shapes[] = {"box", "oval", "pentagon", "diamond"};
      static const int colors[] = {1, 2, 6, 3};
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

void d_prog(const re *r)
{
  d_prog_range(r, 1, r->entry[RE_PROG_ENTRY_REVERSE], TERM);
}

void d_prog_r(const re *r)
{
  d_prog_range(r, r->entry[RE_PROG_ENTRY_REVERSE], re_prog_size(r), TERM);
}

void d_prog_whole(const re *r) { d_prog_range(r, 0, re_prog_size(r), TERM); }

void d_prog_gv(const re *r)
{
  d_prog_range(r, 1, r->entry[RE_PROG_ENTRY_DOTSTAR], GRAPHVIZ);
}

void d_cctree_i(const re_buf(re_compcc_tree) cc_tree, re_u32 ref, re_u32 lvl)
{
  re_u32 i;
  const re_compcc_tree *node = cc_tree + ref;
  printf("%04X [%08X] ", ref, node->aux.pc);
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

void d_cctree(const re_buf(re_compcc_tree) cc_tree, re_u32 ref)
{
  d_cctree_i(cc_tree, ref, 0);
}
#endif

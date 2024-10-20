#include <assert.h> /* assert() */
#include <limits.h> /* CHAR_BIT */
#include <stdarg.h> /* va_list, va_start(), va_arg(), va_end() */
#include <stdlib.h> /* size_t, realloc(), free() */
#include <string.h> /* memcmp(), memset(), memcpy(), strlen() */

#include "bbre.h"

#ifdef BBRE_CONFIG_HEADER_FILE
  #include BBRE_CONFIG_HEADER_FILE
#endif

#define BBRE_NIL     0
#define BBRE_UTF_MAX 0x10FFFF

/* Maximum repetition count for quantifiers. */
#define BBRE_LIMIT_REPETITION_COUNT 100000
/* Maximum size of the AST. This is the sum of node count and argument count. */
#define BBRE_LIMIT_AST_SIZE 1000000
/* Maximum length (in bytes) of a group name. */
#define BBRE_LIMIT_GROUP_NAME_SIZE 1000000
/* Maximum size of a normalized charclass (max number of ranges) */
#define BBRE_LIMIT_CHARCLASS_NORMALIZED_SIZE ((BBRE_UTF_MAX + 1) / 2)

typedef unsigned int bbre_uint;
typedef unsigned char bbre_byte;

/* Macro for declaring a buffer. Serves mostly for readability. */
#define bbre_buf(T) T *

/* Enumeration of AST types. */
typedef enum bbre_ast_type {
  /* A single character: /a/ */
  BBRE_AST_TYPE_CHR = 1,
  /* The concatenation of two regular expressions: /lr/
   *   Argument 0: left child tree (AST)
   *   Argument 1: right child tree (AST) */
  BBRE_AST_TYPE_CAT,
  /* The alternation of two regular expressions: /l|r/
   *   Argument 0: primary alternation tree (AST)
   *   Argument 1: secondary alternation tree (AST) */
  BBRE_AST_TYPE_ALT,
  /* A repeated regular expression: /a+/
   *   Argument 0: child tree (AST)
   *   Argument 1: lower bound, always <= upper bound (number)
   *   Argument 2: upper bound, might be the constant `BBRE_INFTY` (number) */
  BBRE_AST_TYPE_QUANT,
  /* Like `QUANT`, but not greedy: /(a*?)/
   *   Argument 0: child tree (AST)
   *   Argument 1: lower bound, always <= upper bound (number)
   *   Argument 2: upper bound, might be the constant `BBRE_INFTY` (number) */
  BBRE_AST_TYPE_UQUANT,
  /* A matching group: /(?i-s:a)/
   *   Argument 0: child tree (AST)
   *   Argument 1: group flags pulled up, bitset of `enum group_flag` (number)
   *   Argument 2: group flags pulled down (number)
   *   Argument 3: capture index (number) */
  BBRE_AST_TYPE_GROUP,
  /* An inline group: /(?i-s)a/
   *   Argument 0: child tree (AST)
   *   Argument 1: group flags pulled up, bitset of `enum group_flag` (number)
   *   Argument 2: group flags pulled down (number) */
  BBRE_AST_TYPE_IGROUP,
  /* A single range in a character class: /[a-z]/
   *   Argument 0: character range begin (number)
   *   Argument 1: character range end (number) */
  BBRE_AST_TYPE_CC_LEAF,
  /* A builtin character class: /[:digit:]/
   *   Argument 0: starting index into the builtin_cc array
   *   Argument 1: number of character ranges to parse */
  BBRE_AST_TYPE_CC_BUILTIN,
  /* The set-inversion of a character class: //
   *   Argument 0: child tree (AST) */
  BBRE_AST_TYPE_CC_NOT,
  /* The set-disjunction of a character class: //
   *   Argument 0: child tree A (AST)
   *   Argument 1: child tree B (AST) */
  BBRE_AST_TYPE_CC_OR,
  /* The set-conjunction of a character class: //
   *   Argument 0: child tree A (AST)
   *   Argument 1: child tree B (AST) */
  BBRE_AST_TYPE_CC_AND,
  /* Matches any character: /./ */
  BBRE_AST_TYPE_ANYCHAR,
  /* Matches any byte: /\C/ */
  BBRE_AST_TYPE_ANYBYTE,
  /* Empty assertion: /\b/
   *   Argument 0: assertion flags, bitset of `bbre_assert_flag` (number) */
  BBRE_AST_TYPE_ASSERT
} bbre_ast_type;

typedef struct bbre_ast_type_info {
  bbre_byte len, children, prec;
} bbre_ast_type_info;

/* Length (number of arguments) for each AST type. */
static const bbre_ast_type_info bbre_ast_type_infos[] = {
    {0, 0, 0}, /* eps */
    {1, 0, 0}, /* CHR */
    {2, 2, 0}, /* CAT */
    {2, 2, 2}, /* ALT */
    {3, 1, 0}, /* QUANT */
    {3, 1, 0}, /* UQUANT */
    {4, 1, 3}, /* GROUP */
    {3, 1, 1}, /* IGROUP */
    {2, 0, 0}, /* CC_LEAF */
    {2, 0, 0}, /* CC_BUILTIN */
    {1, 1, 0}, /* CC_NOT */
    {2, 2, 0}, /* CC_OR */
    {2, 2, 0}, /* CC_AND */
    {0, 0, 0}, /* ANYCHAR */
    {0, 0, 0}, /* ANYBYTE */
    {1, 0, 0}, /* ASSERT */
};

#define BBRE_AST_MAX_ARGS 4

/* Represents an inclusive range of bytes. */
typedef struct bbre_byte_range {
  bbre_byte l, /* min ordinal */
      h;       /* max ordinal */
} bbre_byte_range;

/* Represents an inclusive range of runes. */
typedef struct bbre_rune_range {
  bbre_uint l, /* min ordinal */
      h;       /* max ordinal */
} bbre_rune_range;

typedef enum bbre_group_flag {
  BBRE_GROUP_FLAG_INSENSITIVE = 1,   /* case-insensitive matching */
  BBRE_GROUP_FLAG_MULTILINE = 2,     /* ^$ match beginning/end of each line */
  BBRE_GROUP_FLAG_DOTNEWLINE = 4,    /* . matches \n */
  BBRE_GROUP_FLAG_UNGREEDY = 8,      /* ungreedy quantifiers */
  BBRE_GROUP_FLAG_NONCAPTURING = 16, /* non-capturing group (?:...) */
  BBRE_GROUP_FLAG_EXPRESSION = 32,   /* the entire regexp */
  BBRE_GROUP_FLAG_CC_DENORM = 64     /* set when compiling charclasses */
} bbre_group_flag;

/* Stack frame for the compiler, used to track a single AST node being
 * compiled. */
/* A single AST node, when compiled, corresponds to a contiguous list of
 * instructions. The first instruction in this list is the single entry point
 * for the node. Using the NFA paradigm, this corresponds to the start state of
 * an automaton.
 * There may be zero or more exits from the list of instructions -- these are
 * instructions that hand off control to the enclosing AST node. Again, using
 * the NFA paradigm, these are transitions from nodes that do not yet have an
 * end state, but will need one later. */
/* Consider the regex /ab/ which is just the concatenation of the literals a and
 * b. The AST for this regex looks like:
 *  CAT
 *  +-CHR A
 *  +-CHR B
 * In terms of an NFA, it looks like this chain of states:
 * --> Q_0 --A-> Q_1 --B-> Q_2 ---> ...
 * The compiler first considers the CAT node. This node links its two children
 * sequentially, so the compiler must next consider the first CHR node. To match
 * a CHR node, we use a RANGE instruction to check for the presence of the A
 * character, and then hand back control to the instructions of the enclosing
 * node. When being compiled, AST nodes do not know anything about their
 * enclosing environment, so they simply keep track of instructions that
 * transfer control back to the enclosing node. So, the list of instructions for
 * the `CHR A` node looks like (starting at PC 1):
 * 0001 RANGE 'A'-'A' -> OUT
 * The compiler then goes back to the CAT node, which moves to its next child;
 * the `CHR B` node. Since the `CAT` node compiles to a program that runs its
 * first child, then subsequently its second, the `CAT` node will link all exits
 * of the `CHR A` node to the entrypoint of the `CHR A` node.
 * 0001 RANGE 'A'-'A' -> 0002
 * 0002 RANGE 'B'-'B' -> OUT
 * The `CAT` node itself compiles to the above list of instructions, and has a
 * single exit point at PC 2.
 * We keep track of the exit points from the program using a trick I first saw
 * in Russ Cox's series on regexps. A linked list, backed by the actual words
 * inside of the instructions, stores the exit points. This list is tracked by
 * `patch_head` and `patch_tail`. */
typedef struct bbre_compframe {
  bbre_uint root_ref, /* reference to the AST node being compiled */
      child_ref,      /* reference to the child AST node to be compiled next */
      idx,            /* used keep track of repetition index */
      head,           /* head of the outgoing patch linked list */
      tail,           /* tail of the outgoing patch linked list */
      pc,             /* location of first instruction compiled for this node */
      flags,          /* group flags in effect (INSENSITIVE, etc.) */
      set_idx;        /* index of the current pattern being compiled */
} bbre_compframe;

/* Bitset of empty assertions. */
typedef enum bbre_assert_flag {
  BBRE_ASSERT_LINE_BEGIN = 1, /* ^ */
  BBRE_ASSERT_LINE_END = 2,   /* $ */
  BBRE_ASSERT_TEXT_BEGIN = 4, /* \A */
  BBRE_ASSERT_TEXT_END = 8,   /* \z */
  BBRE_ASSERT_WORD = 16,      /* \b */
  BBRE_ASSERT_NOT_WORD = 32   /* \B */
} bbre_assert_flag;

/* How many bits inside of the `opcode_next` field we allocate to the opcode
 * itself: currently this is just 2 as we only have exactly 4 distinct opcodes,
 * but it could be increased later if we wish to add more */
#define BBRE_INST_OPCODE_BITS 2

/* The number of distinct opcodes was deliberately kept as low as possible. This
 * makes the compiled programs easy to reason about. */
typedef enum bbre_opcode {
  BBRE_OPCODE_RANGE, /* matches a range of bytes */
  BBRE_OPCODE_SPLIT, /* forks execution into two paths */
  BBRE_OPCODE_MATCH, /* writes the current string position into a submatch */
  BBRE_OPCODE_ASSERT /* continue execution if zero-width assertion */
} bbre_opcode;

/* Compiled program instruction. */
typedef struct bbre_inst {
  /* opcode_next is the opcode and the next program counter (primary branch
   * target), and param is opcode-specific data */
  /*                        3   2   2   2   1   1   0   0   0  */
  /*                         2   8   4   0   6   2   8   4   0 */
  bbre_uint opcode_next; /* / nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnoo */
                         /* \          n = next PC, o = opcode */
  bbre_uint param;       /* / 0000000000000000hhhhhhhhllllllll (RANGE) */
                         /* \      h = high byte, l = low byte (RANGE) */
                         /* / NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN (SPLIT) */
                         /* \            N = secondary next PC (SPLIT) */
                         /* / iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiie (MATCH) */
                         /* \     i = group idx, e = start/end (MATCH) */
                         /* / 00000000000000000000000000aaaaaa (ASSERT) */
                         /* \                  a = assert_flag (ASSERT) */
} bbre_inst;

/* Auxiliary data for tree nodes used for accelerating compilation. */
typedef union bbre_compcc_tree_aux {
  bbre_uint hash, /* node hash, used for tree reduction */
      pc,     /* compiled location, nonzero if this node was compiled already */
      xposed; /* 1 if the node was transposed, 0 otherwise */
} bbre_compcc_tree_aux;

/* Tree node for the character class compiler. */
typedef struct bbre_compcc_tree {
  bbre_uint range, /* range of bytes this node matches */
      child_ref,   /* concatenation */
      sibling_ref; /* alternation */
  bbre_compcc_tree_aux
      aux; /* node hash OR cached PC TODO: replace with union */
} bbre_compcc_tree;

/* Internal storage used for the character class compiler. It uses enough state
 * that it definitely warrants its own struct. */
typedef struct bbre_compcc_data {
  bbre_buf(bbre_compcc_tree) tree;
  bbre_buf(bbre_compcc_tree) tree_2;
  bbre_buf(bbre_uint) hash;
} bbre_compcc_data;

/* Bit flags to identify program entry points in the `entry` field of `re`. */
typedef enum bbre_prog_entry {
  BBRE_PROG_ENTRY_REVERSE = 1, /* reverse execution */
  BBRE_PROG_ENTRY_DOTSTAR = 2, /* .* before execution (unanchored match) */
  BBRE_PROG_ENTRY_MAX = 4
} bbre_prog_entry;

/* A builder class for regular expressions. */
struct bbre_builder {
  bbre_alloc alloc;      /* allocator function */
  const bbre_byte *expr; /* the expression itself */
  size_t expr_size;      /* the length of the expression in bytes */
  bbre_flags flags;      /* regex flags used for parsing / the root AST */
};

typedef struct bbre_exec bbre_exec;

/* Used to hold reportable errors. */
typedef struct bbre_error {
  const char *msg; /* error message, if any */
  size_t pos;      /* position the error was encountered in expr */
} bbre_error;

void bbre_error_set(bbre_error *err, const char *msg)
{
  err->msg = msg;
  err->pos = 0;
}

void bbre_error_init(bbre_error *err) { bbre_error_set(err, NULL); }

/* The compiled form of a regular expression. */
typedef struct bbre_prog {
  bbre_alloc alloc;                     /* allocator function */
  bbre_buf(bbre_inst) prog;             /* The compiled instructions */
  bbre_buf(bbre_uint) set_idxs;         /* pattern index for each instruction */
  bbre_uint entry[BBRE_PROG_ENTRY_MAX]; /* entry points for the program */
  bbre_uint npat;                       /* number of distinct patterns */
  bbre_error *error;                    /* error info, we don't own this */
} bbre_prog;

typedef struct bbre_group_name {
  char *name;
  size_t name_size;
} bbre_group_name;

typedef struct bbre_cc_elem {
  bbre_rune_range range;
  size_t next;
} bbre_cc_elem;

/* A compiled regular expression. */
struct bbre {
  bbre_alloc alloc;                      /* allocator function */
  bbre_buf(bbre_uint) ast;               /* AST arena */
  bbre_uint ast_root;                    /* AST root node reference */
  bbre_buf(bbre_group_name) group_names; /* Named group names */
  bbre_buf(bbre_uint) op_stk;            /* parser operator stack */
  bbre_buf(bbre_compframe) comp_stk;     /* compiler frame stack */
  bbre_buf(bbre_cc_elem) cc_store;
  bbre_uint cc_store_empty;
  size_t cc_store_ops;
  bbre_compcc_data compcc; /* data used for the charclass compiler */
  bbre_prog prog;          /* NFA program */
  const bbre_byte *expr;   /* input parser expression */
  size_t expr_pos,         /* current position in expr */
      expr_size;           /* number of bytes in expr */
  bbre_error error;        /* error message and/or pos */
  bbre_exec *exec; /* local execution context, NULL until actually used */
};

/* A builder class for regular expression sets. */
struct bbre_set_builder {
  bbre_alloc alloc;            /* allocator function */
  bbre_buf(const bbre *) pats; /* patterns that compose this set */
};

/* A set of compiled regular expressions. */
struct bbre_set {
  bbre_alloc alloc; /* allocator function */
  bbre_prog prog;   /* compiled program */
  bbre_exec *exec;  /* local execution context, NULL until actually used */
  bbre_error error; /* error info */
};

/* sparse-set data structure used for quickly storing nfa state sets */
typedef struct bbre_save_slots {
  size_t *slots, slots_size, slots_alloc, last_empty, per_thrd;
} bbre_save_slots;

typedef struct bbre_nfa_thrd {
  bbre_uint pc, slot;
} bbre_nfa_thrd;

typedef struct bbre_sset {
  bbre_uint size, dense_size;
  bbre_buf(bbre_uint) sparse;
  bbre_buf(bbre_nfa_thrd) dense;
} bbre_sset;

typedef struct bbre_nfa {
  bbre_sset a, b, c;
  bbre_buf(bbre_nfa_thrd) thrd_stk;
  bbre_save_slots slots;
  bbre_buf(bbre_uint) pri_stk;
  bbre_buf(bbre_uint) pri_bmp_tmp;
  int reversed, pri;
} bbre_nfa;

#define BBRE_DFA_MAX_NUM_STATES 256

typedef enum bbre_dfa_match_flags {
  BBRE_DFA_MATCH_FLAG_REVERSED = 1,
  BBRE_DFA_MATCH_FLAG_PRI = 2,
  BBRE_DFA_MATCH_FLAG_EXIT_EARLY = 4,
  BBRE_DFA_MATCH_FLAG_MANY = 8
} bbre_dfa_match_flags;

typedef enum bbre_dfa_state_flag {
  BBRE_DFA_STATE_FLAG_FROM_TEXT_BEGIN = 1,
  BBRE_DFA_STATE_FLAG_FROM_LINE_BEGIN = 2,
  BBRE_DFA_STATE_FLAG_FROM_WORD = 4,
  BBRE_DFA_STATE_FLAG_PRIORITY_EXHAUST = 8,
  BBRE_DFA_STATE_FLAG_MAX = 16,
  BBRE_DFA_STATE_FLAG_DIRTY = 16
} bbre_dfa_state_flag;

typedef struct bbre_dfa_state {
  struct bbre_dfa_state *ptrs[256 + 1];
  bbre_uint flags, nstate, nset, alloc;
} bbre_dfa_state;

typedef struct bbre_dfa {
  bbre_dfa_state **states;
  size_t states_size, num_active_states;
  bbre_dfa_state *entry[BBRE_PROG_ENTRY_MAX]
                       [BBRE_DFA_STATE_FLAG_MAX]; /* program entry type
                                                   * dfa_state_flag */
  bbre_buf(bbre_uint) set_buf;
  bbre_buf(bbre_uint) set_bmp;
} bbre_dfa;

struct bbre_exec {
  bbre_alloc alloc;
  const bbre_prog *prog;
  bbre_nfa nfa;
  bbre_dfa dfa;
};

/* Helper macro for assertions. */
#define BBRE_IMPLIES(subject, predicate) (!(subject) || (predicate))

#ifndef BBRE_DEFAULT_ALLOC
/* Default allocation function. Hooks stdlib malloc. */
static void *
bbre_default_alloc(void *user, void *in_ptr, size_t prev, size_t next)
{
  void *ptr = NULL;
  (void)user, (void)prev;
  if (next) {
    assert(BBRE_IMPLIES(!prev, !in_ptr));
    ptr = realloc(in_ptr, next);
  } else if (in_ptr) {
    free(in_ptr);
  }
  return ptr;
}

  #define BBRE_DEFAULT_ALLOC bbre_default_alloc
#endif

static void *
bbre_ialloc(bbre_alloc *alloc, void *old_ptr, size_t old_size, size_t new_size)
{
  return alloc->cb(alloc->user, old_ptr, old_size, new_size);
}

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
typedef struct bbre_buf_hdr {
  size_t size, alloc;
} bbre_buf_hdr;

/* Since we store the dynamic array as a raw T*, a natural implementaion might
 * represent an empty array as NULL. However, this complicates things-- size
 * checks must always have a branch to check for NULL, the grow routine has more
 * scary codepaths, etc. To make code simpler, there exists a special sentinel
 * value that contains the empty array. */
static const bbre_buf_hdr bbre_buf_sentinel = {0};

/* Given a dynamic array, get its header. */
static bbre_buf_hdr *bbre_buf_get_hdr(void *buf)
{
  return ((bbre_buf_hdr *)buf) - 1;
}

/* Given a dynamic array, get its size. */
static size_t bbre_buf_size_t(void *buf) { return bbre_buf_get_hdr(buf)->size; }

/* Reserve enough memory to set the array's size to `size`. Note that this is
 * different from C++'s std::vector::reserve() in that it actually sets the used
 * size of the dynamic array. The caller must initialize the newly available
 * elements. */
static int bbre_buf_reserve_t(bbre_alloc *a, void **buf, size_t size)
{
  bbre_buf_hdr *hdr = NULL;
  size_t next_alloc;
  void *next_ptr;
  int err = 0;
  assert(buf && *buf);
  hdr = bbre_buf_get_hdr(*buf);
  next_alloc = hdr->alloc ? hdr->alloc : /* sentinel */ 1;
  if (size <= hdr->alloc) {
    hdr->size = size;
    goto error;
  }
  while (next_alloc < size)
    next_alloc *= 2;
  next_ptr = bbre_ialloc(
      a, hdr->alloc ? hdr : /* sentinel */ NULL,
      hdr->alloc ? sizeof(bbre_buf_hdr) + hdr->alloc : /* sentinel */ 0,
      sizeof(bbre_buf_hdr) + next_alloc);
  if (!next_ptr) {
    err = BBRE_ERR_MEM;
    goto error;
  }
  hdr = next_ptr;
  hdr->alloc = next_alloc;
  hdr->size = size;
  *buf = hdr + 1;
error:
  return err;
}

/* Initialize an empty dynamic array. */
static void bbre_buf_init_t(void **b)
{
  /* discard const qualifier: this is actually a good thing, because
   * bbre_buf_sentinel resides in rodata, and shouldn't be written to. This
   * cast helps us catch bugs in the buf implementation earlier */
  *b = ((bbre_buf_hdr *)&bbre_buf_sentinel) + 1;
  assert(bbre_buf_get_hdr(*b)->size == 0 && bbre_buf_get_hdr(*b)->alloc == 0);
}

/* Destroy a dynamic array. */
static void bbre_buf_destroy_t(bbre_alloc *a, void **buf)
{
  bbre_buf_hdr *hdr;
  assert(buf && *buf);
  hdr = bbre_buf_get_hdr(*buf);
  if (hdr->alloc)
    bbre_ialloc(a, hdr, sizeof(*hdr) + hdr->alloc, 0);
}

/* Increase size by `incr`. */
static int bbre_buf_grow_t(bbre_alloc *a, void **buf, size_t incr)
{
  assert(buf);
  return bbre_buf_reserve_t(a, buf, bbre_buf_size_t(*buf) + incr);
}

/* Get the last element index of the dynamic array. */
static size_t bbre_buf_tail_t(void *buf, size_t decr)
{
  return bbre_buf_get_hdr(buf)->size - decr;
}

/* Pop the last element of the array, returning its index in storage units. */
static size_t bbre_buf_pop_t(void *buf, size_t decr)
{
  size_t out;
  bbre_buf_hdr *hdr;
  assert(buf);
  out = bbre_buf_tail_t(buf, decr);
  hdr = bbre_buf_get_hdr(buf);
  assert(hdr->size >= decr);
  hdr->size -= decr;
  return out;
}

/* Clear the buffer, without freeing its backing memory */
static void bbre_buf_clear(void *buf)
{
  void *sbuf;
  assert(buf);
  sbuf = *(void **)buf;
  assert(sbuf);
  if (bbre_buf_get_hdr(sbuf) != &bbre_buf_sentinel)
    bbre_buf_get_hdr(sbuf)->size = 0;
}

/* Initialize a dynamic array. */
#define bbre_buf_init(b) bbre_buf_init_t((void **)b)

/* Get the element size of a dynamic array. */
#define bbre_buf_esz(b) sizeof(**(b))

/* Push an element. */
#define bbre_buf_push(r, b, e)                                                 \
  (bbre_buf_grow_t((r), (void **)(b), bbre_buf_esz(b))                         \
       ? BBRE_ERR_MEM                                                          \
       : (((*(b))                                                              \
               [bbre_buf_tail_t((void *)(*b), bbre_buf_esz(b)) /               \
                bbre_buf_esz(b)]) = (e),                                       \
          0))

/* Set the size to `n`. */
#define bbre_buf_reserve(r, b, n)                                              \
  (bbre_buf_reserve_t(r, (void **)(b), bbre_buf_esz(b) * (n)))

/* Pop an element. */
#define bbre_buf_pop(b)                                                        \
  ((*(b))[bbre_buf_pop_t((void *)(*b), bbre_buf_esz(b)) / bbre_buf_esz(b)])

/* Get a pointer to `n` elements from the end. */
#define bbre_buf_peek(b, n)                                                    \
  ((*b) + bbre_buf_tail_t((void *)(*b), bbre_buf_esz(b)) / bbre_buf_esz(b) -   \
   (n))

/* Get the size. */
#define bbre_buf_size(b) (bbre_buf_size_t((void *)(b)) / sizeof(*(b)))

/* Destroy a dynamic array. */
#define bbre_buf_destroy(r, b) (bbre_buf_destroy_t((r), (void **)(b)))

static bbre_alloc bbre_alloc_make(const bbre_alloc *input)
{
  bbre_alloc out;
  if (input)
    out = *input;
  else {
    out.cb = bbre_default_alloc;
    out.user = NULL;
  }
  return out;
}

static int bbre_compile(bbre *r);

int bbre_builder_init(
    bbre_builder **pbuild, const char *s, size_t n, const bbre_alloc *palloc)
{
  int err = 0;
  bbre_builder *build;
  bbre_alloc alloc = bbre_alloc_make(palloc);
  build = bbre_ialloc(&alloc, NULL, 0, sizeof(bbre_builder));
  *pbuild = build;
  if (!build) {
    err = BBRE_ERR_MEM;
    goto error;
  }
  memset(build, 0, sizeof(*build));
  build->alloc = alloc;
  build->expr = (const bbre_byte *)s;
  build->expr_size = n;
  build->flags = 0;
error:
  return err;
}

void bbre_builder_destroy(bbre_builder *build)
{
  if (!build)
    goto done;
  bbre_ialloc(&build->alloc, build, sizeof(bbre_builder), 0);
done:
  return;
}

void bbre_builder_flags(bbre_builder *build, bbre_flags flags)
{
  build->flags = flags;
}

static int
bbre_parse(bbre *r, const bbre_byte *s, size_t sz, bbre_flags start_flags);

static void bbre_prog_init(bbre_prog *prog, bbre_alloc alloc, bbre_error *error)
{
  prog->alloc = alloc;
  bbre_buf_init(&prog->prog), bbre_buf_init(&prog->set_idxs);
  memset(prog->entry, 0, sizeof(prog->entry));
  prog->npat = 0;
  prog->error = error;
}

static void bbre_prog_destroy(bbre_prog *prog)
{
  bbre_buf_destroy(&prog->alloc, &prog->prog),
      bbre_buf_destroy(&prog->alloc, &prog->set_idxs);
}

static int bbre_prog_clone(bbre_prog *out, const bbre_prog *in)
{
  int err = 0;
  assert(bbre_buf_size(out->prog) == 0);
  if ((err =
           bbre_buf_reserve(&out->alloc, &out->prog, bbre_buf_size(in->prog))))
    goto error;
  memcpy(out->prog, in->prog, bbre_buf_size(in->prog) * sizeof(*in->prog));
  if ((err = bbre_buf_reserve(
           &out->alloc, &out->set_idxs, bbre_buf_size(in->set_idxs))))
    goto error;
  memcpy(
      out->set_idxs, in->set_idxs,
      bbre_buf_size(in->set_idxs) * sizeof(*in->set_idxs));
  memcpy(out->entry, in->entry, sizeof(in->entry));
  out->npat = in->npat;
error:
  return err;
}

bbre *bbre_init_pattern(const char *pat_nt)
{
  int err = 0;
  bbre *r = NULL;
  bbre_builder *spec = NULL;
  if ((err = bbre_builder_init(&spec, pat_nt, strlen(pat_nt), NULL)))
    goto error;
  if ((err = bbre_init(&r, spec, NULL)))
    goto error;
  bbre_builder_destroy(spec);
  return r;
error:
  /* bbre_builder_destroy() accepts NULL */
  bbre_builder_destroy(spec);
  bbre_destroy(r);
  return NULL;
}

static int bbre_init_internal(bbre **pr, const bbre_alloc *palloc)
{
  int err = 0;
  bbre *r;
  bbre_alloc alloc = bbre_alloc_make(palloc);
  r = bbre_ialloc(&alloc, NULL, 0, sizeof(bbre));
  *pr = r;
  if (!r) {
    err = BBRE_ERR_MEM;
    goto error;
  }
  r->alloc = alloc;
  bbre_buf_init(&r->ast);
  r->ast_root = 0;
  bbre_buf_init(&r->group_names), bbre_buf_init(&r->op_stk),
      bbre_buf_init(&r->comp_stk), bbre_buf_init(&r->cc_store);
  r->cc_store_empty = BBRE_NIL;
  bbre_buf_init(&r->compcc.tree), bbre_buf_init(&r->compcc.tree_2),
      bbre_buf_init(&r->compcc.hash);
  bbre_prog_init(&r->prog, r->alloc, &r->error);
  r->expr = NULL, r->expr_pos = 0, r->expr_size = 0;
  bbre_error_init(&r->error);
  r->exec = NULL;
error:
  return err;
}

int bbre_init(bbre **pr, const bbre_builder *spec, const bbre_alloc *palloc)
{
  int err = 0;
  if ((err = bbre_init_internal(pr, palloc)))
    goto error;
  if ((err = bbre_parse(*pr, spec->expr, spec->expr_size, spec->flags)))
    goto error;
  (*pr)->prog.npat = 1;
  if ((err = bbre_compile(*pr)))
    goto error;
error:
  return err;
}

static void bbre_exec_destroy(bbre_exec *exec);

void bbre_destroy(bbre *r)
{
  size_t i;
  if (!r)
    goto done;
  bbre_buf_destroy(&r->alloc, (void **)&r->ast);
  for (i = 0; i < bbre_buf_size(r->group_names); i++) {
    bbre_ialloc(
        &r->alloc, r->group_names[i].name, r->group_names[i].name_size, 0);
  }
  bbre_buf_destroy(&r->alloc, &r->group_names);
  bbre_buf_destroy(&r->alloc, &r->op_stk),
      bbre_buf_destroy(&r->alloc, &r->comp_stk),
      bbre_buf_destroy(&r->alloc, &r->cc_store);
  bbre_buf_destroy(&r->alloc, &r->compcc.tree),
      bbre_buf_destroy(&r->alloc, &r->compcc.tree_2),
      bbre_buf_destroy(&r->alloc, &r->compcc.hash);
  bbre_prog_destroy(&r->prog);
  bbre_exec_destroy(r->exec);
  bbre_ialloc(&r->alloc, r, sizeof(*r), 0);
done:
  return;
}

const char *bbre_get_err_msg(const bbre *reg) { return reg->error.msg; }

size_t bbre_get_err_pos(const bbre *reg) { return reg->error.pos; }

/* Make a byte range inline; more convenient than initializing a struct. */
static bbre_byte_range bbre_byte_range_make(bbre_byte l, bbre_byte h)
{
  bbre_byte_range out;
  out.l = l, out.h = h;
  return out;
}

/* Pack a byte range into a u32, low byte first. */
static bbre_uint bbre_byte_range_to_u32(bbre_byte_range br)
{
  return ((bbre_uint)br.l) | ((bbre_uint)br.h) << 8;
}

/* Unpack a byte range from a u32. */
static bbre_byte_range bbre_uint_to_byte_range(bbre_uint u)
{
  return bbre_byte_range_make(u & 0xFF, u >> 8 & 0xFF);
}

/* Check if two byte ranges are adjacent (right directly supersedes left) */
static int
bbre_byte_range_is_adjacent(bbre_byte_range left, bbre_byte_range right)
{
  return ((bbre_uint)left.h) + 1 == ((bbre_uint)right.l);
}

/* Make a rune range inline. */
static bbre_rune_range bbre_rune_range_make(bbre_uint l, bbre_uint h)
{
  bbre_rune_range out;
  out.l = l, out.h = h;
  return out;
}

/* Make a new AST node within the regular expression. */
static int bbre_ast_make(bbre *r, bbre_uint *out_node, bbre_ast_type type, ...)
{
  va_list in_args;
  bbre_uint args[6], arg_idx = 0, i = 0;
  int err = 0;
  va_start(in_args, type);
  if (!bbre_buf_size(r->ast))
    args[arg_idx++] = 0; /* sentinel */
  *out_node = bbre_buf_size(r->ast) + arg_idx;
  args[arg_idx++] = type;
  while (i < bbre_ast_type_infos[type].len)
    args[arg_idx++] = va_arg(in_args, bbre_uint), i++;
  assert(i == bbre_ast_type_infos[type].len);
  for (i = 0; i < arg_idx; i++) {
    if (bbre_buf_size(r->ast) == BBRE_LIMIT_AST_SIZE) {
      bbre_error_set(&r->error, "regular expression is too complex");
      err = BBRE_ERR_LIMIT;
      goto error;
    }
    if ((err = bbre_buf_push(&r->alloc, &r->ast, args[i])))
      goto error;
  }
error:
  va_end(in_args);
  return err;
}

/* Decompose a given AST node, given its reference, into `out_args`. */
static void bbre_ast_decompose(bbre *r, bbre_uint node, bbre_uint *out_args)
{
  bbre_uint *in_args = r->ast + node;
  bbre_uint i;
  for (i = 0; i < bbre_ast_type_infos[*in_args].len; i++)
    out_args[i] = in_args[i + 1];
}

/* Get the type of the given AST node. */
static bbre_uint *bbre_ast_type_ref(bbre *r, bbre_uint node)
{
  assert(node != BBRE_NIL);
  return r->ast + node;
}

/* Get a pointer to the `n`'th parameter of the given AST node. */
static bbre_uint *bbre_ast_param_ref(bbre *r, bbre_uint node, bbre_uint n)
{
  assert(bbre_ast_type_infos[*bbre_ast_type_ref(r, node)].len > n);
  return r->ast + node + 1 + n;
}

/* Returns true if the given ast type is part of a character class subtree. */
static int bbre_ast_type_is_cc(bbre_uint ast_type)
{
  return (ast_type == BBRE_AST_TYPE_CC_LEAF) ||
         (ast_type == BBRE_AST_TYPE_CC_BUILTIN) ||
         (ast_type == BBRE_AST_TYPE_CC_NOT) ||
         (ast_type == BBRE_AST_TYPE_CC_OR) ||
         (ast_type == BBRE_AST_TYPE_CC_AND);
}

/* Below is a UTF-8 decoder implemented as a compact DFA. This was heavily
 * inspired by Bjoern Hoehrmann's ubiquitous "Flexible and Economical UTF-8
 * Decoder" (https://bjoern.hoehrmann.de/utf-8/decoder/dfa/). I chose to write a
 * script that would generate this DFA for me. The first table,
 * bbre_utf8_dfa_class[], encodes equivalence classes for every byte. This helps
 * cut down on the amount of transitions in the DFA-- rather than having 256 for
 * each state, we only need the number of equivalence classes, typically in the
 * tens. The second table, bbre_utf8_dfa_trans[], encodes, for each state, the
 * next state for each equivalence class. This encoding allows the DFA to be
 * reasonably compact while still fairly fast. The third table,
 * bbre_utf8_dfa_shift[], encodes the amount of significant bits to ignore for
 * each input byte when accumulating the 32-bit rune. */
/*{ Generated by `charclass_tree.py dfa` */
#define BBRE_UTF8_DFA_NUM_CLASS 13
#define BBRE_UTF8_DFA_NUM_STATE 9
static const bbre_byte bbre_utf8_dfa_class[256] = {
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
static const bbre_byte
    bbre_utf8_dfa_trans[BBRE_UTF8_DFA_NUM_STATE][BBRE_UTF8_DFA_NUM_CLASS] = {
        {0, 8, 8, 8, 8, 3, 7, 2, 6, 2, 5, 4, 1},
        {8, 2, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8},
        {8, 3, 3, 3, 8, 8, 8, 8, 8, 8, 8, 8, 8},
        {8, 0, 0, 0, 8, 8, 8, 8, 8, 8, 8, 8, 8},
        {8, 2, 2, 2, 8, 8, 8, 8, 8, 8, 8, 8, 8},
        {8, 8, 2, 2, 8, 8, 8, 8, 8, 8, 8, 8, 8},
        {8, 3, 3, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8},
        {8, 8, 8, 3, 8, 8, 8, 8, 8, 8, 8, 8, 8}
};
static const bbre_byte bbre_utf8_dfa_shift[BBRE_UTF8_DFA_NUM_CLASS] = {
    0, 0, 0, 0, 2, 2, 3, 3, 3, 3, 4, 4, 4};

/*} Generated by `charclass_tree.py dfa` */

static bbre_uint
bbre_utf8_decode(bbre_uint *state, bbre_uint *codep, bbre_uint byte)
{
  /* Lookup the equivalence class for the input byte. */
  bbre_uint cls = bbre_utf8_dfa_class[byte];
  *codep =
      *state
          /* If we're getting a continuation byte, accumulate the 6 MSB encoded
           * by it by masking by 0x3F ((1 << 6) - 1) and then shifting by 6. */
          ? (byte & 0x3F) | (*codep << 6)
          /* Otherwise, we got a start byte (or just an ASCII byte); reset codep
             and accumulate the relevant MSB according to the shift table. */
          : (0xFF >> bbre_utf8_dfa_shift[cls]) & byte;
  /* Then execute the transition encoded in the transition table. */
  *state = bbre_utf8_dfa_trans[*state][cls];
  return *state;
}

/* Create and propagate a parsing error.
 * Returns `BBRE_ERR_PARSE` unconditionally. */
static int bbre_err_parse(bbre *r, const char *msg)
{
  bbre_error_set(&r->error, msg);
  r->error.pos = r->expr_pos;
  return BBRE_ERR_PARSE;
}

/* Check if we are at the end of the regex string. */
static int bbre_parse_has_more(bbre *r) { return r->expr_pos != r->expr_size; }

/* Get the next input codepoint. This function assumes that there is a valid
 * codepoint left in the input string, so it will abort the program if there is
 * none. */
static bbre_uint bbre_parse_next(bbre *r)
{
  bbre_uint state = 0, codep;
  assert(bbre_parse_has_more(r));
  while (bbre_utf8_decode(&state, &codep, r->expr[r->expr_pos++]) != 0)
    assert(r->expr_pos < r->expr_size);
  assert(state == 0);
  return codep;
}

/* Get the next input codepoint, or raise a parse error with the given error
 * message if there is no more input. */
static int bbre_parse_next_or(bbre *r, bbre_uint *codep, const char *else_msg)
{
  int err = 0;
  assert(else_msg);
  if (!bbre_parse_has_more(r)) {
    err = bbre_err_parse(r, else_msg);
    goto error;
  }
  *codep = bbre_parse_next(r);
error:
  return err;
}

/* Check that the input string is well-formed UTF-8. */
static int bbre_parse_checkutf8(bbre *r)
{
  bbre_uint state = 0, codep;
  int err = 0;
  while (r->expr_pos < r->expr_size &&
         bbre_utf8_decode(&state, &codep, r->expr[r->expr_pos]) !=
             BBRE_UTF8_DFA_NUM_STATE - 1)
    r->expr_pos++;
  if (state != 0) {
    err = bbre_err_parse(r, "invalid utf-8 sequence");
    goto error;
  }
  r->expr_pos = 0;
error:
  return err;
}

/* Without advancing the parser, check the next character. */
static bbre_uint bbre_peek_next(bbre *r)
{
  size_t prev_pos = r->expr_pos;
  bbre_uint out = bbre_parse_next(r);
  r->expr_pos = prev_pos;
  return out;
}

/* Sentinel value to represent an infinite repetition. */
#define BBRE_INFTY (BBRE_LIMIT_REPETITION_COUNT + 1)

/* Based on node precedence, pop nodes on the operator stack. */
static bbre_uint bbre_ast_pop_prec(bbre *r, bbre_ast_type pop_type)
{
  bbre_uint popped = BBRE_NIL;
  assert(bbre_buf_size(r->op_stk));
  /* The top node is the cat node, it should always be popped. */
  popped = bbre_buf_pop(&r->op_stk);
  while (bbre_buf_size(r->op_stk)) {
    bbre_uint top_ref = *bbre_buf_peek(&r->op_stk, 0);
    bbre_ast_type top_type = *bbre_ast_type_ref(r, top_ref);
    bbre_uint top_prec = bbre_ast_type_infos[top_type].prec,
              pop_prec = bbre_ast_type_infos[pop_type].prec;
    if (top_prec < pop_prec)
      popped = bbre_buf_pop(&r->op_stk);
    else
      break;
  }
  return popped;
}

/* Link the top node on the AST stack to the preceding node on the stack. */
static void bbre_ast_fix(bbre *r)
{
  bbre_uint top_node;
  assert(bbre_buf_size(r->op_stk) > 0);
  top_node = *bbre_buf_peek(&r->op_stk, 0);
  if (bbre_buf_size(r->op_stk) == 1)
    r->ast_root = top_node;
  else {
    bbre_uint parent_node = *bbre_buf_peek(&r->op_stk, 1);
    bbre_ast_type parent_type = *bbre_ast_type_ref(r, parent_node);
    assert(bbre_ast_type_infos[parent_type].children > 0);
    *bbre_ast_param_ref(
        r, parent_node, bbre_ast_type_infos[parent_type].children - 1) =
        top_node;
  }
}

/* Push an AST node to the operator stack, and fixup the furthest right child
 * pointer of the parent node. */
static int bbre_ast_push(bbre *r, bbre_uint node_ref)
{
  int err = 0;
  if ((err = bbre_buf_push(&r->alloc, &r->op_stk, node_ref)))
    goto error;
  bbre_ast_fix(r);
error:
  return err;
}

/* Create a CAT node on the top of the stack. */
static int bbre_ast_cat(bbre *r, bbre_uint right_child_ref)
{
  int err = 0;
  bbre_uint *top;
  assert(bbre_buf_size(r->op_stk));
  top = bbre_buf_peek(&r->op_stk, 0);
  if (!*top) {
    *top = right_child_ref;
    bbre_ast_fix(r);
  } else {
    if ((err = bbre_ast_make(r, top, BBRE_AST_TYPE_CAT, *top, right_child_ref)))
      goto error;
    bbre_ast_fix(r);
    if ((err = bbre_ast_push(r, right_child_ref)))
      goto error;
  }
error:
  return err;
}

/* Create a BBRE_AST_TYPE_CC_OR node with the given two character classes.*/
static int
bbre_ast_cls_union(bbre *r, bbre_uint *out, bbre_uint right, bbre_uint left)
{
  assert(bbre_ast_type_is_cc(*bbre_ast_type_ref(r, left)));
  assert(bbre_ast_type_is_cc(*bbre_ast_type_ref(r, right)));
  return bbre_ast_make(r, out, BBRE_AST_TYPE_CC_OR, left, right);
}

/* Create a BBRE_AST_TYPE_CC_NOT node with the given character class. */
static int bbre_ast_cls_invert(bbre *r, bbre_uint *out, bbre_uint child)
{
  assert(bbre_ast_type_is_cc(*bbre_ast_type_ref(r, child)));
  return bbre_ast_make(r, out, BBRE_AST_TYPE_CC_NOT, child);
}

/* Helper function to add a character to the argument stack.
 * Returns `BBRE_ERR_MEM` if out of memory. */
static int bbre_parse_escape_addchr(
    bbre *r, bbre_uint ch, bbre_uint allowed_outputs, bbre_uint *out)
{
  int err = 0;
  (void)allowed_outputs, assert(allowed_outputs & (1 << BBRE_AST_TYPE_CHR));
  if ((err = bbre_ast_make(r, out, BBRE_AST_TYPE_CHR, ch)))
    goto error;
error:
  return err;
}

/* Convert a hexadecimal digit to a number.
 * Returns ERR_PARSE on invalid hex digit. */
static int bbre_parse_hexdig(bbre *r, bbre_uint ch, bbre_uint *hex_digit)
{
  int err = 0;
  if (ch >= '0' && ch <= '9')
    *hex_digit = ch - '0';
  else if (ch >= 'a' && ch <= 'f')
    *hex_digit = ch - 'a' + 10;
  else if (ch >= 'A' && ch <= 'F')
    *hex_digit = ch - 'A' + 10;
  else
    err = bbre_err_parse(r, "invalid hex digit");
  return err;
}

/* Attempt to parse an octal digit, returning -1 if the digit is not an octal
 * digit, and the value of the digit in [0, 7] otherwise. */
static int bbre_parse_is_octdig(bbre_uint ch)
{
  return (ch >= '0' && ch <= '7') ? ch - '0' : -1;
}

/* These functions are automatically generated and are implemented later in this
 * file. For each type of builtin charclass, there is a function that allows us
 * to look up a charclass by name and create an AST node representing that
 * charclass.*/
static int bbre_builtin_cc_ascii(
    bbre *r, const bbre_byte *name, size_t name_len, bbre_uint *out_ref);
static int bbre_builtin_cc_unicode_property(
    bbre *r, const bbre_byte *name, size_t name_len, bbre_uint *out_ref);
static int bbre_builtin_cc_perl(
    bbre *r, const bbre_byte *name, size_t name_len, bbre_uint *out_ref);

/* This function is called after receiving a \ character when parsing an
 * expression or character class. Since some escape sequences are forbidden
 * within different contexts (for example: charclasses), a bitmap
 * `allowed_outputs` encodes, at each bit position, the respective ast_type that
 * is allowed to be created in this context. */
static int bbre_parse_escape(bbre *r, bbre_uint allowed_outputs, bbre_uint *out)
{
  bbre_uint ch;
  int err = 0;
  if ((err = bbre_parse_next_or(r, &ch, "expected escape sequence")))
    goto error;
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
      (ch == '.') ||                /* dot */
      (ch == '\\') /* escaped slash */) {
    err = bbre_parse_escape_addchr(r, ch, allowed_outputs, out);
    goto error;
  } else if (bbre_parse_is_octdig(ch) >= 0) { /* octal escape */
    int digs = 1;                             /* number of read octal digits */
    bbre_uint ord = ch - '0';                 /* accumulates ordinal value */
    while (digs++ < 3 && bbre_parse_has_more(r) &&
           bbre_parse_is_octdig(ch = bbre_peek_next(r)) >= 0) {
      /* read up to two more octal digits -- for now, we allow octal encodings
       * of codepoints larger than 0xFF. This may change if we allow byte-wise
       * regexps */
      ch = bbre_parse_next(r);
      assert(!err && bbre_parse_is_octdig(ch) >= 0);
      ord = ord * 8 + bbre_parse_is_octdig(ch);
    }
    err = bbre_parse_escape_addchr(r, ord, allowed_outputs, out);
    goto error;
  } else if (ch == 'x') { /* hex escape */
    bbre_uint ord = 0 /* accumulates ordinal value */,
              hex_dig = 0 /* the digit being read */;
    if ((err = bbre_parse_next_or(
             r, &ch, "expected two hex characters or a bracketed hex literal")))
      goto error;
    if (ch == '{') {      /* bracketed hex lit */
      bbre_uint digs = 0; /* number of read hex digits */
      while (1) {
        if (digs == 7) {
          err = bbre_err_parse(r, "expected up to six hex characters");
          goto error;
        }
        if ((err = bbre_parse_next_or(
                 r, &ch, "expected up to six hex characters")))
          goto error;
        if (ch == '}')
          break;
        if ((err = bbre_parse_hexdig(r, ch, &hex_dig)))
          goto error;
        ord = ord * 16 + hex_dig;
        digs++;
      }
      if (!digs) {
        err = bbre_err_parse(r, "expected at least one hex character");
        goto error;
      }
    } else {
      /* two digit hex lit */
      if ((err = bbre_parse_hexdig(r, ch, &hex_dig)))
        goto error;
      ord = hex_dig;
      if ((err = bbre_parse_next_or(r, &ch, "expected two hex characters")))
        goto error;
      else if ((err = bbre_parse_hexdig(r, ch, &hex_dig)))
        goto error;
      ord = ord * 16 + hex_dig;
    }
    if (ord > BBRE_UTF_MAX)
      return bbre_err_parse(r, "ordinal value out of range [0, 0x10FFFF]");
    return bbre_parse_escape_addchr(r, ord, allowed_outputs, out);
  } else if (ch == 'C') { /* any byte: \C */
    if (!(allowed_outputs & (1 << BBRE_AST_TYPE_ANYBYTE))) {
      err = bbre_err_parse(r, "cannot use \\C here");
      goto error;
    }
    if ((err = bbre_ast_make(r, out, BBRE_AST_TYPE_ANYBYTE)))
      goto error;
  } else if (ch == 'Q') { /* quote string */
    bbre_uint cat = BBRE_NIL /* accumulator for concatenations */,
              chr = BBRE_NIL /* generated chr node for each character in
                                   the quoted string */
        ;
    if (!(allowed_outputs & (1 << BBRE_AST_TYPE_CAT))) {
      err = bbre_err_parse(r, "cannot use \\Q...\\E here");
      goto error;
    }
    while (bbre_parse_has_more(r)) {
      ch = bbre_parse_next(r);
      if (ch == '\\' && bbre_parse_has_more(r)) {
        /* mini-escape dsl for \Q..\E */
        ch = bbre_peek_next(r);
        if (ch == 'E') {
          /* \E : actually end the quote */
          ch = bbre_parse_next(r);
          assert(ch == 'E');
          *out = cat;
          goto error;
        } else if (ch == '\\') {
          /* \\ : insert a literal backslash */
          ch = bbre_parse_next(r);
          assert(ch == '\\');
        } else {
          /* \<c> : all other characters, insert a literal backslash, and
           * process the next character normally */
          ch = '\\';
        }
      }
      if ((err = bbre_ast_make(r, &chr, BBRE_AST_TYPE_CHR, ch)))
        goto error;
      /* create a cat node with the character and an epsilon node, replace the
       * old cat node (cat) with the new one (cat') through the &cat ref */
      if ((err = bbre_ast_make(r, &cat, BBRE_AST_TYPE_CAT, cat, chr)))
        goto error;
    }
    /* we got to the end of the string: push the partial quote */
    *out = cat;
  } else if (
      ch == 'D' || ch == 'd' || ch == 'S' || ch == 's' || ch == 'W' ||
      ch == 'w') {
    /* Perl builtin character classes */
    int inverted =
        ch == 'D' || ch == 'S' || ch == 'W'; /* uppercase are inverted */
    bbre_byte lower = inverted ? ch - 'A' + 'a' : ch; /* convert to lowercase */
    if (!(allowed_outputs & (1 << BBRE_AST_TYPE_CC_BUILTIN))) {
      err = bbre_err_parse(r, "cannot use a character class here");
      goto error;
    }
    /* lookup the charclass, optionally invert it */
    if ((err = bbre_builtin_cc_perl(r, &lower, 1, out)))
      goto error;
    if (inverted && (err = bbre_ast_cls_invert(r, out, *out)))
      goto error;
  } else if (ch == 'P' || ch == 'p') { /* Unicode properties */
    size_t name_start_pos = r->expr_pos, name_end_pos;
    int inverted = ch == 'P';
    const char *err_msg =
        "expected one-character property name or bracketed property name "
        "for Unicode property escape";
    if ((err = bbre_parse_next_or(r, &ch, err_msg)))
      goto error;
    if (ch == '{') { /* bracketed property */
      name_start_pos = r->expr_pos;
      while (ch != '}')
        /* read characters until we get to the end of the brack prop */
        if ((err = bbre_parse_next_or(
                 r, &ch, "expected '}' to close bracketed property name")))
          goto error;
      name_end_pos = r->expr_pos - 1;
    } else
      /* single-character property */
      name_end_pos = r->expr_pos;
    if (!(allowed_outputs & (1 << BBRE_AST_TYPE_CC_BUILTIN))) {
      err = bbre_err_parse(r, "cannot use a character class here");
      goto error;
    }
    assert(name_end_pos >= name_start_pos);
    if ((err = bbre_builtin_cc_unicode_property(
             r, r->expr + name_start_pos, name_end_pos - name_start_pos, out)))
      goto error;
    if (inverted && (err = bbre_ast_cls_invert(r, out, *out)))
      goto error;
  } else if (ch == 'A' || ch == 'z' || ch == 'B' || ch == 'b') {
    /* empty asserts */
    if (!(allowed_outputs & (1 << BBRE_AST_TYPE_ASSERT))) {
      err = bbre_err_parse(r, "cannot use an epsilon assertion here");
      goto error;
    }
    if ((err = bbre_ast_make(
             r, out, BBRE_AST_TYPE_ASSERT,
             ch == 'A'   ? BBRE_ASSERT_TEXT_BEGIN
             : ch == 'z' ? BBRE_ASSERT_TEXT_END
             : ch == 'B' ? BBRE_ASSERT_NOT_WORD
                         : BBRE_ASSERT_WORD)))
      goto error;
  } else {
    err = bbre_err_parse(r, "invalid escape sequence");
    goto error;
  }
error:
  return err;
}

/* Parse a decimal number, up to `max_digits`, into *out. */
static int bbre_parse_number(bbre *r, bbre_uint *out, bbre_uint max_digits)
{
  int err = 0;
  bbre_uint ch, acc = 0, ndigs = 0;
  if (!bbre_parse_has_more(r)) {
    err = bbre_err_parse(r, "expected at least one decimal digit");
    goto error;
  }
  while (ndigs < max_digits && bbre_parse_has_more(r) &&
         (ch = bbre_peek_next(r)) >= '0' && ch <= '9')
    acc = acc * 10 + (bbre_parse_next(r) - '0'), ndigs++;
  if (!ndigs) {
    err = bbre_err_parse(r, "expected at least one decimal digit");
    goto error;
  }
  if (ndigs == max_digits) {
    err = bbre_err_parse(r, "too many digits for decimal number");
    goto error;
  }
  *out = acc;
error:
  return err;
}

/* Parse a regular expression, storing its resulting AST node into *root. */
static int
bbre_parse(bbre *r, const bbre_byte *ts, size_t tsz, bbre_flags start_flags)
{
  int err;
  r->expr = ts;
  r->expr_size = tsz, r->expr_pos = 0;
  if ((err = bbre_parse_checkutf8(r)))
    goto error;
  assert(!bbre_buf_size(r->op_stk));
  /* push the initial epsilon node */
  if ((err = bbre_ast_push(r, BBRE_NIL)))
    goto error;
  while (bbre_parse_has_more(r)) {
    bbre_uint ch = bbre_parse_next(r), res = BBRE_NIL;
    assert(bbre_buf_size(r->op_stk));
    if (ch == '*' || ch == '+' || ch == '?' || ch == '{') { /* quantifiers */
      bbre_uint greedy = 1, min_rep, max_rep;
      if (*bbre_buf_peek(&r->op_stk, 0) == BBRE_NIL) {
        err = bbre_err_parse(r, "cannot apply quantifier to empty regex");
        goto error;
      }
      if (ch != '{')
        min_rep = ch == '+', max_rep = ch == '?' ? 1 : BBRE_INFTY;
      else { /* counted repetition */
        if ((err = bbre_parse_number(r, &min_rep, 6)))
          goto error;
        if ((err = bbre_parse_next_or(
                 r, &ch, "expected } to end repetition expression")))
          goto error;
        if (ch == '}')
          /* single number: simple repetition */
          max_rep = min_rep;
        else if (ch == ',') {
          /* comma: either `min_rep` or more, or `min_rep` to `max_rep` */
          if (!bbre_parse_has_more(r)) {
            err = bbre_err_parse(
                r, "expected upper bound or } to end repetition expression");
            goto error;
          }
          ch = bbre_peek_next(r);
          if (ch == '}')
            /* `min_rep` or more (`min_rep` - `INFTY`) */
            ch = bbre_parse_next(r), assert(ch == '}'), max_rep = BBRE_INFTY;
          else {
            /* `min_rep` to `max_rep` */
            if ((err = bbre_parse_number(r, &max_rep, 6)))
              goto error;
            if ((err = bbre_parse_next_or(
                     r, &ch, "expected } to end repetition expression")))
              goto error;
            if (ch != '}') {
              err =
                  bbre_err_parse(r, "expected } to end repetition expression");
              goto error;
            }
          }
        } else {
          err = bbre_err_parse(r, "expected } or , for repetition expression");
          goto error;
        }
      }
      if (bbre_parse_has_more(r) && bbre_peek_next(r) == '?')
        bbre_parse_next(r), greedy = !greedy;
      /* pop one from op stk, create quant, push to op stk */
      if ((err = bbre_ast_make(
               r, &res, greedy ? BBRE_AST_TYPE_QUANT : BBRE_AST_TYPE_UQUANT,
               *bbre_buf_peek(&r->op_stk, 0), min_rep, max_rep)))
        goto error;
      *bbre_buf_peek(&r->op_stk, 0) = res;
      bbre_ast_fix(r);
    } else if (ch == '|') {
      /* pop nodes from op stk until we get one of lower precedence */
      bbre_uint child = bbre_ast_pop_prec(r, BBRE_AST_TYPE_ALT);
      if ((err = bbre_ast_make(
               r, &res, BBRE_AST_TYPE_ALT, child /* left */,
               BBRE_NIL /* right */)))
        goto error;
      /* we just made space for this node in pop_prec() */
      err = bbre_ast_push(r, res);
      assert(!err);
      if ((err = bbre_ast_push(r, BBRE_NIL)))
        goto error;
    } else if (ch == '(') {
      /* capture group */
      bbre_uint inline_group = 0, named_group = 0, hi_flags = 0, lo_flags = 0;
      size_t name_start = 0, name_end = name_start;
      if (!bbre_parse_has_more(r)) {
        err = bbre_err_parse(r, "expected ')' to close group");
        goto error;
      }
      ch = bbre_peek_next(r);
      if (ch == '?') { /* start of group flags */
        ch = bbre_parse_next(r);
        assert(ch == '?'); /* this assert is probably too paranoid */
        if ((err = bbre_parse_next_or(
                 r, &ch,
                 "expected 'P', '<', or group flags after special "
                 "group opener \"(?\"")))
          goto error;
        if (ch == 'P' || ch == '<') {
          /* group name */
          if (ch == 'P' &&
              (err = bbre_parse_next_or(
                   r, &ch, "expected '<' after named group opener \"(?P\"")))
            goto error;
          if (ch != '<') {
            err = bbre_err_parse(
                r, "expected '<' after named group opener \"(?P\"");
            goto error;
          }
          /* parse group name */
          named_group = 1;
          name_start = r->expr_pos;
          while (1) {
            /* read characters until > */
            if ((err = bbre_parse_next_or(
                     r, &ch, "expected name followed by '>' for named group")))
              goto error;
            if (ch == '>')
              break;
          }
          name_end = r->expr_pos - 1; /* backtrack behind > */
        } else {
          bbre_uint neg = 0 /* should we negate flags? */,
                    flag = BBRE_GROUP_FLAG_UNGREEDY; /* default flag (this makes
                                                  coverage testing simpler) */
          while (1) {
            if (ch == ':' /* noncapturing */ || ch == ')' /* inline */)
              break;
            else if (ch == '-') {
              /* negate subsequent flags */
              if (neg) {
                err = bbre_err_parse(r, "cannot apply flag negation '-' twice");
                goto error;
              }
              neg = 1;
            } else if (
                (ch == 'i' && (flag = BBRE_GROUP_FLAG_INSENSITIVE)) ||
                (ch == 'm' && (flag = BBRE_GROUP_FLAG_MULTILINE)) ||
                (ch == 's' && (flag = BBRE_GROUP_FLAG_DOTNEWLINE)) ||
                (ch == 'u')) {
              /* unset bit if negated, set bit if not */
              if (!neg)
                hi_flags |= flag;
              else
                lo_flags |= flag;
            } else {
              err = bbre_err_parse(
                  r, "expected ':', ')', or group flags for special group");
              goto error;
            }
            if ((err = bbre_parse_next_or(
                     r, &ch,
                     "expected ':', ')', or group flags for special group")))
              goto error;
          }
          hi_flags |= BBRE_GROUP_FLAG_NONCAPTURING;
          if (ch == ')')
            /* flags only with no : to denote actual pattern */
            inline_group = 1;
        }
      }
      assert(BBRE_IMPLIES(inline_group, !named_group));
      assert(BBRE_IMPLIES(named_group, !inline_group));
      if (named_group && (name_end - name_start) > BBRE_LIMIT_GROUP_NAME_SIZE) {
        bbre_error_set(&r->error, "group name exceeds maximum length");
        err = BBRE_ERR_LIMIT;
        goto error;
      }
      if (!inline_group) {
        if ((err = bbre_ast_make(
                 r, &res, BBRE_AST_TYPE_GROUP, BBRE_NIL, hi_flags, lo_flags,
                 bbre_buf_size(r->group_names) + 1)))
          goto error;
      } else if ((err = bbre_ast_make(
                      r, &res, BBRE_AST_TYPE_IGROUP, BBRE_NIL, hi_flags,
                      lo_flags)))
        goto error;
      if ((err = bbre_ast_cat(r, res)) || (err = bbre_ast_push(r, BBRE_NIL)))
        goto error;
      if (!inline_group && !(hi_flags & BBRE_GROUP_FLAG_NONCAPTURING)) {
        bbre_group_name name;
        name.name_size = name_end - name_start;
        name.name = NULL;
        if (named_group) {
          if (!(name.name =
                    bbre_ialloc(&r->alloc, name.name, 0, name.name_size + 1))) {
            err = BBRE_ERR_MEM;
            goto error;
          }
          memcpy(name.name, r->expr + name_start, name.name_size);
          name.name[name.name_size] = '\0';
        }
        if ((err = bbre_buf_push(&r->alloc, &r->group_names, name))) {
          /* clean up allocated name, preserves atomicity */
          bbre_ialloc(&r->alloc, name.name, name.name_size, 0);
          goto error;
        }
      }
      hi_flags &= ~(BBRE_GROUP_FLAG_NONCAPTURING);
    } else if (ch == ')') {
      /* pop the cat node */
      res = bbre_ast_pop_prec(r, BBRE_AST_TYPE_GROUP);
      if (!bbre_buf_size(r->op_stk)) {
        err = bbre_err_parse(r, "extra close parenthesis");
        goto error;
      }
    } else if (ch == '.') { /* any char */
      if ((err = bbre_ast_make(r, &res, BBRE_AST_TYPE_ANYCHAR)) ||
          (err = bbre_ast_cat(r, res)))
        goto error;
    } else if (ch == '[') {              /* charclass */
      size_t cc_start_pos = r->expr_pos; /* starting position of charclass */
      bbre_uint inverted = 0 /* is the charclass inverted? */,
                min /* min value of range */, max /* max value of range */;
      res = BBRE_NIL; /* resulting CC node */
      while (1) {
        bbre_uint next; /* temp var to store child classes */
        if ((err = bbre_parse_next_or(r, &ch, "unclosed character class")))
          goto error;
        if ((r->expr_pos - cc_start_pos == 1) && ch == '^') {
          inverted = 1; /* caret at start of CC */
          continue;
        }
        min = ch;
        if (ch == ']') {
          if ((r->expr_pos - cc_start_pos == 1 ||
               (r->expr_pos - cc_start_pos == 2 && inverted))) {
            min = ch; /* charclass starts with ] */
          } else
            break;               /* charclass done */
        } else if (ch == '\\') { /* escape */
          if ((err = bbre_parse_escape(
                   r,
                   (1 << BBRE_AST_TYPE_CHR) | (1 << BBRE_AST_TYPE_CC_BUILTIN |
                                               (1 << BBRE_AST_TYPE_CC_LEAF)),
                   &next)))
            /* parse_escape() could return ERR_PARSE if for example \A */
            goto error;
          assert(
              *bbre_ast_type_ref(r, next) == BBRE_AST_TYPE_CHR ||
              bbre_ast_type_is_cc(*bbre_ast_type_ref(r, next)));
          if (*bbre_ast_type_ref(r, next) == BBRE_AST_TYPE_CHR)
            min = *bbre_ast_param_ref(r, next, 0); /* single-character escape */
          else {
            assert(bbre_ast_type_is_cc(*bbre_ast_type_ref(r, next)));
            if (res && (err = bbre_ast_cls_union(r, &res, res, next)))
              goto error;
            else if (!res)
              res = next;
            /* we parsed an entire class, so there's no ending character */
            continue;
          }
        } else if (
            ch == '[' && bbre_parse_has_more(r) &&
            bbre_peek_next(r) == ':') { /* named class */
          int named_inverted = 0;
          size_t name_start_pos, name_end_pos;
          ch = bbre_parse_next(r); /* : */
          assert(!err && ch == ':');
          if (bbre_parse_has_more(r) &&
              (ch = bbre_peek_next(r)) == '^') { /* inverted named class */
            ch = bbre_parse_next(r);
            assert(ch == '^');
            named_inverted = 1;
          }
          name_start_pos = name_end_pos = r->expr_pos;
          while (1) {
            /* parse character class name */
            if ((err = bbre_parse_next_or(
                     r, &ch, "expected character class name")))
              goto error;
            if (ch == ':')
              break;
            name_end_pos = r->expr_pos;
          }
          if ((err = bbre_parse_next_or(
                   r, &ch,
                   "expected closing bracket for named character class")))
            goto error;
          if (ch != ']') {
            err = bbre_err_parse(
                r, "expected closing bracket for named character class");
            goto error;
          }
          /* lookup the charclass name in the labyrinth of tables */
          if ((err = bbre_builtin_cc_ascii(
                   r, r->expr + name_start_pos, (name_end_pos - name_start_pos),
                   &res)))
            goto error;
          if (named_inverted && (err = bbre_ast_cls_invert(r, &res, res)))
            goto error;
          /* ensure that builtin_cc_ascii returned a value */
          assert(res && bbre_ast_type_is_cc(*bbre_ast_type_ref(r, res)));
          continue;
        }
        max = min;
        if (bbre_parse_has_more(r) && bbre_peek_next(r) == '-') {
          /* optional range expression */
          ch = bbre_parse_next(r);
          assert(ch == '-');
          if ((err = bbre_parse_next_or(
                   r, &ch,
                   "expected ending character after '-' for character class "
                   "range expression")))
            goto error;
          if (ch == '\\') { /* start of escape */
            if ((err = bbre_parse_escape(r, (1 << BBRE_AST_TYPE_CHR), &next)))
              goto error;
            assert(*bbre_ast_type_ref(r, next) == BBRE_AST_TYPE_CHR);
            max = *bbre_ast_param_ref(r, next, 0);
          } else {
            max = ch; /* non-escaped character */
          }
        }
        {
          bbre_uint tmp;
          if ((err = bbre_ast_make(
                   r, &tmp, BBRE_AST_TYPE_CC_LEAF, min < max ? min : max,
                   min < max ? max : min)))
            goto error;
          if (res != BBRE_NIL) {
            if ((err = bbre_ast_make(r, &res, BBRE_AST_TYPE_CC_OR, res, tmp)))
              goto error;
          } else
            res = tmp;
        }
      }
      assert(res); /* charclass cannot be empty */
      if (inverted &&
          ((err = bbre_ast_make(r, &res, BBRE_AST_TYPE_CC_NOT, res))))
        /* inverted character class */
        goto error;
      if ((err = bbre_ast_cat(r, res)))
        goto error;
    } else if (ch == '\\') { /* escape */
      if ((err = bbre_parse_escape(
               r,
               1 << BBRE_AST_TYPE_CHR | 1 << BBRE_AST_TYPE_CC_LEAF |
                   1 << BBRE_AST_TYPE_CC_BUILTIN | 1 << BBRE_AST_TYPE_ANYBYTE |
                   1 << BBRE_AST_TYPE_CAT | 1 << BBRE_AST_TYPE_ASSERT,
               &res)) ||
          (err = bbre_ast_cat(r, res)))
        goto error;
    } else if (ch == '^' || ch == '$') { /* beginning/end of text/line */
      /* these are similar enough that I put them into one condition */
      if ((err = bbre_ast_make(
               r, &res, BBRE_AST_TYPE_ASSERT,
               ch == '^' ? BBRE_ASSERT_LINE_BEGIN : BBRE_ASSERT_LINE_END)) ||
          (err = bbre_ast_cat(r, res)))
        goto error;
    } else { /* char */
      if ((err = bbre_ast_make(r, &res, BBRE_AST_TYPE_CHR, ch)) ||
          (err = bbre_ast_cat(r, res)))
        goto error;
    }
  }
  bbre_buf_pop(&r->op_stk); /* pop argument node */
  while (bbre_buf_size(r->op_stk)) {
    if (*bbre_ast_type_ref(r, bbre_buf_pop(&r->op_stk)) ==
        BBRE_AST_TYPE_GROUP) {
      err = bbre_err_parse(r, "unmatched open parenthesis");
      goto error;
    }
  }
  /* wrap the top node into a nonmatching subexpression group to denote a
   * subpattern */
  if ((err = bbre_ast_make(
           r, &r->ast_root, BBRE_AST_TYPE_GROUP, r->ast_root,
           BBRE_GROUP_FLAG_EXPRESSION |
               /* convert ABI flags to internal flags */
               BBRE_GROUP_FLAG_INSENSITIVE *
                   !!(start_flags & BBRE_FLAG_INSENSITIVE) |
               BBRE_GROUP_FLAG_MULTILINE *
                   !!(start_flags & BBRE_FLAG_MULTILINE) |
               BBRE_GROUP_FLAG_DOTNEWLINE *
                   !!(start_flags & BBRE_FLAG_DOTNEWLINE) |
               BBRE_GROUP_FLAG_UNGREEDY * !!(start_flags & BBRE_FLAG_UNGREEDY),
           0, 0)))
    goto error;
error:
  return err;
}

/* Get the opcode of an instruction. */
static bbre_opcode bbre_inst_opcode(bbre_inst i)
{
  return i.opcode_next & ((1 << BBRE_INST_OPCODE_BITS) - 1);
}

/* Get the primary branch target of the instruction. All instructions have this
 * field. */
static bbre_uint bbre_inst_next(bbre_inst i)
{
  return i.opcode_next >> BBRE_INST_OPCODE_BITS;
}

/* Get the instruction-specific parameter of the instruction. Different
 * instructions assign different meanings to this param. */
static bbre_uint bbre_inst_param(bbre_inst i) { return i.param; }

/* Make an instruction from the relevant fields. */
static bbre_inst bbre_inst_make(bbre_opcode op, bbre_uint next, bbre_uint param)
{
  bbre_inst out;
  out.opcode_next = op | next << BBRE_INST_OPCODE_BITS, out.param = param;
  return out;
}

/* Make the parameter for a match instruction. */
static bbre_uint bbre_inst_match_param_make(
    bbre_uint begin_or_end, bbre_uint slot_idx_or_set_idx)
{
  assert(begin_or_end == 0 || begin_or_end == 1);
  return begin_or_end | (slot_idx_or_set_idx << 1);
}

/* Retrieve the end flag from a match instruction's parameter. */
static bbre_uint bbre_inst_match_param_end(bbre_uint param)
{
  return param & 1;
}

/* Retrieve the index number from a match instruction's parameter. */
static bbre_uint bbre_inst_match_param_idx(bbre_uint param)
{
  return param >> 1;
}

/* Set the program instruction at `pc` to `i`. */
static void bbre_prog_set(bbre_prog *prog, bbre_uint pc, bbre_inst i)
{
  prog->prog[pc] = i;
}

/* Get the program instruction at `pc`. */
static bbre_inst bbre_prog_get(const bbre_prog *prog, bbre_uint pc)
{
  return prog->prog[pc];
}

/* Get the size (number of instructions) in the program. */
static bbre_uint bbre_prog_size(const bbre_prog *prog)
{
  return bbre_buf_size(prog->prog);
}

/* The maximum number ofinstructions allowed in a program. */
#define BBRE_PROG_LIMIT_MAX_INSTS 100000

/* Append the instruction `i` to the program. Also add the relevant subpattern
 * index to the `prog_set_idxs` buf. */
static int bbre_prog_emit(bbre_prog *prog, bbre_inst i, bbre_uint pat_idx)
{
  int err = 0;
  if (bbre_prog_size(prog) == BBRE_PROG_LIMIT_MAX_INSTS) {
    err = BBRE_ERR_LIMIT;
    bbre_error_set(prog->error, "maximum compiled program size exceeded");
    goto error;
  }
  if ((err = bbre_buf_push(&prog->alloc, &prog->prog, i)) ||
      (err = bbre_buf_push(&prog->alloc, &prog->set_idxs, pat_idx)))
    goto error;
error:
  return err;
}

/* According to the value of `pc_param`, set either the primary branch target
 * or, if the instruction at the given pc is a `SPLIT` instruction, the
 * secondary branch target, according to the LSB in `pc_secondary`.
 * The LSB of `pc_secondary` encodes whether or not to use the `next` or the
 * `param` field for the target instruction. The rest of the bits in
 * `pc_secondary` encode the actual PC. */
static bbre_inst bbre_patch_set(bbre *r, bbre_uint pc_secondary, bbre_uint val)
{
  bbre_inst prev = bbre_prog_get(&r->prog, pc_secondary >> 1);
  assert(pc_secondary);
  /* Only SPLIT instructions have a secondary branch target. */
  assert(BBRE_IMPLIES(
      pc_secondary & 1, bbre_inst_opcode(prev) == BBRE_OPCODE_SPLIT));
  bbre_prog_set(
      &r->prog, pc_secondary >> 1,
      bbre_inst_make(
          bbre_inst_opcode(prev), pc_secondary & 1 ? bbre_inst_next(prev) : val,
          pc_secondary & 1 ? val : bbre_inst_param(prev)));
  return prev;
}

/* Add `dest_pc` to `f`'s linked list of patches. If `secondary` is 1, then the
 * secondary branch target of the instruction at `dest_pc` will be used. */
static void
bbre_patch_add(bbre *r, bbre_compframe *f, bbre_uint dest_pc, int secondary)
{
  bbre_uint out_val = dest_pc << 1 | !!secondary;
  assert(dest_pc);
  if (!f->head)
    /* the initial patch is just as the head and tail */
    f->head = f->tail = out_val;
  else {
    /* subsequent patch additions append to the tail of the list */
    bbre_patch_set(r, f->tail, out_val);
    f->tail = out_val;
  }
}

/* Concatenate the patches in `p` with the patches in `q`. */
static void bbre_patch_merge(bbre *r, bbre_compframe *p, bbre_compframe *q)
{
  if (!p->head) {
    p->head = q->head;
    p->tail = q->tail;
    goto done;
  }
  if (!q->head)
    goto done;
  bbre_patch_set(r, p->tail, q->head);
  p->tail = q->tail;
  q->head = q->tail = BBRE_NIL;
done:
  return;
}

/* Transfer ownership of a patch list from `src` to `dst`. */
static void bbre_patch_xfer(bbre_compframe *dst, bbre_compframe *src)
{
  dst->head = src->head;
  dst->tail = src->tail;
  src->head = src->tail = BBRE_NIL;
}

/* Rip through the patch list in `f`, setting each branch target in the
 * instruction list to `dest_pc`. */
static void bbre_patch_apply(bbre *r, bbre_compframe *f, bbre_uint dest_pc)
{
  bbre_uint i = f->head;
  while (i) {
    bbre_inst prev = bbre_patch_set(r, i, dest_pc);
    i = i & 1 ? bbre_inst_param(prev) : bbre_inst_next(prev);
  }
  f->head = f->tail = BBRE_NIL;
}

/* This function is automatically generated and is defined later on. */
static int bbre_compcc_fold_range(
    bbre *r, bbre_rune_range range, bbre_compframe *frame, bbre_uint prev);

static int bbre_compile_cc_append(
    bbre *r, bbre_compframe *frame, bbre_uint prev, bbre_rune_range range)
{
  int err = 0;
  bbre_cc_elem elem = {0};
  bbre_uint next = BBRE_NIL;
  assert(!!frame->head == !!frame->tail && !!frame->tail == !!prev);
  assert(BBRE_IMPLIES(frame->tail, !r->cc_store[frame->tail].next));
  /* Get a new elem in cc_store. */
  if (!bbre_buf_size(r->cc_store)) {
    /* Add the nil element. */
    if ((err = bbre_buf_push(&r->alloc, &r->cc_store, elem)))
      goto error;
  }
  if (!r->cc_store_empty) {
    /* Need to allocate a new element. */
    next = (bbre_uint)bbre_buf_size(r->cc_store);
    if ((err = bbre_buf_push(&r->alloc, &r->cc_store, elem)))
      goto error;
  } else {
    /* Can reuse a previous element. */
    next = r->cc_store_empty;
    r->cc_store_empty = r->cc_store[r->cc_store_empty].next;
  }
  elem.range = range;
  elem.next = BBRE_NIL;
  r->cc_store[next] = elem;
  if (!frame->tail) {
    frame->head = frame->tail = next;
  } else {
    r->cc_store[next].next = prev ? r->cc_store[prev].next : BBRE_NIL;
    if (!prev)
      frame->head = prev;
    else
      r->cc_store[prev].next = next;
    if (prev == frame->tail)
      frame->tail = next;
  }
error:
  return err;
}

static void bbre_compile_cc_append_unwrapped(
    bbre *r, bbre_compframe *frame, bbre_uint prev, bbre_rune_range range)
{
  int err = bbre_compile_cc_append(r, frame, prev, range);
  assert(!err);
  (void)(err); /* for when assert() is not defined */
}

static bbre_rune_range
bbre_compile_cc_pop(bbre *r, bbre_compframe *frame, bbre_uint prev)
{
  bbre_uint ref;
  assert(frame->head && frame->tail); /* list must contain elements */
  assert(prev != frame->tail);
  assert(BBRE_IMPLIES(prev, r->cc_store[prev].next));
  if (prev == BBRE_NIL)
    ref = frame->head, frame->head = r->cc_store[frame->head].next;
  else
    ref = r->cc_store[prev].next,
    r->cc_store[prev].next = r->cc_store[r->cc_store[prev].next].next;
  if (frame->head == BBRE_NIL)
    frame->tail = frame->head;
  r->cc_store[ref].next = r->cc_store_empty;
  r->cc_store_empty = ref;
  return r->cc_store[ref].range;
}

static void bbre_compile_cc_link(bbre *r, bbre_compframe *a, bbre_compframe *b)
{
  if (!a->head)
    a->head = b->head;
  else
    r->cc_store[a->tail].next = b->head;
  if (b->tail)
    a->tail = b->tail;
}

/* An excellent algorithm by Simon Tatham, of PuTTY fame:
 * https://www.chiark.greenend.org.uk/~sgtatham/algorithms/listsort.c */
static void bbre_compile_cc_normalize(bbre *r, bbre_compframe *frame)
{
  bbre_uint num_merges = 0, p, q, k = 1, p_size, q_size;
  if (!frame->head || !(frame->flags & BBRE_GROUP_FLAG_CC_DENORM))
    goto done;
  while (1) {
    num_merges = 0;
    p = frame->head;
    frame->head = BBRE_NIL;
    frame->tail = BBRE_NIL;
    while (p) {
      num_merges++;
      q = p;
      for (p_size = 0; p_size < k && q; p_size++)
        q = r->cc_store[q].next;
      q_size = k;
      while (1) {
        bbre_uint elem, p_more = p_size > 0, q_more = q_size > 0 && q;
        if (!p_more && !q_more)
          break;
        if (!q_more ||
            (p_more && r->cc_store[p].range.l <= r->cc_store[q].range.l))
          elem = p, p = r->cc_store[p].next, p_size--;
        else
          elem = q, q = r->cc_store[q].next, q_size--;
        if (!frame->tail)
          frame->head = elem;
        else
          r->cc_store[frame->tail].next = elem;
        frame->tail = elem;
      }
      p = q;
    }
    r->cc_store[frame->tail].next = BBRE_NIL;
    if (num_merges <= 1)
      break;
    k *= 2;
  }
  {
    /* normalize ranges */
    bbre_compframe new_frame = *frame;
    bbre_rune_range next /* currently processed range */,
        prev; /* previously processed range, yet to be added */
    new_frame.head = new_frame.tail = BBRE_NIL;
    p = 0;
    while (frame->head) {
      next = bbre_compile_cc_pop(r, frame, BBRE_NIL);
      if (!p)
        /* this is the first range */
        prev = bbre_rune_range_make(next.l, next.h);
      else if (next.l <= prev.h + 1) {
        /* next intersects or is adjacent to prev, merge the two ranges by
         * expanding prev so that it envelops both prev and next */
        prev.h = next.h > prev.h ? next.h : prev.h;
      } else {
        /* next and prev are disjoint */
        /* since ranges strictly increase, we know that prev does not
         * intersect with any other range in the input array, so we can push
         * it and move on. */
        bbre_compile_cc_append_unwrapped(r, &new_frame, new_frame.tail, prev);
        prev = next;
      }
      p++;
    }
    if (p)
      bbre_compile_cc_append_unwrapped(r, &new_frame, new_frame.tail, prev);
    *frame = new_frame;
  }
done:
  frame->flags = frame->flags & ~BBRE_GROUP_FLAG_CC_DENORM;
  return;
}

/* Helper function to casefold a character class being built in frame. */
static int bbre_compile_cc_casefold(bbre *r, bbre_compframe *frame)
{
  int err = 0;
  bbre_compframe new_frame = *frame;
  new_frame.head = new_frame.tail = BBRE_NIL;
  while (frame->head) {
    bbre_rune_range next = bbre_compile_cc_pop(r, frame, BBRE_NIL);
    bbre_compile_cc_append_unwrapped(r, &new_frame, new_frame.tail, next);
    if ((err = bbre_compcc_fold_range(r, next, &new_frame, new_frame.tail)))
      goto error;
  }
  bbre_compile_cc_normalize(r, &new_frame);
  *frame = new_frame;
  frame->flags |= BBRE_GROUP_FLAG_CC_DENORM;
error:
  return err;
}

/* Create a new tree node.
 * `node` is the contents of the node itself, and `out_ref` is the output node
 * ID (i.e. arena index) */
static int bbre_compcc_tree_new(
    bbre *r, bbre_buf(bbre_compcc_tree) * cc_out, bbre_compcc_tree node,
    bbre_uint *out_ref)
{
  int err = 0;
  if (!bbre_buf_size(*cc_out)) {
    bbre_compcc_tree sentinel = {0};
    /* need to create sentinel node */
    if ((err = bbre_buf_push(&r->alloc, cc_out, sentinel)))
      goto error;
  }
  if (out_ref)
    *out_ref = bbre_buf_size(*cc_out);
  if ((err = bbre_buf_push(&r->alloc, cc_out, node)))
    goto error;
error:
  return err;
}

/* Append a byte range to an existing tree node.
 * `byte_range` is the packed range of bytes (returned from
 * bbre_byte_range_to_u32()), `parent_ref` is the node ID of the parent node to
 * add to, and `out_ref` is the output node ID. */
static int bbre_compcc_tree_append(
    bbre *r, bbre_buf(bbre_compcc_tree) * cc, bbre_uint byte_range,
    bbre_uint parent_ref, bbre_uint *out_ref)
{
  bbre_compcc_tree *parent_node, child_node = {0};
  bbre_uint child_ref;
  int err;
  parent_node = (*cc) + parent_ref;
  /* link new child node to its next sibling */
  child_node.sibling_ref = parent_node->child_ref,
  child_node.range = byte_range;
  /* actually add the child to the tree */
  if ((err = bbre_compcc_tree_new(r, cc, child_node, &child_ref)))
    goto error;
  /* parent pointer may have changed, reload it */
  parent_node = (*cc) + parent_ref;
  /* set parent's child to the new child */
  parent_node->child_ref = child_ref;
  /* enforce a cuppa invariants */
  assert(parent_node->child_ref != parent_ref);
  assert(parent_node->sibling_ref != parent_ref);
  assert(child_node.child_ref != parent_node->child_ref);
  assert(child_node.sibling_ref != parent_node->child_ref);
  *out_ref = parent_node->child_ref;
error:
  return err;
}

/* Given a rune range and first/rest bits, add node(s) to the tree and
 * optionally compile the rest. */
static int bbre_compcc_tree_build_one(
    bbre *r, bbre_buf(bbre_compcc_tree) * cc_out, bbre_uint parent,
    bbre_uint min, bbre_uint max, bbre_uint rest_bits, bbre_uint first_bits)
{
  bbre_uint rest_mask = (1 << rest_bits) - 1 /* mask for only rest bits */,
            first_min = min >> rest_bits /* minimum first value */,
            first_max = max >> rest_bits /* maximum first value */,
            u_mask = (0xFE << first_bits) &
                     0xFF /* 0b11111110 << first_bits, used to build an actual
                             UTF-8 starting byte */
      ,
            byte_min =
                (first_min & 0xFF) | u_mask /* the minimum starting byte */,
            byte_max =
                (first_max & 0xFF) | u_mask /* the maximum starting byte */,
            i, next;
  int err = 0;
  assert(first_bits <= 7);
  if (rest_bits == 0) {
    /* Final continuation byte or ASCII (terminal) */
    if ((err = bbre_compcc_tree_append(
             r, cc_out,
             bbre_byte_range_to_u32(bbre_byte_range_make(byte_min, byte_max)),
             parent, &next)))
      goto error;
  } else {
    /* nonterminal */
    bbre_uint rest_min = min & rest_mask, rest_max = max & rest_mask, brs[3],
              mins[3], maxs[3], n;
    if (first_min == first_max || (rest_min == 0 && rest_max == rest_mask)) {
      /* Range can be split into either a single byte followed by a range,
       * _or_ one range followed by another maximal range */
      /* Output:
       * ---[FirstMin-FirstMax]---{tree for [RestMin-Xmax]} */
      brs[0] = bbre_byte_range_to_u32(bbre_byte_range_make(byte_min, byte_max));
      mins[0] = rest_min, maxs[0] = rest_max;
      n = 1;
    } else if (!rest_min) {
      /* Range begins on zero, but has multiple starting bytes */
      /* Output:
       * ---[FirstMin-(FirstMax-1)]---{tree for [00-FF]}
       *           |
       *      [FirstMax-FirstMax]----{tree for [00-RestMax]} */
      brs[0] =
          bbre_byte_range_to_u32(bbre_byte_range_make(byte_min, byte_max - 1));
      mins[0] = 0, maxs[0] = rest_mask;
      brs[1] = bbre_byte_range_to_u32(bbre_byte_range_make(byte_max, byte_max));
      mins[1] = 0, maxs[1] = rest_max;
      n = 2;
    } else if (rest_max == rest_mask || first_min == first_max - 1) {
      /* Range ends on all ones, but has multiple starting bytes */
      /* Output:
       * -----[FirstMin-FirstMin]----{tree for [RestMin-FF]}
       *           |
       *    [(FirstMin+1)-FirstMax]---{tree for [00-FF]} */
      /* - or - */
      /* Range occupies exactly two starting bytes */
      /* Output:
       * -----[FirstMin-FirstMin]----{tree for [RestMin-FF]}
       *           |
       *      [FirstMax-FirstMax]----{tree for [00-RestMax]} */
      brs[0] = bbre_byte_range_to_u32(bbre_byte_range_make(byte_min, byte_min));
      mins[0] = rest_min, maxs[0] = rest_mask;
      brs[1] =
          bbre_byte_range_to_u32(bbre_byte_range_make(byte_min + 1, byte_max));
      mins[1] = 0, maxs[1] = rest_max;
      n = 2;
    } else {
      /* Range doesn't begin on all zeroes or all ones, and takes up more
       * than 2 different starting bytes */
      /* Output:
       * -------[FirstMin-FirstMin]-------{tree for [RestMin-FF]}
       *             |
       *    [(FirstMin+1)-(FirstMax-1)]----{tree for [00-FF]}
       *             |
       *        [FirstMax-FirstMax]-------{tree for [00-RestMax]} */
      brs[0] = bbre_byte_range_to_u32(bbre_byte_range_make(byte_min, byte_min));
      mins[0] = rest_min, maxs[0] = rest_mask;
      brs[1] = bbre_byte_range_to_u32(
          bbre_byte_range_make(byte_min + 1, byte_max - 1));
      mins[1] = 0, maxs[1] = rest_mask;
      brs[2] = bbre_byte_range_to_u32(bbre_byte_range_make(byte_max, byte_max));
      mins[2] = 0, maxs[2] = rest_max;
      n = 3;
    }
    for (i = 0; i < n; i++) {
      bbre_compcc_tree *parent_node;
      bbre_uint child_ref;
      /* check if previous child intersects and then compute intersection */
      assert(parent);
      parent_node = (*cc_out) + parent;
      if (parent_node->child_ref &&
          bbre_uint_to_byte_range(brs[i]).l <=
              bbre_uint_to_byte_range(
                  ((*cc_out) + parent_node->child_ref)->range)
                  .h) {
        child_ref = parent_node->child_ref;
      } else {
        if ((err = bbre_compcc_tree_append(
                 r, cc_out, brs[i], parent, &child_ref)))
          goto error;
      }
      if ((err = bbre_compcc_tree_build_one(
               r, cc_out, child_ref, mins[i], maxs[i], rest_bits - 6, 6)))
        goto error;
    }
  }
error:
  return err;
}

/* Given an array of rune ranges, build their tree. This function splits each
 * rune range amount UTF-8 length boundaries, then calls
 * `bbre_compcc_tree_build_one` on each split range. */
static int bbre_compcc_tree_build(
    bbre *r, bbre_compframe *frame_in, bbre_buf(bbre_compcc_tree) * cc_out)
{
  size_t len_idx = 0 /* current UTF-8 length */,
         min_bound = 0 /* current UTF-8 length minimum bound */;
  bbre_uint root_ref; /* tree root */
  bbre_uint in_ref;
  bbre_compcc_tree root_node; /* the actual stored root node */
  int err = 0;
  root_node.child_ref = root_node.sibling_ref = root_node.aux.hash =
      root_node.range = 0;
  /* clear output charclass */
  bbre_buf_clear(cc_out);
  if ((err = bbre_compcc_tree_new(r, cc_out, root_node, &root_ref)))
    goto error;
  for (in_ref = frame_in->head, len_idx = 0; in_ref && len_idx < 4;) {
    /* Loop until we're out of ranges and out of byte lengths */
    static const bbre_uint first_bits[4] = {7, 5, 4, 3};
    static const bbre_uint rest_bits[4] = {0, 6, 12, 18};
    /* What is the maximum codepoint that a UTF-8 sequence of length `len_idx`
     * can encode? */
    bbre_uint max_bound = (1 << (rest_bits[len_idx] + first_bits[len_idx])) - 1;
    bbre_rune_range rr = r->cc_store[in_ref].range;
    if (min_bound <= rr.h && rr.l <= max_bound) {
      /* [rr.l,rr.h] intersects [min_bound,max_bound] */
      /* clip it so that it lies within [min_bound,max_bound] */
      bbre_uint clamped_min = rr.l < min_bound ? min_bound : rr.l,
                clamped_max = rr.h > max_bound ? max_bound : rr.h;
      /* then build it */
      if ((err = bbre_compcc_tree_build_one(
               r, cc_out, root_ref, clamped_min, clamped_max,
               rest_bits[len_idx], first_bits[len_idx])))
        goto error;
    }
    if (rr.h < max_bound)
      /* range is less than [min_bound,max_bound] */
      in_ref = r->cc_store[in_ref].next;
    else
      /* range is greater than [min_bound,max_bound] */
      len_idx++, min_bound = max_bound + 1;
  }
  frame_in->head = frame_in->tail = BBRE_NIL;
error:
  return err;
}

/* Recursively check if two subtrees are equal.
 * I usually avoid recursion in C. However, this function will only recur a
 * maximum of 4 times, since the maximum depth of a tree (child-wise) is 4,
 * which is the maximum length of a UTF-8 sequence. */
static int bbre_compcc_tree_eq(
    const bbre_buf(bbre_compcc_tree) cc_tree_in, bbre_uint a_ref,
    bbre_uint b_ref)
{
  int res = 0;
  /* Loop through children of `a` and `b` */
  while (a_ref && b_ref) {
    const bbre_compcc_tree *a = cc_tree_in + a_ref, *b = cc_tree_in + b_ref;
    if (!(res = bbre_compcc_tree_eq(cc_tree_in, a->child_ref, b->child_ref) &&
                a->range == b->range))
      goto done;
    a_ref = a->sibling_ref, b_ref = b->sibling_ref;
  }
  /* Ensure that both `a` and `b` have no remaining children. */
  assert(a_ref == 0 || b_ref == 0);
  res = a_ref == b_ref;
done:
  return res;
}

/* Merge two adjacent subtrees. */
static void bbre_compcc_tree_merge_one(
    bbre_buf(bbre_compcc_tree) cc_tree_in, bbre_uint child_ref,
    bbre_uint sibling_ref)
{
  bbre_compcc_tree *child = cc_tree_in + child_ref,
                   *sibling = cc_tree_in + sibling_ref;
  child->sibling_ref = sibling->sibling_ref;
  /* Adjacent subtrees can only be merged if their child trees are equal and if
   * their ranges are adjacent. */
  assert(
      bbre_byte_range_is_adjacent(
          bbre_uint_to_byte_range(child->range),
          bbre_uint_to_byte_range(sibling->range)) &&
      bbre_compcc_tree_eq(cc_tree_in, child->child_ref, sibling->child_ref));
  child->range = bbre_byte_range_to_u32(bbre_byte_range_make(
      bbre_uint_to_byte_range(child->range).l,
      bbre_uint_to_byte_range(sibling->range).h));
}

/* General purpose hashing function. This should probably be changed to
 * something a bit better, but works very well for this library.
 * Found by the intrepid Chris Wellons:
 * https://nullprogram.com/blog/2018/07/31/ */
static bbre_uint bbre_hashington(bbre_uint x)
{
  x ^= x >> 16;
  x *= 0x7feb352dU;
  x ^= x >> 15;
  x *= 0x846ca68bU;
  x ^= x >> 16;
  return x;
}

/* Initialize tree reduction hash table. */
static int bbre_compcc_hash_init(
    bbre *r, const bbre_buf(bbre_compcc_tree) cc_tree_in,
    bbre_buf(bbre_uint) * cc_ht_out)
{
  int err = 0;
  if ((err = bbre_buf_reserve(
           &r->alloc, cc_ht_out,
           (bbre_buf_size(cc_tree_in) + (bbre_buf_size(cc_tree_in) >> 1)))))
    goto error;
  memset(*cc_ht_out, 0, bbre_buf_size(*cc_ht_out) * sizeof(**cc_ht_out));
error:
  return err;
}

/* Hash all nodes in the tree, and also merge adjacent nodes with identical
 * subtrees. This is the final optimization opportunity for reducing the
 * resulting amount of instructions. */
static void bbre_compcc_tree_hash(
    bbre *r, bbre_buf(bbre_compcc_tree) cc_tree_in, bbre_uint parent_ref)
{
  /* We also flip sibling -> sibling links backwards -- this reorders the byte
   * ranges into ascending order. */
  bbre_compcc_tree *parent_node = cc_tree_in + parent_ref;
  bbre_uint child_ref, next_child_ref, sibling_ref = 0;
  child_ref = parent_node->child_ref;
  while (child_ref) {
    bbre_compcc_tree *child_node = cc_tree_in + child_ref, *sibling_node;
    next_child_ref = child_node->sibling_ref;
    child_node->sibling_ref = sibling_ref;
    /* Recursively hash child nodes. */
    bbre_compcc_tree_hash(r, cc_tree_in, child_ref);
    if (sibling_ref) {
      /* Attempt to merge this node with its next sibling. */
      sibling_node = cc_tree_in + sibling_ref;
      if (bbre_byte_range_is_adjacent(
              bbre_uint_to_byte_range(child_node->range),
              bbre_uint_to_byte_range(sibling_node->range))) {
        /* Since the input ranges are normalized, terminal nodes (nodes with no
         * concatenation) are NOT adjacent. */
        /* In other words, we guarantee that there are always gaps between
         * terminal bytes ranges within the tree. */
        assert(sibling_node->child_ref && child_node->child_ref);
        if (bbre_compcc_tree_eq(
                cc_tree_in, child_node->child_ref, sibling_node->child_ref))
          bbre_compcc_tree_merge_one(cc_tree_in, child_ref, sibling_ref);
      }
    }
    {
      /* Actually calculate the hash for this node. */
      /* I need to analyze this function and make sure it's fairly resistant to
       * hash attacks, but I know very little about cryptography. I think that
       * an attacker could change the performance of the reduction step from
       * O(N) to O(N^2) if they cause a ton of collisions and make us probe a
       * lot, but I can't convince myself how. */
      /* Three guaranteed random numbers, chosen by a fair dice roll. */
      bbre_uint hash_plain[3] = {0x6D99232E, 0xC281FF0B, 0x54978D96};
      memset(hash_plain, 0, sizeof(hash_plain));
      hash_plain[0] ^= child_node->range;
      if (child_node->sibling_ref)
        /* Derive our hash from the sibling node's hash, which was computed */
        hash_plain[1] = (cc_tree_in + child_node->sibling_ref)->aux.hash;
      if (child_node->child_ref)
        /* Derive our hash from our child node's hash, which was computed */
        hash_plain[2] = (cc_tree_in + child_node->child_ref)->aux.hash;
      /* Compute and set our hash. */
      child_node->aux.hash = bbre_hashington(
          bbre_hashington(bbre_hashington(hash_plain[0]) + hash_plain[1]) +
          hash_plain[2]);
    }
    /* Swap node --> sibling links for node <-- sibling. */
    sibling_ref = child_ref;
    child_ref = next_child_ref;
  }
  /* Finally, update the parent with its new child node, which was previously
   * its very last child node. */
  parent_node->child_ref = sibling_ref;
}

/* Reduce nodes in the tree (eliminate common suffixes) */
static void bbre_compcc_tree_reduce(
    bbre *r, bbre_buf(bbre_compcc_tree) cc_tree_in, bbre_buf(bbre_uint) cc_ht,
    bbre_uint node_ref, bbre_uint *my_out_ref)
{
  bbre_uint prev_sibling_ref = 0;
  assert(node_ref);
  assert(!*my_out_ref);
  while (node_ref) {
    bbre_compcc_tree *node = cc_tree_in + node_ref;
    bbre_uint probe, found, child_ref = 0;
    probe = node->aux.hash;
    node->aux.pc = 0;
    /* check if child is in the hash table */
    while (1) {
      if (!((found = cc_ht[probe % bbre_buf_size(cc_ht)]) & 1))
        /* child is NOT in the cache */
        break;
      else {
        /* something is in the cache, but it might not be a child */
        if (bbre_compcc_tree_eq(cc_tree_in, node_ref, found >> 1)) {
          if (prev_sibling_ref)
            /* link us to our new previous sibling, if any */
            cc_tree_in[prev_sibling_ref].sibling_ref = found >> 1;
          if (!*my_out_ref)
            /* if this was the first node processed, return it */
            *my_out_ref = found >> 1;
          goto done;
        }
      }
      probe += 1; /* linear probe */
    }
    /* this could be slow because of the mod operation-- might be a good idea to
     * use one of nullprogram's MST hash tables here */
    cc_ht[probe % bbre_buf_size(cc_ht)] = node_ref << 1 | 1;
    if (!*my_out_ref)
      /* if this was the first node processed, return it */
      *my_out_ref = node_ref;
    if (node->child_ref) {
      /* reduce our child tree */
      bbre_compcc_tree_reduce(
          r, cc_tree_in, cc_ht, node->child_ref, &child_ref);
      node->child_ref = child_ref;
    }
    prev_sibling_ref = node_ref;
    node_ref = node->sibling_ref;
  }
done:
  assert(*my_out_ref);
  return;
}

/* Convert our tree representation into actual NFA instructions.
 * `node_ref` is the node to be rendered, `my_out_pc` is the PC of `node_ref`'s
 * instructions, once they are compiled. `frame` allows us to keep track of
 * patch exit points. */
static int bbre_compcc_tree_render(
    bbre *r, bbre_buf(bbre_compcc_tree) cc_tree_in, bbre_uint node_ref,
    bbre_uint *my_out_pc, bbre_compframe *frame)
{
  int err = 0;
  bbre_uint split_from = 0 /* location of last compiled SPLIT instruction */,
            my_pc = 0 /* PC of the current node being compiled */,
            range_pc = 0 /* location of last compiled RANGE instruction */;
  while (node_ref) {
    bbre_compcc_tree *node = cc_tree_in + node_ref;
    if (node->aux.pc) {
      /* we've already compiled this node */
      if (split_from) {
        /* instead of compiling the node again, just jump to it and return */
        bbre_inst i = bbre_prog_get(&r->prog, split_from);
        i = bbre_inst_make(
            bbre_inst_opcode(i), bbre_inst_next(i), node->aux.pc);
        bbre_prog_set(&r->prog, split_from, i);
      } else
        /* return the compiled instructions themselves if we haven't compiled
         * anything else yet */
        assert(!*my_out_pc), *my_out_pc = node->aux.pc;
      err = 0;
      goto error;
    }
    /* node wasn't found in the cache: we need to compile it */
    my_pc = bbre_prog_size(&r->prog);
    if (split_from) {
      /* if there was a previous SPLIT instruction: link it to the upcoming
       * SPLIT/RANGE instruction */
      bbre_inst i = bbre_prog_get(&r->prog, split_from);
      /* patch into it */
      i = bbre_inst_make(bbre_inst_opcode(i), bbre_inst_next(i), my_pc);
      bbre_prog_set(&r->prog, split_from, i);
    }
    if (node->sibling_ref) {
      /* there are more siblings (alternations) left, so we need a SPLIT
       * instruction */
      split_from = my_pc;
      if ((err = bbre_prog_emit(
               &r->prog, bbre_inst_make(BBRE_OPCODE_SPLIT, my_pc + 1, 0),
               frame->set_idx)))
        goto error;
    }
    if (!*my_out_pc)
      *my_out_pc = my_pc;
    /* compile this node's RANGE instruction */
    range_pc = bbre_prog_size(&r->prog);
    if ((err = bbre_prog_emit(
             &r->prog,
             bbre_inst_make(
                 BBRE_OPCODE_RANGE, 0,
                 bbre_byte_range_to_u32(bbre_byte_range_make(
                     bbre_uint_to_byte_range(node->range).l,
                     bbre_uint_to_byte_range(node->range).h))),
             frame->set_idx)))
      goto error;
    if (node->child_ref) {
      /* node has children: need to down-compile */
      bbre_uint their_pc = 0;
      bbre_inst i = bbre_prog_get(&r->prog, range_pc);
      if ((err = bbre_compcc_tree_render(
               r, cc_tree_in, node->child_ref, &their_pc, frame)))
        goto error;
      /* modify the primary branch target of the RANGE instruction to point to
       * the child's instructions: this introduces a concatenation */
      i = bbre_inst_make(bbre_inst_opcode(i), their_pc, bbre_inst_param(i));
      bbre_prog_set(&r->prog, range_pc, i);
    } else {
      /* node does not have children: register its branch target as an exit
       * point using the patch list */
      bbre_patch_add(r, frame, range_pc, 0);
    }
    node->aux.pc = my_pc;
    node_ref = node->sibling_ref;
  }
  assert(*my_out_pc);
error:
  return err;
}

/* Transpose the charclass compiler tree: reverse all concatenations. This is
 * used for generating the reverse program.
 * Takes the tree in `cc_tree_in`, and transposes it to `cc_tree_out`.
 * `node_ref` is the node being reversed in `cc_tree_in`, while `root_ref` is
 * the root node of `cc_tree_out`.
 * `cc_tree_out` starts out as a carbon copy of `cc_tree_in`. This function
 * reverses the concatenation edges in the graph, and ends up removing many of
 * the alternation edges in the graph. As such, `cc_tree_out` does not contain
 * the optimal DFA representing the reversed form of the charclass, but it
 * contains roughly the same number of instructions as the forward program, so
 * it is still compact. */
static void bbre_compcc_tree_xpose(
    bbre_buf(bbre_compcc_tree) cc_tree_in,
    bbre_buf(bbre_compcc_tree) cc_tree_out, bbre_uint node_ref,
    bbre_uint root_ref, bbre_uint is_root)
{
  bbre_compcc_tree *src_node = cc_tree_in + node_ref;
  bbre_compcc_tree *dst_node = cc_tree_out + node_ref, *parent_node;
  bbre_uint child_sibling_ref = src_node->child_ref;
  assert(node_ref != BBRE_NIL);
  /* There needs to be enough space in the output tree. This space is
   * preallocated to simplify this function's error checking. */
  assert(bbre_buf_size(cc_tree_out) == bbre_buf_size(cc_tree_in));
  dst_node->sibling_ref = dst_node->child_ref = BBRE_NIL;
  dst_node->aux.pc = 0;
  if (!child_sibling_ref) {
    parent_node = cc_tree_out + root_ref;
    dst_node->sibling_ref = parent_node->child_ref;
    parent_node->child_ref = node_ref;
  }
  while (child_sibling_ref) {
    bbre_compcc_tree *child_sibling_node = cc_tree_in + child_sibling_ref;
    parent_node = cc_tree_out + child_sibling_ref;
    bbre_compcc_tree_xpose(
        cc_tree_in, cc_tree_out, child_sibling_ref, root_ref, 0);
    if (!is_root) {
      assert(parent_node->child_ref == BBRE_NIL);
      parent_node->child_ref = node_ref;
    }
    child_sibling_ref = child_sibling_node->sibling_ref;
  }
}

/* Main function for the character class compiler. `frame` is the compiler frame
 * allocated for the resulting instructions, `ranges` is the normalized set of
 * rune ranges that comprise this character class, and `reversed` tells us
 * whether to compile the charclass in reverse. */
static int bbre_compcc(bbre *r, bbre_compframe *frame, int reversed)
{
  int err = 0;
  bbre_uint start_pc = 0; /* start PC of the compiled charclass, this is filled
                          in by rendertree() */
  /* clear temporary buffers (their space is reserved) */
  bbre_buf_clear(&r->compcc.tree), bbre_buf_clear(&r->compcc.tree_2),
      bbre_buf_clear(&r->compcc.hash);
  bbre_compile_cc_normalize(r, frame);
  if (!frame->head) {
    /* here, it's actually possible to have a charclass that matches no chars,
     * consider the inversion of [\x00-\x{10FFFF}]. Since this case is so rare,
     * we just stub it out by creating an assert that never matches. */
    if ((err = bbre_prog_emit(
             &r->prog,
             bbre_inst_make(
                 BBRE_OPCODE_ASSERT, 0,
                 BBRE_ASSERT_WORD | BBRE_ASSERT_NOT_WORD),
             frame->set_idx))) /* never matches */
      goto error;
    /* just return immediately, the code below assumes that there are actually
     * ranges to compile */
    bbre_patch_add(r, frame, bbre_prog_size(&r->prog) - 1, 0);
    goto error;
  }
  /* build the concat/alt tree */
  if ((err = bbre_compcc_tree_build(r, frame, &r->compcc.tree)))
    goto error;
  /* hash the tree */
  if ((err = bbre_compcc_hash_init(r, r->compcc.tree, &r->compcc.hash)))
    goto error;
  bbre_compcc_tree_hash(r, r->compcc.tree, 1);
  if (reversed) {
    /* optionally reverse the tree, if we're compiling in reverse mode */
    bbre_uint i;
    bbre_buf(bbre_compcc_tree) tmp;
    /* copy all nodes from compcc.tree to compcc.tree_2, this has the side
     * effect of reserving exactly enough space to store the reversed tree */
    bbre_buf_clear(&r->compcc.tree_2);
    for (i = 1 /* skip sentinel */; i < bbre_buf_size(r->compcc.tree); i++) {
      if ((err = bbre_compcc_tree_new(
               r, &r->compcc.tree_2, r->compcc.tree[i], NULL)) == BBRE_ERR_MEM)
        goto error;
      assert(!err);
    }
    /* detach new root */
    r->compcc.tree_2[1].child_ref = BBRE_NIL;
    /* reverse all concatenation edges in the tree */
    bbre_compcc_tree_xpose(r->compcc.tree, r->compcc.tree_2, 1, 1, 1);
    tmp = r->compcc.tree;
    r->compcc.tree = r->compcc.tree_2;
    r->compcc.tree_2 = tmp;
  }
  /* reduce the tree */
  bbre_compcc_tree_reduce(
      r, r->compcc.tree, r->compcc.hash, r->compcc.tree[1].child_ref,
      &start_pc);
  /* finally, generate the charclass' instructions */
  if ((err = bbre_compcc_tree_render(
           r, r->compcc.tree, r->compcc.tree[1].child_ref, &start_pc, frame)))
    goto error;
error:
  return err;
}

static bbre_uint
bbre_inst_relocate_pc(bbre_uint orig, bbre_uint src, bbre_uint dst)
{
  return orig ? orig - src + dst : orig;
}

/* Duplicate the instruction, relocating relative jumps. */
static bbre_inst
bbre_inst_relocate(bbre_inst inst, bbre_uint src, bbre_uint dst)
{
  bbre_inst next_inst = inst;
  if (bbre_inst_opcode(inst) == BBRE_OPCODE_SPLIT)
    next_inst = bbre_inst_make(
        bbre_inst_opcode(next_inst), bbre_inst_next(next_inst),
        bbre_inst_relocate_pc(bbre_inst_param(next_inst), src, dst));
  next_inst = bbre_inst_make(
      bbre_inst_opcode(next_inst),
      bbre_inst_relocate_pc(bbre_inst_next(next_inst), src, dst),
      bbre_inst_param(next_inst));
  return next_inst;
}

/* Given a compiled program described by `src` and `src_end`, duplicate its
 * instructions, and return the duplicate in `dst` as if it was just compiled by
 * an iteration of the compiler loop. */
static int bbre_compile_dup(
    bbre *r, bbre_compframe *src, bbre_uint src_end, bbre_compframe *dst,
    bbre_uint dest_pc)
{
  bbre_uint i;
  int err = 0;
  *dst = *src;
  bbre_patch_apply(r, src, dest_pc);
  dst->pc = bbre_prog_size(&r->prog);
  dst->head = dst->tail = BBRE_NIL;
  for (i = src->pc; i < src_end; i++) {
    bbre_inst inst = bbre_prog_get(&r->prog, i),
              next_inst = bbre_inst_relocate(inst, src->pc, dst->pc);
    int should_patch[2] = {0, 0}, j;
    if (bbre_inst_opcode(inst) == BBRE_OPCODE_SPLIT) {
      /* Any previous patches in `src` should have been linked to `dest_pc`. We
       * can track them thusly. */
      should_patch[1] = bbre_inst_param(inst) == dest_pc;
      /* Duplicate the instruction, relocating relative jumps. */
      next_inst = bbre_inst_make(
          bbre_inst_opcode(next_inst), bbre_inst_next(next_inst),
          should_patch[1] ? 0 : bbre_inst_param(next_inst));
    }
    should_patch[0] = bbre_inst_next(inst) == dest_pc;
    next_inst = bbre_inst_make(
        bbre_inst_opcode(next_inst),
        should_patch[0] ? 0 : bbre_inst_next(next_inst),
        bbre_inst_param(next_inst));
    if ((err = bbre_prog_emit(&r->prog, next_inst, dst->set_idx)))
      goto error;
    /* if the above step found patch points, add them to `dst`'s patch list. */
    for (j = 0; j < 2; j++)
      if (should_patch[j])
        bbre_patch_add(r, dst, i - src->pc + dst->pc, j);
  }
error:
  return err;
}

static int bbre_compile_dotstar(bbre_prog *prog, int reverse, bbre_uint pat_idx)
{
  /* compile in a dotstar for unanchored matches */
  int err = 0;
  /*        +------+
   *  in   /        \
   * ---> S -> R ---+
   *       \
   *        +---------> [X] */
  bbre_uint dstar =
      prog->entry
          [BBRE_PROG_ENTRY_DOTSTAR | (reverse ? BBRE_PROG_ENTRY_REVERSE : 0)] =
          bbre_prog_size(prog);
  bbre_compframe frame = {0};
  frame.set_idx = pat_idx;
  if ((err = bbre_prog_emit(
           prog,
           bbre_inst_make(
               BBRE_OPCODE_SPLIT,
               prog->entry[reverse ? BBRE_PROG_ENTRY_REVERSE : 0], dstar + 1),
           frame.set_idx)))
    goto error;
  if ((err = bbre_prog_emit(
           prog,
           bbre_inst_make(
               BBRE_OPCODE_RANGE, dstar,
               bbre_byte_range_to_u32(bbre_byte_range_make(0, 255))),
           frame.set_idx)))
    goto error;
error:
  return err;
}

/* This function reads from the builtin CC ROM and is defined later. */
static int bbre_builtin_cc_decode(
    bbre *r, bbre_uint start, bbre_uint num_range, bbre_compframe *frame);

/* Main compiler function. Given an AST node through `ast_root`, convert it to
 * compiled instructions. Optionally generate the reversed program if `reverse`
 * is specified. */
static int bbre_compile_internal(bbre *r, bbre_uint ast_root, bbre_uint reverse)
{
  int err = 0;
  bbre_compframe
      initial_frame = {0} /* compiler frame for `ast_root` */,
      returned_frame =
          {0} /* after a child node is compiled, its frame is returned here */,
      child_frame = {
          0}; /* filled when we want to request a child to be compiled */
  bbre_uint sub_idx = 0; /* current subpattern index */
  /* add sentinel 0th instruction, this compiles to all zeroes */
  if (!bbre_prog_size(&r->prog) &&
      ((err = bbre_buf_push(
            &r->alloc, &r->prog.prog,
            bbre_inst_make(BBRE_OPCODE_RANGE, 0, 0))) ||
       (err = bbre_buf_push(&r->alloc, &r->prog.set_idxs, 0))))
    goto error;
  assert(bbre_prog_size(&r->prog) > 0);
  /* create the frame for the root node */
  initial_frame.root_ref = ast_root;
  initial_frame.child_ref = initial_frame.head = initial_frame.tail = BBRE_NIL;
  initial_frame.idx = 0;
  initial_frame.pc = bbre_prog_size(&r->prog);
  /* set the entry point for the forward or reverse program */
  r->prog.entry[reverse ? BBRE_PROG_ENTRY_REVERSE : 0] = initial_frame.pc;
  if ((err = bbre_buf_push(&r->alloc, &r->comp_stk, initial_frame)))
    goto error;
  while (bbre_buf_size(r->comp_stk)) {
    /* walk the AST tree recursively until we are done visiting nodes */
    bbre_compframe frame = *bbre_buf_peek(&r->comp_stk, 0);
    bbre_ast_type type; /* AST node type */
    bbre_uint args[BBRE_AST_MAX_ARGS] = {0} /* AST node args */,
              my_pc =
                  bbre_prog_size(&r->prog); /* PC of this node's instructions */
    /* we tell the compiler to visit a child by setting `frame.child_ref` to
     * some value other than `frame.root_ref`. By default, we set it to
     * `frame.root_ref` to disable visiting a child. */
    frame.child_ref = frame.root_ref;

    child_frame.child_ref = child_frame.root_ref = child_frame.head =
        child_frame.tail = BBRE_NIL;
    child_frame.idx = child_frame.pc = 0;
    type = frame.root_ref ? *bbre_ast_type_ref(r, frame.root_ref)
                          : 0 /* 0 for epsilon */;
    if (frame.root_ref)
      bbre_ast_decompose(r, frame.root_ref, args);
    if (type == BBRE_AST_TYPE_CHR) {
      /* single characters / codepoints, this corresponds to one or more RANGE
       * instructions */
      bbre_patch_apply(r, &frame, my_pc);
      if (args[0] < 128 && !(frame.flags & BBRE_GROUP_FLAG_INSENSITIVE)) {
        /* ascii characters -- these are common enough that it's worth bypassing
         * the charclass compiler and just emitting a single RANGE */
        /*  in     out
         * ---> R ----> */
        if ((err = bbre_prog_emit(
                 &r->prog,
                 bbre_inst_make(
                     BBRE_OPCODE_RANGE, 0,
                     bbre_byte_range_to_u32(
                         bbre_byte_range_make(args[0], args[0]))),
                 frame.set_idx)))
          goto error;
        bbre_patch_add(r, &frame, my_pc, 0);
      } else { /* unicode */
        bbre_patch_apply(r, &frame, my_pc);
        if ((err = bbre_compile_cc_append(
                 r, &frame, frame.tail,
                 bbre_rune_range_make(args[0], args[0]))))
          goto error;
        if ((frame.flags & BBRE_GROUP_FLAG_INSENSITIVE) &&
            (err = bbre_compile_cc_casefold(r, &frame)))
          goto error;
        /* call the character class compiler on the single CC node */
        if ((err = bbre_compcc(r, &frame, reverse)))
          goto error;
      }
    } else if (type == BBRE_AST_TYPE_ANYCHAR) {
      /* . */
      /*  in            out
       * ---> [varies] ----> */
      bbre_patch_apply(r, &frame, my_pc);
      if (frame.flags & BBRE_GROUP_FLAG_DOTNEWLINE) {
        if ((err = bbre_compile_cc_append(
                 r, &frame, frame.tail, bbre_rune_range_make(0, BBRE_UTF_MAX))))
          goto error;
      } else {
        if ((err = bbre_compile_cc_append(
                 r, &frame, frame.tail, bbre_rune_range_make(0, '\n' - 1))))
          goto error;
        if ((err = bbre_compile_cc_append(
                 r, &frame, frame.tail,
                 bbre_rune_range_make('\n' + 1, BBRE_UTF_MAX))))
          goto error;
      }
      if ((err = bbre_compcc(r, &frame, reverse)))
        goto error;
    } else if (type == BBRE_AST_TYPE_ANYBYTE) {
      /* \C */
      /*  in     out
       * ---> R ----> */
      bbre_patch_apply(r, &frame, my_pc);
      /* emit a single range instruction that covers 0x00 - 0xFF */
      if ((err = bbre_prog_emit(
               &r->prog,
               bbre_inst_make(
                   BBRE_OPCODE_RANGE, 0,
                   bbre_byte_range_to_u32(bbre_byte_range_make(0x00, 0xFF))),
               frame.set_idx)))
        goto error;
      bbre_patch_add(r, &frame, my_pc, 0);
    } else if (type == BBRE_AST_TYPE_CAT) {
      /* concatenation: compile child X, then compile and link it to child Y */
      /*  in              out
       * ---> [X] -> [Y] ----> */
      assert(/* frame.idx >= 0 && */ frame.idx <= 2);
      if (frame.idx == 0) {              /* before left child */
        frame.child_ref = args[reverse]; /* push left child */
        bbre_patch_xfer(&child_frame, &frame);
        frame.idx++;
      } else if (frame.idx == 1) {        /* after left child */
        frame.child_ref = args[!reverse]; /* push right child */
        bbre_patch_xfer(&child_frame, &returned_frame);
        frame.idx++;
      } else /* if (frame.idx == 2) */ { /* after right child */
        bbre_patch_xfer(&frame, &returned_frame);
      }
    } else if (type == BBRE_AST_TYPE_ALT) {
      /* alternation: generate a split instruction, then link its outputs to the
       * compiled forms of X and Y */
      /*  in             out
       * ---> S --> [X] ---->
       *       \         out
       *        --> [Y] ----> */
      assert(/* frame.idx >= 0 && */ frame.idx <= 2);
      if (frame.idx == 0) { /* before left child */
        bbre_patch_apply(r, &frame, frame.pc);
        if ((err = bbre_prog_emit(
                 &r->prog, bbre_inst_make(BBRE_OPCODE_SPLIT, 0, 0),
                 frame.set_idx)))
          goto error;
        bbre_patch_add(r, &child_frame, frame.pc, 0);
        frame.child_ref = args[0], frame.idx++;
      } else if (frame.idx == 1) { /* after left child */
        bbre_patch_merge(r, &frame, &returned_frame);
        bbre_patch_add(r, &child_frame, frame.pc, 1);
        frame.child_ref = args[1], frame.idx++;
      } else /* if (frame.idx == 2) */ { /* after right child */
        assert(frame.idx == 2);
        bbre_patch_merge(r, &frame, &returned_frame);
      }
    } else if (type == BBRE_AST_TYPE_QUANT || type == BBRE_AST_TYPE_UQUANT) {
      bbre_uint child = args[0], min = args[1], max = args[2],
                is_greedy = !(frame.flags & BBRE_GROUP_FLAG_UNGREEDY) ^
                            (type == BBRE_AST_TYPE_UQUANT);
      assert(min <= max);
      assert(
          BBRE_IMPLIES((min == BBRE_INFTY || max == BBRE_INFTY), min != max));
      assert(BBRE_IMPLIES(max == BBRE_INFTY, frame.idx <= min + 1));
    again: /* label is used to avoid recompiling child multiple times */
      if (frame.idx < min) {
        /* required repetitions, compile and concatenate child */
        /*  in                 out
         * ---> [X] -> [X...] ----> */
        bbre_patch_xfer(&child_frame, frame.idx ? &returned_frame : &frame);
        frame.child_ref = child;
      } else if (
          frame.idx < max &&
          BBRE_IMPLIES(max == BBRE_INFTY, frame.idx < min + 1)) {
        /* optional repetitions (quests), generate a SPLIT and compile child */
        /*  in               out
         * ---> S -> [X...] ---->
         *       \           out
         *        +-------------> */
        bbre_patch_apply(r, frame.idx ? &returned_frame : &frame, my_pc);
        if ((err = bbre_prog_emit(
                 &r->prog, bbre_inst_make(BBRE_OPCODE_SPLIT, 0, 0),
                 frame.set_idx)))
          goto error;
        frame.pc = my_pc;
        bbre_patch_add(r, &frame, my_pc, is_greedy);
        bbre_patch_add(r, &child_frame, my_pc, !is_greedy);
        if (min > 0 && max == BBRE_INFTY) {
          /* optimization: for reps of the form {>0,}, jump back to previously
           * compiled child instead of generating another */
          /*        +------+
           *       /        \
           * --> [X] -> S ---+
           *             \      out
           *              +----------> */
          bbre_patch_apply(r, &child_frame, returned_frame.pc);
        } else
          /* otherwise generate the child again */
          frame.child_ref = child;
      } else if (max == BBRE_INFTY) {
        /* after inf. bound */
        /* star, link child back to the split instruction generated above */
        /* a second split instruction is needed to keep track of threads that
         * matched an empty string after the first split instruction, if these
         * threads captured an empty group, the group will only be saved if the
         * thread 'parks' itself at the second split instruction. This was an
         * extremely subtle bug that was only found relatively late in
         * development by the fuzzington. */
        /*        +---<---+
         *  in   /         \   out
         * ---> S -> [X] -> S ------>
         *       \             out
         *        +-----------------> */
        assert(frame.idx == min + 1);
        bbre_patch_apply(r, &returned_frame, my_pc);
        if ((err = bbre_prog_emit(
                 &r->prog, bbre_inst_make(BBRE_OPCODE_SPLIT, frame.pc + 1, 0),
                 frame.set_idx)))
          goto error;
        bbre_patch_add(r, &frame, my_pc, 1);
      } else if (frame.idx) {
        /* after maximum bound, finalize patches */
        /*  in            out
         * ---> S -> [X] ---->
         *       \        out
         *        +----------> */
        assert(frame.idx == max);
        bbre_patch_merge(r, &frame, &returned_frame);
      } else {
        /* epsilon */
        /*  in  out  */
        /* --------> */
        assert(!frame.idx);
        assert(frame.idx == max);
        assert(min == 0 && max == 0);
      }
      frame.idx++;
      if (frame.child_ref == child) {
        if (returned_frame.root_ref != child) {
          /* we haven't yet compiled the child -- fall through */
        } else {
          /* we've compiled the child already -- we can duplicate its compiled
           * instructions without actually compiling the child again */
          bbre_compframe next_returned_frame = {0};
          next_returned_frame.pc = bbre_prog_size(&r->prog);
          bbre_patch_apply(r, &child_frame, next_returned_frame.pc);
          if ((err = bbre_compile_dup(
                   r, &returned_frame, my_pc, &next_returned_frame, my_pc)))
            goto error;
          next_returned_frame.root_ref = child;
          returned_frame = next_returned_frame;
          frame.child_ref = frame.root_ref;
          my_pc = bbre_prog_size(&r->prog);
          goto again;
        }
      }
    } else if (type == BBRE_AST_TYPE_GROUP || type == BBRE_AST_TYPE_IGROUP) {
      /* groups: insert opening and closing match instructions, or nothing if
       * the group is a noncapturing group and simply modifies flag state */
      bbre_uint child = args[0], hi_flags = args[1], lo_flags = args[2],
                idx = args[3];
      assert(/* these flags should never be set in `lo_flags` */
             !(lo_flags &
               (BBRE_GROUP_FLAG_NONCAPTURING | BBRE_GROUP_FLAG_EXPRESSION)));
      frame.flags |=
          (hi_flags &
           ~(BBRE_GROUP_FLAG_NONCAPTURING |
             BBRE_GROUP_FLAG_EXPRESSION)); /* we shouldn't propagate these */
      frame.flags &= ~lo_flags;
      if (!frame.idx) { /* before child */
        /* before child */
        if (!(hi_flags & BBRE_GROUP_FLAG_NONCAPTURING)) {
          /* compile in the beginning match instruction */
          /*  in      out
           * ---> Mb ----> */
          bbre_patch_apply(r, &frame, my_pc);
          if (hi_flags & BBRE_GROUP_FLAG_EXPRESSION)
            frame.set_idx = ++sub_idx;
          if ((err = bbre_prog_emit(
                   &r->prog,
                   bbre_inst_make(
                       BBRE_OPCODE_MATCH, 0,
                       bbre_inst_match_param_make(reverse, idx)),
                   frame.set_idx)))
            goto error;
          bbre_patch_add(r, &child_frame, my_pc, 0);
        } else
          /* non-capturing group: don't compile in anything */
          /*  in  out
           * --------> */
          bbre_patch_xfer(&child_frame, &frame);
        frame.child_ref = child, frame.idx++;
      } else { /* after child */
        /* compile in the ending match instruction */
        /*  in                   out
         * ---> Mb -> [X] -> Me ----> */
        if (!(hi_flags & BBRE_GROUP_FLAG_NONCAPTURING)) {
          bbre_patch_apply(r, &returned_frame, my_pc);
          if ((err = bbre_prog_emit(
                   &r->prog,
                   bbre_inst_make(
                       BBRE_OPCODE_MATCH, 0,
                       bbre_inst_match_param_make(
                           !reverse, bbre_inst_match_param_idx(bbre_inst_param(
                                         bbre_prog_get(&r->prog, frame.pc))))),
                   frame.set_idx)))
            goto error;
          if (!(hi_flags & BBRE_GROUP_FLAG_EXPRESSION))
            bbre_patch_add(r, &frame, my_pc, 0);
          else {
            /* for the ending match instruction that corresponds to a
             * subexpression, don't link it anywhere: it signifies the end of a
             * subpattern. Currently, this node only occurs once in a pattern
             * because set compilation doesn't use bbre_compile() anymore, but
             * in the future it might be useful to keep this (group numbering
             * restarting, etc.) */
            /*  in
             * ---> Mb -> [X] -> Me */
          }
        } else
          /* non-capturing group: don't compile in anything */
          /*  in       out
           * ---> [X] ----> */
          bbre_patch_merge(r, &frame, &returned_frame);
      }
    } else if (bbre_ast_type_is_cc(type)) {
      /* Character class subtree. */
      bbre_uint cc_root =
          bbre_buf_size(r->comp_stk) > 1
              ? !bbre_ast_type_is_cc(*bbre_ast_type_ref(
                    r, bbre_buf_peek(&r->comp_stk, 1)->root_ref))
              : 1;
      if (cc_root && !frame.idx) {
        assert(!(frame.flags & BBRE_GROUP_FLAG_CC_DENORM));
        /* Free up head/tail members in frame for our use. */
        bbre_patch_apply(r, &frame, my_pc);
      }
      if (type == BBRE_AST_TYPE_CC_LEAF) {
        /* Leaf: create an array of length 1 containing the character class. */
        if ((err = bbre_compile_cc_append(
                 r, &frame, frame.tail,
                 bbre_rune_range_make(args[0], args[1]))) ||
            ((frame.flags & BBRE_GROUP_FLAG_INSENSITIVE) &&
             (err = bbre_compile_cc_casefold(r, &frame))))
          goto error;
      } else if (type == BBRE_AST_TYPE_CC_BUILTIN) {
        /* Builtins: read the character class from ROM. */
        if ((err = bbre_builtin_cc_decode(r, args[0], args[1], &frame)) ||
            ((frame.flags & BBRE_GROUP_FLAG_INSENSITIVE) &&
             (err = bbre_compile_cc_casefold(r, &frame))))
          goto error;
      } else if (type == BBRE_AST_TYPE_CC_NOT) {
        /* Negation: evaluate child, then negate it. */
        if (frame.idx == 0) {
          frame.child_ref = args[0]; /* push child */
          frame.idx++;
        } else {
          bbre_uint current = 0;
          assert(frame.idx == 1);
          /* in order to invert the charclass, it must be normalized */
          bbre_compile_cc_normalize(r, &returned_frame);
          while (returned_frame.head) {
            bbre_rune_range next =
                bbre_compile_cc_pop(r, &returned_frame, BBRE_NIL);
            if (next.l > current) {
              bbre_compile_cc_append_unwrapped(
                  r, &frame, frame.tail,
                  bbre_rune_range_make(current, next.l - 1));
            }
            current = next.h + 1;
          }
          if (current < BBRE_UTF_MAX &&
              (err = bbre_compile_cc_append(
                   r, &frame, frame.tail,
                   bbre_rune_range_make(current, BBRE_UTF_MAX))))
            goto error;
          assert(!returned_frame.head && !returned_frame.tail);
        }
      } else if (type == BBRE_AST_TYPE_CC_OR || type == BBRE_AST_TYPE_CC_AND) {
        /* Conjunction/disjunction: evaluate left and right children, then
         * compose them into a single character class. */
        if (frame.idx == 0) {
          frame.child_ref = args[0]; /* push left child */
          frame.idx++;
        } else if (frame.idx == 1) {
          frame.head = returned_frame.head, frame.tail = returned_frame.tail;
          frame.child_ref = args[1]; /* push right child */
          frame.idx++;
        } else {
          /* evaluate both children */
          assert(frame.idx == 2);
          if (type == BBRE_AST_TYPE_CC_OR) {
            bbre_compile_cc_link(r, &frame, &returned_frame);
            frame.flags |= BBRE_GROUP_FLAG_CC_DENORM;
          } else {
            bbre_compframe a = frame, b = returned_frame;
            bbre_rune_range current = {BBRE_UTF_MAX + 1, BBRE_UTF_MAX + 1},
                            next = {0};
            while (1) {
              if (!a.head && !b.head)
                break;
              assert(
                  BBRE_IMPLIES(!a.head, b.head) &&
                  BBRE_IMPLIES(!b.head, a.head));
              if (!b.head || (a.head && r->cc_store[a.head].range.l <
                                            r->cc_store[b.head].range.l))
                next = bbre_compile_cc_pop(r, &a, BBRE_NIL);
              else
                next = bbre_compile_cc_pop(r, &b, BBRE_NIL);
              if (type == BBRE_AST_TYPE_CC_OR) {
                if (current.l == BBRE_UTF_MAX + 1)
                  current = next;
                else if (next.l <= current.h)
                  current = bbre_rune_range_make(
                      current.l, next.h > current.h ? next.h : current.h);
                else if (next.l == current.h + 1)
                  current = bbre_rune_range_make(current.l, next.h);
                else if (next.l > current.h + 1) {
                  if ((err = bbre_compile_cc_append(
                           r, &frame, frame.tail, current)))
                    goto error;
                  current = next;
                }
              } else {
                assert(type == BBRE_AST_TYPE_CC_AND);
                if (current.l == BBRE_UTF_MAX + 1)
                  current = next;
                else if (next.l <= current.h) {
                  bbre_uint lo = current.h < next.h ? current.h : next.h,
                            hi = current.h > next.h ? current.h : next.h;
                  if ((err = bbre_compile_cc_append(
                           r, &frame, frame.tail,
                           bbre_rune_range_make(next.l, lo))))
                    goto error;
                  if (lo != hi)
                    current = bbre_rune_range_make(lo + 1, hi);
                } else if (next.l == current.h + 1 || next.l > current.h + 1)
                  current = next;
              }
            }
            if (current.l != BBRE_UTF_MAX + 1 && type == BBRE_AST_TYPE_CC_OR &&
                (err = bbre_compile_cc_append(r, &frame, frame.tail, current)))
              goto error;
            assert(!a.head && !a.tail && !b.head && !b.tail);
          }
        }
      }
      if (frame.child_ref == frame.root_ref) {
        if (cc_root) {
          /* If we're done compiling this AST node, and this is the root of a CC
           * subtree, then we can hand off the normalized range array to the
           * character class compiler. */
          if ((err = bbre_compcc(r, &frame, reverse)))
            goto error;
        }
      }
    } else if (type == BBRE_AST_TYPE_ASSERT) {
      /* assertions: add a single ASSERT instruction */
      /*  in     out
       * ---> A ----> */
      bbre_uint flag = args[0], real_flag;
      bbre_patch_apply(r, &frame, my_pc);
      if (reverse) {
        real_flag = 0;
        if (flag & BBRE_ASSERT_TEXT_BEGIN)
          real_flag |= BBRE_ASSERT_TEXT_END;
        if (flag & BBRE_ASSERT_TEXT_END)
          real_flag |= BBRE_ASSERT_TEXT_BEGIN;
        if (flag & BBRE_ASSERT_LINE_BEGIN)
          real_flag |= BBRE_ASSERT_LINE_END;
        if (flag & BBRE_ASSERT_LINE_END)
          real_flag |= BBRE_ASSERT_LINE_BEGIN;
        real_flag |= (flag & (BBRE_ASSERT_WORD | BBRE_ASSERT_NOT_WORD));
        flag = real_flag;
      }
      if (!(frame.flags & BBRE_GROUP_FLAG_MULTILINE) &&
          flag & BBRE_ASSERT_LINE_BEGIN)
        flag = (flag & ~BBRE_ASSERT_LINE_BEGIN) | BBRE_ASSERT_TEXT_BEGIN;
      if (!(frame.flags & BBRE_GROUP_FLAG_MULTILINE) &&
          flag & BBRE_ASSERT_LINE_END)
        flag = (flag & ~BBRE_ASSERT_LINE_END) | BBRE_ASSERT_TEXT_END;
      if ((err = bbre_prog_emit(
               &r->prog, bbre_inst_make(BBRE_OPCODE_ASSERT, 0, flag),
               frame.set_idx)))
        goto error;
      bbre_patch_add(r, &frame, my_pc, 0);
    } else {
      /* epsilon */
      /*  in  out  */
      /* --------> */
      assert(!frame.root_ref);
      assert(type == 0);
    }
    if (frame.child_ref != frame.root_ref) {
      /* should we push a child? */
      *bbre_buf_peek(&r->comp_stk, 0) = frame;
      child_frame.root_ref = frame.child_ref;
      child_frame.idx = 0;
      child_frame.pc = bbre_prog_size(&r->prog);
      child_frame.flags = frame.flags;
      child_frame.set_idx = frame.set_idx;
      if ((err = bbre_buf_push(&r->alloc, &r->comp_stk, child_frame)))
        goto error;
    } else {
      (void)bbre_buf_pop(&r->comp_stk);
    }
    returned_frame = frame;
  }
  assert(!bbre_buf_size(r->comp_stk));
  assert(!returned_frame.head && !returned_frame.tail);
  if ((err = bbre_compile_dotstar(&r->prog, reverse, 1)))
    goto error;
error:
  return err;
}

int bbre_set_builder_init(bbre_set_builder **pspec, const bbre_alloc *palloc)
{
  int err = 0;
  bbre_set_builder *spec;
  bbre_alloc alloc = bbre_alloc_make(palloc);
  spec = bbre_ialloc(&alloc, NULL, 0, sizeof(bbre_builder));
  *pspec = spec;
  if (!spec) {
    err = BBRE_ERR_MEM;
    goto error;
  }
  memset(spec, 0, sizeof(*spec));
  spec->alloc = alloc;
  bbre_buf_init(&spec->pats);
error:
  return err;
}

int bbre_set_builder_add(bbre_set_builder *set, const bbre *b)
{
  return bbre_buf_push(&set->alloc, &set->pats, b);
}

void bbre_set_builder_destroy(bbre_set_builder *spec)
{
  if (!spec)
    goto done;
  bbre_buf_destroy(&spec->alloc, &spec->pats);
  bbre_ialloc(&spec->alloc, spec, sizeof(bbre_builder), 0);
done:
  return;
}

static int bbre_set_compile(bbre_set *set, const bbre **rs, size_t n);

int bbre_set_init_internal(bbre_set **pset, const bbre_alloc *palloc)
{
  int err = 0;
  bbre_set *set;
  bbre_alloc alloc = bbre_alloc_make(palloc);
  *pset = bbre_ialloc(&alloc, NULL, 0, sizeof(bbre_set));
  if (!*pset) {
    err = BBRE_ERR_MEM;
    goto error;
  }
  set = *pset;
  memset(set, 0, sizeof(*set));
  set->alloc = alloc;
  bbre_prog_init(&set->prog, set->alloc, &set->error);
  set->exec = NULL;
error:
  return err;
}

int bbre_set_init(
    bbre_set **pset, const bbre_set_builder *spec, const bbre_alloc *palloc)
{
  int err = 0;
  if ((err = bbre_set_init_internal(pset, palloc)))
    goto error;
  if ((err = bbre_set_compile(*pset, spec->pats, bbre_buf_size(spec->pats))))
    goto error;
error:
  return err;
}

bbre_set *bbre_set_init_patterns(const char *const *pats_nt, size_t num_pats)
{
  int err = 0;
  size_t i;
  bbre_alloc a = bbre_alloc_make(NULL);
  bbre **regs = bbre_ialloc(&a, NULL, 0, sizeof(bbre *) * num_pats);
  bbre_set *set = NULL;
  bbre_set_builder *spec = NULL;
  if (!regs)
    goto done;
  for (i = 0; i < num_pats; i++)
    regs[i] = NULL;
  for (i = 0; i < num_pats; i++) {
    regs[i] = bbre_init_pattern(pats_nt[i]);
    if (!regs[i])
      goto done;
  }
  if ((err = bbre_set_builder_init(&spec, &a)))
    goto done;
  for (i = 0; i < num_pats; i++) {
    if ((err = bbre_set_builder_add(spec, regs[i])))
      goto done;
  }
  if ((err = bbre_set_init(&set, spec, &a))) {
    bbre_set_destroy(set);
    set = NULL;
    goto done;
  }
done:
  bbre_set_builder_destroy(spec);
  if (regs) {
    for (i = 0; i < num_pats; i++)
      bbre_destroy(regs[i]);
    bbre_ialloc(&a, regs, sizeof(bbre *) * num_pats, 0);
  }
  return set;
}

void bbre_set_destroy(bbre_set *set)
{
  if (!set)
    goto done;
  bbre_prog_destroy(&set->prog);
  if (set->exec)
    bbre_exec_destroy(set->exec);
  bbre_ialloc(&set->alloc, set, sizeof(*set), 0);
done:
  return;
}

static int bbre_set_compile(bbre_set *set, const bbre **rs, size_t n)
{
  int err = 0;
  size_t i;
  bbre_uint prev_split = 0;
  /* add sentinel 0th instruction */
  if ((err = bbre_buf_push(
           &set->alloc, &set->prog.prog,
           bbre_inst_make(BBRE_OPCODE_RANGE, 0, 0))) ||
      (err = bbre_buf_push(&set->alloc, &set->prog.set_idxs, 0)))
    goto error;
  set->prog.entry[0] = bbre_prog_size(&set->prog);
  for (i = 0; i < n; i++) {
    /* relocate all subpatterns */
    const bbre *r = rs[i];
    bbre_uint src_pc, dst_pc;
    if (i) {
      assert(prev_split);
      bbre_prog_set(
          &set->prog, prev_split,
          bbre_inst_make(
              BBRE_OPCODE_SPLIT,
              bbre_inst_next(bbre_prog_get(&set->prog, prev_split)),
              bbre_prog_size(&set->prog)));
    }
    if (i != n - 1) {
      prev_split = bbre_prog_size(&set->prog);
      if ((err = bbre_prog_emit(
               &set->prog,
               bbre_inst_make(
                   BBRE_OPCODE_SPLIT, bbre_prog_size(&set->prog) + 1, 0),
               0)))
        goto error;
    }
    for (src_pc = r->prog.entry[0], dst_pc = bbre_prog_size(&set->prog);
         src_pc < r->prog.entry[BBRE_PROG_ENTRY_DOTSTAR]; src_pc++, dst_pc++) {
      if ((err = bbre_prog_emit(
               &set->prog,
               bbre_inst_relocate(r->prog.prog[src_pc], src_pc, dst_pc),
               i + 1)))
        goto error;
    }
    set->prog.npat++;
  }
  if ((err = bbre_compile_dotstar(&set->prog, 0, 0)))
    goto error;
error:
  return err;
}

static int bbre_sset_reset(bbre_exec *exec, bbre_sset *s, size_t next_size)
{
  int err = 0;
  assert(next_size); /* programs are never of size 0 */
  if ((err = bbre_buf_reserve(&exec->alloc, &s->sparse, next_size)))
    goto error;
  if ((err = bbre_buf_reserve(&exec->alloc, &s->dense, next_size)))
    goto error;
  s->size = next_size, s->dense_size = 0;
error:
  return err;
}

static void bbre_sset_clear(bbre_sset *s) { s->dense_size = 0; }

static void bbre_sset_init(bbre_sset *s)
{
  bbre_buf_init(&s->sparse), bbre_buf_init(&s->dense);
  s->size = s->dense_size = 0;
}

static void bbre_sset_destroy(bbre_exec *exec, bbre_sset *s)
{
  bbre_buf_destroy(&exec->alloc, &s->sparse),
      bbre_buf_destroy(&exec->alloc, &s->dense);
}

static int bbre_sset_is_memb(bbre_sset *s, bbre_uint pc)
{
  assert(pc < s->size);
  return s->sparse[pc] < s->dense_size && s->dense[s->sparse[pc]].pc == pc;
}

static void bbre_sset_add(bbre_sset *s, bbre_nfa_thrd spec)
{
  assert(spec.pc < s->size);
  assert(s->dense_size < s->size);
  assert(spec.pc);
  if (bbre_sset_is_memb(s, spec.pc))
    goto done;
  s->dense[s->dense_size] = spec;
  s->sparse[spec.pc] = s->dense_size++;
done:
  return;
}

static void bbre_save_slots_init(bbre_save_slots *s)
{
  s->slots = NULL;
  s->slots_size = s->slots_alloc = s->last_empty = s->per_thrd = 0;
}

static void bbre_save_slots_destroy(bbre_exec *exec, bbre_save_slots *s)
{
  bbre_ialloc(&exec->alloc, s->slots, sizeof(size_t) * s->slots_alloc, 0);
}

static void bbre_save_slots_clear(bbre_save_slots *s, size_t per_thrd)
{
  s->slots_size = 0, s->last_empty = 0,
  s->per_thrd = per_thrd + 1 /* for refcnt */;
}

#define BBRE_UNSET_POSN (((size_t)0 - (size_t)1))

static int
bbre_save_slots_new(bbre_exec *exec, bbre_save_slots *s, bbre_uint *next)
{
  bbre_uint i;
  int err = 0;
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
      size_t *new_slots = bbre_ialloc(
          &exec->alloc, s->slots, s->slots_alloc * sizeof(size_t),
          new_alloc * sizeof(size_t));
      if (!new_slots) {
        err = BBRE_ERR_MEM;
        goto error;
      }
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
  for (i = 0; i < s->per_thrd - 1; i++)
    (s->slots + *next * s->per_thrd)[i] = BBRE_UNSET_POSN;
  s->slots[*next * s->per_thrd + s->per_thrd - 1] =
      1; /* initial refcount = 1 */
error:
  return err;
}

static bbre_uint bbre_save_slots_fork(bbre_save_slots *s, bbre_uint ref)
{
  if (s->per_thrd)
    s->slots[ref * s->per_thrd + s->per_thrd - 1]++;
  return ref;
}

static void bbre_save_slots_kill(bbre_save_slots *s, bbre_uint ref)
{
  if (!s->per_thrd)
    goto done;
  if (!s->slots[ref * s->per_thrd + s->per_thrd - 1]--) {
    /* prepend to free list */
    s->slots[ref * s->per_thrd] = s->last_empty;
    s->last_empty = ref;
  }
done:
  return;
}

static int bbre_save_slots_set_internal(
    bbre_exec *exec, bbre_save_slots *s, bbre_uint ref, bbre_uint idx, size_t v,
    bbre_uint *out)
{
  int err = 0;
  *out = ref;
  assert(s->per_thrd);
  assert(idx < s->per_thrd);
  assert(s->slots[ref * s->per_thrd + s->per_thrd - 1]);
  if (v == s->slots[ref * s->per_thrd + idx]) {
    /* not changing anything */
  } else {
    if ((err = bbre_save_slots_new(exec, s, out)))
      goto error;
    bbre_save_slots_kill(s, ref); /* decrement refcount */
    assert(
        s->slots[*out * s->per_thrd + s->per_thrd - 1] ==
        1); /* new refcount is 1 */
    memcpy(
        s->slots + *out * s->per_thrd, s->slots + ref * s->per_thrd,
        sizeof(*s->slots) *
            (s->per_thrd - 1) /* leave refcount at 1 for new slot */);
    s->slots[*out * s->per_thrd + idx] = v; /* and update the requested value */
  }
error:
  return err;
}

static bbre_uint bbre_save_slots_per_thrd(bbre_save_slots *s)
{
  return s->per_thrd ? s->per_thrd - 1 : s->per_thrd;
}

static int bbre_save_slots_set(
    bbre_exec *exec, bbre_save_slots *s, bbre_uint ref, bbre_uint idx, size_t v,
    bbre_uint *out)
{
  assert(idx < bbre_save_slots_per_thrd(s));
  return bbre_save_slots_set_internal(exec, s, ref, idx, v, out);
}

static size_t
bbre_save_slots_get(bbre_save_slots *s, bbre_uint ref, bbre_uint idx)
{
  assert(idx < bbre_save_slots_per_thrd(s));
  return s->slots[ref * s->per_thrd + idx];
}

static void bbre_nfa_init(bbre_nfa *n)
{
  bbre_sset_init(&n->a), bbre_sset_init(&n->b), bbre_sset_init(&n->c);
  bbre_buf_init(&n->thrd_stk);
  bbre_save_slots_init(&n->slots);
  bbre_buf_init(&n->pri_stk);
  bbre_buf_init(&n->pri_bmp_tmp);
  n->reversed = 0;
}

static void bbre_nfa_destroy(bbre_exec *exec, bbre_nfa *n)
{
  bbre_sset_destroy(exec, &n->a), bbre_sset_destroy(exec, &n->b),
      bbre_sset_destroy(exec, &n->c);
  bbre_buf_destroy(&exec->alloc, &n->thrd_stk);
  bbre_save_slots_destroy(exec, &n->slots);
  bbre_buf_destroy(&exec->alloc, &n->pri_stk),
      bbre_buf_destroy(&exec->alloc, &n->pri_bmp_tmp);
}

#define BBRE_BITS_PER_U32 (sizeof(bbre_uint) * CHAR_BIT)

static int
bbre_bmp_init(bbre_alloc alloc, bbre_buf(bbre_uint) * b, bbre_uint size)
{
  bbre_uint i;
  int err = 0;
  bbre_buf_clear(b);
  if ((err = bbre_buf_reserve(
           &alloc, b, (size + BBRE_BITS_PER_U32) / BBRE_BITS_PER_U32)))
    goto error;
  for (i = 0; i < (size + BBRE_BITS_PER_U32) / BBRE_BITS_PER_U32; i++)
    *b[i] = 0;
error:
  return err;
}

static void bbre_bmp_clear(bbre_buf(bbre_uint) * b)
{
  assert(*b);
  memset(*b, 0, bbre_buf_size(*b));
}

static void bbre_bmp_set(bbre_buf(bbre_uint) b, bbre_uint idx)
{
  /* TODO: assert idx < nsets */
  b[idx / BBRE_BITS_PER_U32] |= (1 << (idx % BBRE_BITS_PER_U32));
}

/* returns 0 or a positive value (not necessarily 1) */
static bbre_uint bbre_bmp_get(bbre_buf(bbre_uint) b, bbre_uint idx)
{
  return b[idx / BBRE_BITS_PER_U32] & (1 << (idx % BBRE_BITS_PER_U32));
}

static int bbre_nfa_start(
    bbre_exec *exec, bbre_nfa *n, bbre_uint pc, bbre_uint noff, int reversed,
    int pri)
{
  bbre_nfa_thrd initial_thrd;
  bbre_uint i;
  int err = 0;
  if ((err = bbre_sset_reset(exec, &n->a, bbre_prog_size(exec->prog))) ||
      (err = bbre_sset_reset(exec, &n->b, bbre_prog_size(exec->prog))) ||
      (err = bbre_sset_reset(exec, &n->c, bbre_prog_size(exec->prog))))
    goto error;
  bbre_buf_clear(&n->thrd_stk), bbre_buf_clear(&n->pri_stk);
  bbre_save_slots_clear(&n->slots, noff);
  initial_thrd.pc = pc;
  if ((err = bbre_save_slots_new(exec, &n->slots, &initial_thrd.slot)))
    goto error;
  bbre_sset_add(&n->a, initial_thrd);
  initial_thrd.pc = initial_thrd.slot = 0;
  for (i = 0; i < exec->prog->npat; i++)
    if ((err = bbre_buf_push(&exec->alloc, &n->pri_stk, 0)))
      goto error;
  if ((err = bbre_bmp_init(exec->alloc, &n->pri_bmp_tmp, exec->prog->npat)))
    goto error;
  n->reversed = reversed;
  n->pri = pri;
error:
  return err;
}

static int
bbre_nfa_eps(bbre_exec *exec, bbre_nfa *n, size_t pos, bbre_assert_flag ass)
{
  int err = 0;
  size_t i;
  bbre_sset_clear(&n->b);
  for (i = 0; i < n->a.dense_size; i++) {
    bbre_nfa_thrd dense_thrd = n->a.dense[i];
    if ((err = bbre_buf_push(&exec->alloc, &n->thrd_stk, dense_thrd)))
      goto error;
    bbre_sset_clear(&n->c);
    while (bbre_buf_size(n->thrd_stk)) {
      bbre_nfa_thrd thrd = *bbre_buf_peek(&n->thrd_stk, 0);
      bbre_inst op = bbre_prog_get(exec->prog, thrd.pc);
      assert(thrd.pc);
      if (bbre_sset_is_memb(&n->c, thrd.pc)) {
        /* we already processed this thread */
        bbre_buf_pop(&n->thrd_stk);
        continue;
      }
      bbre_sset_add(&n->c, thrd);
      switch (bbre_inst_opcode(bbre_prog_get(exec->prog, thrd.pc))) {
      case BBRE_OPCODE_MATCH: {
        bbre_uint idx = bbre_inst_match_param_idx(bbre_inst_param(op)) * 2 +
                        bbre_inst_match_param_end(bbre_inst_param(op));
        if (idx < bbre_save_slots_per_thrd(&n->slots) &&
            (err = bbre_save_slots_set(
                 exec, &n->slots, thrd.slot, idx, pos, &thrd.slot)))
          goto error;
        if (bbre_inst_next(op)) {
          if (bbre_inst_match_param_idx(bbre_inst_param(op)) > 0 ||
              !n->pri_stk[exec->prog->set_idxs[thrd.pc] - 1]) {
            thrd.pc = bbre_inst_next(op);
            *bbre_buf_peek(&n->thrd_stk, 0) = thrd;
          } else
            (void)bbre_buf_pop(&n->thrd_stk);
          break;
        }
      }
        /* fall through */
      case BBRE_OPCODE_RANGE:
        (void)bbre_buf_pop(&n->thrd_stk);
        bbre_sset_add(&n->b, thrd); /* this is a range or final match */
        break;
      case BBRE_OPCODE_SPLIT: {
        bbre_nfa_thrd pri, sec;
        pri.pc = bbre_inst_next(op), pri.slot = thrd.slot;
        sec.pc = bbre_inst_param(op),
        sec.slot = bbre_save_slots_fork(&n->slots, thrd.slot);
        /* In rare situations, the compiler will emit a SPLIT instruction with
         * one of its branch targets set to the address of the instruction
         * itself. I observed this happening after a fuzzington run that
         * produced a regexp with nested empty-width quantifiers: a{0,0}*.
         * The way that bbre works now, this is harmless. Preventing these
         * instructions from being emitted would add some complexity to the
         * program for no clear benefit. */
        /* assert(pri.pc != thrd.pc && sec.pc != thrd.pc); */
        *bbre_buf_peek(&n->thrd_stk, 0) = sec;
        if ((err = bbre_buf_push(&exec->alloc, &n->thrd_stk, pri)))
          /* sec is pushed first because it needs to be processed after pri.
           * pri comes off the stack first because it's FIFO. */
          goto error;
        break;
      }
      default: /* ASSERT */ {
        assert(
            bbre_inst_opcode(bbre_prog_get(exec->prog, thrd.pc)) ==
            BBRE_OPCODE_ASSERT);
        assert(!!(ass & BBRE_ASSERT_WORD) ^ !!(ass & BBRE_ASSERT_NOT_WORD));
        if ((bbre_inst_param(op) & ass) == bbre_inst_param(op)) {
          thrd.pc = bbre_inst_next(op);
          *bbre_buf_peek(&n->thrd_stk, 0) = thrd;
        } else {
          bbre_save_slots_kill(&n->slots, thrd.slot);
          (void)bbre_buf_pop(&n->thrd_stk);
        }
        break;
      }
      }
    }
  }
  bbre_sset_clear(&n->a);
error:
  return err;
}

static int bbre_nfa_match_end(
    bbre_exec *exec, bbre_nfa *n, bbre_nfa_thrd thrd, size_t pos,
    unsigned int ch)
{
  int err = 0;
  bbre_uint idx = exec->prog->set_idxs[thrd.pc];
  bbre_uint *memo = n->pri_stk + idx - 1;
  assert(idx > 0);
  assert(idx - 1 < bbre_buf_size(n->pri_stk));
  if (!n->pri && ch < 256)
    goto out_kill;
  if (n->slots.per_thrd) {
    bbre_uint slot_idx = !n->reversed;
    if (*memo)
      bbre_save_slots_kill(&n->slots, *memo);
    *memo = thrd.slot;
    if (slot_idx < bbre_save_slots_per_thrd(&n->slots) &&
        (err = bbre_save_slots_set(
             exec, &n->slots, thrd.slot, slot_idx, pos, memo)))
      goto error;
    goto out_survive;
  } else {
    *memo = 1; /* just mark that a set was matched */
    goto out_kill;
  }
out_kill:
  bbre_save_slots_kill(&n->slots, thrd.slot);
out_survive:
error:
  return err;
}

static int
bbre_nfa_chr(bbre_exec *exec, bbre_nfa *n, unsigned int ch, size_t pos)
{
  int err = 0;
  size_t i;
  bbre_bmp_clear(&n->pri_bmp_tmp);
  for (i = 0; i < n->b.dense_size; i++) {
    bbre_nfa_thrd thrd = n->b.dense[i];
    bbre_inst op = bbre_prog_get(exec->prog, thrd.pc);
    bbre_uint pri = bbre_bmp_get(n->pri_bmp_tmp, exec->prog->set_idxs[thrd.pc]),
              opcode = bbre_inst_opcode(op);
    if (pri && n->pri)
      continue; /* priority exhaustion: disregard this thread */
    assert(opcode == BBRE_OPCODE_RANGE || opcode == BBRE_OPCODE_MATCH);
    if (opcode == BBRE_OPCODE_RANGE) {
      bbre_byte_range br = bbre_uint_to_byte_range(bbre_inst_param(op));
      if (ch >= br.l && ch <= br.h) {
        thrd.pc = bbre_inst_next(op);
        bbre_sset_add(&n->a, thrd);
      } else
        bbre_save_slots_kill(&n->slots, thrd.slot);
    } else /* if opcode == MATCH */ {
      assert(!bbre_inst_next(op));
      if ((err = bbre_nfa_match_end(exec, n, thrd, pos, ch)))
        goto error;
      if (n->pri)
        bbre_bmp_set(n->pri_bmp_tmp, exec->prog->set_idxs[thrd.pc]);
      bbre_save_slots_kill(&n->slots, thrd.slot);
    }
  }
error:
  return err;
}

#define BBRE_SENTINEL_CH 256

static bbre_uint bbre_is_word_char(bbre_uint ch)
{
  return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') ||
         (ch >= 'a' && ch <= 'z') || ch == '_';
}

static bbre_assert_flag bbre_make_assert_flag_raw(
    bbre_uint prev_text_begin, bbre_uint prev_line_begin, bbre_uint prev_word,
    bbre_uint next_ch)
{
  return !!prev_text_begin * BBRE_ASSERT_TEXT_BEGIN |
         (next_ch == BBRE_SENTINEL_CH) * BBRE_ASSERT_TEXT_END |
         !!prev_line_begin * BBRE_ASSERT_LINE_BEGIN |
         (next_ch == BBRE_SENTINEL_CH || next_ch == '\n') *
             BBRE_ASSERT_LINE_END |
         ((!!prev_word == bbre_is_word_char(next_ch)) ? BBRE_ASSERT_NOT_WORD
                                                      : BBRE_ASSERT_WORD);
}

static bbre_assert_flag
bbre_make_assert_flag(bbre_uint prev_ch, bbre_uint next_ch)
{
  return bbre_make_assert_flag_raw(
      prev_ch == BBRE_SENTINEL_CH,
      (prev_ch == BBRE_SENTINEL_CH || prev_ch == '\n'),
      bbre_is_word_char(prev_ch), next_ch);
}

static int bbre_nfa_end(
    bbre_exec *exec, size_t pos, bbre_nfa *n, bbre_uint max_span,
    bbre_uint max_set, bbre_span *out_span, bbre_uint *out_set,
    bbre_uint prev_ch)
{
  int err = 0;
  size_t j, sets = 0, nset = 0;
  if ((err = bbre_nfa_eps(
           exec, n, pos, bbre_make_assert_flag(prev_ch, BBRE_SENTINEL_CH))) ||
      (err = bbre_nfa_chr(exec, n, 256, pos)))
    goto error;
  for (sets = 0;
       sets < exec->prog->npat && (max_set ? nset < max_set : nset < 1);
       sets++) {
    bbre_uint slot = n->pri_stk[sets];
    if (!slot)
      continue; /* no match for this set */
    for (j = 0; (j < max_span) && out_span; j++) {
      out_span[nset * max_span + j].begin =
          bbre_save_slots_get(&n->slots, slot, j * 2);
      out_span[nset * max_span + j].end =
          bbre_save_slots_get(&n->slots, slot, j * 2 + 1);
    }
    if (out_set)
      out_set[nset] = sets;
    nset++;
  }
  err = nset;
error:
  return err;
}

static int bbre_nfa_run(
    bbre_exec *exec, bbre_nfa *n, bbre_uint ch, size_t pos, bbre_uint prev_ch)
{
  int err;
  if ((err = bbre_nfa_eps(exec, n, pos, bbre_make_assert_flag(prev_ch, ch))))
    goto error;
  if ((err = bbre_nfa_chr(exec, n, ch, pos)))
    goto error;
error:
  return err;
}

static void bbre_dfa_init(bbre_dfa *d)
{
  d->states = NULL;
  d->states_size = d->num_active_states = 0;
  memset(d->entry, 0, sizeof(d->entry));
  bbre_buf_init(&d->set_buf), bbre_buf_init(&d->set_bmp);
}

static void bbre_dfa_reset(bbre_dfa *d)
{
  size_t i;
  for (i = 0; i < d->states_size; i++)
    if (d->states[i])
      d->states[i]->flags |= BBRE_DFA_STATE_FLAG_DIRTY;
  d->num_active_states = 0;
  bbre_buf_clear(&d->set_buf), bbre_buf_clear(&d->set_bmp);
  memset(d->entry, 0, sizeof(d->entry));
}

static void bbre_dfa_destroy(bbre_exec *exec, bbre_dfa *d)
{
  size_t i;
  for (i = 0; i < d->states_size; i++)
    if (d->states[i])
      bbre_ialloc(&exec->alloc, d->states[i], d->states[i]->alloc, 0);
  bbre_ialloc(
      &exec->alloc, d->states, d->states_size * sizeof(bbre_dfa_state *), 0);
  bbre_buf_destroy(&exec->alloc, &d->set_buf),
      bbre_buf_destroy(&exec->alloc, &d->set_bmp);
}

static bbre_uint bbre_dfa_state_alloc(bbre_uint nstate, bbre_uint nset)
{
  bbre_uint minsz =
      sizeof(bbre_dfa_state) + (nstate + nset) * sizeof(bbre_uint);
  bbre_uint alloc = sizeof(bbre_dfa_state) & 0x800;
  while (alloc < minsz)
    alloc *= 2;
  return alloc;
}

static bbre_uint *bbre_dfa_state_data(bbre_dfa_state *state)
{
  return (bbre_uint *)(state + 1);
}

/* need: current state, but ALSO the previous state's matches */
static int bbre_dfa_construct(
    bbre_exec *exec, bbre_dfa *d, bbre_dfa_state *prev_state, unsigned int ch,
    bbre_uint prev_flag, bbre_nfa *n, bbre_dfa_state **out_next_state)
{
  size_t i;
  int err = 0;
  bbre_uint hash, table_pos, num_checked, *state_data, next_alloc;
  bbre_dfa_state *next_state;
  assert(!(prev_flag & BBRE_DFA_STATE_FLAG_DIRTY));
  /* check threads in n, and look them up in the dfa cache */
  hash = bbre_hashington(prev_flag);
  hash = bbre_hashington(hash + n->a.dense_size);
  hash = bbre_hashington(hash + bbre_buf_size(d->set_buf));
  for (i = 0; i < n->a.dense_size; i++)
    hash = bbre_hashington(hash + n->a.dense[i].pc);
  for (i = 0; i < bbre_buf_size(d->set_buf); i++)
    hash = bbre_hashington(hash + d->set_buf[i]);
  if (!d->states_size) {
    /* need to allocate initial cache */
    bbre_dfa_state **next_cache = bbre_ialloc(
        &exec->alloc, NULL, 0,
        sizeof(bbre_dfa_state *) * BBRE_DFA_MAX_NUM_STATES);
    if (!next_cache) {
      err = BBRE_ERR_MEM;
      goto error;
    }
    memset(next_cache, 0, sizeof(bbre_dfa_state *) * BBRE_DFA_MAX_NUM_STATES);
    assert(!d->states);
    d->states = next_cache, d->states_size = BBRE_DFA_MAX_NUM_STATES;
  }
  table_pos = hash % d->states_size, num_checked = 0;
  while (1) {
    /* linear probe for next state */
    if (!d->states[table_pos] ||
        d->states[table_pos]->flags & BBRE_DFA_STATE_FLAG_DIRTY) {
      next_state = NULL;
      break;
    }
    next_state = d->states[table_pos];
    assert(!(next_state->flags & BBRE_DFA_STATE_FLAG_DIRTY));
    state_data = bbre_dfa_state_data(next_state);
    if (next_state->flags != prev_flag)
      goto not_found;
    if (next_state->nstate != n->a.dense_size)
      goto not_found;
    if (next_state->nset != bbre_buf_size(d->set_buf))
      goto not_found;
    for (i = 0; i < n->a.dense_size; i++)
      if (state_data[i] != n->a.dense[i].pc)
        goto not_found;
    for (i = 0; i < bbre_buf_size(d->set_buf); i++)
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
    if (d->num_active_states == BBRE_DFA_MAX_NUM_STATES) {
      /* clear cache */
      for (i = 0; i < d->states_size; i++)
        if (d->states[i])
          d->states[i]->flags |= BBRE_DFA_STATE_FLAG_DIRTY;
      d->num_active_states = 0;
      table_pos = hash % d->states_size;
      memset(d->entry, 0, sizeof(d->entry));
      prev_state = NULL;
    }
    /* can we reuse the previous state? */
    assert(BBRE_IMPLIES(
        d->states[table_pos],
        d->states[table_pos]->flags & BBRE_DFA_STATE_FLAG_DIRTY));
    {
      bbre_uint prev_alloc =
          d->states[table_pos] ? d->states[table_pos]->alloc : 0;
      next_alloc =
          bbre_dfa_state_alloc(n->a.dense_size, bbre_buf_size(d->set_buf));
      if (!prev_alloc || prev_alloc < next_alloc) {
        next_state = bbre_ialloc(
            &exec->alloc, d->states[table_pos], prev_alloc, next_alloc);
        if (!next_state) {
          err = BBRE_ERR_MEM;
          goto error;
        }
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
    next_state->nset = bbre_buf_size(d->set_buf);
    state_data = bbre_dfa_state_data(next_state);
    for (i = 0; i < n->a.dense_size; i++)
      state_data[i] = n->a.dense[i].pc;
    for (i = 0; i < bbre_buf_size(d->set_buf); i++)
      state_data[n->a.dense_size + i] = d->set_buf[i];
    assert(d->states[table_pos] == next_state);
    d->num_active_states++;
  }
  assert(next_state);
  if (prev_state)
    /* link the states */
    assert(!prev_state->ptrs[ch]), prev_state->ptrs[ch] = next_state;
  *out_next_state = next_state;
error:
  return err;
}

static int bbre_dfa_construct_start(
    bbre_exec *exec, bbre_dfa *d, bbre_nfa *n, bbre_uint entry,
    bbre_uint prev_flag, bbre_dfa_state **out_next_state)
{
  int err = 0;
  /* clear the set buffer so that it can be used to compare dfa states later */
  bbre_buf_clear(&d->set_buf);
  *out_next_state = d->entry[entry][prev_flag];
  if (!*out_next_state) {
    bbre_nfa_thrd spec;
    spec.pc = exec->prog->entry[entry];
    spec.slot = 0;
    bbre_sset_clear(&n->a);
    bbre_sset_add(&n->a, spec);
    if ((err = bbre_dfa_construct(
             exec, d, NULL, 0, prev_flag, n, out_next_state)))
      goto error;
    d->entry[entry][prev_flag] = *out_next_state;
  }
error:
  return err;
}

static int bbre_dfa_construct_chr(
    bbre_exec *exec, bbre_dfa *d, bbre_nfa *n, bbre_dfa_state *prev_state,
    unsigned int ch, bbre_dfa_state **out_next_state)
{
  int err;
  size_t i;
  /* clear the set buffer so that it can be used to compare dfa states later */
  bbre_buf_clear(&d->set_buf);
  /* we only care about `ch` if `prev_state != NULL`. we only care about
   * `prev_flag` if `prev_state == NULL` */
  /* import prev_state into n */
  bbre_sset_clear(&n->a);
  for (i = 0; i < prev_state->nstate; i++) {
    bbre_nfa_thrd thrd;
    thrd.pc = bbre_dfa_state_data(prev_state)[i];
    thrd.slot = 0;
    bbre_sset_add(&n->a, thrd);
  }
  /* run eps on n */
  if ((err = bbre_nfa_eps(
           exec, n, 0,
           bbre_make_assert_flag_raw(
               prev_state->flags & BBRE_DFA_STATE_FLAG_FROM_TEXT_BEGIN,
               prev_state->flags & BBRE_DFA_STATE_FLAG_FROM_LINE_BEGIN,
               prev_state->flags & BBRE_DFA_STATE_FLAG_FROM_WORD, ch))))
    goto error;
  /* collect matches and match priorities into d->set_buf */
  bbre_bmp_clear(&n->pri_bmp_tmp);
  for (i = 0; i < n->b.dense_size; i++) {
    bbre_nfa_thrd thrd = n->b.dense[i];
    bbre_inst op = bbre_prog_get(exec->prog, thrd.pc);
    int pri = bbre_bmp_get(n->pri_bmp_tmp, exec->prog->set_idxs[thrd.pc]);
    if (pri && n->pri)
      continue; /* priority exhaustion: disregard this thread */
    switch (bbre_inst_opcode(op)) {
    case BBRE_OPCODE_RANGE: {
      bbre_byte_range br = bbre_uint_to_byte_range(bbre_inst_param(op));
      if (ch >= br.l && ch <= br.h) {
        thrd.pc = bbre_inst_next(op);
        bbre_sset_add(&n->a, thrd);
      } else
        bbre_save_slots_kill(&n->slots, thrd.slot);
      break;
    }
    case BBRE_OPCODE_MATCH: {
      assert(!bbre_inst_next(op));
      /* NOTE: since there only exists one match instruction for a set n, we
       * don't need to check if we've already pushed the match instruction. */
      if ((err = bbre_buf_push(
               &exec->alloc, &d->set_buf, exec->prog->set_idxs[thrd.pc] - 1)))
        goto error;
      if (n->pri)
        bbre_bmp_set(n->pri_bmp_tmp, exec->prog->set_idxs[thrd.pc]);
      break;
    }
    default:
      assert(0);
    }
  }
  /* feed ch to n -> this was accomplished by the above code */
  if ((err = bbre_dfa_construct(
           exec, d, prev_state, ch,
           (ch == BBRE_SENTINEL_CH) * BBRE_DFA_STATE_FLAG_FROM_TEXT_BEGIN |
               (ch == BBRE_SENTINEL_CH || ch == '\n') *
                   BBRE_DFA_STATE_FLAG_FROM_LINE_BEGIN |
               (bbre_is_word_char(ch) ? BBRE_DFA_STATE_FLAG_FROM_WORD : 0),
           n, out_next_state)))
    goto error;
error:
  return err;
}

static void bbre_dfa_save_matches(bbre_dfa *dfa, bbre_dfa_state *state)
{
  bbre_uint *start, *end;
  for (start = bbre_dfa_state_data(state) + state->nstate,
      end = start + state->nset;
       start < end; start++)
    bbre_bmp_set(dfa->set_bmp, *start);
}

static int bbre_dfa_match(
    bbre_exec *exec, bbre_byte *s, size_t n, size_t pos, size_t *out_pos,
    const bbre_dfa_match_flags flags)
{
  int err;
  bbre_dfa_state *state = NULL;
  int reversed = !!(flags & BBRE_DFA_MATCH_FLAG_REVERSED);
  int pri = !!(flags & BBRE_DFA_MATCH_FLAG_PRI);
  int exit_early = !!(flags & BBRE_DFA_MATCH_FLAG_EXIT_EARLY);
  int many = !!(flags & BBRE_DFA_MATCH_FLAG_MANY);
  bbre_uint entry =
      !reversed ? BBRE_PROG_ENTRY_DOTSTAR : BBRE_PROG_ENTRY_REVERSE;
  bbre_uint prev_ch = reversed ? (pos == n ? BBRE_SENTINEL_CH : s[pos])
                               : (pos == 0 ? BBRE_SENTINEL_CH : s[pos - 1]);
  bbre_uint incoming_assert_flag =
      (prev_ch == BBRE_SENTINEL_CH) * BBRE_DFA_STATE_FLAG_FROM_TEXT_BEGIN |
      (prev_ch == BBRE_SENTINEL_CH || prev_ch == '\n') *
          BBRE_DFA_STATE_FLAG_FROM_LINE_BEGIN |
      (bbre_is_word_char(prev_ch) ? BBRE_DFA_STATE_FLAG_FROM_WORD : 0);
  assert(BBRE_IMPLIES(!out_pos, exit_early));
  assert(BBRE_IMPLIES(exit_early, !pri)); /* enforces inner loop invariant */
  assert(BBRE_IMPLIES(exit_early, !many));
  bbre_dfa_reset(&exec->dfa);
  if ((err = bbre_nfa_start(
           exec, &exec->nfa, exec->prog->entry[entry], 0, reversed, pri)))
    goto error;
  if (many) {
    if ((err =
             bbre_bmp_init(exec->alloc, &exec->dfa.set_bmp, exec->prog->npat)))
      goto error;
  }
  {
    const bbre_byte *start = reversed ? s + pos - 1 : s + pos,
                    *end = reversed ? s - 1 : s + n, *out = NULL;
    /* The amount to increment each iteration of the loop. */
    int increment = reversed ? -1 : 1;
    if (!(state = exec->dfa.entry[entry][incoming_assert_flag]) &&
        (err = bbre_dfa_construct_start(
             exec, &exec->dfa, &exec->nfa, entry, incoming_assert_flag,
             &state)))
      goto error;
    /* This is a *very* hot loop. Don't change this without profiling first. */
    /* Originally this loop used an index on the `s` variable. It was determined
     * through profiling that it was faster to just keep a pointer and
     * dereference+increment it every iteration of the character loop. So, we
     * compute the start and end pointers of the span of the string, and then
     * rip through the string until start == end. */
    while (start != end) {
      bbre_byte ch = *start;
      bbre_dfa_state *next = state->ptrs[ch];
      if (exit_early) {
        if (state->nset) {
          err = 1;
          goto error;
        }
      } else {
        if (pri) {
          if (state->nset)
            out = start;
          if (!state->nstate) {
            *out_pos = reversed ? out - end - increment : out - s - increment;
            goto done_success;
          }
        }
        if (many)
          bbre_dfa_save_matches(&exec->dfa, state);
      }
      start += increment;
      if (!next) {
        if ((err = bbre_dfa_construct_chr(
                 exec, &exec->dfa, &exec->nfa, state, ch, &next)))
          goto error;
      }
      state = next;
    }
    if (exit_early) {
      if (state->nset) {
        err = 1;
        goto error;
      }
    } else {
      if (pri) {
        if (state->nset)
          out = start;
        if (!state->nstate) {
          *out_pos = reversed ? out - end - increment : out - s - increment;
          goto done_success;
        }
      }
      if (many)
        bbre_dfa_save_matches(&exec->dfa, state);
    }
  }
  if (!state->ptrs[BBRE_SENTINEL_CH]) {
    if ((err = bbre_dfa_construct_chr(
             exec, &exec->dfa, &exec->nfa, state, BBRE_SENTINEL_CH, &state)))
      goto error;
  } else
    state = state->ptrs[BBRE_SENTINEL_CH];
  if (many)
    bbre_dfa_save_matches(&exec->dfa, state);
  if (out_pos && state->nset)
    *out_pos = reversed ? 0 : n;
  assert(state);
  err = !!state->nset;
  goto error;
done_success:
  err = 1;
error:
  return err;
}

static int bbre_exec_init(
    bbre_exec **pexec, const bbre_prog *prog, const bbre_alloc *palloc)
{
  int err = 0;
  bbre_alloc alloc = bbre_alloc_make(palloc);
  bbre_exec *exec = bbre_ialloc(&alloc, NULL, 0, sizeof(bbre_exec));
  *pexec = exec;
  assert(bbre_prog_size(prog));
  if (!exec) {
    err = BBRE_ERR_MEM;
    goto error;
  }
  memset(exec, 0, sizeof(bbre_exec));
  exec->alloc = alloc;
  exec->prog = prog;
  bbre_nfa_init(&exec->nfa);
  bbre_dfa_init(&exec->dfa);
error:
  return err;
}

static void bbre_exec_destroy(bbre_exec *exec)
{
  if (!exec)
    goto done;
  bbre_nfa_destroy(exec, &exec->nfa);
  bbre_dfa_destroy(exec, &exec->dfa);
  bbre_ialloc(&exec->alloc, exec, sizeof(bbre_exec), 0);
done:
  return;
}

static int bbre_compile(bbre *r)
{
  int err = 0;
  assert(!bbre_prog_size(&r->prog));
  if ((err = bbre_compile_internal(r, r->ast_root, 0)) ||
      (err = bbre_compile_internal(r, r->ast_root, 1))) {
    goto error;
  }
error:
  return err;
}

static int bbre_exec_match(
    bbre_exec *exec, const char *s, size_t n, size_t pos, bbre_span *out_span,
    unsigned int *which_spans, bbre_uint max_span)
{
  int err = 0;
  bbre_uint entry = BBRE_PROG_ENTRY_DOTSTAR;
  size_t i;
  bbre_uint prev_ch = BBRE_SENTINEL_CH;
  assert(BBRE_IMPLIES(max_span, out_span));
  if (max_span == 0) {
    err = bbre_dfa_match(
        exec, (bbre_byte *)s, n, pos, NULL, BBRE_DFA_MATCH_FLAG_EXIT_EARLY);
    goto error;
  } else if (max_span == 1) {
    err = bbre_dfa_match(
        exec, (bbre_byte *)s, n, pos, &out_span[0].end,
        BBRE_DFA_MATCH_FLAG_PRI);
    if (err <= 0)
      goto error;
    err = bbre_dfa_match(
        exec, (bbre_byte *)s, n, out_span[0].end, &out_span[0].begin,
        BBRE_DFA_MATCH_FLAG_REVERSED | BBRE_DFA_MATCH_FLAG_PRI);
    if (err < 0)
      goto error;
    assert(err == 1);
    if (which_spans)
      *which_spans = 1;
    err = 1;
    goto error;
  }
  if ((err = bbre_nfa_start(
           exec, &exec->nfa, exec->prog->entry[entry], max_span * 2, 0, 1)))
    goto error;
  for (i = 0; i < n; i++) {
    if ((err = bbre_nfa_run(
             exec, &exec->nfa, ((const bbre_byte *)s)[i], i, prev_ch)))
      goto error;
    prev_ch = ((const bbre_byte *)s)[i];
  }
  if ((err = bbre_nfa_end(
           exec, n, &exec->nfa, max_span, 0, out_span, NULL, prev_ch)) <= 0)
    goto error;
  for (i = 0; i < max_span; i++) {
    int span_bad = out_span[i].begin == BBRE_UNSET_POSN ||
                   out_span[i].end == BBRE_UNSET_POSN;
    if (span_bad)
      out_span[i].begin = 0, out_span[i].end = 0;
    if (which_spans)
      which_spans[i] = !span_bad;
  }
error:
  return err;
}

static int bbre_match_internal(
    bbre *r, const char *s, size_t n, size_t pos, bbre_span *out_spans,
    bbre_uint *which_spans, bbre_uint out_spans_size)
{
  int err = 0;
  if (!r->exec)
    if ((err = bbre_exec_init(&r->exec, &r->prog, &r->alloc)))
      goto error;
  if ((err = bbre_exec_match(
           r->exec, s, n, pos, out_spans, which_spans, out_spans_size)))
    goto error;
error:
  return err;
}

int bbre_is_match(bbre *reg, const char *text, size_t text_size)
{
  return bbre_match_internal(reg, text, text_size, 0, NULL, NULL, 0);
}

int bbre_find(
    bbre *reg, const char *text, size_t text_size, bbre_span *out_bounds)
{
  return bbre_match_internal(reg, text, text_size, 0, out_bounds, NULL, 1);
}

int bbre_captures(
    bbre *reg, const char *text, size_t text_size, bbre_span *out_captures,
    bbre_uint out_captures_size)
{
  return bbre_match_internal(
      reg, text, text_size, 0, out_captures, NULL, out_captures_size);
}

int bbre_which_captures(
    bbre *reg, const char *text, size_t text_size, bbre_span *out_captures,
    unsigned int *out_captures_did_match, unsigned int out_captures_size)
{
  return bbre_match_internal(
      reg, text, text_size, 0, out_captures, out_captures_did_match,
      out_captures_size);
}

int bbre_is_match_at(bbre *reg, const char *text, size_t text_size, size_t pos)
{
  return bbre_match_internal(reg, text, text_size, pos, NULL, NULL, 0);
}

int bbre_find_at(
    bbre *reg, const char *text, size_t text_size, size_t pos,
    bbre_span *out_bounds)
{
  return bbre_match_internal(reg, text, text_size, pos, out_bounds, NULL, 1);
}

int bbre_captures_at(
    bbre *reg, const char *text, size_t text_size, size_t pos,
    bbre_span *out_captures, bbre_uint num_captures)
{
  return bbre_match_internal(
      reg, text, text_size, pos, out_captures, NULL, num_captures);
}

int bbre_which_captures_at(
    bbre *reg, const char *text, size_t text_size, size_t pos,
    bbre_span *out_captures, unsigned int *out_captures_did_match,
    unsigned int out_captures_size)
{
  return bbre_match_internal(
      reg, text, text_size, pos, out_captures, out_captures_did_match,
      out_captures_size);
}

unsigned int bbre_capture_count(const bbre *reg)
{
  return bbre_buf_size(reg->group_names) + 1;
}

const char *bbre_capture_name(
    const bbre *reg, unsigned int capture_idx, size_t *out_name_size)
{
  const char *out = NULL;
  size_t size = 0;
  if (capture_idx > bbre_buf_size(reg->group_names))
    goto done;
  if (capture_idx == 0) {
    out = "";
    goto done;
  }
  out = reg->group_names[capture_idx - 1].name;
  size = reg->group_names[capture_idx - 1].name_size;
done:
  if (out_name_size)
    *out_name_size = size;
  return out;
}

static int bbre_exec_set_match(
    bbre_exec *exec, const char *s, size_t n, size_t pos, bbre_uint idxs_size,
    bbre_uint *out_idxs, bbre_uint *out_num_idxs)
{
  int err = 0;
  assert(BBRE_IMPLIES(idxs_size, out_idxs != NULL));
  if (!idxs_size) {
    /* boolean match */
    err = bbre_dfa_match(
        exec, (bbre_byte *)s, n, pos, NULL,
        BBRE_DFA_MATCH_FLAG_PRI | BBRE_DFA_MATCH_FLAG_EXIT_EARLY);
  } else {
    bbre_uint i, j;
    size_t dummy;
    err = bbre_dfa_match(
        exec, (bbre_byte *)s, n, pos, &dummy,
        BBRE_DFA_MATCH_FLAG_PRI | BBRE_DFA_MATCH_FLAG_MANY);
    if (err < 0)
      goto error;
    for (i = 0, j = 0; i < exec->prog->npat && j < idxs_size; i++) {
      if (bbre_bmp_get(exec->dfa.set_bmp, i))
        out_idxs[j++] = i;
    }
    *out_num_idxs = j;
    err = !!j;
  }
error:
  return err;
}

static int bbre_set_match_internal(
    bbre_set *set, const char *s, size_t n, size_t pos, bbre_uint *out_idxs,
    bbre_uint out_idxs_size, bbre_uint *out_num_idxs)
{
  int err = 0;
  if (!set->exec)
    if ((err = bbre_exec_init(&set->exec, &set->prog, &set->alloc)))
      goto error;
  if ((err = bbre_exec_set_match(
           set->exec, s, n, pos, out_idxs_size, out_idxs, out_num_idxs)))
    goto error;
error:
  return err;
}

int bbre_set_is_match(bbre_set *set, const char *text, size_t text_size)
{
  return bbre_set_match_internal(set, text, text_size, 0, NULL, 0, NULL);
}

int bbre_set_matches(
    bbre_set *set, const char *text, size_t text_size, bbre_uint *out_idxs,
    bbre_uint out_idxs_size, bbre_uint *out_num_idxs)
{
  return bbre_set_match_internal(
      set, text, text_size, 0, out_idxs, out_idxs_size, out_num_idxs);
}

int bbre_set_is_match_at(
    bbre_set *set, const char *text, size_t text_size, size_t pos)
{
  return bbre_set_match_internal(set, text, text_size, pos, NULL, 0, NULL);
}

int bbre_set_matches_at(
    bbre_set *set, const char *s, size_t n, size_t pos, bbre_uint *out_idxs,
    bbre_uint out_idxs_size, bbre_uint *out_num_idxs)
{
  return bbre_set_match_internal(
      set, s, n, pos, out_idxs, out_idxs_size, out_num_idxs);
}

int bbre_clone(bbre **pout, const bbre *reg, const bbre_alloc *alloc)
{
  int err = 0;
  if ((err = bbre_init_internal(pout, alloc)))
    goto error;
  if ((err = bbre_prog_clone(&(*pout)->prog, &reg->prog)))
    goto error;
error:
  return err;
}

int bbre_set_clone(
    bbre_set **pout, const bbre_set *set, const bbre_alloc *alloc)
{
  int err = 0;
  if ((err = bbre_set_init_internal(pout, alloc)))
    goto error;
  if ((err = bbre_prog_clone(&(*pout)->prog, &set->prog)))
    goto error;
error:
  return err;
}

/*{ Generated by `unicode_data.py gen_casefold` */
static const signed int bbre_compcc_fold_array_0[] = {
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
static const unsigned short bbre_compcc_fold_array_1[] = {
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
static const unsigned short bbre_compcc_fold_array_2[] = {
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
static const unsigned char bbre_compcc_fold_array_3[] = {
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
static const unsigned short bbre_compcc_fold_array_4[] = {
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
static const unsigned char bbre_compcc_fold_array_5[] = {
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

static int bbre_compcc_fold_next(bbre_uint rune)
{
  return bbre_compcc_fold_array_0
      [bbre_compcc_fold_array_1
           [bbre_compcc_fold_array_2
                [bbre_compcc_fold_array_3
                     [bbre_compcc_fold_array_4
                          [bbre_compcc_fold_array_5[((rune >> 13) & 0xFF)] +
                           ((rune >> 9) & 0x0F)] +
                      ((rune >> 4) & 0x1F)] +
                 ((rune >> 3) & 0x01)] +
            ((rune >> 1) & 0x03)] +
       (rune & 0x01)];
}

static int bbre_compcc_fold_range(
    bbre *r, bbre_rune_range range, bbre_compframe *frame, bbre_uint prev)
{
  bbre_uint current, x0, x1, x2, x3, x4, x5, begin = range.l, end = range.h;
  int err = 0;
  signed int a0;
  unsigned char a3, a5;
  unsigned short a1, a2, a4;
  assert(begin <= BBRE_UTF_MAX && end <= BBRE_UTF_MAX && begin <= end);
  for (x5 = ((begin >> 13) & 0xFF); x5 <= 0x87 && begin <= end; x5++) {
    if ((a5 = bbre_compcc_fold_array_5[x5]) == 0x3C) {
      begin = ((begin >> 13) + 1) << 13;
      continue;
    }
    for (x4 = ((begin >> 9) & 0x0F); x4 <= 0xF && begin <= end; x4++) {
      if ((a4 = bbre_compcc_fold_array_4[a5 + x4]) == 0xCC) {
        begin = ((begin >> 9) + 1) << 9;
        continue;
      }
      for (x3 = ((begin >> 4) & 0x1F); x3 <= 0x1F && begin <= end; x3++) {
        if ((a3 = bbre_compcc_fold_array_3[a4 + x3]) == 0x30) {
          begin = ((begin >> 4) + 1) << 4;
          continue;
        }
        for (x2 = ((begin >> 3) & 0x01); x2 <= 0x1 && begin <= end; x2++) {
          if ((a2 = bbre_compcc_fold_array_2[a3 + x2]) == 0x7D) {
            begin = ((begin >> 3) + 1) << 3;
            continue;
          }
          for (x1 = ((begin >> 1) & 0x03); x1 <= 0x3 && begin <= end; x1++) {
            if ((a1 = bbre_compcc_fold_array_1[a2 + x1]) == 0x60) {
              begin = ((begin >> 1) + 1) << 1;
              continue;
            }
            for (x0 = (begin & 0x01); x0 <= 0x1 && begin <= end; x0++) {
              if ((a0 = bbre_compcc_fold_array_0[a1 + x0]) == +0x0) {
                begin = ((begin >> 0) + 1) << 0;
                continue;
              }
              current = begin + a0;
              while (current != begin) {
                if ((err = bbre_compile_cc_append(
                         r, frame, prev,
                         bbre_rune_range_make(current, current))))
                  return err;
                current =
                    (bbre_uint)((int)current + bbre_compcc_fold_next(current));
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

/*} Generated by `unicode_data.py gen_casefold` */

typedef struct bbre_builtin_cc {
  bbre_uint name_len, num_range, start_bit_offset;
  const char *name;
} bbre_builtin_cc;

/* builtin_cc_data is a bitstream representing compressed rune ranges.
 * Normalized ranges are flattened into an array of integers so that even
 * indices are range minimums, and odd indices are range maximums. Then the
 * array is derived into an array of deltas between adjacent integers. For
 * compression optimality, 1s and 2s are swapped. Then each integer (of which
 * all are positive, since the ranges always increase) becomes:
 *
 *  0         if integer == 0
 *  0         if integer == 1 && previous_integer == 0
 *  1 <var>   if integer  > 1 && previous_integer == 0
 *  1 0       if integer == 1 && previous_integer != 0
 *  1 1 <var> if integer  > 1 && previous_integer != 0
 *
 * where <var> is the variable-length encoding of the integer - 2, split into
 * 3-bit chunks, with a fourth bit added to signify 'done'. For example:
 *
 *  1   -> 1 0 0 0
 *  8   -> 0 0 0 1 1 0 0 0
 *  127 -> 1 1 1 1 1 1 1 1 1 1 0 0
 *
 * This was the best compression scheme I could come up with. For property data,
 * each integer uses about 5.14 bits on average (~0.63 bytes). This represents
 * about an 84% reduction in size compared to just storing each range as two
 * 32-bit integers. */

/*{ Generated by `unicode_data.py gen_ccs impl` */
/* 3360 ranges, 6720 integers, 4244 bytes */
static const bbre_uint bbre_builtin_cc_data[1061] = {
    0x7ACF7CF7, 0xADFF7AD7, 0x7F27AD77, 0x6BD16A7D, 0xB7CF71F6, 0xFB36ECDF,
    0x0D0DF7AD, 0xF667D92B, 0x998E6FD8, 0x9DB69D8E, 0xC9596FA6, 0xF3DDEB7F,
    0xAC6DEB3D, 0x6CF7CF77, 0xCD7A6D3B, 0x6DACFB3E, 0x6B6D2B6A, 0xD82E7FA9,
    0xE7CCC37F, 0x6FFE8B67, 0x0BCB4ECB, 0xAFDCDF4B, 0x3343FA3C, 0x2A3C823A,
    0x335CD277, 0xB34DFB26, 0xA3B5CF3A, 0x35E962BE, 0xFFFDCD7B, 0xE97FA723,
    0xF27FEE89, 0xF249BFFF, 0xDB99BFFF, 0xAFEE47FF, 0xE61AFE61, 0xADFB32FF,
    0x6B0D93F7, 0x00000575, 0x00000000, 0x4300010C, 0x00000000, 0x13412000,
    0x926C3292, 0xC48124D2, 0x0D20A490, 0x01249753, 0x00010C00, 0x000A130C,
    0x00000000, 0x24C70000, 0x3300690D, 0x08EC3B4A, 0xE92B4A28, 0x52C34272,
    0x92C00000, 0xDCAF0D24, 0x00000015, 0x00000C80, 0x00000000, 0x10C00120,
    0x00000000, 0x00000000, 0x60000000, 0xE37739DF, 0xFB3530DC, 0xD22A76DE,
    0xF4DCEF33, 0x37ED2CCF, 0x00000167, 0x00000000, 0x00000000, 0x00000000,
    0xC0000000, 0x00000013, 0x00000000, 0x00000000, 0x336DF3C0, 0x6DF5DF5D,
    0xF5DF5D33, 0xDF5D36CD, 0xD2DF5DF5, 0x7C352970, 0xD77C34D3, 0x4A9C354C,
    0xA2E8B0CA, 0x4DF0D269, 0xB6B61B9B, 0x043295DC, 0x01DB431A, 0x00000000,
    0x00000000, 0xC0000000, 0x76C9A0F0, 0xA99F865A, 0x00000002, 0x00AA0000,
    0xE2A00000, 0x00014000, 0x00000000, 0x48570000, 0x05121A00, 0x00618000,
    0x80161A00, 0x1B9C8A6E, 0x33CF1C37, 0x7F9F9D73, 0x8ACB6CC7, 0xCEADEB0D,
    0x778AD671, 0x4332EAD2, 0xEC347473, 0xFDC2F289, 0xDADD7B1C, 0xBABD7B7F,
    0x74EDEB4E, 0xEB4EDF34, 0xD1C534ED, 0xB7AD3B0C, 0xAD3B7AD3, 0x3B7AD3B7,
    0x7AD3B7AD, 0xD3B7AD3B, 0xB4ED3B7A, 0x3B6D3ADB, 0xD3B6D3AD, 0xAD3B6D3A,
    0x3AD3B6D3, 0xF6B9E96D, 0x9DB5D2B5, 0xACDFB3BF, 0x336DF33D, 0xA83CB5CD,
    0xA5EF8618, 0xC369A967, 0xFA6C31C9, 0x7EA8A0C8, 0x6AEA8E6A, 0x1B8C8FF2,
    0x2DC93BBA, 0x7CF8A732, 0xC7F5DADB, 0x329D261C, 0xF21C82EB, 0xCFBF72CD,
    0x3FA82FB0, 0xCB2D86BE, 0xB30C2721, 0x96A7EF47, 0xC9DB49EA, 0x36E92F25,
    0xCCCF0FCC, 0xD0DC8EA7, 0x6A1AFC32, 0x9B720CA9, 0x339CC31A, 0x622B60CD,
    0xEFEC31D9, 0xCF5E75B7, 0xAD318BCB, 0x7FCB33CC, 0xDB222643, 0x23B0D1D4,
    0x33B6FC2E, 0xA876F31C, 0x906D63EC, 0xA6D3FF47, 0x97CE4F9D, 0x8EE9B61D,
    0x194EFABD, 0x6F52139A, 0x3E49A998, 0xD663DB76, 0x7DBD4599, 0xA6ED58D6,
    0x8E199E75, 0x3856DAB5, 0x16D797E7, 0xBE6F9C95, 0x1A6BB639, 0x523AD5A6,
    0x393E45A6, 0x986B9A86, 0x61B6DBC9, 0xA1A3AD5A, 0x299F61A1, 0xA9EF9A55,
    0x6868EB56, 0x67925459, 0x6B964758, 0x3AD5A61A, 0xBD165A1A, 0x05479A86,
    0x65A6A5B6, 0x96196188, 0x72D69996, 0x68D6AAED, 0x26A745AE, 0xBB4BD869,
    0x5AFA35AA, 0x86867D16, 0x9E158679, 0x3E499CEA, 0xB6F5AFA3, 0xAD65BE63,
    0xA7E3A49E, 0xDB661ABB, 0x6962197E, 0x661AF8AD, 0xA6759690, 0x3AB9FCFD,
    0x5E659769, 0xF93561B9, 0x945A6DB6, 0x659B69E1, 0xC6E17936, 0x988E9A69,
    0xA69A73A6, 0x23A69A7D, 0xDE8E69A6, 0x84669A69, 0x179AE633, 0xE69A6E66,
    0x6663BD69, 0xBE67AEB8, 0x6B985639, 0xA966B9BE, 0x4F3A5E79, 0x57A13946,
    0x2FDA659E, 0x699B4663, 0x9B76178F, 0xDA6E5996, 0x8D6B7BD6, 0xFB595E19,
    0x7AE158EE, 0x8639B76B, 0xE9DA6E99, 0x699A1BA4, 0x6A6179B7, 0x7C54586B,
    0x79DFEE9A, 0x6635BD6B, 0x3A3A3A38, 0x3A3A3A3A, 0x4371CC66, 0x663ED59B,
    0xA1B8CDBD, 0xBD856DD9, 0xFFEB9BEE, 0xFCBF7393, 0x56BFF1B3, 0x198DE56B,
    0x64EFACE5, 0x699AE6DA, 0x985C9198, 0x3906D6D1, 0xA9AA3947, 0x6978F635,
    0xDAFEFBAE, 0x76598616, 0x1D8D699A, 0xB8EE7976, 0x999E9963, 0xA759CE96,
    0x6AE6D5AE, 0x52FB945B, 0x50996986, 0x7866586F, 0x6DA6DAE4, 0x3A3866DA,
    0xF6138556, 0x64937B50, 0x67BB635B, 0xDBBB44C5, 0x466F39A6, 0x96966BE1,
    0x9B9A1A18, 0x561BB84E, 0xED7A6BFA, 0xB5E699BC, 0x6E6315A5, 0xDA65BAF8,
    0x6DA6D963, 0x994EA6DA, 0xA15AF5A9, 0xD9A639A1, 0x5E1F9A4E, 0x7B965D8C,
    0x8E6BD9EE, 0xD3AEBA95, 0x3A6DDA66, 0xBFE6BB69, 0x3A4E6D99, 0x75697BEB,
    0x5866373B, 0xD56BA66D, 0x6A6E26DB, 0x6635A458, 0x3D86635A, 0x1A158466,
    0xA66D5A66, 0xB7AC66F5, 0x793FE1AE, 0x9B976AA6, 0x39765976, 0x5DA76AE5,
    0xB5699B5E, 0x63985699, 0xC66BB9BE, 0xBA4E7759, 0x86BBCEDD, 0x99976B99,
    0x9A6ED5BC, 0x7655AEEF, 0x57B66359, 0x3926187E, 0x9D6FD96E, 0x43DA4E9D,
    0x64584EF2, 0x69AE6BBB, 0xAF994C0D, 0xFE195675, 0x8E6A6239, 0xB38EE7BE,
    0x569869AE, 0x596868EB, 0x596D9254, 0x69595EBD, 0xEEBDAD5A, 0xDD486D5A,
    0xE986E3BB, 0xF356BBB4, 0x643986E5, 0x38CE1D9C, 0x769B87D6, 0xAE926B95,
    0x079AD686, 0xCE9AEBD9, 0x64DD0F98, 0x4351EB3A, 0x5156DB96, 0x7139C669,
    0xC1594E9E, 0xBEE6DD85, 0xD6D3A1A3, 0x686B61D0, 0x9C6CB9AF, 0x9661E615,
    0x64DF9BF6, 0xF6F5799E, 0x66E91DAC, 0x9E67D9B6, 0xD856BB15, 0x19987DFE,
    0x987DC563, 0x63D9E771, 0x85639985, 0xEBBA56DD, 0x158E5595, 0x199BEEE6,
    0xF647B50E, 0x5756F2DF, 0xD951C9BB, 0x7984CE77, 0x6B9268F4, 0x33A65EFA,
    0x6386E6D1, 0xBE79E596, 0xDFCFB995, 0x1B04E5B8, 0x6E95B761, 0x9876D3FA,
    0x6A68E37D, 0x94768E68, 0x76A65F35, 0x6BE24868, 0x6A034B0A, 0x48600248,
    0x9A9A3A9A, 0xA39E6BE2, 0xB199E696, 0xF77564D1, 0xDC464FD2, 0x493774B3,
    0x4B93FE76, 0x4791ECDE, 0x937336E6, 0x3F5B7466, 0x3066E649, 0x3F2F6464,
    0x2599249A, 0xDF5C6AEF, 0xC9B35DF5, 0xD6FF8F63, 0xE8D6339B, 0x00000138,
    0x00000000, 0x09000090, 0x00000000, 0x19421800, 0x6A69A862, 0x086865A8,
    0x8A862486, 0x49247161, 0x00240002, 0x00A24900, 0x00000000, 0xA19C0000,
    0x300A6261, 0x8B3C5013, 0x9E9E6862, 0x0016A453, 0x1890C000, 0x03EE17A6,
    0x90000000, 0x00000001, 0x18000000, 0x00024002, 0x00000000, 0x00000000,
    0xD3A40000, 0x2D3866EE, 0x59A57643, 0x1BA754ED, 0x003FCEA6, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00019000, 0x00000000, 0x00000000,
    0x86400000, 0xBA66DBEB, 0x66DBEBBE, 0xC66BBC01, 0x669B669B, 0x665B669B,
    0x4D2C4E99, 0x96526A69, 0x69A6980B, 0xC3F0E1A6, 0xEEBBB7E6, 0x929809A3,
    0x000002BC, 0x00000000, 0x00000000, 0xFCD0F000, 0x00000E6C, 0x50000000,
    0x00000005, 0x14000715, 0x00000000, 0x90000000, 0x0D008609, 0x00000509,
    0x80009696, 0x3740CB29, 0xBD65B3DB, 0x5ACE31D5, 0xDD5A4EF1, 0x8E8E6866,
    0x5E9BDD86, 0xAF63BFB8, 0xAF6FFB5B, 0xBD6FD757, 0x69DBD69D, 0x26189DBD,
    0xAEA69869, 0x69DBD69D, 0x8EAE9A68, 0x96A6865D, 0xF5976394, 0xA76F5A76,
    0x6F5A76F5, 0x5A76F5A7, 0x4E75AF6F, 0x7584E758, 0x84E7584E, 0x31904E75,
    0x133BF637, 0x6FA91DC9, 0xF869786A, 0x86986BA9, 0xA9F16C99, 0x3EA7C919,
    0x9F863786, 0x986986B0, 0x1A1ACE49, 0x1B266A96, 0x63FA63FA, 0x1A6589F8,
    0x7618661A, 0xA9F86B93, 0xA6C99AA3, 0xBAE96661, 0xA66E1A56, 0x65B51FE1,
    0xD8692CD8, 0xE9A99861, 0xB6986358, 0xDE76A649, 0x70454BD3, 0x69DB86AE,
    0xB686DA9A, 0x09F86FDD, 0x6DBE1819, 0x60CFB055, 0x2F43F869, 0x937C986D,
    0xBBEE194A, 0x516D61BE, 0x1ADCE643, 0x6195FF7E, 0x9786F592, 0x86B95AE6,
    0xB61BEC7B, 0x1AEE6A61, 0x3B3D61A6, 0xE1A43B90, 0x86863BD0, 0x15455C86,
    0xDA3B1FE4, 0xBD457986, 0x9AFB17E1, 0xF6439861, 0x9B521968, 0x69F867DA,
    0xA9869A68, 0x761A6419, 0x9161BE85, 0x2698BA9B, 0x9A6BA3BD, 0x21BE85E4,
    0x92E183B9, 0xC4CD861B, 0x677D0668, 0x5424D86B, 0x9369BEAE, 0xFE18F4D5,
    0x92E47572, 0xD7491C9B, 0xDB21B658, 0xBECD986B, 0x11B21BE1, 0xF398DE79,
    0x657B1786, 0x7155B6B8, 0x4D71D986, 0x66A9AF47, 0xF66965D4, 0x54EBB99F,
    0x5B864E59, 0xC6486862, 0x55BEE19B, 0x8E3393E6, 0xA6869B69, 0x61DAF453,
    0xA7E19976, 0xA6F50667, 0xA5B96A9E, 0xD69BAEDF, 0xD077AF6A, 0x66394DAE,
    0x49F0F61A, 0x86D53E9B, 0x07E1A49D, 0xA986D86D, 0x9161AF45, 0x5B41F865,
    0x86D5361A, 0x927CB6B5, 0x98673E98, 0x0FCBD865, 0xDC525CD9, 0x67A6A3A1,
    0xC3D86598, 0x8632C927, 0x86DD86D5, 0xFA6D861F, 0x90F61B54, 0x9D929CF1,
    0x6BB663A4, 0x599E924E, 0xD861998E, 0xAD99DC05, 0xA198E1A5, 0xB3906693,
    0x6986B6A6, 0x9AD861D8, 0x1A439A6F, 0xFD64792E, 0xF6A5DE69, 0xF61AF618,
    0x3A1BFE1A, 0x1986693E, 0x637928EC, 0x6ADE4938, 0xDAB0661B, 0x27C9865D,
    0xEBAE908E, 0xAD9BEC9B, 0xEE985EB9, 0xEF30C963, 0x6FD86D99, 0x8F7A869A,
    0xAE9FA161, 0x6AF55869, 0x52CD8E96, 0xAFEB1D86, 0xD966F9D9, 0xFFEE9994,
    0xFD90E56A, 0x69B19AF6, 0x5F865B9A, 0xF6FB4D5F, 0xE1BE661B, 0x1D3453E4,
    0x19D54386, 0x0E6F9A76, 0x661DAEB3, 0xA4FBABB8, 0x91CE1A69, 0x9869B651,
    0x7B3CD986, 0x3869A15C, 0x3E1A6C86, 0xCCD24BBD, 0x13D93ECF, 0xAE6F9AE6,
    0x24F439F9, 0x15D96355, 0x3A6386AB, 0x18CD4DAF, 0x5E98FC66, 0x6BE66194,
    0x85E19AC6, 0x6B717E69, 0x61A41B8E, 0xA6985EA6, 0xD3A3F1E1, 0x64BFAE96,
    0x667B5E1B, 0xA7D9269A, 0x5492E189, 0x635AE50F, 0xCC5861F8, 0x47659638,
    0x4752A6B9, 0x86D2DB56, 0xBA6BBD86, 0x865D8686, 0x189AE359, 0x2DA426E6,
    0x6A69A339, 0x869E5139, 0x53486FFD, 0xD869A6F9, 0xDBCEFBF4, 0x6193E9A6,
    0x966BBA9B, 0x68EB5786, 0x6D5A564B, 0xE61A1A3A, 0xE8616DA7, 0x161BC648,
    0x9661976C, 0x40E5B5E1, 0xE6B0FF56, 0x969D5DD8, 0xF5158E5F, 0x056699FC,
    0x986F7573, 0x9B6E1399, 0xAFD198D6, 0xD8E9AE15, 0xDAD55A6B, 0xED8DE5F7,
    0xB52E4FBE, 0x9B58E696, 0xE99E68EF, 0xD3996868, 0xDEE3BF54, 0xDFFA63F1,
    0x8EFDF9A6, 0x91D8E3B9, 0xAEF6377D, 0xB31DBE7B, 0xDBEB15BE, 0xEDD7BEB1,
    0x79BEB79B, 0xBEB79BEB, 0xB79BEB79, 0x9BEB79BE, 0xEB79BEB7, 0xD9BEB79B,
    0xBEB79BEF, 0xB53BEB19, 0xDBEB19BE, 0xEB3BEB1B, 0xF9BEDB3B, 0xBEB35BEF,
    0xBEB75BEB, 0xB15BEB59, 0x319BEBBE, 0x359BEB1F, 0xDBEB3BEB, 0xBEB5BEB1,
    0xB57BEB59, 0xEB539BBE, 0x3BEB175B, 0xB39BEB15, 0xBEFF9BED, 0xEF95BEDF,
    0x5BBEB53B, 0xBEB79BEB, 0xB39BEB7B, 0x7BEB39BE, 0xEB39BEB3, 0xDBEB7D9B,
    0xEB19BEB7, 0xB3BEB37B, 0xB59BEB13, 0x7BEB15BE, 0x3BEED797, 0xB37BEFF3,
    0x5BEB7FBE, 0x599BEB59, 0xBDD9BEB5, 0x4E7B9BA3, 0xBF9FA698, 0xEAE67874,
    0xEEF96D77, 0x7E57BE66, 0x5AC54F36, 0xB9A6C456, 0x0E185D63, 0xB63733A9,
    0xF79B6F7B, 0xDD8E315A, 0x79E158E1, 0x3715BE17, 0xE5795A56, 0xD574FDFB,
    0xDBEBB650, 0x41BAE6B1, 0x669FAD76, 0xDE66D5AE, 0x06ED6DDA, 0x95A6D555,
    0x6AEBDBE9, 0x73BEFD8E, 0xFBB5F8E6, 0xE15D3BB6, 0x5A611996, 0x7635B861,
    0x735A6D38, 0x38E1DAED, 0x965999E7, 0x6FD5B6B5, 0x6E9AE698, 0x6D79EFFB,
    0x6599ABD8, 0xF5AEF399, 0x9B8E1BAE, 0xF6FDBB69, 0x9BBEBD58, 0x58EFB9A6,
    0x5FBA56B1, 0x631B5A56, 0xB99EBB78, 0x5B985673, 0x17B39565, 0x6BD398EB,
    0x61B1578D, 0x9A56D9A5, 0xB599D6DB, 0x13799EB9, 0x99A6A87E, 0x98E696ED,
    0xD996691F, 0x19F7FE4B, 0xDF7B9156, 0xBDAF586B, 0xBB6A6DC7, 0x8233E2B9,
    0x3226188A, 0x48223F6C, 0x6E9B0CFA, 0x722A97EE, 0x7CBB9C8F, 0xA93219C3,
    0x38FAFE0D, 0x7C7D15CF, 0x2F6F40FD, 0x91DC1B73, 0xF427E647, 0x000BF152,
    0x00FD3E64, 0x0000355C, 0x54130FF0, 0x036C00CC, 0x050036DC, 0x37398690,
    0x3D0774BD, 0x05450000, 0xD15C9B50, 0x4FAC9247, 0xA287B7F2, 0x6878FB9B,
    0xB58A3C92, 0x936EFE49, 0xF7074986, 0x7924D0F1, 0x1355FB14, 0xCB0D330C,
    0x668C8BB0, 0xB23C35C8, 0xD2BE797E, 0x925B8376, 0xDAB0DB64, 0xCD0730D0,
    0x659CD34C, 0x437B6CCB, 0x8FB1CD6F, 0xA4CC3189, 0xF27BC9B2, 0x9B258B83,
    0xC93B23DD, 0x7379AC34, 0x4CC9F724, 0x3DCC36CB, 0x7322DADB, 0x862733DA,
    0x338CD6FC, 0x19D51EAC, 0x30F9D35B, 0xFCC37AEC, 0x6DADB477, 0xFCC36EC7,
    0xFCB2FD31, 0xCD77FC35, 0xF0D23722, 0x4D33DF5D, 0xF10CCB53, 0x3534EABD,
    0xCF2A7DCC, 0x4F4935B0, 0xD330D243, 0x314D37D2, 0xD6DBD4CB, 0xAF87EA0F,
    0x1C9C3488, 0xC93229CD, 0x36FDDB2B, 0x79C35ACD, 0x8F70C2E5, 0x7CCB309C,
    0xCD36FCC3, 0xC37CC35F, 0xA63360FE, 0xAA5A931D, 0xD4B4D30D, 0xAC3174F4,
    0xC304D51A, 0xEC32C34C, 0xBC349A62, 0x66EACD4E, 0x7B25EB9F, 0x8FA38E8E,
    0x259CF7C9, 0xD2331DF7, 0xF34C3B31, 0x4DB72DEE, 0x7731C7EB, 0xD7F34D0C,
    0xF330DF74, 0x341C9B4C, 0x8B736DEB, 0x34CCB09B, 0x4FE9E724, 0xED0DCC6B,
    0xA6CCCB36, 0x99BFB522, 0xB22EAD78, 0xD4AB35DB, 0xE77C7B32, 0x30D372CE,
    0x3330C62B, 0xA8F6B2CD, 0xFDDCB7DC, 0x2FCDEC36, 0x23218AC3, 0x4ADC9F2C,
    0xAE638DD3, 0x39FBC9BE, 0xC34AEFCB, 0xE3E92E39, 0x7B7A17EB, 0x98A5FD99,
    0x323C8EE5, 0x8A97A13F, 0xF320005F, 0xAAE007E9, 0x7F800001, 0x0662A098,
    0x804A83A0, 0x00A006DB, 0x099B9C92, 0x001E8EBA, 0xA802A280, 0xA3E92E4D,
    0x3F914E48, 0xE41BD5A6, 0xF8697F17, 0xDF478697, 0xC6647130, 0x74C5D730,
    0xF4667DB4, 0x51F5B1DE, 0x49D536E4, 0x61961977, 0xE69ADFFE, 0xB732F4E4,
    0x8C81ECCF, 0x8C8A6963, 0xB36CD30C, 0x33CC471D, 0xAC35C86F, 0xAE7B2489,
    0xD1CD2CD1, 0xCC31CD1C, 0xEFC36EA8, 0x0CC6B29C, 0xCC339CC3, 0x70D727CF,
    0x33CD6323, 0x926A0BF7, 0xCB3A8AFC, 0x07F5F24D, 0xE8666876, 0x8C97FB23,
    0x2F8DCD3C, 0x1CD39872, 0x2CE62CAD, 0x1CB68C97, 0x8E4926C3, 0x3E84C33E,
    0xC37ED327, 0x3AD7A4EC, 0x86BF6DE7, 0x735D6E0C, 0x4CB7CD8F, 0xD734CC7B,
    0xAC22B7FE, 0xD7B6C7F5, 0xB7DDFFB4, 0xF9CDB4CA, 0x1EE726EF, 0xF5F269AD,
    0x358A2A07, 0xA6AEEDCD, 0xE83A3E83, 0x3A3E83A3, 0xEC83A3E8, 0x19AC36D9,
    0x0AFC8692, 0xFF30D326, 0x4C973B0C, 0x8EFB0CAA, 0x86F6288C, 0xA2A5B48A,
    0xB8363CE9, 0xD343CD38, 0x18A81AB6, 0x31C35B57, 0xECC318ED, 0x2AECDF7D,
    0x1EA92BB2, 0xDF09DDFB, 0x28BACF0C, 0x4CC35343, 0x6816D70C, 0x31730CB2,
    0xC330D3E4, 0x0D0D4D32, 0x0D31ED1D, 0x76C9C7B1, 0xC74D2B6D, 0xDBB4F334,
    0x335D670E, 0xCC330ECA, 0x5ADB330A, 0xAF4F46EB, 0xFB47737D, 0xFD376DD6,
    0x7FFD7FB7, 0x5C31AD77, 0x357B4C67, 0xDB19ECE7, 0xB5DC319D, 0x6CCEB35E,
    0x734EDABB, 0xB30C726D, 0xC35C31A9, 0xDF6C37CD, 0x22CD277E, 0xECB31EDF,
    0xD7B3C9F6, 0x73CC674C, 0x7FB9CD7E, 0x7CAEDD7F, 0x309DCC6F, 0xE32434CD,
    0xD63B3747, 0x1D8FF35C, 0x368A69FD, 0x0F9C31CC, 0x4CF30FCF, 0xCF62CB35,
    0x0D3F3B2D, 0xBCB8F333, 0xB5C6AA65, 0x337673CD, 0xAD8D874D, 0xCCAEB325,
    0x6BEDBF4B, 0xFD319D33, 0xF0D6B474, 0xB2FDB6EC, 0xFA8B7FC6, 0xDAAC6B34,
    0x33BD7FF0, 0x5B3574BD, 0x7678EEC3, 0xB208A9BB, 0xCDB4DC2B, 0x31CDB349,
    0x9D1CD1CD, 0xF3EACEB2, 0xDC732EDE, 0x30CF3DB4, 0xED3AB6D7, 0x5AECC70F,
    0x2CCB3CDB, 0xCDB1BCCB, 0x9B4CD71E, 0x6F6D333C, 0xD675DF7D, 0xCC34DBB7,
    0x6CD2B75C, 0x2CB34DB3, 0xC75B73CF, 0x3CF6DB37, 0xF42AB3CF, 0x63988AC6,
    0x8FB3CC45, 0xFBEB23FC, 0xC333FD98, 0xEBF8F669, 0x00000007};
static const bbre_builtin_cc bbre_builtin_ccs_ascii[16] = {
    {5,  3, 0,   "alnum"     },
    {5,  2, 48,  "alpha"     },
    {5,  1, 84,  "ascii"     },
    {5,  2, 98,  "blank"     },
    {5,  2, 115, "cntrl"     },
    {5,  1, 140, "digit"     },
    {5,  1, 156, "graph"     },
    {5,  1, 180, "lower"     },
    {10, 3, 204, "perl_space"},
    {5,  1, 235, "print"     },
    {5,  4, 259, "punct"     },
    {5,  2, 327, "space"     },
    {5,  1, 350, "upper"     },
    {4,  4, 370, "word"      },
    {6,  3, 420, "xdigit"    },
    {0,  0, 0,   ""          }
};
static const bbre_builtin_cc bbre_builtin_ccs_unicode_property[37] = {
    {2, 2,   464,   "Cc"                   },
    {2, 21,  498,   "Cf"                   },
    {2, 6,   906,   "Co"                   },
    {2, 4,   1043,  "Cs"                   },
    {2, 658, 1132,  "Ll"                   },
    {2, 71,  4150,  "Lm"                   },
    {2, 524, 5261,  "Lo"                   },
    {2, 10,  12472, "Lt"                   },
    {2, 646, 12591, "Lu"                   },
    {2, 182, 15379, "Mc"                   },
    {2, 5,   17519, "Me"                   },
    {2, 346, 17621, "Mn"                   },
    {2, 64,  21983, "Nd"                   },
    {2, 12,  23311, "Nl"                   },
    {2, 72,  23557, "No"                   },
    {2, 6,   24983, "Pc"                   },
    {2, 19,  25094, "Pd"                   },
    {2, 76,  25371, "Pe"                   },
    {2, 10,  25842, "Pf"                   },
    {2, 11,  25943, "Pi"                   },
    {2, 187, 26056, "Po"                   },
    {2, 79,  28702, "Ps"                   },
    {2, 21,  29193, "Sc"                   },
    {2, 31,  29574, "Sk"                   },
    {2, 64,  30046, "Sm"                   },
    {2, 185, 30898, "So"                   },
    {2, 1,   33766, "Zl"                   },
    {2, 1,   33789, "Zp"                   },
    {2, 7,   33812, "Zs"                   },
    {1, 0,   0,     "CCc,Cf,Cs,Co"         },
    {1, 0,   0,     "LLu,Ll,Lo,Lt,Lm"      },
    {1, 0,   0,     "MMn,Me,Mc"            },
    {1, 0,   0,     "NNd,No,Nl"            },
    {1, 0,   0,     "PPo,Ps,Pe,Pd,Pc,Pi,Pf"},
    {1, 0,   0,     "SSc,Sm,Sk,So"         },
    {1, 0,   0,     "ZZs,Zl,Zp"            },
    {0, 0,   0,     ""                     }
};
static const bbre_builtin_cc bbre_builtin_ccs_perl[4] = {
    {1, 1, 140, "d"},
    {1, 3, 204, "s"},
    {1, 4, 370, "w"},
    {0, 0, 0,   "" }
};
/*} Generated by `unicode_data.py gen_ccs impl` */

#define BBRE_COMPRESSED_CC_BITS_PER_WORD 32

/* Read a single bit from the compressed bit stream. Update the pointer and the
 * bit index variables appropriately. */
static int bbre_builtin_cc_next_bit(const bbre_uint **p, bbre_uint *idx)
{
  bbre_uint out = ((**p) & ((bbre_uint)1 << (*idx)++));
  if (*idx == BBRE_COMPRESSED_CC_BITS_PER_WORD)
    *idx = 0, (*p)++;
  return (int)!!out;
}

static int bbre_builtin_cc_make(
    bbre *r, const bbre_byte *name, size_t name_len,
    const bbre_builtin_cc *start, bbre_uint *out_ref)
{
  const bbre_builtin_cc *p = NULL, *found = NULL;
  int err = 0;
  *out_ref = 0;
  /* Find the property with the matching name. */
  for (p = start; p->name_len; p++)
    if (p->name_len == name_len && !memcmp(p->name, name, name_len)) {
      found = p;
      break;
    }
  if (!found) {
    err = bbre_err_parse(r, "invalid Unicode property name");
    goto error;
  }
  if (found->num_range) {
    if ((err = bbre_ast_make(
             r, out_ref, BBRE_AST_TYPE_CC_BUILTIN, found->start_bit_offset,
             found->num_range)))
      goto error;
  } else {
    /* if !found->num_range, then this is the logical OR of several classes */
    const char *name_begin = p->name + p->name_len;
    while (*name_begin) {
      bbre_uint subcls = BBRE_NIL;
      const char *name_end = name_begin;
      while (*name_end && *name_end != ',')
        name_end++;
      if ((err = bbre_builtin_cc_make(
               r, (const bbre_byte *)name_begin, name_end - name_begin, start,
               &subcls)))
        goto error;
      if (!*out_ref)
        *out_ref = subcls;
      else if ((err = bbre_ast_make(
                    r, out_ref, BBRE_AST_TYPE_CC_OR, *out_ref, subcls)))
        goto error;
      if (*name_end == ',')
        name_end++;
      name_begin = name_end;
    }
  }
error:
  return err;
}

static int bbre_builtin_cc_decode(
    bbre *r, bbre_uint start, bbre_uint num_range, bbre_compframe *frame)
{
  const bbre_uint *read; /* pointer to compressed data */
  bbre_uint i, bit_idx, prev = BBRE_UTF_MAX + 1, accum = 0, range[2];
  int err;
  /* Start reading from the p->start offset in the compressed bit stream. */
  read = bbre_builtin_cc_data + start / BBRE_COMPRESSED_CC_BITS_PER_WORD,
  bit_idx = start % BBRE_COMPRESSED_CC_BITS_PER_WORD;
  assert(num_range); /* there are always ranges in builtin charclasses */
  for (i = 0; i < num_range; i++) {
    bbre_uint *number, k;
    range[0] = 0, range[1] = 0;
    /* Read two integers per range. */
    for (number = range; number < &(range[2]); number++) {
      /* If the previous number was zero, we *know* that the next number is
       * nonzero. So, we don't read the 'is zero' bit if we don't need to. */
      int not_zero = prev == 0 ? 1 : bbre_builtin_cc_next_bit(&read, &bit_idx);
      if (!not_zero)
        *number = 0;
      else {
        /* The 'not one' bit is always necessary. */
        int not_one = bbre_builtin_cc_next_bit(&read, &bit_idx);
        if (!not_one)
          *number = 1;
        else {
          do
            for (k = 0; k < 3; k++)
              *number =
                  (*number << 1) | bbre_builtin_cc_next_bit(&read, &bit_idx);
          while (bbre_builtin_cc_next_bit(&read, &bit_idx));
          *number += 2;
        }
      }
      /* Swap 1s and 2s. */
      *number = *number == 1 ? 2 : *number == 2 ? 1 : *number;
      prev = *number;
      /* Add the accumulated delta, and then update the accumulator itself. */
      *number = accum + *number, accum = *number;
    }
    /* We now have decoded the low and high ordinals of the range. */
    if ((err = bbre_compile_cc_append(
             r, frame, frame->tail, bbre_rune_range_make(range[0], range[1]))))
      goto error;
  }
  assert(
      range[1] <
      BBRE_UTF_MAX); /* builtin charclasses never reach BBRE_UTF_MAX */
  assert(i);         /* builtin charclasses are not length zero */
error:
  return err;
}

static int bbre_builtin_cc_unicode_property(
    bbre *r, const bbre_byte *name, size_t name_len, bbre_uint *out_ref)
{
  return bbre_builtin_cc_make(
      r, name, name_len, bbre_builtin_ccs_unicode_property, out_ref);
}

static int bbre_builtin_cc_ascii(
    bbre *r, const bbre_byte *name, size_t name_len, bbre_uint *out_ref)
{
  return bbre_builtin_cc_make(
      r, name, name_len, bbre_builtin_ccs_ascii, out_ref);
}

static int bbre_builtin_cc_perl(
    bbre *r, const bbre_byte *name, size_t name_len, bbre_uint *out_ref)
{
  return bbre_builtin_cc_make(
      r, name, name_len, bbre_builtin_ccs_perl, out_ref);
}

#ifdef BBRE_DEBUG_UTILS
  #include BBRE_DEBUG_UTILS
#endif

/* Copyright 2024 Max Nurzia
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

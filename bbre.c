#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "bbre.h"

#ifdef BBRE_CONFIG_HEADER_FILE
  #include BBRE_CONFIG_HEADER_FILE
#endif

#define BBRE_REF_NONE 0
#define BBRE_UTF_MAX  0x10FFFF

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
  /* A matching group: /(a)/
   *   Argument 0: child tree (AST)
   *   Argument 1: group flags, bitset of `enum group_flag` (number)
   *   Argument 2: scratch used by the parser to store old flags (number) */
  BBRE_AST_TYPE_GROUP,
  /* An inline group: /(?i)a/
   *   Argument 0: child tree (AST)
   *   Argument 1: group flags, bitset of `enum group_flag` (number)
   *   Argument 2: scratch used by the parser to store old flags (number) */
  BBRE_AST_TYPE_IGROUP,
  /* A character class: /[a-zA-Z]/
   *   Argument 0: BBRE_REF_NONE or another CLS node in the charclass (AST)
   *   Argument 1: character range begin (number)
   *   Argument 2: character range end (number) */
  BBRE_AST_TYPE_CC,
  /* An inverted character class: /[^a-zA-Z]/
   *   Argument 0: BBRE_REF_NONE or another CLS node in the charclass (AST)
   *   Argument 1: character range begin (number)
   *   Argument 2: character range end (number) */
  BBRE_AST_TYPE_ICC,
  /* Matches any byte: /\C/ */
  BBRE_AST_TYPE_ANYBYTE,
  /* Empty assertion: /\b/
   *   Argument 0: assertion flags, bitset of `bbre_assert_flag` (number) */
  BBRE_AST_TYPE_ASSERT
} bbre_ast_type;

/* Length (number of arguments) for each AST type. */
static const unsigned int bbre_ast_type_lens[] = {
    0, /* eps */
    1, /* CHR */
    2, /* CAT */
    2, /* ALT */
    3, /* QUANT */
    3, /* UQUANT */
    3, /* GROUP */
    3, /* IGROUP */
    3, /* CC */
    3, /* ICC */
    0, /* ANYBYTE */
    1, /* AASSERT */
};

typedef enum bbre_group_flag {
  BBRE_GROUP_FLAG_INSENSITIVE = 1,   /* case-insensitive matching */
  BBRE_GROUP_FLAG_MULTILINE = 2,     /* ^$ match beginning/end of each line */
  BBRE_GROUP_FLAG_DOTNEWLINE = 4,    /* . matches \n */
  BBRE_GROUP_FLAG_UNGREEDY = 8,      /* ungreedy quantifiers */
  BBRE_GROUP_FLAG_NONCAPTURING = 16, /* non-capturing group (?:...) */
  BBRE_GROUP_FLAG_SUBEXPRESSION = 32 /* set-match component */
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
 * inside of the instructions, stores the exit points. This list is tracked
 * `patch_head` and `patch_tail`. */
typedef struct bbre_compframe {
  bbre_uint root_ref, /* reference to the AST node being compiled */
      child_ref,      /* reference to the child AST node to be compiled next */
      idx,            /* used keep track of repetition index */
      patch_head,     /* head of the outgoing patch linked list */
      patch_tail,     /* tail of the outgoing patch linked list */
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
  bbre_buf(bbre_rune_range) ranges;
  bbre_buf(bbre_rune_range) ranges_2;
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
struct bbre_spec {
  bbre_alloc alloc;      /* allocator function */
  const bbre_byte *expr; /* the expression itself */
  size_t expr_size;      /* the length of the expression in bytes */
  bbre_flags flags;      /* regex flags used for parsing / the root AST */
};

typedef struct bbre_exec bbre_exec;

/* The compiled form of a regular expression. */
typedef struct bbre_prog {
  bbre_alloc alloc;                     /* allocator function */
  bbre_buf(bbre_inst) prog;             /* The compiled instructions */
  bbre_buf(bbre_uint) set_idxs;         /* pattern index for each instruction */
  bbre_uint entry[BBRE_PROG_ENTRY_MAX]; /* entry points for the program */
  bbre_uint npat;                       /* number of distinct patterns */
} bbre_prog;

/* A compiled regular expression. */
struct bbre {
  bbre_alloc alloc;            /* allocator function */
  bbre_buf(bbre_uint) ast;     /* AST arena */
  bbre_uint ast_root;          /* AST root node reference */
  bbre_buf(bbre_uint) arg_stk; /* parser argument stack */
  bbre_buf(bbre_uint) op_stk;  /* parser operator stack */
  bbre_buf(
      bbre_compframe) comp_stk; /* compiler frame stack (see bbre_compframe) */
  bbre_compcc_data compcc;      /* data used for the charclass compiler */
  bbre_prog prog;               /* NFA program */
  const bbre_byte *expr;        /* input parser expression */
  size_t expr_pos,              /* current position in expr */
      expr_size;                /* number of bytes in expr */
  const char *error;            /* error message, if any */
  size_t error_pos;             /* position the error was encountered in expr */
  bbre_exec *exec; /* local execution context, NULL until actually used */
};

/* A builder class for regular expression sets. */
struct bbre_set_spec {
  bbre_alloc alloc;            /* allocator function */
  bbre_buf(const bbre *) pats; /* patterns that compose this set */
};

/* A set of compiled regular expressions. */
struct bbre_set {
  bbre_alloc alloc; /* allocator function */
  bbre_prog prog;   /* compiled program */
  bbre_exec *exec;  /* local execution context, NULL until actually used */
};

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
static void *bbre_default_alloc(void *user, void *ptr, size_t prev, size_t next)
{
  (void)user, (void)prev;
  if (next) {
    assert(BBRE_IMPLIES(!prev, !ptr));
    return realloc(ptr, next);
  } else if (ptr) {
    free(ptr);
  }
  return NULL;
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
static bbre_buf_hdr bbre_buf_sentinel = {0};

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
  assert(buf && *buf);
  hdr = bbre_buf_get_hdr(*buf);
  next_alloc = hdr->alloc ? hdr->alloc : /* sentinel */ 1;
  if (size <= hdr->alloc) {
    hdr->size = size;
    return 0;
  }
  while (next_alloc < size)
    next_alloc *= 2;
  next_ptr = bbre_ialloc(
      a, hdr->alloc ? hdr : /* sentinel */ NULL,
      hdr->alloc ? sizeof(bbre_buf_hdr) + hdr->alloc : /* sentinel */ 0,
      sizeof(bbre_buf_hdr) + next_alloc);
  if (!next_ptr)
    return BBRE_ERR_MEM;
  hdr = next_ptr;
  hdr->alloc = next_alloc;
  hdr->size = size;
  *buf = hdr + 1;
  return 0;
}

/* Initialize an empty dynamic array. */
static void bbre_buf_init_t(void **b)
{
  *b = &bbre_buf_sentinel + 1;
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
  if (!sbuf)
    return;
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

int bbre_spec_init(
    bbre_spec **pspec, const char *s, size_t n, const bbre_alloc *palloc)
{
  int err = 0;
  bbre_spec *spec;
  bbre_alloc alloc = bbre_alloc_make(palloc);
  spec = bbre_ialloc(&alloc, NULL, 0, sizeof(bbre_spec));
  *pspec = spec;
  if (!spec) {
    err = BBRE_ERR_MEM;
    goto error;
  }
  memset(spec, 0, sizeof(*spec));
  spec->alloc = alloc;
  spec->expr = (const bbre_byte *)s;
  spec->expr_size = n;
  spec->flags = 0;
error:
  return err;
}

void bbre_spec_destroy(bbre_spec *spec)
{
  if (!spec)
    return;
  bbre_ialloc(&spec->alloc, spec, sizeof(bbre_spec), 0);
}

void bbre_spec_flags(bbre_spec *b, bbre_flags flags) { b->flags = flags; }

static int bbre_parse(bbre *r, const bbre_byte *s, size_t sz, bbre_uint *root);

static void bbre_prog_init(bbre_prog *prog, bbre_alloc alloc)
{
  prog->alloc = alloc;
  bbre_buf_init(&prog->prog), bbre_buf_init(&prog->set_idxs);
  memset(prog->entry, 0, sizeof(prog->entry));
  prog->npat = 0;
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
  bbre_spec *spec = NULL;
  if ((err = bbre_spec_init(&spec, pat_nt, strlen(pat_nt), NULL)))
    goto error;
  if ((err = bbre_init(&r, spec, NULL)))
    goto error;
error:
  /* bbre_spec_destroy() accepts NULL */
  bbre_spec_destroy(spec);
  if (err == BBRE_ERR_MEM) {
    bbre_destroy(r);
    r = NULL;
  }
  return r;
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
  bbre_buf_init(&r->arg_stk), bbre_buf_init(&r->op_stk),
      bbre_buf_init(&r->comp_stk);
  bbre_buf_init(&r->compcc.ranges), bbre_buf_init(&r->compcc.tree),
      bbre_buf_init(&r->compcc.ranges_2), bbre_buf_init(&r->compcc.tree_2),
      bbre_buf_init(&r->compcc.hash);
  bbre_prog_init(&r->prog, r->alloc);
  r->exec = NULL;
error:
  return err;
}

int bbre_init(bbre **pr, const bbre_spec *spec, const bbre_alloc *palloc)
{
  int err = 0;
  if ((err = bbre_init_internal(pr, palloc)))
    goto error;
  if ((err = bbre_parse(*pr, spec->expr, spec->expr_size, &(*pr)->ast_root)))
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
  if (!r)
    return;
  bbre_buf_destroy(&r->alloc, (void **)&r->ast);
  bbre_buf_destroy(&r->alloc, &r->op_stk),
      bbre_buf_destroy(&r->alloc, &r->arg_stk),
      bbre_buf_destroy(&r->alloc, &r->comp_stk);
  bbre_buf_destroy(&r->alloc, &r->compcc.ranges),
      bbre_buf_destroy(&r->alloc, &r->compcc.ranges_2),
      bbre_buf_destroy(&r->alloc, &r->compcc.tree),
      bbre_buf_destroy(&r->alloc, &r->compcc.tree_2),
      bbre_buf_destroy(&r->alloc, &r->compcc.hash);
  bbre_prog_destroy(&r->prog);
  bbre_exec_destroy(r->exec);
  bbre_ialloc(&r->alloc, r, sizeof(*r), 0);
}

size_t bbre_get_error(bbre *r, const char **out, size_t *pos)
{
  *out = r->error, *pos = r->error_pos;
  return r->error ? strlen(r->error) : 0;
}

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
static int bbre_ast_make(
    bbre *r, bbre_ast_type type, bbre_uint p0, bbre_uint p1, bbre_uint p2,
    bbre_uint *out_node)
{
  bbre_uint args[4], i;
  int err;
  args[0] = type, args[1] = p0, args[2] = p1, args[3] = p2;
  if (type && !bbre_buf_size(r->ast) &&
      (err = bbre_ast_make(r, 0, 0, 0, 0, out_node))) /* sentinel node */
    return err;
  *out_node = bbre_buf_size(r->ast);
  for (i = 0; i < 1 + bbre_ast_type_lens[type]; i++)
    if ((err = bbre_buf_push(&r->alloc, &r->ast, args[i])))
      return err;
  return 0;
}

/* Decompose a given AST node, given its reference, into `out_args`. */
static void bbre_ast_decompose(bbre *r, bbre_uint node, bbre_uint *out_args)
{
  bbre_uint *in_args = r->ast + node;
  bbre_uint i;
  for (i = 0; i < bbre_ast_type_lens[*in_args]; i++)
    out_args[i] = in_args[i + 1];
}

/* Get the type of the given AST node. */
static bbre_uint *bbre_ast_type_ref(bbre *r, bbre_uint node)
{
  return r->ast + node;
}

/* Get a pointer to the `n`'th parameter of the given AST node. */
static bbre_uint *bbre_ast_param_ref(bbre *r, bbre_uint node, bbre_uint n)
{
  assert(bbre_ast_type_lens[*bbre_ast_type_ref(r, node)] > n);
  return r->ast + node + 1 + n;
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
static int bbre_parse_err(bbre *r, const char *msg)
{
  r->error = msg, r->error_pos = r->expr_pos;
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
  assert(else_msg);
  if (!bbre_parse_has_more(r))
    return bbre_parse_err(r, else_msg);
  *codep = bbre_parse_next(r);
  return 0;
}

/* Check that the input string is well-formed UTF-8. */
static int bbre_parse_checkutf8(bbre *r)
{
  bbre_uint state = 0, codep;
  while (r->expr_pos < r->expr_size &&
         bbre_utf8_decode(&state, &codep, r->expr[r->expr_pos]) !=
             BBRE_UTF8_DFA_NUM_STATE - 1)
    r->expr_pos++;
  if (state != 0)
    return bbre_parse_err(r, "invalid utf-8 sequence");
  r->expr_pos = 0;
  return 0;
}

/* Without advancing the parser, check the next character. */
static bbre_uint bbre_peek_next(bbre *r)
{
  size_t prev_pos = r->expr_pos;
  bbre_uint out = bbre_parse_next(r);
  r->expr_pos = prev_pos;
  return out;
}

/* Maximum repetition count for quantifiers. */
#define BBRE_LIMIT_REPETITION_COUNT 100000

/* Sentinel value to represent an infinite repetition. */
#define BBRE_INFTY (BBRE_LIMIT_REPETITION_COUNT + 1)

/* Given nodes R_1..R_N on the argument stack, fold them into a single CAT
 * node. If there are no nodes on the stack, create an epsilon node.
 * Returns `BBRE_ERR_MEM` if out of memory. */
static int bbre_fold(bbre *r)
{
  int err = 0;
  if (!bbre_buf_size(r->arg_stk)) {
    /* arg_stk: | */
    return bbre_buf_push(&r->alloc, &r->arg_stk, /* epsilon */ BBRE_REF_NONE);
    /* arg_stk: | eps |*/
  }
  while (bbre_buf_size(r->arg_stk) > 1) {
    /* arg_stk: | ... | R_N-1 | R_N | */
    bbre_uint right, left, rest;
    right = bbre_buf_pop(&r->arg_stk);
    left = *bbre_buf_peek(&r->arg_stk, 0);
    if ((err = bbre_ast_make(r, BBRE_AST_TYPE_CAT, left, right, 0, &rest)))
      return err;
    *bbre_buf_peek(&r->arg_stk, 0) = rest;
    /* arg_stk: | ... | R_N-1R_N | */
  }
  /* arg_stk: | R1R2...Rn | */
  return 0;
}

/* Given a node R on the argument stack and an arbitrary number of ALT nodes at
 * the end of the operator stack, fold and finish each ALT node into a single
 * resulting ALT node on the argument stack.
 * Returns `BBRE_ERR_MEM` if out of memory. */
static void bbre_fold_alts(bbre *r, bbre_uint *flags)
{
  assert(bbre_buf_size(r->arg_stk) == 1);
  /* First pop all inline groups. */
  while (bbre_buf_size(r->op_stk) &&
         *bbre_ast_type_ref(r, *bbre_buf_peek(&r->op_stk, 0)) ==
             BBRE_AST_TYPE_IGROUP) {
    /* arg_stk: |  R  | */
    /* op_stk:  | ... | (S) | */
    bbre_uint igrp = bbre_buf_pop(&r->op_stk),
              cat = *bbre_ast_param_ref(r, igrp, 0),
              old_flags = *bbre_ast_param_ref(r, igrp, 2);
    *bbre_ast_param_ref(r, igrp, 0) = *bbre_buf_peek(&r->arg_stk, 0);
    *flags = old_flags;
    *bbre_ast_param_ref(r, cat, 1) = igrp;
    *bbre_buf_peek(&r->arg_stk, 0) = cat;
    /* arg_stk: | S(R)| */
    /* op_stk:  | ... | */
  }
  assert(bbre_buf_size(r->arg_stk) == 1);
  /* arg_stk: |  R  | */
  /* op_stk:  | ... | */
  if (bbre_buf_size(r->op_stk) &&
      *bbre_ast_type_ref(r, *bbre_buf_peek(&r->op_stk, 0)) ==
          BBRE_AST_TYPE_ALT) {
    /* op_stk:  | ... |  A  | */
    /* finish the last alt */
    *bbre_ast_param_ref(r, *bbre_buf_peek(&r->op_stk, 0), 1) =
        *bbre_buf_peek(&r->arg_stk, 0);
    /* arg_stk: | */
    /* op_stk:  | ... | */
    while (bbre_buf_size(r->op_stk) > 1 &&
           *bbre_ast_type_ref(r, *bbre_buf_peek(&r->op_stk, 1)) ==
               BBRE_AST_TYPE_ALT) {
      /* op_stk:  | ... | A_1 | A_2 | */
      bbre_uint right = bbre_buf_pop(&r->op_stk),
                left = *bbre_buf_peek(&r->op_stk, 0);
      *bbre_ast_param_ref(r, left, 1) = right;
      *bbre_buf_peek(&r->op_stk, 0) = left;
      /* op_stk:  | ... | A_1(|A_2) | */
    }
    /* op_stk:  | ... |  A  | */
    assert(bbre_buf_size(r->arg_stk) == 1);
    *bbre_buf_peek(&r->arg_stk, 0) = bbre_buf_pop(&r->op_stk);
    /* arg_stk: |  A  | */
    /* op_stk:  | ... | */
  }
  assert(bbre_buf_size(r->arg_stk) == 1);
}

/* Add the CC node `rest` to the CC node `first`. */
static bbre_uint bbre_ast_cls_union(bbre *r, bbre_uint rest, bbre_uint first)
{
  bbre_uint cur = first, *next;
  assert(first);
  assert(
      *bbre_ast_type_ref(r, first) == BBRE_AST_TYPE_CC ||
      *bbre_ast_type_ref(r, first) == BBRE_AST_TYPE_ICC);
  assert(BBRE_IMPLIES(rest, *bbre_ast_type_ref(r, rest) == BBRE_AST_TYPE_CC));
  while (*(next = bbre_ast_param_ref(r, cur, 0)))
    cur = *next;
  *next = rest;
  return first;
}

/* Helper function to add a character to the argument stack.
 * Returns `BBRE_ERR_MEM` if out of memory. */
static int
bbre_parse_escape_addchr(bbre *r, bbre_uint ch, bbre_uint allowed_outputs)
{
  int err = 0;
  bbre_uint res;
  (void)allowed_outputs, assert(allowed_outputs & (1 << BBRE_AST_TYPE_CHR));
  if ((err = bbre_ast_make(r, BBRE_AST_TYPE_CHR, ch, 0, 0, &res)) ||
      (err = bbre_buf_push(&r->alloc, &r->arg_stk, res)))
    return err;
  return 0;
}

/* Convert a hexadecimal digit to a number.
 * Returns ERR_PARSE on invalid hex digit. */
static int bbre_parse_hexdig(bbre *r, bbre_uint ch, bbre_uint *hex_digit)
{
  if (ch >= '0' && ch <= '9')
    *hex_digit = ch - '0';
  else if (ch >= 'a' && ch <= 'f')
    *hex_digit = ch - 'a' + 10;
  else if (ch >= 'A' && ch <= 'F')
    *hex_digit = ch - 'A' + 10;
  else
    return bbre_parse_err(r, "invalid hex digit");
  return 0;
}

/* Attempt to parse an octal digit, returning -1 if the digit is not an octal
 * digit, and the value of the digit in [0, 7] otherwise. */
static int bbre_parse_is_octdig(bbre_uint ch)
{
  if (ch >= '0' && ch <= '7')
    return ch - '0';
  return -1;
}

/* These functions are automatically generated and are implemented later in this
 * file. For each type of builtin charclass, there is a function that allows us
 * to look up a charclass by name and create an AST node representing that
 * charclass.*/
static int bbre_builtin_cc_ascii(
    bbre *r, const bbre_byte *name, size_t name_len, int invert);
static int bbre_builtin_cc_unicode_property(
    bbre *r, const bbre_byte *name, size_t name_len, int invert);
static int bbre_builtin_cc_perl(
    bbre *r, const bbre_byte *name, size_t name_len, int invert);

/* This function is called after receiving a \ character when parsing an
 * expression or character class. Since some escape sequences are forbidden
 * within different contexts (for example: charclasses), a bitmap
 * `allowed_outputs` encodes, at each bit position, the respective ast_type that
 * is allowed to be created in this context. */
static int bbre_parse_escape(bbre *r, bbre_uint allowed_outputs)
{
  bbre_uint ch;
  int err = 0;
  if ((err = bbre_parse_next_or(r, &ch, "expected escape sequence")))
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
    return bbre_parse_escape_addchr(r, ch, allowed_outputs);
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
    return bbre_parse_escape_addchr(r, ord, allowed_outputs);
  } else if (ch == 'x') { /* hex escape */
    bbre_uint ord = 0 /* accumulates ordinal value */,
              hex_dig = 0 /* the digit being read */;
    if ((err = bbre_parse_next_or(
             r, &ch, "expected two hex characters or a bracketed hex literal")))
      return err;
    if (ch == '{') {      /* bracketed hex lit */
      bbre_uint digs = 0; /* number of read hex digits */
      while (1) {
        if (digs == 7)
          return bbre_parse_err(r, "expected up to six hex characters");
        if ((err = bbre_parse_next_or(
                 r, &ch, "expected up to six hex characters")))
          return err;
        if (ch == '}')
          break;
        if ((err = bbre_parse_hexdig(r, ch, &hex_dig)))
          return err;
        ord = ord * 16 + hex_dig;
        digs++;
      }
      if (!digs)
        return bbre_parse_err(r, "expected at least one hex character");
    } else {
      /* two digit hex lit */
      if ((err = bbre_parse_hexdig(r, ch, &hex_dig)))
        return err;
      ord = hex_dig;
      if ((err = bbre_parse_next_or(r, &ch, "expected two hex characters")))
        return err;
      else if ((err = bbre_parse_hexdig(r, ch, &hex_dig)))
        return err;
      ord = ord * 16 + hex_dig;
    }
    if (ord > BBRE_UTF_MAX)
      return bbre_parse_err(r, "ordinal value out of range [0, 0x10FFFF]");
    return bbre_parse_escape_addchr(r, ord, allowed_outputs);
  } else if (ch == 'C') { /* any byte: \C */
    bbre_uint res;        /* resulting AST node */
    if (!(allowed_outputs & (1 << BBRE_AST_TYPE_ANYBYTE)))
      return bbre_parse_err(r, "cannot use \\C here");
    if ((err = bbre_ast_make(r, BBRE_AST_TYPE_ANYBYTE, 0, 0, 0, &res)) ||
        (err = bbre_buf_push(&r->alloc, &r->arg_stk, res)))
      return err;
  } else if (ch == 'Q') { /* quote string */
    bbre_uint cat = BBRE_REF_NONE /* accumulator for concatenations */,
              chr = BBRE_REF_NONE /* generated chr node for each character in
                                   the quoted string */
        ;
    if (!(allowed_outputs & (1 << BBRE_AST_TYPE_CAT)))
      return bbre_parse_err(r, "cannot use \\Q...\\E here");
    while (bbre_parse_has_more(r)) {
      ch = bbre_parse_next(r);
      if (ch == '\\' && bbre_parse_has_more(r)) {
        /* mini-escape dsl for \Q..\E */
        ch = bbre_peek_next(r);
        if (ch == 'E') {
          /* \E : actually end the quote */
          ch = bbre_parse_next(r);
          assert(ch == 'E');
          return bbre_buf_push(&r->alloc, &r->arg_stk, cat);
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
      if ((err = bbre_ast_make(r, BBRE_AST_TYPE_CHR, ch, 0, 0, &chr)))
        return err;
      /* create a cat node with the character and an epsilon node, replace the
       * old cat node (cat) with the new one (cat') through the &cat ref */
      if ((err = bbre_ast_make(r, BBRE_AST_TYPE_CAT, cat, chr, 0, &cat)))
        return err;
    }
    /* we got to the end of the string: push the partial quote */
    if ((err = bbre_buf_push(&r->alloc, &r->arg_stk, cat)))
      return err;
  } else if (
      ch == 'D' || ch == 'd' || ch == 'S' || ch == 's' || ch == 'W' ||
      ch == 'w') {
    /* Perl builtin character classes */
    int inverted =
        ch == 'D' || ch == 'S' || ch == 'W'; /* uppercase are inverted */
    bbre_byte lower = inverted ? ch - 'A' + 'a' : ch; /* convert to lowercase */
    if (!(allowed_outputs & (1 << BBRE_AST_TYPE_CC)))
      return bbre_parse_err(r, "cannot use a character class here");
    /* lookup the charclass, optionally invert it */
    if ((err = bbre_builtin_cc_perl(r, &lower, 1, inverted)))
      return err;
  } else if (ch == 'P' || ch == 'p') { /* Unicode properties */
    size_t name_start_pos = r->expr_pos, name_end_pos;
    int inverted = ch == 'P';
    const char *err_msg =
        "expected one-character property name or bracketed property name "
        "for Unicode property escape";
    if ((err = bbre_parse_next_or(r, &ch, err_msg)))
      return err;
    if (ch == '{') { /* bracketed property */
      name_start_pos = r->expr_pos;
      while (ch != '}')
        /* read characters until we get to the end of the brack prop */
        if ((err = bbre_parse_next_or(
                 r, &ch, "expected '}' to close bracketed property name")))
          return err;
      name_end_pos = r->expr_pos - 1;
    } else
      /* single-character property */
      name_end_pos = r->expr_pos;
    if (!(allowed_outputs & (1 << BBRE_AST_TYPE_CC)))
      return bbre_parse_err(r, "cannot use a character class here");
    assert(name_end_pos >= name_start_pos);
    if ((err = bbre_builtin_cc_unicode_property(
             r, r->expr + name_start_pos, name_end_pos - name_start_pos,
             inverted)))
      return err;
  } else if (ch == 'A' || ch == 'z' || ch == 'B' || ch == 'b') {
    /* empty asserts */
    bbre_uint res; /* resulting AST node */
    if (!(allowed_outputs & (1 << BBRE_AST_TYPE_ASSERT)))
      return bbre_parse_err(r, "cannot use an epsilon assertion here");
    if ((err = bbre_ast_make(
             r, BBRE_AST_TYPE_ASSERT,
             ch == 'A'   ? BBRE_ASSERT_TEXT_BEGIN
             : ch == 'z' ? BBRE_ASSERT_TEXT_END
             : ch == 'B' ? BBRE_ASSERT_NOT_WORD
                         : BBRE_ASSERT_WORD,
             0, 0, &res)) ||
        (err = bbre_buf_push(&r->alloc, &r->arg_stk, res)))
      return err;
  } else {
    return bbre_parse_err(r, "invalid escape sequence");
  }
  return 0;
}

/* Parse a decimal number, up to `max_digits`, into *out. */
static int bbre_parse_number(bbre *r, bbre_uint *out, bbre_uint max_digits)
{
  int err = 0;
  bbre_uint ch, acc = 0, ndigs = 0;
  if (!bbre_parse_has_more(r))
    return bbre_parse_err(r, "expected at least one decimal digit");
  while (ndigs < max_digits && bbre_parse_has_more(r) &&
         (ch = bbre_peek_next(r)) >= '0' && ch <= '9')
    acc = acc * 10 + (bbre_parse_next(r) - '0'), ndigs++;
  if (!ndigs)
    return bbre_parse_err(r, "expected at least one decimal digit");
  if (ndigs == max_digits)
    return bbre_parse_err(r, "too many digits for decimal number");
  *out = acc;
  return err;
}

/* Parse a regular expression, storing its resulting AST node into *root. */
static int bbre_parse(bbre *r, const bbre_byte *ts, size_t tsz, bbre_uint *root)
{
  int err;
  bbre_uint flags = 0;
  r->expr = ts;
  r->expr_size = tsz, r->expr_pos = 0;
  if ((err = bbre_parse_checkutf8(r)))
    return err;
  while (bbre_parse_has_more(r)) {
    bbre_uint ch = bbre_parse_next(r), res = BBRE_REF_NONE;
    if (ch == '*' || ch == '+' || ch == '?') {
      bbre_uint q = ch, greedy = 1;
      /* arg_stk: | ... |  R  | */
      /* pop one from arg stk, create quant, push to arg stk */
      if (!bbre_buf_size(r->arg_stk))
        return bbre_parse_err(r, "cannot apply quantifier to empty regex");
      if (bbre_parse_has_more(r) && bbre_peek_next(r) == '?')
        bbre_parse_next(r), greedy = 0;
      if ((err = bbre_ast_make(
               r, greedy ? BBRE_AST_TYPE_QUANT : BBRE_AST_TYPE_UQUANT,
               *bbre_buf_peek(&r->arg_stk, 0) /* child */, q == '+' /* min */,
               q == '?' ? 1 : BBRE_INFTY /* max */, &res)))
        return err;
      *bbre_buf_peek(&r->arg_stk, 0) = res;
      /* arg_stk: | ... | *(R) | */
    } else if (ch == '|') {
      /* fold the arg stk into a concat, create alt, push it to the arg stk */
      /* op_stk:  | ... | */
      /* arg_stk: | R_1 | R_2 | ... | R_N | */
      if ((err = bbre_fold(r)))
        return err;
      /* arg_stk: |  R  | */
      if ((err = bbre_ast_make(
               r, BBRE_AST_TYPE_ALT, bbre_buf_pop(&r->arg_stk) /* left */,
               BBRE_REF_NONE /* right */, 0, &res)) ||
          (err = bbre_buf_push(&r->alloc, &r->op_stk, res)))
        return err;
      /* arg_stk: | */
      /* op_stk:  | ... | R(|) | */
    } else if (ch == '(') {
      /* capture group */
      bbre_uint old_flags = flags, inline_group = 0, child;
      if (!bbre_parse_has_more(r))
        return bbre_parse_err(r, "expected ')' to close group");
      ch = bbre_peek_next(r);
      if (ch == '?') { /* start of group flags */
        ch = bbre_parse_next(r);
        assert(ch == '?'); /* this assert is probably too paranoid */
        if ((err = bbre_parse_next_or(
                 r, &ch,
                 "expected 'P', '<', or group flags after special "
                 "group opener \"(?\"")))
          return err;
        if (ch == 'P' || ch == '<') {
          /* group name */
          if (ch == 'P' &&
              (err = bbre_parse_next_or(
                   r, &ch, "expected '<' after named group opener \"(?P\"")))
            return err;
          if (ch != '<')
            return bbre_parse_err(
                r, "expected '<' after named group opener \"(?P\"");
          /* parse group name */
          while (1) {
            /* read characters until > */
            if ((err = bbre_parse_next_or(
                     r, &ch, "expected name followed by '>' for named group")))
              return err;
            if (ch == '>')
              break;
          }
          /* currently we don't do anything with the group name. Later revisions
           * might introduce an API for retrieving the group names. */
        } else {
          bbre_uint neg = 0 /* should we negate flags? */,
                    flag =
                        BBRE_GROUP_FLAG_UNGREEDY /* default flag (this makes
                                                  coverage testing simpler) */
              ;
          while (1) {
            if (ch == ':' /* noncapturing */ || ch == ')' /* inline */)
              break;
            else if (ch == '-') {
              /* negate subsequent flags */
              if (neg)
                return bbre_parse_err(
                    r, "cannot apply flag negation '-' twice");
              neg = 1;
            } else if (
                (ch == 'i' && (flag = BBRE_GROUP_FLAG_INSENSITIVE)) ||
                (ch == 'm' && (flag = BBRE_GROUP_FLAG_MULTILINE)) ||
                (ch == 's' && (flag = BBRE_GROUP_FLAG_DOTNEWLINE)) ||
                (ch == 'u')) {
              /* unset bit if negated, set bit if not */
              flags = neg ? flags & ~flag : flags | flag;
            } else {
              return bbre_parse_err(
                  r, "expected ':', ')', or group flags for special group");
            }
            if ((err = bbre_parse_next_or(
                     r, &ch,
                     "expected ':', ')', or group flags for special group")))
              return err;
          }
          flags |= BBRE_GROUP_FLAG_NONCAPTURING;
          if (ch == ')')
            /* flags only with no : to denote actual pattern */
            inline_group = 1;
        }
      }
      /* op_stk:  | ... | */
      /* arg_stk: | R_1 | R_2 | ... | R_N | */
      if ((err = bbre_fold(r)))
        return err;
      child = bbre_buf_pop(&r->arg_stk);
      if (inline_group &&
          (err = bbre_ast_make(r, BBRE_AST_TYPE_CAT, child, 0, 0, &child)))
        return err;
      /* arg_stk: |  R  | */
      if ((err = bbre_ast_make(
               r, inline_group ? BBRE_AST_TYPE_IGROUP : BBRE_AST_TYPE_GROUP,
               child, flags, old_flags, &res)) ||
          (err = bbre_buf_push(&r->alloc, &r->op_stk, res)))
        return err;
      flags &= ~(BBRE_GROUP_FLAG_NONCAPTURING);
      /* op_stk:  | ... | (R) | */
    } else if (ch == ')') {
      bbre_uint grp, prev;
      /* arg_stk: | S_1 | S_2 | ... | S_N | */
      /* op_stk:  | ... | (R) | ... | */
      /* fold the arg stk into a concat, fold remaining alts, create group,
       * push it to the arg stk */
      if ((err = bbre_fold(r)))
        return err;
      bbre_fold_alts(r, &flags);
      /* arg_stk has one value */
      assert(bbre_buf_size(r->arg_stk) == 1);
      if (!bbre_buf_size(r->op_stk))
        return bbre_parse_err(r, "extra close parenthesis");
      /* arg_stk: |  S  | */
      /* op_stk:  | ... | (R) | */
      grp = *bbre_buf_peek(&r->op_stk, 0);
      /* retrieve the previous contents of arg_stk */
      prev = *bbre_ast_param_ref(r, grp, 0);
      /* add it to the group */
      *(bbre_ast_param_ref(r, grp, 0)) = *bbre_buf_peek(&r->arg_stk, 0);
      /* restore group flags */
      flags = *(bbre_ast_param_ref(r, grp, 2));
      /* push the saved contents of arg_stk */
      *bbre_buf_peek(&r->arg_stk, 0) = prev;
      /* pop the group frame into arg_stk */
      if ((err =
               bbre_buf_push(&r->alloc, &r->arg_stk, bbre_buf_pop(&r->op_stk))))
        return err;
      /* arg_stk: |  R  | (S) | */
      /* op_stk:  | ... | */
    } else if (ch == '.') { /* any char */
      /* arg_stk: | ... | */
      if (((flags & BBRE_GROUP_FLAG_DOTNEWLINE) &&
           (err = bbre_ast_make(
                r, BBRE_AST_TYPE_CC, BBRE_REF_NONE, 0, BBRE_UTF_MAX, &res))) ||
          (!(flags & BBRE_GROUP_FLAG_DOTNEWLINE) &&
           ((err = bbre_ast_make(
                 r, BBRE_AST_TYPE_CC, BBRE_REF_NONE, 0, '\n' - 1, &res)) ||
            (err = bbre_ast_make(
                 r, BBRE_AST_TYPE_CC, res, '\n' + 1, BBRE_UTF_MAX, &res)))) ||
          (err = bbre_buf_push(&r->alloc, &r->arg_stk, res)))
        return err;
      /* arg_stk: | ... |  .  | */
    } else if (ch == '[') {              /* charclass */
      size_t cc_start_pos = r->expr_pos; /* starting position of charclass */
      bbre_uint inverted = 0 /* is the charclass inverted? */,
                min /* min value of range */, max /* max value of range */;
      res = BBRE_REF_NONE; /* resulting CC node */
      while (1) {
        bbre_uint next; /* temp var to store child classes */
        if ((err = bbre_parse_next_or(r, &ch, "unclosed character class")))
          return err;
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
                   r, (1 << BBRE_AST_TYPE_CHR) | (1 << BBRE_AST_TYPE_CC))))
            /* parse_escape() could return ERR_PARSE if for example \A */
            return err;
          next = bbre_buf_pop(&r->arg_stk);
          assert(
              *bbre_ast_type_ref(r, next) == BBRE_AST_TYPE_CHR ||
              *bbre_ast_type_ref(r, next) == BBRE_AST_TYPE_CC);
          if (*bbre_ast_type_ref(r, next) == BBRE_AST_TYPE_CHR)
            min = *bbre_ast_param_ref(r, next, 0); /* single-character escape */
          else {
            assert(*bbre_ast_type_ref(r, next) == BBRE_AST_TYPE_CC);
            res = bbre_ast_cls_union(r, res, next);
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
              return err;
            if (ch == ':')
              break;
            name_end_pos = r->expr_pos;
          }
          if ((err = bbre_parse_next_or(
                   r, &ch,
                   "expected closing bracket for named character class")))
            return err;
          if (ch != ']')
            return bbre_parse_err(
                r, "expected closing bracket for named character class");
          /* lookup the charclass name in the labyrinth of tables */
          if ((err = bbre_builtin_cc_ascii(
                   r, r->expr + name_start_pos, (name_end_pos - name_start_pos),
                   named_inverted)))
            return err;
          next = bbre_buf_pop(&r->arg_stk);
          /* ensure that builtin_cc_ascii returned a value */
          assert(next && *bbre_ast_type_ref(r, next) == BBRE_AST_TYPE_CC);
          res = bbre_ast_cls_union(r, res, next);
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
            return err;
          if (ch == '\\') { /* start of escape */
            if ((err = bbre_parse_escape(r, (1 << BBRE_AST_TYPE_CHR))))
              return err;
            next = bbre_buf_pop(&r->arg_stk);
            assert(*bbre_ast_type_ref(r, next) == BBRE_AST_TYPE_CHR);
            max = *bbre_ast_param_ref(r, next, 0);
          } else {
            max = ch; /* non-escaped character */
          }
        }
        if ((err = bbre_ast_make(r, BBRE_AST_TYPE_CC, res, min, max, &res)))
          return err;
      }
      assert(res);  /* charclass cannot be empty */
      if (inverted) /* inverted character class */
        *bbre_ast_type_ref(r, res) = BBRE_AST_TYPE_ICC;
      if ((err = bbre_buf_push(&r->alloc, &r->arg_stk, res)))
        return err;
    } else if (ch == '\\') { /* escape */
      if ((err = bbre_parse_escape(
               r, 1 << BBRE_AST_TYPE_CHR | 1 << BBRE_AST_TYPE_CC |
                      1 << BBRE_AST_TYPE_ANYBYTE | 1 << BBRE_AST_TYPE_CAT |
                      1 << BBRE_AST_TYPE_ASSERT)))
        return err;
    } else if (ch == '{') { /* repetition */
      bbre_uint min_rep = 0 /* minimum bound */,
                max_rep = 0 /* maximum bound */;
      if ((err = bbre_parse_number(r, &min_rep, 6)))
        return err;
      if ((err = bbre_parse_next_or(
               r, &ch, "expected } to end repetition expression")))
        return err;
      if (ch == '}')
        /* single number: simple repetition */
        max_rep = min_rep;
      else if (ch == ',') {
        /* comma: either `min_rep` or more, or `min_rep` to `max_rep` */
        if (!bbre_parse_has_more(r))
          return bbre_parse_err(
              r, "expected upper bound or } to end repetition expression");
        ch = bbre_peek_next(r);
        if (ch == '}')
          /* `min_rep` or more (`min_rep` - `INFTY`) */
          ch = bbre_parse_next(r), assert(ch == '}'), max_rep = BBRE_INFTY;
        else {
          /* `min_rep` to `max_rep` */
          if ((err = bbre_parse_number(r, &max_rep, 6)))
            return err;
          if ((err = bbre_parse_next_or(
                   r, &ch, "expected } to end repetition expression")))
            return err;
          if (ch != '}')
            return bbre_parse_err(r, "expected } to end repetition expression");
        }
      } else
        return bbre_parse_err(r, "expected } or , for repetition expression");
      if (!bbre_buf_size(r->arg_stk))
        return bbre_parse_err(r, "cannot apply quantifier to empty regex");
      if ((err = bbre_ast_make(
               r, BBRE_AST_TYPE_QUANT, *bbre_buf_peek(&r->arg_stk, 0), min_rep,
               max_rep, &res)))
        return err;
      *bbre_buf_peek(&r->arg_stk, 0) = res;
    } else if (ch == '^' || ch == '$') { /* beginning/end of text/line */
      /* these are similar enough that I put them into one condition */
      if ((err = bbre_ast_make(
               r, BBRE_AST_TYPE_ASSERT,
               ch == '^'
                   ? (flags & BBRE_GROUP_FLAG_MULTILINE
                          ? BBRE_ASSERT_LINE_BEGIN
                          : BBRE_ASSERT_TEXT_BEGIN)
                   : (flags & BBRE_GROUP_FLAG_MULTILINE ? BBRE_ASSERT_LINE_END
                                                        : BBRE_ASSERT_TEXT_END),
               0, 0, &res)) ||
          (err = bbre_buf_push(&r->alloc, &r->arg_stk, res)))
        return err;
    } else { /* char: push to the arg stk */
      /* arg_stk: | ... | */
      if ((err = bbre_ast_make(r, BBRE_AST_TYPE_CHR, ch, 0, 0, &res)) ||
          (err = bbre_buf_push(&r->alloc, &r->arg_stk, res)))
        return err;
      /* arg_stk: | ... | chr | */
    }
  }
  /* fold everything on the stacks into a single node */
  if ((err = bbre_fold(r)))
    return err;
  bbre_fold_alts(r, &flags);
  if (bbre_buf_size(r->op_stk))
    return bbre_parse_err(r, "unmatched open parenthesis");
  /* then wrap that node into a nonmatching subexpression group to denote a
   * subpattern */
  if ((err = bbre_ast_make(
           r, BBRE_AST_TYPE_GROUP, bbre_buf_pop(&r->arg_stk),
           BBRE_GROUP_FLAG_SUBEXPRESSION, 0, root)))
    return err;
  return 0;
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
 * index to the `prog_set_idxs` buf.*/
static int bbre_prog_emit(bbre_prog *prog, bbre_inst i, bbre_uint pat_idx)
{
  int err = 0;
  if (bbre_prog_size(prog) == BBRE_PROG_LIMIT_MAX_INSTS)
    return BBRE_ERR_LIMIT;
  if ((err = bbre_buf_push(&prog->alloc, &prog->prog, i)) ||
      (err = bbre_buf_push(&prog->alloc, &prog->set_idxs, pat_idx)))
    return err;
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
  if (!f->patch_head)
    /* the initial patch is just as the head and tail */
    f->patch_head = f->patch_tail = out_val;
  else {
    /* subsequent patch additions append to the tail of the list */
    bbre_patch_set(r, f->patch_tail, out_val);
    f->patch_tail = out_val;
  }
}

/* Concatenate the patches in `p` with the patches in `q`. */
static void bbre_patch_merge(bbre *r, bbre_compframe *p, bbre_compframe *q)
{
  if (!p->patch_head) {
    p->patch_head = q->patch_head;
    p->patch_tail = q->patch_tail;
    return;
  }
  if (!q->patch_head)
    return;
  bbre_patch_set(r, p->patch_tail, q->patch_head);
  p->patch_tail = q->patch_tail;
  q->patch_head = q->patch_tail = BBRE_REF_NONE;
}

/* Transfer ownership of a patch list from `src` to `dst`. */
static void bbre_patch_xfer(bbre_compframe *dst, bbre_compframe *src)
{
  dst->patch_head = src->patch_head;
  dst->patch_tail = src->patch_tail;
  src->patch_head = src->patch_tail = BBRE_REF_NONE;
}

/* Rip through the patch list in `f`, setting each branch target in the
 * instruction list to `dest_pc`. */
static void bbre_patch_apply(bbre *r, bbre_compframe *f, bbre_uint dest_pc)
{
  bbre_uint i = f->patch_head;
  while (i) {
    bbre_inst prev = bbre_patch_set(r, i, dest_pc);
    i = i & 1 ? bbre_inst_param(prev) : bbre_inst_next(prev);
  }
  f->patch_head = f->patch_tail = BBRE_REF_NONE;
}

/* We sort arrays of rune_range by their lower bound. */
static bbre_uint bbre_compcc_array_key(bbre_buf(bbre_rune_range) cc, size_t idx)
{
  return cc[idx].l;
}

/* Swap two values in an array of rune_range by their indices. */
static void
bbre_compcc_array_swap(bbre_buf(bbre_rune_range) cc, size_t a, size_t b)
{
  bbre_rune_range tmp = cc[a];
  cc[a] = cc[b];
  cc[b] = tmp;
}

/* Sort the array of rune_range by the lower bound of each range. */
static void bbre_compcc_hsort(bbre_buf(bbre_rune_range) cc)
{
  size_t end = bbre_buf_size(cc), start = end >> 1, root, child;
  while (end > 1) {
    if (start)
      start--;
    else
      bbre_compcc_array_swap(cc, --end, 0);
    root = start;
    while ((child = 2 * root + 1) < end) {
      if (child + 1 < end && bbre_compcc_array_key(cc, child) <
                                 bbre_compcc_array_key(cc, child + 1))
        child++;
      if (bbre_compcc_array_key(cc, root) < bbre_compcc_array_key(cc, child)) {
        bbre_compcc_array_swap(cc, root, child);
        root = child;
      } else
        break;
    }
  }
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
      return err;
  }
  if (out_ref)
    *out_ref = bbre_buf_size(*cc_out);
  if ((err = bbre_buf_push(&r->alloc, cc_out, node)))
    return err;
  return 0;
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
    return err;
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
      return err;
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
          return err;
      }
      if ((err = bbre_compcc_tree_build_one(
               r, cc_out, child_ref, mins[i], maxs[i], rest_bits - 6, 6)))
        return err;
    }
  }
  return err;
}

/* Given an array of rune ranges, build their tree. This function splits each
 * rune range amount UTF-8 length boundaries, then calls
 * `bbre_compcc_tree_build_one` on each split range. */
static int bbre_compcc_tree_build(
    bbre *r, const bbre_buf(bbre_rune_range) cc_in,
    bbre_buf(bbre_compcc_tree) * cc_out)
{
  size_t cc_idx = 0 /* current rune range index in `cc_in` */,
         len_idx = 0 /* current UTF-8 length */,
         min_bound = 0 /* current UTF-8 length minimum bound */;
  bbre_uint root_ref;         /* tree root */
  bbre_compcc_tree root_node; /* the actual stored root node */
  int err = 0;
  root_node.child_ref = root_node.sibling_ref = root_node.aux.hash =
      root_node.range = 0;
  /* clear output charclass */
  bbre_buf_clear(cc_out);
  if ((err = bbre_compcc_tree_new(r, cc_out, root_node, &root_ref)))
    return err;
  for (cc_idx = 0, len_idx = 0; cc_idx < bbre_buf_size(cc_in) && len_idx < 4;) {
    /* Loop until we're out of ranges and out of byte lengths */
    static const bbre_uint first_bits[4] = {7, 5, 4, 3};
    static const bbre_uint rest_bits[4] = {0, 6, 12, 18};
    /* What is the maximum codepoint that a UTF-8 sequence of length `len_idx`
     * can encode? */
    bbre_uint max_bound = (1 << (rest_bits[len_idx] + first_bits[len_idx])) - 1;
    bbre_rune_range rr = cc_in[cc_idx];
    if (min_bound <= rr.h && rr.l <= max_bound) {
      /* [rr.l,rr.h] intersects [min_bound,max_bound] */
      /* clip it so that it lies within [min_bound,max_bound] */
      bbre_uint clamped_min = rr.l < min_bound ? min_bound : rr.l,
                clamped_max = rr.h > max_bound ? max_bound : rr.h;
      /* then build it */
      if ((err = bbre_compcc_tree_build_one(
               r, cc_out, root_ref, clamped_min, clamped_max,
               rest_bits[len_idx], first_bits[len_idx])))
        return err;
    }
    if (rr.h < max_bound)
      /* range is less than [min_bound,max_bound] */
      cc_idx++;
    else
      /* range is greater than [min_bound,max_bound] */
      len_idx++, min_bound = max_bound + 1;
  }
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
  /* Loop through children of `a` and `b` */
  while (a_ref && b_ref) {
    const bbre_compcc_tree *a = cc_tree_in + a_ref, *b = cc_tree_in + b_ref;
    if (!bbre_compcc_tree_eq(cc_tree_in, a->child_ref, b->child_ref))
      return 0;
    if (a->range != b->range)
      return 0;
    a_ref = a->sibling_ref, b_ref = b->sibling_ref;
  }
  /* Ensure that both `a` and `b` have no remaining children. */
  assert(a_ref == 0 || b_ref == 0);
  return a_ref == b_ref;
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
    return err;
  memset(*cc_ht_out, 0, bbre_buf_size(*cc_ht_out) * sizeof(**cc_ht_out));
  return 0;
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
          return;
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
      return 0;
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
        return err;
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
      return err;
    if (node->child_ref) {
      /* node has children: need to down-compile */
      bbre_uint their_pc = 0;
      bbre_inst i = bbre_prog_get(&r->prog, range_pc);
      if ((err = bbre_compcc_tree_render(
               r, cc_tree_in, node->child_ref, &their_pc, frame)))
        return err;
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
  return 0;
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
  assert(node_ref != BBRE_REF_NONE);
  /* There needs to be enough space in the output tree. This space is
   * preallocated to simplify this function's error checking. */
  assert(bbre_buf_size(cc_tree_out) == bbre_buf_size(cc_tree_in));
  dst_node->sibling_ref = dst_node->child_ref = BBRE_REF_NONE;
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
      assert(parent_node->child_ref == BBRE_REF_NONE);
      parent_node->child_ref = node_ref;
    }
    child_sibling_ref = child_sibling_node->sibling_ref;
  }
}

/* This function is automatically generated and is defined later in this file.
 */
static int bbre_compcc_fold_range(
    bbre *r, bbre_uint begin, bbre_uint end,
    bbre_buf(bbre_rune_range) * cc_out);

/* Main function for the character class compiler. `ast_root` is the AST ID of
 * the CC node, `frame` is the compiler frame allocated for that node, and
 * `reversed` tells us whether to compile the charclass in reverse. */
static int
bbre_compcc(bbre *r, bbre_uint ast_root, bbre_compframe *frame, int reversed)
{
  int err = 0,
      is_inverted = *bbre_ast_type_ref(r, frame->root_ref) == BBRE_AST_TYPE_ICC,
      is_insensitive = !!(frame->flags & BBRE_GROUP_FLAG_INSENSITIVE);
  bbre_uint start_pc = 0; /* start PC of the compiled charclass, this is filled
                          in by rendertree() */
  /* clear temporary buffers (their space is reserved) */
  bbre_buf_clear(&r->compcc.ranges), bbre_buf_clear(&r->compcc.ranges_2),
      bbre_buf_clear(&r->compcc.tree), bbre_buf_clear(&r->compcc.tree_2),
      bbre_buf_clear(&r->compcc.hash);
  /* push ranges */
  while (ast_root) {
    /* decompose the tree of [I]CC nodes into a flat array in compcc.ranges */
    bbre_uint args[3] = {0} /* ast arguments */,
              rune_lo /* lower bound of rune range */,
              rune_hi /* upper bound of rune range */;
    bbre_ast_decompose(r, ast_root, args);
    ast_root = args[0], rune_lo = args[1], rune_hi = args[2];
    if ((err = bbre_buf_push(
             &r->alloc, &r->compcc.ranges,
             bbre_rune_range_make(
                 /* handle out-of-order ranges (lo > hi) */
                 rune_lo > rune_hi ? rune_hi : rune_lo,
                 rune_lo > rune_hi ? rune_lo : rune_hi))))
      return err;
  }
  /* for now, we disallow empty charclasses */
  assert(bbre_buf_size(r->compcc.ranges));
  /* sort and normalize ranges. This is done in a loop, because we may need to
   * do it twice in case the charclass is marked as case-insensitive */
  do {
    /* sort ranges: we want all ranges to be ordered by their lower bound, this
     * makes all subsequent steps O(1). Ideally, we want compilation time to be
     * dominated by this step. */
    bbre_compcc_hsort(r->compcc.ranges);
    /* normalize ranges: we want to eliminate all instances of range overlap,
     * and we also want to merge adjacent ranges. */
    {
      size_t i;
      bbre_rune_range next /* currently processed range */,
          prev /* previously processed range, yet to be added to the array */;
      for (i = 0; i < bbre_buf_size(r->compcc.ranges); i++) {
        next = r->compcc.ranges[i];
        assert(next.l <= next.h); /* ensure ranges are not swapped */
        if (!i)
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
          if ((err = bbre_buf_push(&r->alloc, &r->compcc.ranges_2, prev)))
            return err;
          prev = next;
        }
      }
      assert(i); /* the charclass is never empty here */
      if ((err = bbre_buf_push(&r->alloc, &r->compcc.ranges_2, prev)))
        return err;
      if (is_insensitive) {
        /* casefold normalized ranges */
        bbre_buf_clear(&r->compcc.ranges);
        for (i = 0; i < bbre_buf_size(r->compcc.ranges_2); i++) {
          next = r->compcc.ranges_2[i];
          if ((err = bbre_buf_push(&r->alloc, &r->compcc.ranges, next)))
            return err;
          if ((err = bbre_compcc_fold_range(
                   r, next.l, next.h, &r->compcc.ranges)))
            return err;
        }
        bbre_buf_clear(&r->compcc.ranges_2);
      }
    }
  } while (is_insensitive &&
           is_insensitive-- /* re-normalize by looping again */);
  if (is_inverted) {
    /* invert ranges in place, if appropriate */
    bbre_uint hi = 0 /* largest rune encountered plus one */,
              read /* read index into `compcc_ranges_2` */,
              write = 0 /* write index into `compcc_ranges_2` */,
              old_size = bbre_buf_size(r->compcc.ranges_2);
    bbre_rune_range cur = bbre_rune_range_make(0, 0);
    for (read = 0; read < old_size; read++) {
      cur = r->compcc.ranges_2[read];
      /* for inverting in place to work, the write index must always lag the
       * read index */
      assert(write <= read);
      if (cur.l > hi) {
        /* create a range that 'fills in the gap' between the previous range and
         * the next one */
        r->compcc.ranges_2[write++] = bbre_rune_range_make(hi, cur.l - 1);
        hi = cur.h + 1;
      }
    }
    /* it is possible for the amount of inverted ranges to be greater than the
     * amound of ranges (specifically, it may be exactly one greater if the
     * input range does not extend to the maximum codepoint) */
    if ((err = bbre_buf_reserve(
             &r->alloc, &r->compcc.ranges_2, write += (cur.h < BBRE_UTF_MAX))))
      return err;
    /* make the final inverted range */
    if (cur.h < BBRE_UTF_MAX)
      r->compcc.ranges_2[write - 1] =
          bbre_rune_range_make(cur.h + 1, BBRE_UTF_MAX);
  }
  if (!bbre_buf_size(r->compcc.ranges_2)) {
    /* here, it's actually possible to have a charclass that matches no chars,
     * consider the inversion of [\x00-\x{10FFFF}]. Since this case is so rare,
     * we just stub it out by creating an assert that never matches. */
    if ((err = bbre_prog_emit(
             &r->prog,
             bbre_inst_make(
                 BBRE_OPCODE_ASSERT, 0,
                 BBRE_ASSERT_WORD | BBRE_ASSERT_NOT_WORD),
             frame->set_idx))) /* never matches */
      return err;
    /* just return immediately, the code below assumes that there are actually
     * ranges to compile */
    bbre_patch_add(r, frame, bbre_prog_size(&r->prog) - 1, 0);
    return err;
  }
  /* build the concat/alt tree */
  if ((err = bbre_compcc_tree_build(r, r->compcc.ranges_2, &r->compcc.tree)))
    return err;
  /* hash the tree */
  if ((err = bbre_compcc_hash_init(r, r->compcc.tree, &r->compcc.hash)))
    return err;
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
        return err;
      assert(!err);
    }
    /* detach new root */
    r->compcc.tree_2[1].child_ref = BBRE_REF_NONE;
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
    return err;
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
  switch (bbre_inst_opcode(inst)) {
  case BBRE_OPCODE_SPLIT:
    next_inst = bbre_inst_make(
        bbre_inst_opcode(next_inst), bbre_inst_next(next_inst),
        bbre_inst_relocate_pc(bbre_inst_param(next_inst), src, dst));
    /* fall through */
  case BBRE_OPCODE_RANGE:
  case BBRE_OPCODE_MATCH:
  case BBRE_OPCODE_ASSERT:
    next_inst = bbre_inst_make(
        bbre_inst_opcode(next_inst),
        bbre_inst_relocate_pc(bbre_inst_next(next_inst), src, dst),
        bbre_inst_param(next_inst));
  }
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
  int err;
  *dst = *src;
  bbre_patch_apply(r, src, dest_pc);
  dst->pc = bbre_prog_size(&r->prog);
  dst->patch_head = dst->patch_tail = BBRE_REF_NONE;
  for (i = src->pc; i < src_end; i++) {
    bbre_inst inst = bbre_prog_get(&r->prog, i),
              next_inst = bbre_inst_relocate(inst, src->pc, dst->pc);
    int should_patch[2] = {0, 0}, j;
    switch (bbre_inst_opcode(inst)) {
    case BBRE_OPCODE_SPLIT:
      /* Any previous patches in `src` should have been linked to `dest_pc`. We
       * can track them thusly. */
      should_patch[1] = bbre_inst_param(inst) == dest_pc;
      /* Duplicate the instruction, relocating relative jumps. */
      next_inst = bbre_inst_make(
          bbre_inst_opcode(next_inst), bbre_inst_next(next_inst),
          should_patch[1] ? 0 : bbre_inst_param(next_inst));
      /* fall through */
    case BBRE_OPCODE_RANGE:
    case BBRE_OPCODE_MATCH:
    case BBRE_OPCODE_ASSERT:
      should_patch[0] = bbre_inst_next(inst) == dest_pc;
      next_inst = bbre_inst_make(
          bbre_inst_opcode(next_inst),
          should_patch[0] ? 0 : bbre_inst_next(next_inst),
          bbre_inst_param(next_inst));
    }
    if ((err = bbre_prog_emit(&r->prog, next_inst, dst->set_idx)))
      return err;
    /* if the above step found patch points, add them to `dst`'s patch list. */
    for (j = 0; j < 2; j++)
      if (should_patch[j])
        bbre_patch_add(r, dst, i - src->pc + dst->pc, j);
  }
  return 0;
}

static int bbre_compile_dotstar(bbre_prog *prog, int reverse, bbre_uint pat_idx)
{
  /* compile in a dotstar for unanchored matches */
  int err;
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
    return err;
  if ((err = bbre_prog_emit(
           prog,
           bbre_inst_make(
               BBRE_OPCODE_RANGE, dstar,
               bbre_byte_range_to_u32(bbre_byte_range_make(0, 255))),
           frame.set_idx)))
    return err;
  return err;
}

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
  bbre_uint sub_idx = 0 /* current subpattern index */,
            grp_idx = 1 /* current capture group index */,
            tmp_cc_ast = BBRE_REF_NONE; /* temporary AST node for converting CHR
                                         nodes into CC nodes */
  /* add sentinel 0th instruction, this compiles to all zeroes */
  if (!bbre_prog_size(&r->prog) &&
      ((err = bbre_buf_push(
            &r->alloc, &r->prog.prog,
            bbre_inst_make(BBRE_OPCODE_RANGE, 0, 0))) ||
       (err = bbre_buf_push(&r->alloc, &r->prog.set_idxs, 0))))
    return err;
  assert(bbre_prog_size(&r->prog) > 0);
  /* create the frame for the root node */
  initial_frame.root_ref = ast_root;
  initial_frame.child_ref = initial_frame.patch_head =
      initial_frame.patch_tail = BBRE_REF_NONE;
  initial_frame.idx = 0;
  initial_frame.pc = bbre_prog_size(&r->prog);
  /* set the entry point for the forward or reverse program */
  r->prog.entry[reverse ? BBRE_PROG_ENTRY_REVERSE : 0] = initial_frame.pc;
  if ((err = bbre_buf_push(&r->alloc, &r->comp_stk, initial_frame)))
    return err;
  while (bbre_buf_size(r->comp_stk)) {
    /* walk the AST tree recursively until we are done visiting nodes */
    bbre_compframe frame = *bbre_buf_peek(&r->comp_stk, 0);
    bbre_ast_type type; /* AST node type */
    bbre_uint args[4] = {0} /* AST node args */,
              my_pc =
                  bbre_prog_size(&r->prog); /* PC of this node's instructions */
    /* we tell the compiler to visit a child by setting `frame.child_ref` to
     * some value other than `frame.root_ref`. By default, we set it to
     * `frame.root_ref` to disable visiting a child. */
    frame.child_ref = frame.root_ref;

    child_frame.child_ref = child_frame.root_ref = child_frame.patch_head =
        child_frame.patch_tail = BBRE_REF_NONE;
    child_frame.idx = child_frame.pc = 0;
    type = *bbre_ast_type_ref(r, frame.root_ref); /* may return 0 if epsilon */
    if (frame.root_ref)
      bbre_ast_decompose(r, frame.root_ref, args);
    if (type == BBRE_AST_TYPE_CHR) {
      /* single characters / codepoints, this corresponds to one or more RANGE
       * instructions */
      bbre_patch_apply(r, &frame, my_pc);
      if (args[0] < 128 && !(frame.flags & BBRE_GROUP_FLAG_INSENSITIVE)) {
        /* ascii characters -- these are common enough that it's worth
         * bypassing
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
          return err;
        bbre_patch_add(r, &frame, my_pc, 0);
      } else { /* unicode */
        /* create temp ast */
        if (!tmp_cc_ast &&
            (err = bbre_ast_make(
                 r, BBRE_AST_TYPE_CC, BBRE_REF_NONE, 0, 0, &tmp_cc_ast)))
          return err;
        /* create a CC node with a range comprising the single codepoint */
        *bbre_ast_param_ref(r, tmp_cc_ast, 1) =
            *bbre_ast_param_ref(r, tmp_cc_ast, 2) = args[0];
        /* call the character class compiler on the single CC node */
        if ((err = bbre_compcc(r, tmp_cc_ast, &frame, reverse)))
          return err;
      }
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
        return err;
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
          return err;
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
          return err;
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
        /*        +-------+
         *  in   /         \
         * ---> S -> [X] ---+
         *       \             out
         *        +-----------------> */
        assert(frame.idx == min + 1);
        bbre_patch_apply(r, &returned_frame, my_pc);
        if ((err = bbre_prog_emit(
                 &r->prog, bbre_inst_make(BBRE_OPCODE_SPLIT, frame.pc + 1, 0),
                 frame.set_idx)))
          return err;
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
            return err;
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
      bbre_uint child = args[0], flags = args[1];
      frame.flags =
          flags &
          ~BBRE_GROUP_FLAG_SUBEXPRESSION; /* we shouldn't propagate this */
      if (!frame.idx) {                   /* before child */
        /* before child */
        if (!(flags & BBRE_GROUP_FLAG_NONCAPTURING)) {
          /* compile in the beginning match instruction */
          /*  in      out
           * ---> Mb ----> */
          bbre_patch_apply(r, &frame, my_pc);
          if (flags & BBRE_GROUP_FLAG_SUBEXPRESSION)
            grp_idx = 0, frame.set_idx = ++sub_idx;
          if ((err = bbre_prog_emit(
                   &r->prog,
                   bbre_inst_make(
                       BBRE_OPCODE_MATCH, 0,
                       bbre_inst_match_param_make(reverse, grp_idx++)),
                   frame.set_idx)))
            return err;
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
        if (!(flags & BBRE_GROUP_FLAG_NONCAPTURING)) {
          bbre_patch_apply(r, &returned_frame, my_pc);
          if ((err = bbre_prog_emit(
                   &r->prog,
                   bbre_inst_make(
                       BBRE_OPCODE_MATCH, 0,
                       bbre_inst_match_param_make(
                           !reverse, bbre_inst_match_param_idx(bbre_inst_param(
                                         bbre_prog_get(&r->prog, frame.pc))))),
                   frame.set_idx)))
            return err;
          if (!(flags & BBRE_GROUP_FLAG_SUBEXPRESSION))
            bbre_patch_add(r, &frame, my_pc, 0);
          else {
            /* for the ending match instruction that corresponds to a
             * subexpression, don't link it anywhere: it signifies the end of a
             * subpattern. */
            /*  in
             * ---> Mb -> [X] -> Me */
          }
        } else
          /* non-capturing group: don't compile in anything */
          /*  in       out
           * ---> [X] ----> */
          bbre_patch_merge(r, &frame, &returned_frame);
      }
    } else if (type == BBRE_AST_TYPE_CC || type == BBRE_AST_TYPE_ICC) {
      /* charclasses: pass off compilation to the character class compiler */
      bbre_patch_apply(r, &frame, my_pc);
      if ((err = bbre_compcc(r, frame.root_ref, &frame, reverse)))
        return err;
    } else if (type == BBRE_AST_TYPE_ASSERT) {
      /* assertions: add a single ASSERT instruction */
      /*  in     out
       * ---> A ----> */
      bbre_uint assert_flag = args[0], real_assert_flag = 0;
      bbre_patch_apply(r, &frame, my_pc);
      if (reverse) {
        if (assert_flag & BBRE_ASSERT_TEXT_BEGIN)
          real_assert_flag |= BBRE_ASSERT_TEXT_END;
        if (assert_flag & BBRE_ASSERT_TEXT_END)
          real_assert_flag |= BBRE_ASSERT_TEXT_BEGIN;
        if (assert_flag & BBRE_ASSERT_LINE_BEGIN)
          real_assert_flag |= BBRE_ASSERT_LINE_END;
        if (assert_flag & BBRE_ASSERT_LINE_END)
          real_assert_flag |= BBRE_ASSERT_LINE_BEGIN;
        real_assert_flag |=
            (assert_flag & (BBRE_ASSERT_WORD | BBRE_ASSERT_NOT_WORD));
      } else {
        real_assert_flag = assert_flag;
      }
      if ((err = bbre_prog_emit(
               &r->prog,
               bbre_inst_make(BBRE_OPCODE_ASSERT, 0, real_assert_flag),
               frame.set_idx)))
        return err;
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
        return err;
    } else {
      (void)bbre_buf_pop(&r->comp_stk);
    }
    returned_frame = frame;
  }
  assert(!bbre_buf_size(r->comp_stk));
  assert(!returned_frame.patch_head && !returned_frame.patch_tail);
  return bbre_compile_dotstar(&r->prog, reverse, 1);
}

int bbre_set_spec_init(bbre_set_spec **pspec, const bbre_alloc *palloc)
{
  int err = 0;
  bbre_set_spec *spec;
  bbre_alloc alloc = bbre_alloc_make(palloc);
  spec = bbre_ialloc(&alloc, NULL, 0, sizeof(bbre_spec));
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

int bbre_set_spec_add(bbre_set_spec *set, const bbre *b)
{
  return bbre_buf_push(&set->alloc, &set->pats, b);
}

void bbre_set_spec_destroy(bbre_set_spec *spec)
{
  if (!spec)
    return;
  bbre_buf_destroy(&spec->alloc, &spec->pats);
  bbre_ialloc(&spec->alloc, spec, sizeof(bbre_spec), 0);
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
  bbre_prog_init(&set->prog, set->alloc);
  set->exec = NULL;
error:
  return err;
}

int bbre_set_init(
    bbre_set **pset, const bbre_set_spec *spec, const bbre_alloc *palloc)
{
  int err = 0;
  if ((err = bbre_set_init_internal(pset, palloc)))
    goto error;
  if ((err = bbre_set_compile(*pset, spec->pats, bbre_buf_size(spec->pats))))
    goto error;
error:
  return err;
}

void bbre_set_destroy(bbre_set *set)
{
  if (!set)
    return;
  bbre_prog_destroy(&set->prog);
  if (set->exec)
    bbre_exec_destroy(set->exec);
  bbre_ialloc(&set->alloc, set, sizeof(*set), 0);
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
    return err;
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
        return err;
    }
    for (src_pc = r->prog.entry[0], dst_pc = bbre_prog_size(&set->prog);
         src_pc < r->prog.entry[BBRE_PROG_ENTRY_DOTSTAR]; src_pc++, dst_pc++) {
      if ((err = bbre_prog_emit(
               &set->prog,
               bbre_inst_relocate(r->prog.prog[src_pc], src_pc, dst_pc),
               i + 1)))
        return err;
    }
    set->prog.npat++;
  }
  if ((err = bbre_compile_dotstar(&set->prog, 0, 0)))
    return err;
  return err;
}

static int bbre_sset_reset(bbre_exec *exec, bbre_sset *s, size_t next_size)
{
  int err;
  assert(next_size); /* programs are never of size 0 */
  if ((err = bbre_buf_reserve(&exec->alloc, &s->sparse, next_size)))
    return err;
  if ((err = bbre_buf_reserve(&exec->alloc, &s->dense, next_size)))
    return err;
  s->size = next_size, s->dense_size = 0;
  return 0;
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
    return;
  s->dense[s->dense_size] = spec;
  s->sparse[spec.pc] = s->dense_size++;
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
      if (!new_slots)
        return BBRE_ERR_MEM;
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
  return 0;
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
    return;
  if (!s->slots[ref * s->per_thrd + s->per_thrd - 1]--) {
    /* prepend to free list */
    s->slots[ref * s->per_thrd] = s->last_empty;
    s->last_empty = ref;
  }
}

static int bbre_save_slots_set_internal(
    bbre_exec *exec, bbre_save_slots *s, bbre_uint ref, bbre_uint idx, size_t v,
    bbre_uint *out)
{
  int err;
  *out = ref;
  assert(s->per_thrd);
  assert(idx < s->per_thrd);
  assert(s->slots[ref * s->per_thrd + s->per_thrd - 1]);
  if (v == s->slots[ref * s->per_thrd + idx]) {
    /* not changing anything */
  } else {
    if ((err = bbre_save_slots_new(exec, s, out)))
      return err;
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
  return 0;
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
    return err;
  for (i = 0; i < (size + BBRE_BITS_PER_U32) / BBRE_BITS_PER_U32; i++)
    *b[i] = 0;
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
    return err;
  bbre_buf_clear(&n->thrd_stk), bbre_buf_clear(&n->pri_stk);
  bbre_save_slots_clear(&n->slots, noff);
  initial_thrd.pc = pc;
  if ((err = bbre_save_slots_new(exec, &n->slots, &initial_thrd.slot)))
    return err;
  bbre_sset_add(&n->a, initial_thrd);
  initial_thrd.pc = initial_thrd.slot = 0;
  for (i = 0; i < exec->prog->npat; i++)
    if ((err = bbre_buf_push(&exec->alloc, &n->pri_stk, 0)))
      return err;
  if ((err = bbre_bmp_init(exec->alloc, &n->pri_bmp_tmp, exec->prog->npat)))
    return err;
  n->reversed = reversed;
  n->pri = pri;
  return 0;
}

static int
bbre_nfa_eps(bbre_exec *exec, bbre_nfa *n, size_t pos, bbre_assert_flag ass)
{
  int err;
  size_t i;
  bbre_sset_clear(&n->b);
  for (i = 0; i < n->a.dense_size; i++) {
    bbre_nfa_thrd dense_thrd = n->a.dense[i];
    if ((err = bbre_buf_push(&exec->alloc, &n->thrd_stk, dense_thrd)))
      return err;
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
          return err;
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
          return err;
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
  return 0;
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
      return err;
    goto out_survive;
  } else {
    *memo = 1; /* just mark that a set was matched */
    goto out_kill;
  }
out_survive:
  return err;
out_kill:
  bbre_save_slots_kill(&n->slots, thrd.slot);
  return err;
}

static int
bbre_nfa_chr(bbre_exec *exec, bbre_nfa *n, unsigned int ch, size_t pos)
{
  int err;
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
        return err;
      if (n->pri)
        bbre_bmp_set(n->pri_bmp_tmp, exec->prog->set_idxs[thrd.pc]);
      bbre_save_slots_kill(&n->slots, thrd.slot);
    }
  }
  return 0;
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
  int err;
  size_t j, sets = 0, nset = 0;
  if ((err = bbre_nfa_eps(
           exec, n, pos, bbre_make_assert_flag(prev_ch, BBRE_SENTINEL_CH))) ||
      (err = bbre_nfa_chr(exec, n, 256, pos)))
    return err;
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
  return nset;
}

static int bbre_nfa_run(
    bbre_exec *exec, bbre_nfa *n, bbre_uint ch, size_t pos, bbre_uint prev_ch)
{
  int err;
  if ((err = bbre_nfa_eps(exec, n, pos, bbre_make_assert_flag(prev_ch, ch))))
    return err;
  if ((err = bbre_nfa_chr(exec, n, ch, pos)))
    return err;
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
    if (!next_cache)
      return BBRE_ERR_MEM;
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
        if (!next_state)
          return BBRE_ERR_MEM;
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
      return err;
    d->entry[entry][prev_flag] = *out_next_state;
  }
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
    return err;
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
        return err;
      if (n->pri)
        bbre_bmp_set(n->pri_bmp_tmp, exec->prog->set_idxs[thrd.pc]);
      break;
    }
    default:
      assert(0);
    }
  }
  /* feed ch to n -> this was accomplished by the above code */
  return bbre_dfa_construct(
      exec, d, prev_state, ch,
      (ch == BBRE_SENTINEL_CH) * BBRE_DFA_STATE_FLAG_FROM_TEXT_BEGIN |
          (ch == BBRE_SENTINEL_CH || ch == '\n') *
              BBRE_DFA_STATE_FLAG_FROM_LINE_BEGIN |
          (bbre_is_word_char(ch) ? BBRE_DFA_STATE_FLAG_FROM_WORD : 0),
      n, out_next_state);
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
    const int reversed, const int pri, const int exit_early, const int many)
{
  int err;
  bbre_dfa_state *state = NULL;
  size_t i;
  bbre_uint entry =
      !reversed ? BBRE_PROG_ENTRY_DOTSTAR : BBRE_PROG_ENTRY_REVERSE;
  bbre_uint prev_ch = reversed ? (pos == n ? BBRE_SENTINEL_CH : s[pos + 1])
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
    return err;
  if (many) {
    if ((err =
             bbre_bmp_init(exec->alloc, &exec->dfa.set_bmp, exec->prog->npat)))
      return err;
  }
  i = reversed ? n : 0;
  {
    const bbre_byte *start = reversed ? s + n - 1 : s,
                    *end = reversed ? s - 1 : s + n, *out = NULL;
    /* The amount to increment each iteration of the loop. */
    int increment = reversed ? -1 : 1;
    if (!(state = exec->dfa.entry[entry][incoming_assert_flag]) &&
        (err = bbre_dfa_construct_start(
             exec, &exec->dfa, &exec->nfa, entry, incoming_assert_flag,
             &state)))
      return err;
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
          return 1;
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
          return err;
      }
      state = next;
    }
    if (exit_early) {
      if (state->nset) {
        return 1;
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
      return err;
  } else
    state = state->ptrs[s[i]];
  if (many)
    bbre_dfa_save_matches(&exec->dfa, state);
  if (out_pos && state->nset)
    *out_pos = reversed ? 0 : n;
  assert(state);
  return !!state->nset;
done_success:
  return 1;
}

static int bbre_exec_init(
    bbre_exec **pexec, const bbre_prog *prog, const bbre_alloc *palloc)
{
  int err = 0;
  bbre_alloc alloc = bbre_alloc_make(palloc);
  bbre_exec *exec = bbre_ialloc(&alloc, NULL, 0, sizeof(bbre_exec));
  *pexec = exec;
  assert(bbre_prog_size(prog));
  if (!exec)
    return BBRE_ERR_MEM;
  memset(exec, 0, sizeof(bbre_exec));
  exec->alloc = alloc;
  exec->prog = prog;
  bbre_nfa_init(&exec->nfa);
  bbre_dfa_init(&exec->dfa);
  return err;
}

static void bbre_exec_destroy(bbre_exec *exec)
{
  if (!exec)
    return;
  bbre_nfa_destroy(exec, &exec->nfa);
  bbre_dfa_destroy(exec, &exec->dfa);
  bbre_ialloc(&exec->alloc, exec, sizeof(bbre_exec), 0);
}

static int bbre_compile(bbre *r)
{
  int err;
  assert(!bbre_prog_size(&r->prog));
  if ((err = bbre_compile_internal(r, r->ast_root, 0)) ||
      (err = bbre_compile_internal(r, r->ast_root, 1))) {
    return err;
  }
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
    return bbre_dfa_match(exec, (bbre_byte *)s, n, pos, NULL, 0, 0, 1, 0);
  } else if (max_span == 1) {
    err = bbre_dfa_match(
        exec, (bbre_byte *)s, n, 0, &out_span[0].end, 0, 1, 0, 0);
    if (err <= 0)
      return err;
    err = bbre_dfa_match(
        exec, (bbre_byte *)s, n, out_span[0].end, &out_span[0].begin, 1, 0, 0,
        0);
    if (err < 0)
      return err;
    assert(err == 1);
    if (which_spans)
      *which_spans = 1;
    return 1;
  }
  if ((err = bbre_nfa_start(
           exec, &exec->nfa, exec->prog->entry[entry], max_span * 2, 0, 1)))
    return err;
  for (i = 0; i < n; i++) {
    if ((err = bbre_nfa_run(
             exec, &exec->nfa, ((const bbre_byte *)s)[i], i, prev_ch)))
      return err;
    prev_ch = ((const bbre_byte *)s)[i];
  }
  if ((err = bbre_nfa_end(
           exec, n, &exec->nfa, max_span, 0, out_span, NULL, prev_ch)) <= 0)
    return err;
  for (i = 0; i < max_span; i++) {
    int span_bad = out_span[i].begin == BBRE_UNSET_POSN ||
                   out_span[i].end == BBRE_UNSET_POSN;
    if (span_bad)
      out_span[i].begin = 0, out_span[i].end = 0;
    if (which_spans)
      which_spans[i] = !span_bad;
  }
  return err;
}

static int bbre_match_internal(
    bbre *r, const char *s, size_t n, size_t pos, bbre_span *out_spans,
    bbre_uint *which_spans, bbre_uint out_spans_size)
{
  int err = 0;
  if (!r->exec)
    if ((err = bbre_exec_init(&r->exec, &r->prog, &r->alloc)))
      return err;
  if ((err = bbre_exec_match(
           r->exec, s, n, pos, out_spans, which_spans, out_spans_size)))
    goto done;
done:
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

static int bbre_exec_set_match(
    bbre_exec *exec, const char *s, size_t n, size_t pos, bbre_uint idxs_size,
    bbre_uint *out_idxs, bbre_uint *out_num_idxs)
{
  int err;
  assert(BBRE_IMPLIES(idxs_size, out_idxs != NULL));
  if (!idxs_size) {
    /* boolean match */
    return bbre_dfa_match(exec, (bbre_byte *)s, n, pos, NULL, 0, 1, 1, 0);
  } else {
    bbre_uint i, j;
    size_t dummy;
    err = bbre_dfa_match(exec, (bbre_byte *)s, n, pos, &dummy, 0, 1, 0, 1);
    if (err < 0)
      return err;
    for (i = 0, j = 0; i < exec->prog->npat && j < idxs_size; i++) {
      if (bbre_bmp_get(exec->dfa.set_bmp, i))
        out_idxs[j++] = i;
    }
    *out_num_idxs = j;
    return !!j;
  }
}

static int bbre_set_match_internal(
    bbre_set *set, const char *s, size_t n, size_t pos, bbre_uint *out_idxs,
    bbre_uint out_idxs_size, bbre_uint *out_num_idxs)
{
  int err = 0;
  if (!set->exec)
    if ((err = bbre_exec_init(&set->exec, &set->prog, &set->alloc)))
      return err;
  if ((err = bbre_exec_set_match(
           set->exec, s, n, pos, out_idxs_size, out_idxs, out_num_idxs)))
    goto done;
done:
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
    bbre *r, bbre_uint begin, bbre_uint end, bbre_buf(bbre_rune_range) * cc_out)
{
  bbre_uint current, x0, x1, x2, x3, x4, x5;
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
                if ((err = bbre_buf_push(
                         &r->alloc, cc_out,
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
  bbre_uint name_len, num_range, start;
  const char *name;
} bbre_builtin_cc;

/* builtin_cc_data is a bitstream representing compressed rune ranges.
 * Normalized ranges are flattened into an array of integers so that even
 * indices are range minimums, and odd indices are range maximums. Then the the
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
/* 3360 ranges, 6720 integers, 4320 bytes */
static const bbre_uint bbre_builtin_cc_data[1080] = {
    0x7ACF7CF7, 0x00007AD7, 0xAD77ADFF, 0x00000007, 0x000017F2, 0x00005A9F,
    0x003ECD7A, 0x00007CF7, 0x006ECDFB, 0x007ADFB3, 0x12B0D0DF, 0x001ECCFB,
    0xD331CDFB, 0xD3B6D3B1, 0x00000004, 0x0012B2DF, 0x0007ADFF, 0x7ACF7CF7,
    0x0001EB1B, 0xB6CF7CF7, 0x000006D3, 0xFB3ECD7A, 0x00000000, 0x4ADA9B6B,
    0x9FEA5ADB, 0x30DFF60B, 0xA2D9F9F3, 0xD3B2DBFF, 0x37D2C2F2, 0xFE8F2BF7,
    0x208E8CD0, 0x349DCA8F, 0x7EC98CD7, 0x73CEACD3, 0x58AFA8ED, 0x005ECD7A,
    0xC8FFFF73, 0xA27A5FE9, 0xFFFC9FFB, 0xFFFC926F, 0x0000006F, 0xC8FFFB73,
    0x5FCC35FD, 0x005FFCC3, 0x3F7ADFB3, 0x5756B0D9, 0x00000000, 0x10C00000,
    0x00043000, 0x00000000, 0x29213412, 0x4D2926C3, 0x490C4812, 0x7530D20A,
    0xC0001249, 0x30C00010, 0x000000A1, 0x00000000, 0x90D24C70, 0xB4A33006,
    0xA2808EC3, 0x272E92B4, 0x00052C34, 0xD2492C00, 0x015DCAF0, 0xC8000000,
    0x00000000, 0x12000000, 0x00010C00, 0x00000000, 0x00000000, 0x9DF60000,
    0x0DCE3773, 0x6DEFB353, 0xF33D22A7, 0xCCFF4DCE, 0x16737ED2, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x013C0000, 0x00000000, 0x00000000,
    0x3C000000, 0xF5D336DF, 0xD336DF5D, 0x6CDF5DF5, 0xDF5DF5D3, 0x970D2DF5,
    0x4D37C352, 0x54CD77C3, 0x0CA4A9C3, 0x269A2E8B, 0xB9B4DF0D, 0x5DCB6B61,
    0x31A04329, 0x00001DB4, 0x00000000, 0x00000000, 0x0F0C0000, 0x65A76C9A,
    0x002A99F8, 0x00000000, 0x00000AA0, 0x000E2A00, 0x00000014, 0x00000000,
    0xA0048570, 0x00005121, 0xA0000618, 0xA6E80161, 0xC371B9C8, 0xD7333CF1,
    0xCC77F9F9, 0xB0D8ACB6, 0x671CEADE, 0xAD2778AD, 0x4734332E, 0x289EC347,
    0xB1CFDC2F, 0xB7FDADD7, 0xB4EBABD7, 0xF3474EDE, 0x4EDEB4ED, 0xB0CD1C53,
    0xAD3B7AD3, 0x3B7AD3B7, 0x7AD3B7AD, 0xD3B7AD3B, 0xB7AD3B7A, 0xADBB4ED3,
    0x3AD3B6D3, 0xD3AD3B6D, 0x6D3AD3B6, 0x96D3AD3B, 0x2B5F6B9E, 0x3BF9DB5D,
    0x000001FB, 0xB7CCF6B3, 0xF2D734CD, 0xBE1862A0, 0xA6A59E97, 0xB0C7270D,
    0xA28323E9, 0xAA39A9FA, 0x323FC9AB, 0x24EEE86E, 0xE29CC8B7, 0xD76B6DF3,
    0x7498731F, 0x720BACCA, 0xFDCB37C8, 0xA0BEC33E, 0xB61AF8FE, 0x309C872C,
    0x9FBD1ECC, 0x6D27AA5A, 0xA4BC9727, 0x3C3F30DB, 0x723A9F33, 0x6BF0CB43,
    0xC832A5A8, 0x730C6A6D, 0xAD8334CE, 0xB0C76588, 0x79D6DFBF, 0xC62F2F3D,
    0x2CCF32B4, 0x88990DFF, 0xC347536C, 0xDBF0B88E, 0xDBCC70CE, 0x000FB2A1,
    0xFA3C836B, 0x7CED369F, 0xB0ECBE72, 0xD5EC774D, 0x9CD0CA77, 0x4CC37A90,
    0xDBB1F24D, 0x2CCEB31E, 0xC6B3EDEA, 0xF3AD376A, 0xD5AC70CC, 0xBF39C2B6,
    0xE4A8B6BC, 0xB1CDF37C, 0xAD30D35D, 0x2D3291D6, 0xD431C9F2, 0xDE4CC35C,
    0x6AD30DB6, 0x0D0D0D1D, 0xD2A94CFB, 0x5AB54F7C, 0xA2CB4347, 0x3AC33C92,
    0x30D35CB2, 0xD0D1D6AD, 0xD435E8B2, 0x2DB02A3C, 0x0C432D35, 0xCCB4B0CB,
    0x576B96B4, 0x2D7346B5, 0xC349353A, 0xAD55DA5E, 0xE8B2D7D1, 0x33CC3433,
    0xE754F0AC, 0x7D19F24C, 0xF31DB7AD, 0x24F56B2D, 0xD5DD3F1D, 0xCBF6DB30,
    0xC56B4B10, 0xB48330D7, 0xE7ED33AC, 0xBB49D5CF, 0x0DCAF32C, 0x6DB7C9AB,
    0x4F0CA2D3, 0xC9B32CDB, 0xD34E370B, 0x9D34C474, 0xD3ED34D3, 0x4D311D34,
    0xD34EF473, 0x319C2334, 0x7330BCD7, 0xEB4F34D3, 0x75C3331D, 0xB1CDF33D,
    0xCDF35CC2, 0xF3CD4B35, 0xCA3279D2, 0x2CF2BD09, 0x33197ED3, 0xBC7B4CDA,
    0xCCB4DBB0, 0xDEB6D372, 0xF0CC6B5B, 0xC777DACA, 0xBB5BD70A, 0x74CC31CD,
    0xDD274ED3, 0xCDBB4CD0, 0xC35B530B, 0x74D3E2A2, 0xEB5BCEFF, 0xD1C331AD,
    0xD1D1D1D1, 0x6331D1D1, 0xACDA1B8E, 0x6DEB31F6, 0x6ECD0DC6, 0xDF75EC2B,
    0x9C9FFF5C, 0x8D9FE5FB, 0x2B5AB5FF, 0x6728CC6F, 0x36D3277D, 0x8CC34CD7,
    0xB68CC2E4, 0xCA39C836, 0xB1AD4D51, 0xDD734BC7, 0x30B6D7F7, 0x4CD3B2CC,
    0xCBB0EC6B, 0xCB1DC773, 0x74B4CCF4, 0xAD753ACE, 0xA2DB5736, 0x4C3297DC,
    0xC37A84CB, 0xD723C332, 0x36D36D36, 0x2AB1D1C3, 0xDA87B09C, 0x1ADB249B,
    0x262B3DDB, 0xCD36DDDA, 0x5F0A3379, 0xD0C4B4B3, 0xC274DCD0, 0x5FD2B0DD,
    0xCDE76BD3, 0xAD2DAF34, 0xD7C37318, 0xCB1ED32D, 0x36D36D36, 0xAD4CCA75,
    0xCD0D0AD7, 0xD276CD31, 0xEC62F0FC, 0xCF73DCB2, 0xD4AC735E, 0xD3369D75,
    0xDB49D36E, 0x6CCDFF35, 0xDF59D273, 0xB9DBAB4B, 0x336AC331, 0x36DEAB5D,
    0x22C35371, 0x1AD331AD, 0x2331EC33, 0xD330D0AC, 0x37AD336A, 0x0D75BD63,
    0x5533C9FF, 0xCBB4DCBB, 0x5729CBB2, 0xDAF2ED3B, 0xB4CDAB4C, 0xCDF31CC2,
    0xBACE335D, 0x76EDD273, 0x5CCC35DE, 0xADE4CCBB, 0x777CD376, 0x1ACBB2AD,
    0xC3F2BDB3, 0xCB71C930, 0x74ECEB7E, 0x77921ED2, 0x5DDB22C2, 0x606B4D73,
    0xB3AD7CCA, 0x11CFF0CA, 0x3DF47353, 0x4D759C77, 0x475AB4C3, 0x92A2CB43,
    0xF5EACB6C, 0x6AD34ACA, 0x6AD775ED, 0x1DDEEA43, 0xDDA74C37, 0x372F9AB5,
    0xECE321CC, 0x3EB1C670, 0x5CABB4DC, 0xB4357493, 0x5EC83CD6, 0x7CC674D7,
    0x59D326E8, 0xDCB21A8F, 0x334A8AB6, 0x74F389CE, 0xEC2E0ACA, 0x0D1DF736,
    0x0E86B69D, 0xCD7B435B, 0x30ACE365, 0xDFB4B30F, 0xCCF326FC, 0xED67B7AB,
    0xCDB33748, 0xD8ACF33E, 0xEFF6C2B5, 0x2B18CCC3, 0x3B8CC3EE, 0xCC2B1ECF,
    0xB6EC2B1C, 0xACAF5DD2, 0x7730AC72, 0xA870CCDF, 0x96FFB23D, 0x4DDABAB7,
    0x73BECA8E, 0x47A3CC26, 0xF7D35C93, 0x36899D32, 0x2CB31C37, 0xCCADF3CF,
    0x2DC6FE7D, 0xBB08D827, 0x9FD374AD, 0x1BECC3B6, 0x73435347, 0xF9ACA3B4,
    0x4343B532, 0x58535F12, 0x1243501A, 0xD4D24300, 0x5F14D4D1, 0x34B51CF3,
    0x268D8CCF, 0x7E97BBAB, 0xA59EE232, 0xF3B249BB, 0x66F25C9F, 0xB7323C8F,
    0xA3349B99, 0x3249FADB, 0x23218337, 0x0000017B, 0x99249A3F, 0x5C6AEF25,
    0xB35DF5DF, 0x000F63C9, 0x6737ADFF, 0x0271D1AC, 0x00000000, 0x01200000,
    0x00001200, 0x30000000, 0x50C43284, 0xCB50D4D3, 0x490C10D0, 0xE2C3150C,
    0x00049248, 0x92000048, 0x00000144, 0x00000000, 0xC4C34338, 0xA0266014,
    0xD0C51678, 0x48A73D3C, 0x8000002D, 0x2F4C3121, 0x000007DC, 0x00032000,
    0x00000000, 0x80043000, 0x00000004, 0x00000000, 0x00000000, 0xCDDDA748,
    0xEC865A70, 0xA9DAB34A, 0x9D4C374E, 0x0000007F, 0x00000000, 0x00000000,
    0x00000000, 0x20000000, 0x00000003, 0x00000000, 0x00000000, 0xB7D70C80,
    0xD77D74CD, 0x7802CDB7, 0xCD378CD7, 0xCD36CD36, 0x9D32CCB6, 0xD4D29A58,
    0x30172CA4, 0xC34CD34D, 0x6FCD87E1, 0x1347DD77, 0x05792530, 0x00000000,
    0x00000000, 0xE0000000, 0x1CD9F9A1, 0x00000000, 0x000AA000, 0x0E2A0000,
    0x00002800, 0x00000000, 0x0C132000, 0x0A121A01, 0x2D2C0000, 0x96530001,
    0x67B66E81, 0x63AB7ACB, 0x9DE2B59C, 0xD0CDBAB4, 0xBB0D1D1C, 0x7F70BD37,
    0xF6B75EC7, 0xAEAF5EDF, 0xAD3B7ADF, 0x3B7AD3B7, 0x30D24C31, 0xAD3B5D4D,
    0x34D0D3B7, 0x0CBB1D5D, 0xC7292D4D, 0xB4EDEB2E, 0xEDEB4EDE, 0xEB4EDEB4,
    0x5EDEB4ED, 0xCEB09CEB, 0xB09CEB09, 0x9CEB09CE, 0xEC6E6320, 0x00000007,
    0x23B92267, 0x2F0D4DF5, 0x0D753F0D, 0x2D9330D3, 0xF923353E, 0xC6F0C7D4,
    0x30D613F0, 0x59C9330D, 0xCD52C343, 0x4C7F4364, 0xB13F0C7F, 0x0CC3434C,
    0x0D726EC3, 0x3354753F, 0x2CCC34D9, 0xC34AD75D, 0xA3FC34CD, 0x259B0CB6,
    0x330C3B0D, 0x0C6B1D35, 0xD4C936D3, 0xA97A7BCE, 0x70D5CE08, 0xDB534D3B,
    0x0DFBB6D0, 0xC303213F, 0xF60AADB7, 0x7F0D2C19, 0x930DA5E8, 0xC329526F,
    0xAC37D77D, 0x9CC86A2D, 0xBFEFC35B, 0xDEB24C32, 0x2B5CD2F0, 0x7D8F70D7,
    0xCD4C36C3, 0xAC34C35D, 0x87720767, 0xC77A1C34, 0xAB90D0D0, 0x63FC82A8,
    0xAF30DB47, 0x62FC37A8, 0x730C335F, 0x432D1EC8, 0x0CFB536A, 0xD34D0D3F,
    0x4C833530, 0x37D0AEC3, 0x1753722C, 0x7477A4D3, 0xD0BC934D, 0x30772437,
    0xB0C3725C, 0xA0CD1899, 0x9B0D6CEF, 0x37D5CA84, 0x1E9AB26D, 0x8EAE5FC3,
    0x2393725C, 0x36CB1AE9, 0xB30D7B64, 0x437C37D9, 0x1BCF2236, 0x62F0DE73,
    0x06D70CAF, 0xB30CE2AB, 0x5E8E9AE3, 0xCBA8CD53, 0x00000012, 0x5DCCFFB3,
    0x3272CAA7, 0x434312DC, 0xF70CDE32, 0x9C9F32AD, 0x34DB4C71, 0xD7A29D34,
    0x0CCBB30E, 0xA8333D3F, 0xCB54F537, 0xDD76FD2D, 0xBD7B56B4, 0xCA6D7683,
    0x87B0D331, 0xA9F4DA4F, 0x0D24EC36, 0x36C3683F, 0x0D7A2D4C, 0x0FC32C8B,
    0xA9B0D2DA, 0xE5B5AC36, 0x39F4C493, 0x5EC32CC3, 0x92E6C87E, 0x351D0EE2,
    0xC32CC33D, 0x96493E1E, 0xEC36AC31, 0x6C30FC36, 0xB0DAA7D3, 0x94E78C87,
    0xB31D24EC, 0xF492735D, 0x0CCC72CC, 0xCEE02EC3, 0xC70D2D6C, 0x83349D0C,
    0x35B5359C, 0xC30EC34C, 0x1CD37CD6, 0x23C970D2, 0x2EF34FEB, 0xD7B0C7B5,
    0xDFF0D7B0, 0x3349F1D0, 0xC94760CC, 0xF249C31B, 0x8330DB56, 0x4C32EED5,
    0x7484713E, 0xDF64DF5D, 0xC2F5CD6C, 0x864B1F74, 0xC36CCF79, 0xD434D37E,
    0xFD0B0C7B, 0xAAC34D74, 0x6C74B357, 0x58EC3296, 0x37CECD7F, 0x74CCA6CB,
    0x872B57FF, 0x8CD7B7EC, 0x32DCD34D, 0xDA6AFAFC, 0xF330DFB7, 0xA29F270D,
    0xAA1C30E9, 0x7CD3B0CE, 0xED759873, 0xDD5DC330, 0x70D34D27, 0x4DB28C8E,
    0xE6CC34C3, 0x4D0AE3D9, 0xD36431C3, 0x925DE9F0, 0xC9F67E66, 0x7CD7309E,
    0xA1CFCD73, 0xCB1AA927, 0x1C3558AE, 0x6A6D79D3, 0xC7E330C6, 0x330CA2F4,
    0x0CD6335F, 0x8BF34C2F, 0x20DC735B, 0xC2F5330D, 0x1F8F0D34, 0xFD74B69D,
    0xDAF0DB25, 0xC934D333, 0x970C4D3E, 0xD7287AA4, 0xC30FC31A, 0x2CB1C662,
    0x9535CA3B, 0x96DAB23A, 0x5DEC3436, 0xEC3435D3, 0xD71ACC32, 0x213730C4,
    0x4D19C96D, 0xF289CB53, 0x437FEC34, 0x4D37CA9A, 0x77DFA6C3, 0x9F4D36DE,
    0x5DD4DB0C, 0x5ABC34B3, 0xD2B25B47, 0xD0D1D36A, 0x0B6D3F30, 0xDE324743,
    0x0CBB60B0, 0x2DAF0CB3, 0x87FAB207, 0xEAEEC735, 0xAC72FCB4, 0x34CFE7A8,
    0x7BAB982B, 0x709CCCC3, 0x8CC6B4DB, 0x4D70AD7E, 0xAAD35EC7, 0x6F2FBED6,
    0x727DF76C, 0xC734B5A9, 0xF3477CDA, 0xCB43474C, 0x1DFAA69C, 0xD31F8EF7,
    0xEFCD36FF, 0xC71DCC77, 0xB1BBEC8E, 0x00000177, 0x663B7CF7, 0xB7D62B7D,
    0xDBAF7D63, 0xF37D6F37, 0x7D6F37D6, 0x6F37D6F3, 0x37D6F37D, 0xD6F37D6F,
    0xB37D6F37, 0x7D6F37DF, 0x6A77D633, 0xB7D6337D, 0xD677D637, 0xF37DB677,
    0x7D66B7DF, 0x7D6EB7D7, 0x62B7D6B3, 0x6337D77D, 0x6B37D63E, 0xB7D677D6,
    0x7D6B7D63, 0x6AF7D6B3, 0xD6A7377D, 0x77D62EB7, 0x6737D62A, 0x7DFF37DB,
    0xDF2B7DBF, 0xB77D6A77, 0x7D6F37D6, 0x6737D6F7, 0xF7D6737D, 0xD6737D66,
    0xB7D6FB37, 0xD6337D6F, 0x677D66F7, 0x6B37D627, 0xF7D62B7D, 0x77DDAF2E,
    0x66F7DFE6, 0xB7D6FF7D, 0xB337D6B2, 0x00007D6A, 0x37477BB3, 0x4D309CF7,
    0xF0E97F3F, 0xDAEFD5CC, 0x7CCDDDF2, 0x9E6CFCAF, 0x88ACB58A, 0x0007734D,
    0x4870C2EB, 0xDDB1B99D, 0xD7BCDB7B, 0x0EEC718A, 0xBBCF0AC7, 0xB1B8ADF0,
    0xDF2BCAD2, 0x86ABA7EF, 0x8EDF5DB2, 0xB20DD735, 0x7334FD6B, 0xD6F336AD,
    0xA8376B6E, 0x4CAD36AA, 0x73575EDF, 0x339DF7EC, 0xB7DDAFC7, 0xB70AE9DD,
    0x0AD308CC, 0xC3B1ADC3, 0x6B9AD369, 0x39C70ED7, 0xACB2CCCF, 0xC37EADB5,
    0xDB74D734, 0xC36BCF7F, 0xCB2CCD5E, 0x77AD779C, 0x4CDC70DD, 0xC7B7EDDB,
    0x34DDF5EA, 0x8AC77DCD, 0xB2FDD2B5, 0xC318DAD2, 0x9DCCF5DB, 0x2ADCC2B3,
    0x58BD9CAB, 0x6B5E9CC7, 0x2B0D8ABC, 0xDCD2B6CD, 0xCDACCEB6, 0xF09BCCF5,
    0x6CCD3543, 0xFCC734B7, 0x0000B348, 0xEFFC97B3, 0xF722AC33, 0x5EB0D7BE,
    0x00000F7B, 0xE6EDA9B7, 0x2A08CF8A, 0xB0C89862, 0xE92088FD, 0xB9BA6C33,
    0x3DC8AA5F, 0x0DF2EE72, 0x36A4C867, 0x0003EBF8, 0x8FA2B9E7, 0xEDE81FAF,
    0x3B836E65, 0x84FCC8F2, 0x017E2A5E, 0x1FA7CC80, 0x0006AB80, 0x8261FE00,
    0x6D80198A, 0xA006DB80, 0xE730D200, 0xA0EE97A6, 0xA8A00007, 0x2B936A00,
    0x001248FA, 0xEDFC93EB, 0x3EE6E8A1, 0x8F249A1E, 0x00000002, 0xDDFC936B,
    0x0E930D26, 0x49A1E3EE, 0x000028F2, 0x0C1355FB, 0xB0CB0D33, 0xC8668C8B,
    0x7EB23C35, 0x76D2BE79, 0x64925B83, 0xD0DAB0DB, 0x4CCD0730, 0xCB659CD3,
    0x6F437B6C, 0x898FB1CD, 0xB2A4CC31, 0x83F27BC9, 0xDD9B258B, 0x34C93B23,
    0x247379AC, 0xCB4CC9F7, 0xDB3DCC36, 0xDA7322DA, 0xFC862733, 0xAC338CD6,
    0x5B19D51E, 0xEC30F9D3, 0x77FCC37A, 0xC76DADB4, 0x31FCC36E, 0x35FCB2FD,
    0x22CD77FC, 0x5DF0D237, 0x534D33DF, 0xBDF10CCB, 0xCC3534EA, 0xB0CF2A7D,
    0x434F4935, 0xD2D330D2, 0xCB314D37, 0x0FD6DBD4, 0x88AF87EA, 0xCD1C9C34,
    0x2BC93229, 0xCD36FDDB, 0xE579C35A, 0x9C8F70C2, 0xC37CCB30, 0x5FCD36FC,
    0xFEC37CC3, 0x1DA63360, 0x0DAA5A93, 0xF4D4B4D3, 0x1AAC3174, 0x4CC304D5,
    0x62EC32C3, 0x4EBC349A, 0x9F66EACD, 0x8E7B25EB, 0xC98FA38E, 0xF7259CF7,
    0x31D2331D, 0xEEF34C3B, 0xEB4DB72D, 0x0C7731C7, 0x74D7F34D, 0x4CF330DF,
    0xEB341C9B, 0x9B8B736D, 0x2434CCB0, 0x6B4FE9E7, 0x36ED0DCC, 0x22A6CCCB,
    0x7899BFB5, 0xDBB22EAD, 0x32D4AB35, 0xCEE77C7B, 0x2B30D372, 0xCD3330C6,
    0xDCA8F6B2, 0x36FDDCB7, 0xC32FCDEC, 0x2C23218A, 0xD34ADC9F, 0xBEAE638D,
    0xCB39FBC9, 0x00034AEF, 0x8FA4B8E7, 0xEDE85FAF, 0x6297F665, 0xC8F23B96,
    0x2A5E84FC, 0xCC80017E, 0xAB801FA7, 0xFE000006, 0x198A8261, 0x012A0E80,
    0x02801B6E, 0x266E7248, 0x007A3AE8, 0xA00A8A00, 0x8FA4B936, 0x00000122,
    0xD31FC8A7, 0x8BF20DEA, 0x4BFC34BF, 0x986FA3C3, 0x98633238, 0xDA3A62EB,
    0xEF7A333E, 0x7228FAD8, 0xBBA4EA9B, 0xFF30CB0C, 0x72734D6F, 0x07DB997A,
    0x8E3207B3, 0x323229A5, 0x76CDB34C, 0xBCCF311C, 0x26B0D721, 0x46B9EC92,
    0x734734B3, 0xA330C734, 0x73BF0DBA, 0x0C331ACA, 0x3F30CE73, 0x8DC35C9F,
    0xDCCF358C, 0xF249A82F, 0x002CEA2B, 0x1FD7C937, 0xA199A1D8, 0x325FEC8F,
    0xBE3734F2, 0x734E61C8, 0xB398B2B4, 0x72DA325C, 0x39249B0C, 0xFA130CFA,
    0x0DFB4C9C, 0xEB5E93B3, 0x1AFDB79C, 0xCD75B832, 0x32DF363D, 0x5CD331ED,
    0xB08ADFFB, 0x5EDB1FD6, 0xDF77FED3, 0xE736D32A, 0x7B9C9BBF, 0xD7C9A6B4,
    0xD628A81F, 0x9ABBB734, 0xA0E8FA0E, 0xE8FA0E8F, 0xB20E8FA0, 0x0000DB67,
    0x21A4866B, 0x34C982BF, 0xCEC33FCC, 0xC32A9325, 0x8A2323BE, 0x6D22A1BD,
    0x8F3A68A9, 0xF34E2E0D, 0x06ADB4D0, 0xD6D5C62A, 0xC63B4C70, 0x37DF7B30,
    0x4AEC8ABB, 0x777EC7AA, 0xB3C337C2, 0xD4D0CA2E, 0xB5C31330, 0xC32C9A05,
    0x34F90C5C, 0x534CB0CC, 0x7B474343, 0x71EC434C, 0x4ADB5DB2, 0x3CCD31D3,
    0x59C3B6ED, 0xC3B28CD7, 0xCCC2B30C, 0xD1BAD6B6, 0xDCDF6BD3, 0xDB75BED1,
    0x5FEDFF4D, 0x6B5DDFFF, 0xD319D70C, 0x7B39CD5E, 0x0C6776C6, 0xACD7AD77,
    0xB6AEDB33, 0x1C9B5CD3, 0x0C6A6CC3, 0x0DF370D7, 0x49DFB7DB, 0xC7B7C8B3,
    0xF27DBB2C, 0x19D335EC, 0x735F9CF3, 0xB75FDFEE, 0x731BDF2B, 0x0D334C27,
    0xCDD1F8C9, 0xFCD7358E, 0x9A7F4763, 0x0C730DA2, 0xC3F3C3E7, 0xB2CD533C,
    0xCECB73D8, 0x3CCCC34F, 0xAA996F2E, 0x9CF36D71, 0x61D34CDD, 0xACC96B63,
    0x6FD2F32B, 0x674CDAFB, 0xAD1D3F4C, 0x6DBB3C35, 0xDFF1ACBF, 0x1ACD3EA2,
    0x5FFC36AB, 0x5D2F4CEF, 0x3BB0D6CD, 0x2A6EDD9E, 0x370AEC82, 0x6CD2736D,
    0x34734C73, 0xB3ACA747, 0xCBB7BCFA, 0xCF6D371C, 0xADB5CC33, 0x31C3FB4E,
    0xCF36D6BB, 0x6F32CB32, 0x35C7B36C, 0x4CCF26D3, 0x77DF5BDB, 0x36EDF59D,
    0xADD7330D, 0xD36CDB34, 0xDCF3CB2C, 0xB6CDF1D6, 0xACF3CF3D, 0x0001BD0A,
    0x000E622B, 0x001E622B, 0xB23FC8FB, 0x3FD98FBE, 0x8F669C33, 0x00007EBF};
static const bbre_builtin_cc bbre_builtin_ccs_ascii[16] = {
    {5,  3, 0,  "alnum"     },
    {5,  2, 2,  "alpha"     },
    {5,  1, 4,  "ascii"     },
    {5,  2, 5,  "blank"     },
    {5,  2, 6,  "cntrl"     },
    {5,  1, 7,  "digit"     },
    {5,  1, 8,  "graph"     },
    {5,  1, 9,  "lower"     },
    {10, 3, 10, "perl_space"},
    {5,  1, 11, "print"     },
    {5,  4, 12, "punct"     },
    {5,  2, 15, "space"     },
    {5,  1, 16, "upper"     },
    {4,  4, 17, "word"      },
    {6,  3, 19, "xdigit"    },
    {0,  0, 0,  ""          }
};
static const bbre_builtin_cc bbre_builtin_ccs_unicode_property[30] = {
    {2, 2,   21,   "Cc"},
    {2, 21,  23,   "Cf"},
    {2, 6,   36,   "Co"},
    {2, 4,   41,   "Cs"},
    {2, 658, 44,   "Ll"},
    {2, 71,  139,  "Lm"},
    {2, 524, 174,  "Lo"},
    {2, 10,  400,  "Lt"},
    {2, 646, 404,  "Lu"},
    {2, 182, 492,  "Mc"},
    {2, 5,   559,  "Me"},
    {2, 346, 563,  "Mn"},
    {2, 64,  700,  "Nd"},
    {2, 12,  742,  "Nl"},
    {2, 72,  750,  "No"},
    {2, 6,   795,  "Pc"},
    {2, 19,  799,  "Pd"},
    {2, 76,  808,  "Pe"},
    {2, 10,  823,  "Pf"},
    {2, 11,  827,  "Pi"},
    {2, 187, 831,  "Po"},
    {2, 79,  914,  "Ps"},
    {2, 21,  930,  "Sc"},
    {2, 31,  942,  "Sk"},
    {2, 64,  957,  "Sm"},
    {2, 185, 984,  "So"},
    {2, 1,   1074, "Zl"},
    {2, 1,   1075, "Zp"},
    {2, 7,   1076, "Zs"},
    {0, 0,   0,    ""  }
};
static const bbre_builtin_cc bbre_builtin_ccs_perl[4] = {
    {1, 1, 7,  "d"},
    {1, 3, 10, "s"},
    {1, 4, 17, "w"},
    {0, 0, 0,  "" }
};

/*} Generated by `unicode_data.py gen_ccs impl` */

/* Read a single bit from the compressed bit stream. Update the pointer and the
 * bit index variables appropriately. */
static int bbre_builtin_cc_next_bit(const bbre_uint **p, bbre_uint *idx)
{
  bbre_uint out = ((**p) & ((bbre_uint)1 << (*idx)++));
  if (*idx == 32)
    *idx = 0, (*p)++;
  return (int)!!out;
}

static int bbre_builtin_cc_decode(
    bbre *r, const bbre_byte *name, size_t name_len, int invert,
    const bbre_builtin_cc *start)
{

  const bbre_builtin_cc *p = NULL, *found = NULL;
  const bbre_uint *read; /* pointer to compressed data */
  bbre_uint i, bit_idx, prev = BBRE_UTF_MAX + 1, accum = 0, res = BBRE_REF_NONE;
  bbre_uint max = 0, range[2];
  int err;
  /* Find the property with the matching name. */
  for (p = start; p->name_len; p++)
    if (p->name_len == name_len && !memcmp(p->name, name, name_len)) {
      found = p;
      break;
    }
  if (!found)
    return bbre_parse_err(r, "invalid Unicode property name");
  /* Start reading from the p->start offset in the compressed bit stream. */
  read = bbre_builtin_cc_data + p->start, bit_idx = 0;
  assert(p->num_range); /* there are always ranges in builtin charclasses */
  for (i = 0; i < p->num_range; i++) {
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
    {
      /* We now have decoded the low and high ordinals of the range, so
       * optionally invert it. */
      if (!invert) {
        if ((err = bbre_ast_make(
                 r, BBRE_AST_TYPE_CC, res, range[0], range[1], &res)))
          return err;
      } else {
        assert(range[0] >= max);
        if (max != range[0] &&
            (err = bbre_ast_make(
                 r, BBRE_AST_TYPE_CC, res, max, range[0] - 1, &res)))
          return err;
        else
          max = range[1] + 1;
      }
    }
  }
  assert(
      range[1] <
      BBRE_UTF_MAX); /* builtin charclasses never reach BBRE_UTF_MAX */
  assert(i);         /* builtin charclasses are not length zero */
  if (invert &&
      (err = bbre_ast_make(
           r, BBRE_AST_TYPE_CC, res, range[1] + 1, BBRE_UTF_MAX, &res)))
    return err;
  return bbre_buf_push(&r->alloc, &r->arg_stk, res);
}

static int bbre_builtin_cc_unicode_property(
    bbre *r, const bbre_byte *name, size_t name_len, int invert)
{
  return bbre_builtin_cc_decode(
      r, name, name_len, invert, bbre_builtin_ccs_unicode_property);
}

static int bbre_builtin_cc_ascii(
    bbre *r, const bbre_byte *name, size_t name_len, int invert)
{
  return bbre_builtin_cc_decode(
      r, name, name_len, invert, bbre_builtin_ccs_ascii);
}

static int bbre_builtin_cc_perl(
    bbre *r, const bbre_byte *name, size_t name_len, int invert)
{
  return bbre_builtin_cc_decode(
      r, name, name_len, invert, bbre_builtin_ccs_perl);
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

/* bbre.c - non-backtracking regular expression library */
/* Originally written by Max Nurzia, Jan-Dec 2024 */

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

/* Macro for declaring a buffer (see the tirade about dynamic arrays later in
 * this file). Serves mostly for readability. */
#define bbre_buf(T) T *

/* Enumeration of AST types. */
typedef enum bbre_ast_type {
  /* An epsilon node: /|/ */
  BBRE_AST_TYPE_EPS = 0,
  /* A single character: /a/ */
  BBRE_AST_TYPE_CHR,
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
  /* A builtin character class: /[[:digit:]]/
   *   Argument 0: starting index into the builtin_cc array
   *   Argument 1: number of character ranges to parse */
  BBRE_AST_TYPE_CC_BUILTIN,
  /* The set-inversion of a character class: /[^a]/
   *   Argument 0: child tree (AST) */
  BBRE_AST_TYPE_CC_NOT,
  /* The set-disjunction of a character class: /[az]/
   *   Argument 0: child tree A (AST)
   *   Argument 1: child tree B (AST) */
  BBRE_AST_TYPE_CC_OR,
  /* Matches any character: /./ */
  BBRE_AST_TYPE_ANYCHAR,
  /* Matches any byte: /\C/ */
  BBRE_AST_TYPE_ANYBYTE,
  /* Empty assertion: /\b/
   *   Argument 0: assertion flags, bitset of `bbre_assert_flag` (number) */
  BBRE_AST_TYPE_ASSERT
} bbre_ast_type;

/* Information needed by the parser about each AST node type. */
typedef struct bbre_ast_type_info {
  bbre_byte size;     /* Number of arguments */
  bbre_byte children; /* Number of children (last N nodes in arguments) */
  bbre_byte prec;     /* Node precedence in relation to enclosing nodes */
} bbre_ast_type_info;

/* Table of AST type information. */
static const bbre_ast_type_info bbre_ast_type_infos[] = {
    {0, 0, 0}, /* EPS */
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
    {0, 0, 0}, /* ANYCHAR */
    {0, 0, 0}, /* ANYBYTE */
    {1, 0, 0}, /* ASSERT */
};

/* Max number of arguments an AST node can contain. */
#define BBRE_AST_MAX_ARGS 4

/* Represents an inclusive range of bytes. */
typedef struct bbre_byte_range {
  bbre_byte l; /* min ordinal */
  bbre_byte h; /* max ordinal */
} bbre_byte_range;

/* Represents an inclusive range of runes. */
typedef struct bbre_rune_range {
  bbre_uint l; /* min ordinal */
  bbre_uint h; /* max ordinal */
} bbre_rune_range;

/* Enumeration of the various flags a group can set or clear. Note that some of
 * these flags are duplicates of `bbre_flags`, and some are not. I think it's a
 * good idea to keep the ABI flags separate from our internal flags. */
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
 * `head` and `tail`. */
/* When the compiler is evaluating a character class (resolving ands/ors/nots)
 * it uses head and tail to refer to offsets in the `bbre.cc_store` array--
 * `head` and `tail`, in this case, form the ends of a linked list containing
 * all of the character class components (rune ranges).*/
typedef struct bbre_compframe {
  bbre_uint root_hdl, /* handle to the AST node being compiled */
      child_hdl,      /* handle to the child AST node to be compiled next */
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
 * makes the compiled programs easy to reason about manually. */
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

/* Auxiliary data for tree nodes used for accelerating compilation of character
 * classes. */
typedef union bbre_compcc_tree_aux {
  bbre_uint hash, /* node hash, used for tree reduction */
      pc,     /* compiled location, nonzero if this node was compiled already */
      xposed; /* 1 if the node was transposed, 0 otherwise */
} bbre_compcc_tree_aux;

/* Tree node for the character class compiler. */
typedef struct bbre_compcc_tree {
  bbre_uint range,          /* range of bytes this node matches */
      child_hdl,            /* handle to concatenation node */
      sibling_hdl;          /* handle to alternation node */
  bbre_compcc_tree_aux aux; /* node hash OR cached PC */
} bbre_compcc_tree;

/* Element of a character class, used when compiling charclasses. */
typedef struct bbre_cc_elem {
  bbre_rune_range range; /* the rune range this describes */
  size_t next_hdl; /* handle to the next range in this list (0 to denote the end
        of the list) */
} bbre_cc_elem;

/* Internal storage used for the character class compiler. It uses enough state
 * that it definitely warrants its own struct. */
typedef struct bbre_compcc_data {
  bbre_buf(bbre_compcc_tree) tree;
  bbre_buf(bbre_compcc_tree) tree_2;
  bbre_buf(bbre_uint) hash;
  bbre_buf(bbre_cc_elem) store; /* character class storage */
  bbre_uint store_empty;        /* freelist for cc_store */
  size_t store_ops;             /* number of evaluation operations  */
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

/* Forward declaration */
typedef struct bbre_exec bbre_exec;

/* Used to hold reportable errors. */
typedef struct bbre_error {
  const char *msg; /* error message, if any */
  size_t pos;      /* position the error was encountered in expr */
} bbre_error;

/* The compiled form of a regular expression. */
typedef struct bbre_prog {
  bbre_alloc alloc;                     /* allocator function */
  bbre_buf(bbre_inst) insts;            /* The compiled instructions */
  bbre_buf(bbre_uint) set_idxs;         /* pattern index for each instruction */
  bbre_uint entry[BBRE_PROG_ENTRY_MAX]; /* entry points for the program */
  bbre_uint npat;                       /* number of distinct patterns */
  bbre_error *error;                    /* error info, we don't own this */
} bbre_prog;

/* Internal structure used to store a named group's name. */
typedef struct bbre_group_name {
  char *name;       /* The actual name (null-terminated) */
  size_t name_size; /* The size of the name (allocation is this + 1) */
} bbre_group_name;

/* A compiled regular expression. */
struct bbre {
  bbre_alloc alloc;                      /* allocator function */
  bbre_buf(bbre_uint) ast;               /* AST arena */
  bbre_uint ast_root_hdl;                /* AST root node reference */
  bbre_buf(bbre_group_name) group_names; /* Named group names */
  bbre_buf(bbre_uint) op_stk;            /* operator stack of node handles */
  bbre_buf(bbre_compframe) comp_stk;     /* compiler frame stack */
  bbre_compcc_data compcc; /* data used for the charclass compiler */
  bbre_prog prog;          /* NFA program */
  const bbre_byte *expr;   /* input parser expression (i.e. the regexp) */
  size_t expr_pos,         /* parser's current position in expr */
      expr_size;           /* number of *bytes* in expr */
  bbre_error error;        /* error message and/or pos within expr */
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

/* Arena-like data structure used for quickly storing nfa state sets.
 * Threads in the NFA need to hold on to their saved match offsets, but these
 * offsets rarely change. Instead of holding them directly within the thread,
 * the thread holds a handle from this arena, and the handle is copied around
 * within the NFA. When a thread needs to update a match offset, the NFA will
 * call bbre_save_slots_set(), which will update the backing array in this
 * function accordingly. The data structure is smart enough to handle reference
 * counting, so it will not allocate more slots until two or more threads need
 * to store different sets of match offsets. */
typedef struct bbre_save_slots {
  size_t *slots,   /* slot storage array */
      slots_size,  /* size in threads of `slots` */
      slots_alloc, /* allocation size in `size_t` of `slots` */
      last_empty,  /* freelist head within `slots` */
      per_thrd; /* number of slots within `slots` allocated to each thread (the
                  last slot is reserved for the reference count, so this is the
                  number of groups times two plus one) */
} bbre_save_slots;

/* Thread structure used within the NFA's Pike VM. */
typedef struct bbre_nfa_thrd {
  bbre_uint pc, /* program counter of the thread */
      slot_hdl; /* slot handle within the NFA's save_slots */
} bbre_nfa_thrd;

/* Sparse-set data structure used to accelerate the Pike VM. This data structure
 * is slightly different from the classical sparse-set data structure
 * (https://research.swtch.com/sparse), in that it can be used in sparse-set or
 * sparse-map mode, depending on the context, with different performance levels.
 * In this engine, I model threads as a <pc, saved> pair, and use those as the
 * key and value for this data structure respectively. The DFA does not concern
 * itself with saved match offsets, so it only considers a thread's program
 * counter, and thus uses this structure in sparse-set mode. The NFA, in
 * contrast, needs to consider match offsets, and it uses the slower sparse-map
 * mode. When the data structure is in sparse-set mode, the `dense_slot` array
 * remains empty. The data structure is robust, but could use some error
 * checking to ensure that sparse-set and sparse-map functions are not used
 * during the same generation of the structure. */
typedef struct bbre_sset {
  bbre_uint
      size; /* reserved maximum size of the arrays (tracks the program size) */
  bbre_uint dense_pc_size;        /* current size of `dense_pc` */
  bbre_uint dense_slot_size;      /* current size of `dense_slot` */
  bbre_buf(bbre_uint) sparse;     /* sparse array */
  bbre_buf(bbre_uint) dense_pc;   /* dense key array */
  bbre_buf(bbre_uint) dense_slot; /* dense value array */
} bbre_sset;

/* Pike VM-based NFA executor. This is a pretty run-of-the-mill implementation
 * of the algorithm, with the exception of the `pri_stk` and `pri_bmp_tmp`
 * members which are used to track pattern indices when matching a set of
 * patterns. */
typedef struct bbre_nfa {
  /* Thread frontier for epsilon execution */
  bbre_buf(bbre_nfa_thrd) thrd_stk;
  /* Match offset save slots for each thread */
  bbre_save_slots slots;
  /* Array of saved offsets for leftmost-longest tracking */
  bbre_buf(bbre_uint) pri_stk;
  /* Bitmap describing if each position in `pri_stk` is occupied */
  bbre_buf(bbre_uint) pri_bmp_tmp;
  /* Whether or not the NFA is being run in reverse mode */
  int reversed;
} bbre_nfa;

/* Maximum number of states the DFA can cache at once before incurring a cache
 * flush. */
#define BBRE_DFA_MAX_NUM_STATES 256

/* Flags that control how the DFA matches text. */
typedef enum bbre_dfa_match_flags {
  /* Run the DFA in reverse mode */
  BBRE_DFA_MATCH_FLAG_REVERSED = 1,
  /* Exit early when finding a match (just return boolean match) */
  BBRE_DFA_MATCH_FLAG_EXIT_EARLY = 2,
  /* Track sets of match pattern indices */
  BBRE_DFA_MATCH_FLAG_MANY = 4,
  /* Use accurate pattern priority tracking when running epsilon transitions,
   * this is only needed for certain types of matches */
  BBRE_DFA_MATCH_FLAG_PRI = 8
} bbre_dfa_match_flags;

/* Flags that apply to and disambiguate between individual states in the DFA. */
typedef enum bbre_dfa_state_flag {
  /* State was created from the beginning of text. */
  BBRE_DFA_STATE_FLAG_FROM_TEXT_BEGIN = 1,
  /* State was created from the beginning of a line. */
  BBRE_DFA_STATE_FLAG_FROM_LINE_BEGIN = 2,
  /* State was created after a word boundary. */
  BBRE_DFA_STATE_FLAG_FROM_WORD = 4,
  /* State has a previous match. */
  BBRE_DFA_STATE_FLAG_PRI = 8,
  /* State's memory can be reused. */
  BBRE_DFA_STATE_FLAG_DIRTY = 16,
  /* MAX is the same as DIRTY because the DIRTY flag is never stored on a state
   * normally. */
  BBRE_DFA_STATE_FLAG_MAX = 16
} bbre_dfa_state_flag;

/* Represents a DFA state. Keeps track of a transition for every possible input
 * byte, plus another transition for the end of text. Also remembers the NFA
 * states (PCs) of threads, and the set indices that the state matches. */
/* Currently, states have a flexible array immediately after them in memory that
 * holds `num_state` program counters immediately followed by `num_set` pattern
 * indices. The `alloc` member tracks the total size (sizeof(bbre_dfa_state) +
 * sizeof(bbre_uint) * (num_state + num_set)) */
typedef struct bbre_dfa_state {
  /* Transitions: These always point to other states within the same DFA cache.
   * The 257'th transition is the end of text transition. */
  struct bbre_dfa_state *ptrs[256 + 1];
  /* Allocation size of this state.  */
  bbre_uint alloc;
  /* Bitset of `bbre_dfa_state_flag` */
  bbre_uint flags;
  /* Number of NFA threads tracked by this state */
  bbre_uint num_state;
  /* Number of pattern indices tracked by this state */
  bbre_uint num_set;
} bbre_dfa_state;

/* Lazily-generated DFA execution context. Like the NFA, this is a fairly simple
 * and common implementation, with the somewhat less common ability to perform
 * multipattern matching. It uses a cache to keep track of common states. */
typedef struct bbre_dfa {
  /* Thread frontier for epsilon execution (similar to `bbre_nfa.thrd_stk`) */
  bbre_buf(bbre_uint) thrd_stk;
  /* The state cache */
  bbre_dfa_state **states;
  /* Number of slots in the cache */
  size_t states_size;
  /* Cache utilization */
  size_t num_active_states;
  /* Start states for every combination of state flag and entry point */
  bbre_dfa_state *entry[BBRE_PROG_ENTRY_MAX][BBRE_DFA_STATE_FLAG_MAX];
  /* Keeps track of which patterns have been matched throughout the text */
  bbre_buf(bbre_uint) set_bmp;
  /* Keeps track of which patterns that have been matched when constructing a
   * new state */
  bbre_buf(bbre_uint) set_buf;
} bbre_dfa;

/* Execution context that is shared between the NFA and DFA, and embedded in
 * both `bbre` and `bbre_set` structs. */
struct bbre_exec {
  /* Source thread set; the threads that resulted from the previous character */
  /* Also used to keep track of which threads were found when exploring epsilon
   * transitions */
  bbre_sset src;
  /* Destination thread set; the threads that resulted from exploring all
   * epsilon transitions in `src` */
  bbre_sset dst;
  /* Allocator callback */
  bbre_alloc alloc;
  /* NFA program */
  const bbre_prog *prog;
  /* NFA executor */
  bbre_nfa nfa;
  /* DFA executor */
  bbre_dfa dfa;
};

/* Helper macro for assertions. */
#define BBRE_IMPLIES(subject, predicate) (!(subject) || (predicate))

/* Set a generic error message. */
void bbre_error_set(bbre_error *err, const char *msg)
{
  err->msg = msg;
  err->pos = 0;
}

/* Initialize an error value. */
void bbre_error_init(bbre_error *err) { bbre_error_set(err, NULL); }

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

/* Call alloc->cb and get/free memory, given a `bbre_alloc` object. */
static void *
bbre_alloci(bbre_alloc *alloc, void *old_ptr, size_t old_size, size_t new_size)
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
/* One caveat to this approach is that it introduces weird alignment concerns.
 * You have to be sure that you correctly offset the size of the header from the
 * returned pointer; specifically you must ensure that the alignment of the
 * returned pointer is identical to that of malloc() (the largest alignment of
 * any built-in type, typically long double or size_t, but left
 * implementation-defined in C89)
 * This is one of the cases where this program delves into pseudo-undefined
 * behavior. The pointers used for each bbre_buf type are aligned to size_t,
 * which happens to be the largest-width type that this library will ever store
 * in them, *assuming that size_t is the same alignment (or greater) than a
 * pointer*. On all major ABIs, this is not an issue. */

/* Dynamic array header, stored before the data pointer in memory. */
typedef struct bbre_buf_hdr {
  size_t size, /* container size */ alloc; /* reserved capacity */
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
static int bbre_buf_resize_t(bbre_alloc *a, void **buf, size_t size)
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
#ifdef BBRE_COV
  /* For code coverage, be much lazier about our allocation policy -- this
   * ensures that almost every call to this function will allocate memory. For
   * testing, this is really valuable, and is the only case in the main
   * implementation of this library where we explicitly fuse off a part of the
   * code when we are checking coverage. */
  next_alloc = size < 128 ? size : next_alloc;
#endif
  while (next_alloc < size)
    next_alloc *= 2;
  next_ptr = bbre_alloci(
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
    bbre_alloci(a, hdr, sizeof(*hdr) + hdr->alloc, 0);
}

/* Increase size by `incr`. */
static int bbre_buf_grow_t(bbre_alloc *a, void **buf, size_t incr)
{
  assert(buf);
  return bbre_buf_resize_t(a, buf, bbre_buf_size_t(*buf) + incr);
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
  (bbre_buf_resize_t(r, (void **)(b), bbre_buf_esz(b) * (n)))

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

/* Make a byte range; more convenient than struct initialization in '89. */
static bbre_byte_range bbre_byte_range_make(bbre_byte l, bbre_byte h)
{
  bbre_byte_range out;
  out.l = l, out.h = h;
  return out;
}

/* Pack a byte range into a uint, low byte first. */
static bbre_uint bbre_byte_range_to_u32(bbre_byte_range br)
{
  return ((bbre_uint)br.l) | ((bbre_uint)br.h) << 8;
}

/* Unpack a byte range from a uint. */
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

/* Make a rune range. */
static bbre_rune_range bbre_rune_range_make(bbre_uint l, bbre_uint h)
{
  bbre_rune_range out;
  out.l = l, out.h = h;
  return out;
}

/* General purpose hashing function. This should probably be changed to
 * something a bit better, but works very well for this library.
 * Found by the intrepid Chris Wellons:
 * https://nullprogram.com/blog/2018/07/31/ */
static bbre_uint bbre_hash(bbre_uint x)
{
  x ^= x >> 16;
  x *= 0x7feb352dU;
  x ^= x >> 15;
  x *= 0x846ca68bU;
  x ^= x >> 16;
  return x;
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

/* These functions are defined near the automatically-generated parts of the
 * file (the end) for readability purposes. */
static bbre_uint
bbre_utf8_decode(bbre_uint *state, bbre_uint *codep, bbre_uint byte);
static int bbre_parse_check_well_formed_utf8(bbre *r);

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

/* Helper function to check the next character of input without advancing the
 * parser past it. */
static bbre_uint bbre_peek_next(bbre *r)
{
  size_t prev_pos = r->expr_pos;
  bbre_uint out = bbre_parse_next(r);
  r->expr_pos = prev_pos;
  return out;
}

/* Sentinel value to represent an infinite repetition. */
#define BBRE_INFTY (BBRE_LIMIT_REPETITION_COUNT + 1)

/* Make a new AST node within the regular expression. Variadic for convenience
 * when creating new nodes, which is done frequently in the parser. */
static int
bbre_ast_make(bbre *r, bbre_uint *out_node_hdl, bbre_ast_type type, ...)
{
  va_list in_args;
  bbre_uint args[6], arg_idx = 0, i = 0;
  int err = 0;
  va_start(in_args, type);
  if (!bbre_buf_size(r->ast))
    args[arg_idx++] = 0; /* sentinel */
  *out_node_hdl = bbre_buf_size(r->ast) + arg_idx;
  args[arg_idx++] = type;
  while (i < bbre_ast_type_infos[type].size)
    args[arg_idx++] = va_arg(in_args, bbre_uint), i++;
  assert(i == bbre_ast_type_infos[type].size);
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
static void bbre_ast_decompose(bbre *r, bbre_uint node_hdl, bbre_uint *out_args)
{
  bbre_uint *in_args = r->ast + node_hdl;
  bbre_uint i;
  for (i = 0; i < bbre_ast_type_infos[*in_args].size; i++)
    out_args[i] = in_args[i + 1];
}

/* Get the type of the given AST node. */
static bbre_uint *bbre_ast_type_ptr(bbre *r, bbre_uint node_hdl)
{
  assert(node_hdl != BBRE_NIL);
  return r->ast + node_hdl;
}

/* Get a pointer to the `n`'th parameter of the given AST node. */
static bbre_uint *bbre_ast_param_ptr(bbre *r, bbre_uint node_hdl, bbre_uint n)
{
  assert(bbre_ast_type_infos[*bbre_ast_type_ptr(r, node_hdl)].size > n);
  return r->ast + node_hdl + 1 + n;
}

/* Returns true if the given ast type is part of a character class subtree. */
static int bbre_ast_type_is_cc(bbre_ast_type ast_type)
{
  return (ast_type == BBRE_AST_TYPE_CC_LEAF) ||
         (ast_type == BBRE_AST_TYPE_CC_BUILTIN) ||
         (ast_type == BBRE_AST_TYPE_CC_NOT) ||
         (ast_type == BBRE_AST_TYPE_CC_OR);
}

/* Based on node precedence, pop nodes on the operator stack. This will pop
 * nodes until a node of equal or greater precedence is at the top. */
static bbre_uint bbre_ast_pop_prec(bbre *r, bbre_ast_type pop_type)
{
  bbre_uint popped_hdl = BBRE_NIL;
  assert(bbre_buf_size(r->op_stk));
  /* The top node is the cat node, it should always be popped. */
  popped_hdl = bbre_buf_pop(&r->op_stk);
  while (bbre_buf_size(r->op_stk)) {
    bbre_uint top_hdl = *bbre_buf_peek(&r->op_stk, 0);
    bbre_ast_type top_type = *bbre_ast_type_ptr(r, top_hdl);
    bbre_uint top_prec = bbre_ast_type_infos[top_type].prec,
              pop_prec = bbre_ast_type_infos[pop_type].prec;
    if (top_prec < pop_prec)
      popped_hdl = bbre_buf_pop(&r->op_stk);
    else
      break;
  }
  return popped_hdl;
}

/* Link the top node on the AST stack to the preceding node on the stack. */
static void bbre_ast_fix(bbre *r)
{
  bbre_uint top_hdl;
  assert(bbre_buf_size(r->op_stk) > 0);
  top_hdl = *bbre_buf_peek(&r->op_stk, 0);
  if (bbre_buf_size(r->op_stk) == 1)
    r->ast_root_hdl = top_hdl;
  else {
    bbre_uint parent_hdl = *bbre_buf_peek(&r->op_stk, 1);
    bbre_ast_type parent_type = *bbre_ast_type_ptr(r, parent_hdl);
    assert(bbre_ast_type_infos[parent_type].children > 0);
    *bbre_ast_param_ptr(
        r, parent_hdl, bbre_ast_type_infos[parent_type].children - 1) = top_hdl;
  }
}

/* Push an AST node to the operator stack, and fixup the furthest right child
 * pointer of the parent node. */
static int bbre_ast_push(bbre *r, bbre_uint node_hdl)
{
  int err = 0;
  if ((err = bbre_buf_push(&r->alloc, &r->op_stk, node_hdl)))
    goto error;
  bbre_ast_fix(r);
error:
  return err;
}

/* Create a CAT node on the top of the stack. */
static int bbre_ast_cat(bbre *r, bbre_uint right_child_hdl)
{
  int err = 0;
  bbre_uint *top;
  assert(bbre_buf_size(r->op_stk));
  top = bbre_buf_peek(&r->op_stk, 0);
  if (!*top) {
    *top = right_child_hdl;
    bbre_ast_fix(r);
  } else {
    if ((err = bbre_ast_make(r, top, BBRE_AST_TYPE_CAT, *top, right_child_hdl)))
      goto error;
    bbre_ast_fix(r);
    if ((err = bbre_ast_push(r, right_child_hdl)))
      goto error;
  }
error:
  return err;
}

/* Create a BBRE_AST_TYPE_CC_NOT node with the given character class. */
static int
bbre_ast_cls_invert(bbre *r, bbre_uint *out_node_hdl, bbre_uint child_hdl)
{
  assert(bbre_ast_type_is_cc(*bbre_ast_type_ptr(r, child_hdl)));
  return bbre_ast_make(r, out_node_hdl, BBRE_AST_TYPE_CC_NOT, child_hdl);
}

/* Helper function to add a character to the argument stack.
 * Returns `BBRE_ERR_MEM` if out of memory. */
static int bbre_parse_escape_addchr(
    bbre *r, bbre_uint ch, bbre_uint allowed_outputs, bbre_uint *out_node_hdl)
{
  int err = 0;
  (void)allowed_outputs, assert(allowed_outputs & (1 << BBRE_AST_TYPE_CHR));
  if ((err = bbre_ast_make(r, out_node_hdl, BBRE_AST_TYPE_CHR, ch)))
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
  return (ch >= '0' && ch <= '7') ? (int)(ch - '0') : -1;
}

/* These functions are automatically generated and are implemented later in this
 * file. For each type of builtin charclass, there is a function that allows us
 * to look up a charclass by name and create an AST node representing that
 * charclass.*/
static int bbre_builtin_cc_ascii(
    bbre *r, const bbre_byte *name, size_t name_len, bbre_uint *out_node_hdl);
static int bbre_builtin_cc_unicode_property(
    bbre *r, const bbre_byte *name, size_t name_len, bbre_uint *out_node_hdl);
static int bbre_builtin_cc_perl(
    bbre *r, const bbre_byte *name, size_t name_len, bbre_uint *out_node_hdl);

/* This function is called after receiving a \ character when parsing an
 * expression or character class. Since some escape sequences are forbidden
 * within different contexts (for example: charclasses), a bitmap
 * `allowed_outputs` encodes, at each bit position, the respective ast_type that
 * is allowed to be created in this context. */
static int
bbre_parse_escape(bbre *r, bbre_uint allowed_outputs, bbre_uint *out_node_hdl)
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
    err = bbre_parse_escape_addchr(r, ch, allowed_outputs, out_node_hdl);
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
    err = bbre_parse_escape_addchr(r, ord, allowed_outputs, out_node_hdl);
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
    return bbre_parse_escape_addchr(r, ord, allowed_outputs, out_node_hdl);
  } else if (ch == 'C') { /* any byte: \C */
    if (!(allowed_outputs & (1 << BBRE_AST_TYPE_ANYBYTE))) {
      err = bbre_err_parse(r, "cannot use \\C here");
      goto error;
    }
    if ((err = bbre_ast_make(r, out_node_hdl, BBRE_AST_TYPE_ANYBYTE)))
      goto error;
  } else if (ch == 'Q') { /* quote string */
    bbre_uint cat_hdl = BBRE_NIL /* accumulator for concatenations */,
              chr_hdl = BBRE_NIL /* generated chr node for each character in
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
          *out_node_hdl = cat_hdl;
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
      if ((err = bbre_ast_make(r, &chr_hdl, BBRE_AST_TYPE_CHR, ch)))
        goto error;
      /* create a cat node with the character and an epsilon node, replace the
       * old cat node (cat) with the new one (cat') through the &cat ref */
      if ((err =
               bbre_ast_make(r, &cat_hdl, BBRE_AST_TYPE_CAT, cat_hdl, chr_hdl)))
        goto error;
    }
    /* we got to the end of the string: push the partial quote */
    *out_node_hdl = cat_hdl;
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
    if ((err = bbre_builtin_cc_perl(r, &lower, 1, out_node_hdl)))
      goto error;
    if (inverted && (err = bbre_ast_cls_invert(r, out_node_hdl, *out_node_hdl)))
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
             r, r->expr + name_start_pos, name_end_pos - name_start_pos,
             out_node_hdl)))
      goto error;
    if (inverted && (err = bbre_ast_cls_invert(r, out_node_hdl, *out_node_hdl)))
      goto error;
  } else if (ch == 'A' || ch == 'z' || ch == 'B' || ch == 'b') {
    /* empty asserts */
    if (!(allowed_outputs & (1 << BBRE_AST_TYPE_ASSERT))) {
      err = bbre_err_parse(r, "cannot use an epsilon assertion here");
      goto error;
    }
    if ((err = bbre_ast_make(
             r, out_node_hdl, BBRE_AST_TYPE_ASSERT,
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
  /* ensure that we've obeyed the allowed_outputs flag */
  assert(BBRE_IMPLIES(
      !err,
      allowed_outputs &
          (*out_node_hdl ? (1 << *bbre_ast_type_ptr(r, *out_node_hdl)) : 1)));
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
  if ((err = bbre_parse_check_well_formed_utf8(r)))
    goto error;
  assert(!bbre_buf_size(r->op_stk));
  /* push the initial epsilon node */
  if ((err = bbre_ast_push(r, BBRE_NIL)))
    goto error;
  while (bbre_parse_has_more(r)) {
    bbre_uint ch = bbre_parse_next(r), res_hdl = BBRE_NIL;
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
               r, &res_hdl, greedy ? BBRE_AST_TYPE_QUANT : BBRE_AST_TYPE_UQUANT,
               *bbre_buf_peek(&r->op_stk, 0), min_rep, max_rep)))
        goto error;
      *bbre_buf_peek(&r->op_stk, 0) = res_hdl;
      bbre_ast_fix(r);
    } else if (ch == '|') {
      /* pop nodes from op stk until we get one of lower precedence */
      bbre_uint child_hdl = bbre_ast_pop_prec(r, BBRE_AST_TYPE_ALT);
      if ((err = bbre_ast_make(
               r, &res_hdl, BBRE_AST_TYPE_ALT, child_hdl /* left */,
               BBRE_NIL /* right */)))
        goto error;
      /* we just made space for this node in pop_prec() */
      err = bbre_ast_push(r, res_hdl);
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
                 r, &res_hdl, BBRE_AST_TYPE_GROUP, BBRE_NIL, hi_flags, lo_flags,
                 bbre_buf_size(r->group_names) + 1)))
          goto error;
      } else if ((err = bbre_ast_make(
                      r, &res_hdl, BBRE_AST_TYPE_IGROUP, BBRE_NIL, hi_flags,
                      lo_flags)))
        goto error;
      if ((err = bbre_ast_cat(r, res_hdl)) ||
          (err = bbre_ast_push(r, BBRE_NIL)))
        goto error;
      if (!inline_group && !(hi_flags & BBRE_GROUP_FLAG_NONCAPTURING)) {
        bbre_group_name name;
        name.name_size = name_end - name_start;
        name.name = NULL;
        if (named_group) {
          if (!(name.name =
                    bbre_alloci(&r->alloc, name.name, 0, name.name_size + 1))) {
            err = BBRE_ERR_MEM;
            goto error;
          }
          memcpy(name.name, r->expr + name_start, name.name_size);
          name.name[name.name_size] = '\0';
        }
        if ((err = bbre_buf_push(&r->alloc, &r->group_names, name))) {
          /* clean up allocated name, preserves atomicity */
          bbre_alloci(&r->alloc, name.name, name.name_size, 0);
          goto error;
        }
      }
      hi_flags &= ~(BBRE_GROUP_FLAG_NONCAPTURING);
    } else if (ch == ')') {
      /* pop the cat node */
      res_hdl = bbre_ast_pop_prec(r, BBRE_AST_TYPE_GROUP);
      if (!bbre_buf_size(r->op_stk)) {
        err = bbre_err_parse(r, "extra close parenthesis");
        goto error;
      }
    } else if (ch == '.') { /* any char */
      if ((err = bbre_ast_make(r, &res_hdl, BBRE_AST_TYPE_ANYCHAR)) ||
          (err = bbre_ast_cat(r, res_hdl)))
        goto error;
    } else if (ch == '[') {              /* charclass */
      size_t cc_start_pos = r->expr_pos; /* starting position of charclass */
      bbre_uint inverted = 0 /* is the charclass inverted? */,
                min /* min value of range */, max /* max value of range */;
      res_hdl = BBRE_NIL; /* resulting CC node */
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
                   (1 << BBRE_AST_TYPE_CHR) | (1 << BBRE_AST_TYPE_CC_BUILTIN) |
                       (1 << BBRE_AST_TYPE_CC_LEAF) |
                       (1 << BBRE_AST_TYPE_CC_NOT) | (1 << BBRE_AST_TYPE_CC_OR),
                   &next)))
            /* parse_escape() could return ERR_PARSE if for example \A */
            goto error;
          assert(
              *bbre_ast_type_ptr(r, next) == BBRE_AST_TYPE_CHR ||
              bbre_ast_type_is_cc(*bbre_ast_type_ptr(r, next)));
          if (*bbre_ast_type_ptr(r, next) == BBRE_AST_TYPE_CHR)
            min = *bbre_ast_param_ptr(r, next, 0); /* single-character escape */
          else {
            assert(bbre_ast_type_is_cc(*bbre_ast_type_ptr(r, next)));
            if (res_hdl &&
                (err = bbre_ast_make(
                     r, &res_hdl, BBRE_AST_TYPE_CC_OR, res_hdl, next)))
              goto error;
            else if (!res_hdl)
              res_hdl = next;
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
                   &res_hdl)))
            goto error;
          if (named_inverted &&
              (err = bbre_ast_cls_invert(r, &res_hdl, res_hdl)))
            goto error;
          /* ensure that builtin_cc_ascii returned a value */
          assert(
              res_hdl && bbre_ast_type_is_cc(*bbre_ast_type_ptr(r, res_hdl)));
          continue;
        }
        max = min;
        if (bbre_parse_has_more(r) && bbre_peek_next(r) == '-') {
          /* optional range expression */
          ch = bbre_parse_next(r);
          assert(ch == '-');
          if ((err = bbre_parse_next_or(
                   r, &ch,
                   "expected ']' or ending character after '-' for character "
                   "class "
                   "range expression")))
            goto error;
          if (ch == '\\') { /* start of escape */
            if ((err = bbre_parse_escape(r, (1 << BBRE_AST_TYPE_CHR), &next)))
              goto error;
            assert(*bbre_ast_type_ptr(r, next) == BBRE_AST_TYPE_CHR);
            max = *bbre_ast_param_ptr(r, next, 0);
          } else {
            max = ch; /* non-escaped character */
          }
        }
        {
          bbre_uint tmp_hdl;
          if ((err = bbre_ast_make(
                   r, &tmp_hdl, BBRE_AST_TYPE_CC_LEAF, min < max ? min : max,
                   min < max ? max : min)))
            goto error;
          if (res_hdl != BBRE_NIL) {
            if ((err = bbre_ast_make(
                     r, &res_hdl, BBRE_AST_TYPE_CC_OR, res_hdl, tmp_hdl)))
              goto error;
          } else
            res_hdl = tmp_hdl;
        }
      }
      assert(res_hdl); /* charclass cannot be empty */
      if (inverted &&
          ((err = bbre_ast_make(r, &res_hdl, BBRE_AST_TYPE_CC_NOT, res_hdl))))
        /* inverted character class */
        goto error;
      if ((err = bbre_ast_cat(r, res_hdl)))
        goto error;
    } else if (ch == '\\') { /* escape */
      if ((err = bbre_parse_escape(
               r,
               1 << 0 | 1 << BBRE_AST_TYPE_CHR | 1 << BBRE_AST_TYPE_CC_LEAF |
                   1 << BBRE_AST_TYPE_CC_BUILTIN | 1 << BBRE_AST_TYPE_CC_NOT |
                   1 << BBRE_AST_TYPE_CC_OR | 1 << BBRE_AST_TYPE_CAT |
                   1 << BBRE_AST_TYPE_ANYBYTE | 1 << BBRE_AST_TYPE_ASSERT,
               &res_hdl)) ||
          (err = bbre_ast_cat(r, res_hdl)))
        goto error;
    } else if (ch == '^' || ch == '$') { /* beginning/end of text/line */
      /* these are similar enough that I put them into one condition */
      if ((err = bbre_ast_make(
               r, &res_hdl, BBRE_AST_TYPE_ASSERT,
               ch == '^' ? BBRE_ASSERT_LINE_BEGIN : BBRE_ASSERT_LINE_END)) ||
          (err = bbre_ast_cat(r, res_hdl)))
        goto error;
    } else { /* char */
      if ((err = bbre_ast_make(r, &res_hdl, BBRE_AST_TYPE_CHR, ch)) ||
          (err = bbre_ast_cat(r, res_hdl)))
        goto error;
    }
  }
  (void)(bbre_buf_pop(&r->op_stk)); /* pop argument node */
  while (bbre_buf_size(r->op_stk)) {
    if (*bbre_ast_type_ptr(r, bbre_buf_pop(&r->op_stk)) ==
        BBRE_AST_TYPE_GROUP) {
      err = bbre_err_parse(r, "unmatched open parenthesis");
      goto error;
    }
  }
  /* wrap the top node into a nonmatching subexpression group to denote a
   * subpattern */
  if ((err = bbre_ast_make(
           r, &r->ast_root_hdl, BBRE_AST_TYPE_GROUP, r->ast_root_hdl,
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

/* Initialize a NFA program. */
static void bbre_prog_init(bbre_prog *prog, bbre_alloc alloc, bbre_error *error)
{
  prog->alloc = alloc;
  bbre_buf_init(&prog->insts), bbre_buf_init(&prog->set_idxs);
  memset(prog->entry, 0, sizeof(prog->entry));
  prog->npat = 0;
  prog->error = error;
}

/* Destroy a NFA program. */
static void bbre_prog_destroy(bbre_prog *prog)
{
  bbre_buf_destroy(&prog->alloc, &prog->insts),
      bbre_buf_destroy(&prog->alloc, &prog->set_idxs);
}

/* Helper function to clone a program's contents into a new program. */
static int bbre_prog_clone(bbre_prog *out, const bbre_prog *in)
{
  int err = 0;
  assert(bbre_buf_size(out->insts) == 0);
  if ((err = bbre_buf_reserve(
           &out->alloc, &out->insts, bbre_buf_size(in->insts))))
    goto error;
  memcpy(out->insts, in->insts, bbre_buf_size(in->insts) * sizeof(*in->insts));
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

/* Set the program instruction at `pc` to `i`. */
static void bbre_prog_set(bbre_prog *prog, bbre_uint pc, bbre_inst i)
{
  prog->insts[pc] = i;
}

/* Get the program instruction at `pc`. */
static bbre_inst bbre_prog_get(const bbre_prog *prog, bbre_uint pc)
{
  return prog->insts[pc];
}

/* Get the size (number of instructions) in the program. */
static bbre_uint bbre_prog_size(const bbre_prog *prog)
{
  return bbre_buf_size(prog->insts);
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
  if ((err = bbre_buf_push(&prog->alloc, &prog->insts, i)) ||
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

static int bbre_compile_ranges_append(
    bbre *r, bbre_compframe *frame, bbre_uint prev, bbre_rune_range range)
{
  int err = 0;
  bbre_cc_elem elem = {0};
  bbre_uint next = BBRE_NIL;
  assert(!!frame->head == !!frame->tail && !!frame->tail == !!prev);
  assert(BBRE_IMPLIES(frame->tail, !r->compcc.store[frame->tail].next_hdl));
  /* Get a new elem in cc_store. */
  if (!bbre_buf_size(r->compcc.store)) {
    /* Add the nil element. */
    if ((err = bbre_buf_push(&r->alloc, &r->compcc.store, elem)))
      goto error;
  }
  if (!r->compcc.store_empty) {
    /* Need to allocate a new element. */
    next = (bbre_uint)bbre_buf_size(r->compcc.store);
    if ((err = bbre_buf_push(&r->alloc, &r->compcc.store, elem)))
      goto error;
  } else {
    /* Can reuse a previous element. */
    next = r->compcc.store_empty;
    r->compcc.store_empty = r->compcc.store[r->compcc.store_empty].next_hdl;
  }
  elem.range = range;
  elem.next_hdl = BBRE_NIL;
  r->compcc.store[next] = elem;
  if (!prev)
    frame->head = next;
  if (!frame->tail) {
    frame->tail = next;
  } else {
    assert(!r->compcc.store[BBRE_NIL].next_hdl);
    r->compcc.store[next].next_hdl = r->compcc.store[prev].next_hdl;
    r->compcc.store[prev].next_hdl = !!prev * next;
    if (prev == frame->tail)
      frame->tail = next;
  }
error:
  return err;
}

static void bbre_compile_ranges_append_unwrapped(
    bbre *r, bbre_compframe *frame, bbre_uint prev, bbre_rune_range range)
{
  int err = bbre_compile_ranges_append(r, frame, prev, range);
  assert(!err);
  (void)(err); /* for when assert() is not defined */
}

static bbre_rune_range
bbre_compile_ranges_pop_front(bbre *r, bbre_compframe *frame)
{
  bbre_uint ref;
  assert(frame->head && frame->tail); /* list must contain elements */
  ref = frame->head, frame->head = r->compcc.store[frame->head].next_hdl;
  if (frame->head == BBRE_NIL)
    frame->tail = frame->head;
  r->compcc.store[ref].next_hdl = r->compcc.store_empty;
  r->compcc.store_empty = ref;
  return r->compcc.store[ref].range;
}

/* Link two nonempty lists. */
static void
bbre_compile_ranges_link(bbre *r, bbre_compframe *a, bbre_compframe *b)
{
  assert(a->head && a->tail && b->head && b->tail);
  r->compcc.store[a->tail].next_hdl = b->head;
  a->tail = b->tail;
}

/* An excellent algorithm by Simon Tatham, of PuTTY fame:
 * https://www.chiark.greenend.org.uk/~sgtatham/algorithms/listsort.c */
static void bbre_compile_ranges_normalize(bbre *r, bbre_compframe *frame)
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
        q = r->compcc.store[q].next_hdl;
      q_size = k;
      while (1) {
        bbre_uint elem, p_more = p_size > 0, q_more = q_size > 0 && q;
        if (!p_more && !q_more)
          break;
        if (!q_more || (p_more && r->compcc.store[p].range.l <=
                                      r->compcc.store[q].range.l))
          elem = p, p = r->compcc.store[p].next_hdl, p_size--;
        else
          elem = q, q = r->compcc.store[q].next_hdl, q_size--;
        if (!frame->tail)
          frame->head = elem;
        else
          r->compcc.store[frame->tail].next_hdl = elem;
        frame->tail = elem;
      }
      p = q;
    }
    r->compcc.store[frame->tail].next_hdl = BBRE_NIL;
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
      next = bbre_compile_ranges_pop_front(r, frame);
      if (!p++)
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
        bbre_compile_ranges_append_unwrapped(
            r, &new_frame, new_frame.tail, prev);
        prev = next;
      }
    }
    /* empty ranges (p=0) are elided at the top of the function */
    assert(p);
    bbre_compile_ranges_append_unwrapped(r, &new_frame, new_frame.tail, prev);
    *frame = new_frame;
  }
done:
  frame->flags = frame->flags & ~BBRE_GROUP_FLAG_CC_DENORM;
  return;
}

/* Helper function to casefold a character class being built in frame. */
static int bbre_compile_ranges_casefold(bbre *r, bbre_compframe *frame)
{
  int err = 0;
  bbre_compframe new_frame = *frame;
  new_frame.head = new_frame.tail = BBRE_NIL;
  while (frame->head) {
    bbre_rune_range next = bbre_compile_ranges_pop_front(r, frame);
    bbre_compile_ranges_append_unwrapped(r, &new_frame, new_frame.tail, next);
    if ((err = bbre_compcc_fold_range(r, next, &new_frame, new_frame.tail)))
      goto error;
  }
  bbre_compile_ranges_normalize(r, &new_frame);
  *frame = new_frame;
  frame->flags |= BBRE_GROUP_FLAG_CC_DENORM;
error:
  return err;
}

/* Create a new tree node.
 * `node` is the contents of the node itself, and `out_hdl` is the output node
 * ID (i.e. arena index) */
static int bbre_compcc_tree_new(
    bbre *r, bbre_buf(bbre_compcc_tree) * cc_out, bbre_compcc_tree node,
    bbre_uint *out_hdl)
{
  int err = 0;
  if (!bbre_buf_size(*cc_out)) {
    bbre_compcc_tree sentinel = {0};
    /* need to create sentinel node */
    if ((err = bbre_buf_push(&r->alloc, cc_out, sentinel)))
      goto error;
  }
  if (out_hdl)
    *out_hdl = bbre_buf_size(*cc_out);
  if ((err = bbre_buf_push(&r->alloc, cc_out, node)))
    goto error;
error:
  return err;
}

/* Append a byte range to an existing tree node.
 * `byte_range` is the packed range of bytes (returned from
 * bbre_byte_range_to_u32()), `parent_hdl` is the node ID of the parent node to
 * add to, and `out_hdl` is the output node ID. */
static int bbre_compcc_tree_append(
    bbre *r, bbre_buf(bbre_compcc_tree) * cc, bbre_uint byte_range,
    bbre_uint parent_hdl, bbre_uint *out_hdl)
{
  bbre_compcc_tree *parent_node, child_node = {0};
  bbre_uint child_hdl;
  int err;
  parent_node = (*cc) + parent_hdl;
  /* link new child node to its next sibling */
  child_node.sibling_hdl = parent_node->child_hdl,
  child_node.range = byte_range;
  /* actually add the child to the tree */
  if ((err = bbre_compcc_tree_new(r, cc, child_node, &child_hdl)))
    goto error;
  /* parent pointer may have changed, reload it */
  parent_node = (*cc) + parent_hdl;
  /* set parent's child to the new child */
  parent_node->child_hdl = child_hdl;
  /* enforce a cuppa invariants */
  assert(parent_node->child_hdl != parent_hdl);
  assert(parent_node->sibling_hdl != parent_hdl);
  assert(child_node.child_hdl != parent_node->child_hdl);
  assert(child_node.sibling_hdl != parent_node->child_hdl);
  *out_hdl = parent_node->child_hdl;
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
      bbre_uint child_hdl;
      /* check if previous child intersects and then compute intersection */
      assert(parent);
      parent_node = (*cc_out) + parent;
      if (parent_node->child_hdl &&
          bbre_uint_to_byte_range(brs[i]).l <=
              bbre_uint_to_byte_range(
                  ((*cc_out) + parent_node->child_hdl)->range)
                  .h) {
        child_hdl = parent_node->child_hdl;
      } else {
        if ((err = bbre_compcc_tree_append(
                 r, cc_out, brs[i], parent, &child_hdl)))
          goto error;
      }
      if ((err = bbre_compcc_tree_build_one(
               r, cc_out, child_hdl, mins[i], maxs[i], rest_bits - 6, 6)))
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
  bbre_uint root_hdl; /* tree root */
  bbre_uint in_hdl;
  bbre_compcc_tree root_node; /* the actual stored root node */
  int err = 0;
  root_node.child_hdl = root_node.sibling_hdl = root_node.aux.hash =
      root_node.range = 0;
  /* clear output charclass */
  bbre_buf_clear(cc_out);
  if ((err = bbre_compcc_tree_new(r, cc_out, root_node, &root_hdl)))
    goto error;
  for (in_hdl = frame_in->head, len_idx = 0; in_hdl && len_idx < 4;) {
    /* Loop until we're out of ranges and out of byte lengths */
    static const bbre_uint first_bits[4] = {7, 5, 4, 3};
    static const bbre_uint rest_bits[4] = {0, 6, 12, 18};
    /* What is the maximum codepoint that a UTF-8 sequence of length `len_idx`
     * can encode? */
    bbre_uint max_bound = (1 << (rest_bits[len_idx] + first_bits[len_idx])) - 1;
    bbre_rune_range rr = r->compcc.store[in_hdl].range;
    if (min_bound <= rr.h && rr.l <= max_bound) {
      /* [rr.l,rr.h] intersects [min_bound,max_bound] */
      /* clip it so that it lies within [min_bound,max_bound] */
      bbre_uint clamped_min = rr.l < min_bound ? min_bound : rr.l,
                clamped_max = rr.h > max_bound ? max_bound : rr.h;
      /* then build it */
      if ((err = bbre_compcc_tree_build_one(
               r, cc_out, root_hdl, clamped_min, clamped_max,
               rest_bits[len_idx], first_bits[len_idx])))
        goto error;
    }
    if (rr.h < max_bound)
      /* range is less than [min_bound,max_bound] */
      in_hdl = r->compcc.store[in_hdl].next_hdl;
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
    const bbre_buf(bbre_compcc_tree) cc_tree_in, bbre_uint a_hdl,
    bbre_uint b_hdl)
{
  int res = 0;
  /* Loop through children of `a` and `b` */
  while (a_hdl && b_hdl) {
    const bbre_compcc_tree *a = cc_tree_in + a_hdl, *b = cc_tree_in + b_hdl;
    if (!(res = bbre_compcc_tree_eq(cc_tree_in, a->child_hdl, b->child_hdl) &&
                a->range == b->range))
      goto done;
    a_hdl = a->sibling_hdl, b_hdl = b->sibling_hdl;
  }
  /* Ensure that both `a` and `b` have no remaining children. */
  assert(a_hdl == 0 || b_hdl == 0);
  res = a_hdl == b_hdl;
done:
  return res;
}

/* Merge two adjacent subtrees. */
static void bbre_compcc_tree_merge_one(
    bbre_buf(bbre_compcc_tree) cc_tree_in, bbre_uint child_hdl,
    bbre_uint sibling_hdl)
{
  bbre_compcc_tree *child = cc_tree_in + child_hdl,
                   *sibling = cc_tree_in + sibling_hdl;
  child->sibling_hdl = sibling->sibling_hdl;
  /* Adjacent subtrees can only be merged if their child trees are equal and if
   * their ranges are adjacent. */
  assert(
      bbre_byte_range_is_adjacent(
          bbre_uint_to_byte_range(child->range),
          bbre_uint_to_byte_range(sibling->range)) &&
      bbre_compcc_tree_eq(cc_tree_in, child->child_hdl, sibling->child_hdl));
  child->range = bbre_byte_range_to_u32(bbre_byte_range_make(
      bbre_uint_to_byte_range(child->range).l,
      bbre_uint_to_byte_range(sibling->range).h));
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
    bbre *r, bbre_buf(bbre_compcc_tree) cc_tree_in, bbre_uint parent_hdl)
{
  /* We also flip sibling -> sibling links backwards -- this reorders the byte
   * ranges into ascending order. */
  bbre_compcc_tree *parent_node = cc_tree_in + parent_hdl;
  bbre_uint child_hdl, next_child_hdl, sibling_hdl = 0;
  child_hdl = parent_node->child_hdl;
  while (child_hdl) {
    bbre_compcc_tree *child_node = cc_tree_in + child_hdl, *sibling_node;
    next_child_hdl = child_node->sibling_hdl;
    child_node->sibling_hdl = sibling_hdl;
    /* Recursively hash child nodes. */
    bbre_compcc_tree_hash(r, cc_tree_in, child_hdl);
    if (sibling_hdl) {
      /* Attempt to merge this node with its next sibling. */
      sibling_node = cc_tree_in + sibling_hdl;
      if (bbre_byte_range_is_adjacent(
              bbre_uint_to_byte_range(child_node->range),
              bbre_uint_to_byte_range(sibling_node->range))) {
        /* Since the input ranges are normalized, terminal nodes (nodes with no
         * concatenation) are NOT adjacent. */
        /* In other words, we guarantee that there are always gaps between
         * terminal bytes ranges within the tree. */
        assert(sibling_node->child_hdl && child_node->child_hdl);
        if (bbre_compcc_tree_eq(
                cc_tree_in, child_node->child_hdl, sibling_node->child_hdl))
          bbre_compcc_tree_merge_one(cc_tree_in, child_hdl, sibling_hdl);
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
      if (child_node->sibling_hdl)
        /* Derive our hash from the sibling node's hash, which was computed */
        hash_plain[1] = (cc_tree_in + child_node->sibling_hdl)->aux.hash;
      if (child_node->child_hdl)
        /* Derive our hash from our child node's hash, which was computed */
        hash_plain[2] = (cc_tree_in + child_node->child_hdl)->aux.hash;
      /* Compute and set our hash. */
      child_node->aux.hash = bbre_hash(
          bbre_hash(bbre_hash(hash_plain[0]) + hash_plain[1]) + hash_plain[2]);
    }
    /* Swap node --> sibling links for node <-- sibling. */
    sibling_hdl = child_hdl;
    child_hdl = next_child_hdl;
  }
  /* Finally, update the parent with its new child node, which was previously
   * its very last child node. */
  parent_node->child_hdl = sibling_hdl;
}

/* Reduce nodes in the tree (eliminate common suffixes) */
static void bbre_compcc_tree_reduce(
    bbre *r, bbre_buf(bbre_compcc_tree) cc_tree_in, bbre_buf(bbre_uint) cc_ht,
    bbre_uint node_hdl, bbre_uint *my_out_hdl)
{
  bbre_uint prev_sibling_hdl = 0;
  assert(node_hdl);
  assert(!*my_out_hdl);
  while (node_hdl) {
    bbre_compcc_tree *node = cc_tree_in + node_hdl;
    bbre_uint probe, found, child_hdl = 0;
    probe = node->aux.hash;
    node->aux.pc = 0;
    /* check if child is in the hash table */
    while (1) {
      if (!((found = cc_ht[probe % bbre_buf_size(cc_ht)]) & 1))
        /* child is NOT in the cache */
        break;
      else {
        /* something is in the cache, but it might not be a child */
        if (bbre_compcc_tree_eq(cc_tree_in, node_hdl, found >> 1)) {
          if (prev_sibling_hdl)
            /* link us to our new previous sibling, if any */
            cc_tree_in[prev_sibling_hdl].sibling_hdl = found >> 1;
          if (!*my_out_hdl)
            /* if this was the first node processed, return it */
            *my_out_hdl = found >> 1;
          goto done;
        }
      }
      probe += 1; /* linear probe */
    }
    /* this could be slow because of the mod operation-- might be a good idea to
     * use one of nullprogram's MST hash tables here */
    cc_ht[probe % bbre_buf_size(cc_ht)] = node_hdl << 1 | 1;
    if (!*my_out_hdl)
      /* if this was the first node processed, return it */
      *my_out_hdl = node_hdl;
    if (node->child_hdl) {
      /* reduce our child tree */
      bbre_compcc_tree_reduce(
          r, cc_tree_in, cc_ht, node->child_hdl, &child_hdl);
      node->child_hdl = child_hdl;
    }
    prev_sibling_hdl = node_hdl;
    node_hdl = node->sibling_hdl;
  }
done:
  assert(*my_out_hdl);
  return;
}

/* Convert our tree representation into actual NFA instructions.
 * `node_hdl` is the node to be rendered, `my_out_pc` is the PC of `node_hdl`'s
 * instructions, once they are compiled. `frame` allows us to keep track of
 * patch exit points. */
static int bbre_compcc_tree_render(
    bbre *r, bbre_buf(bbre_compcc_tree) cc_tree_in, bbre_uint node_hdl,
    bbre_uint *my_out_pc, bbre_compframe *frame)
{
  int err = 0;
  bbre_uint split_from_pc = 0 /* location of last compiled SPLIT instruction */,
            my_pc = 0 /* PC of the current node being compiled */,
            range_pc = 0 /* location of last compiled RANGE instruction */;
  while (node_hdl) {
    bbre_compcc_tree *node = cc_tree_in + node_hdl;
    if (node->aux.pc) {
      /* we've already compiled this node */
      if (split_from_pc) {
        /* instead of compiling the node again, just jump to it and return */
        bbre_inst i = bbre_prog_get(&r->prog, split_from_pc);
        i = bbre_inst_make(
            bbre_inst_opcode(i), bbre_inst_next(i), node->aux.pc);
        bbre_prog_set(&r->prog, split_from_pc, i);
      } else
        /* return the compiled instructions themselves if we haven't compiled
         * anything else yet */
        assert(!*my_out_pc), *my_out_pc = node->aux.pc;
      err = 0;
      goto error;
    }
    /* node wasn't found in the cache: we need to compile it */
    my_pc = bbre_prog_size(&r->prog);
    if (split_from_pc) {
      /* if there was a previous SPLIT instruction: link it to the upcoming
       * SPLIT/RANGE instruction */
      bbre_inst i = bbre_prog_get(&r->prog, split_from_pc);
      /* patch into it */
      i = bbre_inst_make(bbre_inst_opcode(i), bbre_inst_next(i), my_pc);
      bbre_prog_set(&r->prog, split_from_pc, i);
    }
    if (node->sibling_hdl) {
      /* there are more siblings (alternations) left, so we need a SPLIT
       * instruction */
      split_from_pc = my_pc;
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
    if (node->child_hdl) {
      /* node has children: need to down-compile */
      bbre_uint their_pc = 0;
      bbre_inst i = bbre_prog_get(&r->prog, range_pc);
      if ((err = bbre_compcc_tree_render(
               r, cc_tree_in, node->child_hdl, &their_pc, frame)))
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
    node_hdl = node->sibling_hdl;
  }
  assert(*my_out_pc);
error:
  return err;
}

/* Transpose the charclass compiler tree: reverse all concatenations. This is
 * used for generating the reverse program.
 * Takes the tree in `cc_tree_in`, and transposes it to `cc_tree_out`.
 * `node_hdl` is the node being reversed in `cc_tree_in`, while `root_hdl` is
 * the root node of `cc_tree_out`.
 * `cc_tree_out` starts out as a carbon copy of `cc_tree_in`. This function
 * reverses the concatenation edges in the graph, and ends up removing many of
 * the alternation edges in the graph. As such, `cc_tree_out` does not contain
 * the optimal DFA representing the reversed form of the charclass, but it
 * contains roughly the same number of instructions as the forward program, so
 * it is still compact. */
static void bbre_compcc_tree_xpose(
    bbre_buf(bbre_compcc_tree) cc_tree_in,
    bbre_buf(bbre_compcc_tree) cc_tree_out, bbre_uint node_hdl,
    bbre_uint root_hdl, bbre_uint is_root)
{
  bbre_compcc_tree *src_node = cc_tree_in + node_hdl;
  bbre_compcc_tree *dst_node = cc_tree_out + node_hdl, *parent_node;
  bbre_uint child_sibling_hdl = src_node->child_hdl;
  assert(node_hdl != BBRE_NIL);
  /* There needs to be enough space in the output tree. This space is
   * preallocated to simplify this function's error checking. */
  assert(bbre_buf_size(cc_tree_out) == bbre_buf_size(cc_tree_in));
  dst_node->sibling_hdl = dst_node->child_hdl = BBRE_NIL;
  dst_node->aux.pc = 0;
  if (!child_sibling_hdl) {
    parent_node = cc_tree_out + root_hdl;
    dst_node->sibling_hdl = parent_node->child_hdl;
    parent_node->child_hdl = node_hdl;
  }
  while (child_sibling_hdl) {
    bbre_compcc_tree *child_sibling_node = cc_tree_in + child_sibling_hdl;
    parent_node = cc_tree_out + child_sibling_hdl;
    bbre_compcc_tree_xpose(
        cc_tree_in, cc_tree_out, child_sibling_hdl, root_hdl, 0);
    if (!is_root) {
      assert(parent_node->child_hdl == BBRE_NIL);
      parent_node->child_hdl = node_hdl;
    }
    child_sibling_hdl = child_sibling_node->sibling_hdl;
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
  bbre_compile_ranges_normalize(r, frame);
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
    assert(frame->head == BBRE_NIL && frame->tail == BBRE_NIL);
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
    r->compcc.tree_2[1].child_hdl = BBRE_NIL;
    /* reverse all concatenation edges in the tree */
    bbre_compcc_tree_xpose(r->compcc.tree, r->compcc.tree_2, 1, 1, 1);
    tmp = r->compcc.tree;
    r->compcc.tree = r->compcc.tree_2;
    r->compcc.tree_2 = tmp;
  }
  /* reduce the tree */
  bbre_compcc_tree_reduce(
      r, r->compcc.tree, r->compcc.hash, r->compcc.tree[1].child_hdl,
      &start_pc);
  /* finally, generate the charclass' instructions */
  if ((err = bbre_compcc_tree_render(
           r, r->compcc.tree, r->compcc.tree[1].child_hdl, &start_pc, frame)))
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
            &r->alloc, &r->prog.insts,
            bbre_inst_make(BBRE_OPCODE_RANGE, 0, 0))) ||
       (err = bbre_buf_push(&r->alloc, &r->prog.set_idxs, 0))))
    goto error;
  assert(bbre_prog_size(&r->prog) > 0);
  /* create the frame for the root node */
  initial_frame.root_hdl = ast_root;
  initial_frame.child_hdl = initial_frame.head = initial_frame.tail = BBRE_NIL;
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
    /* we tell the compiler to visit a child by setting `frame.child_hdl` to
     * some value other than `frame.root_hdl`. By default, we set it to
     * `frame.root_hdl` to disable visiting a child. */
    frame.child_hdl = frame.root_hdl;

    child_frame.child_hdl = child_frame.root_hdl = child_frame.head =
        child_frame.tail = BBRE_NIL;
    child_frame.idx = child_frame.pc = 0;
    type = frame.root_hdl ? *bbre_ast_type_ptr(r, frame.root_hdl)
                          : 0 /* 0 for epsilon */;
    if (frame.root_hdl)
      bbre_ast_decompose(r, frame.root_hdl, args);
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
        if ((err = bbre_compile_ranges_append(
                 r, &frame, frame.tail,
                 bbre_rune_range_make(args[0], args[0]))))
          goto error;
        if ((frame.flags & BBRE_GROUP_FLAG_INSENSITIVE) &&
            (err = bbre_compile_ranges_casefold(r, &frame)))
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
        if ((err = bbre_compile_ranges_append(
                 r, &frame, frame.tail, bbre_rune_range_make(0, BBRE_UTF_MAX))))
          goto error;
      } else {
        if ((err = bbre_compile_ranges_append(
                 r, &frame, frame.tail, bbre_rune_range_make(0, '\n' - 1))))
          goto error;
        if ((err = bbre_compile_ranges_append(
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
        frame.child_hdl = args[reverse]; /* push left child */
        bbre_patch_xfer(&child_frame, &frame);
        frame.idx++;
      } else if (frame.idx == 1) {        /* after left child */
        frame.child_hdl = args[!reverse]; /* push right child */
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
        frame.child_hdl = args[0], frame.idx++;
      } else if (frame.idx == 1) { /* after left child */
        bbre_patch_merge(r, &frame, &returned_frame);
        bbre_patch_add(r, &child_frame, frame.pc, 1);
        frame.child_hdl = args[1], frame.idx++;
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
        frame.child_hdl = child;
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
          frame.child_hdl = child;
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
                 &r->prog,
                 bbre_inst_make(
                     BBRE_OPCODE_SPLIT, is_greedy ? frame.pc : 0,
                     is_greedy ? 0 : frame.pc),
                 frame.set_idx)))
          goto error;
        bbre_patch_add(r, &frame, my_pc, is_greedy);
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
      if (frame.child_hdl == child) {
        if (returned_frame.root_hdl != child) {
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
          next_returned_frame.root_hdl = child;
          returned_frame = next_returned_frame;
          frame.child_hdl = frame.root_hdl;
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
        frame.child_hdl = child, frame.idx++;
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
      bbre_uint cc_root;
      /* In the current implementation, the first element on the stack is always
       * a group node, so we don't need a bounds check here. In the future, if
       * this changes, this assert will fail. */
      assert(bbre_buf_size(r->comp_stk) > 1);
      cc_root = !bbre_ast_type_is_cc(
          *bbre_ast_type_ptr(r, bbre_buf_peek(&r->comp_stk, 1)->root_hdl));
      if (cc_root && !frame.idx) {
        assert(!(frame.flags & BBRE_GROUP_FLAG_CC_DENORM));
        /* Free up head/tail members in frame for our use. */
        bbre_patch_apply(r, &frame, my_pc);
      }
      if (type == BBRE_AST_TYPE_CC_LEAF) {
        /* Leaf: create an array of length 1 containing the character class. */
        if ((err = bbre_compile_ranges_append(
                 r, &frame, frame.tail,
                 bbre_rune_range_make(args[0], args[1]))) ||
            ((frame.flags & BBRE_GROUP_FLAG_INSENSITIVE) &&
             (err = bbre_compile_ranges_casefold(r, &frame))))
          goto error;
      } else if (type == BBRE_AST_TYPE_CC_BUILTIN) {
        /* Builtins: read the character class from ROM. */
        if ((err = bbre_builtin_cc_decode(r, args[0], args[1], &frame)) ||
            ((frame.flags & BBRE_GROUP_FLAG_INSENSITIVE) &&
             (err = bbre_compile_ranges_casefold(r, &frame))))
          goto error;
      } else if (type == BBRE_AST_TYPE_CC_NOT) {
        /* Negation: evaluate child, then negate it. */
        if (frame.idx == 0) {
          frame.child_hdl = args[0]; /* push child */
          frame.idx++;
        } else {
          bbre_uint current = 0;
          assert(frame.idx == 1);
          /* in order to invert the charclass, it must be normalized */
          bbre_compile_ranges_normalize(r, &returned_frame);
          while (returned_frame.head) {
            bbre_rune_range next =
                bbre_compile_ranges_pop_front(r, &returned_frame);
            if (next.l > current) {
              bbre_compile_ranges_append_unwrapped(
                  r, &frame, frame.tail,
                  bbre_rune_range_make(current, next.l - 1));
            }
            current = next.h + 1;
          }
          if (current < BBRE_UTF_MAX &&
              (err = bbre_compile_ranges_append(
                   r, &frame, frame.tail,
                   bbre_rune_range_make(current, BBRE_UTF_MAX))))
            goto error;
          assert(!returned_frame.head && !returned_frame.tail);
        }
      } else {
        assert(type == BBRE_AST_TYPE_CC_OR);
        /* Conjunction: evaluate left and right children, then compose them
         * into a single character class. */
        if (frame.idx == 0) {
          frame.child_hdl = args[0]; /* push left child */
          frame.idx++;
        } else if (frame.idx == 1) {
          /* save left child's list in our frame */
          frame.head = returned_frame.head, frame.tail = returned_frame.tail;
          frame.child_hdl = args[1]; /* push right child */
          frame.idx++;
        } else {
          /* evaluate both children */
          assert(frame.idx == 2);
          bbre_compile_ranges_link(r, &frame, &returned_frame);
          frame.flags |= BBRE_GROUP_FLAG_CC_DENORM;
        }
      }
      if (frame.child_hdl == frame.root_hdl) {
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
      assert(!frame.root_hdl);
      assert(type == 0);
    }
    if (frame.child_hdl != frame.root_hdl) {
      /* should we push a child? */
      *bbre_buf_peek(&r->comp_stk, 0) = frame;
      child_frame.root_hdl = frame.child_hdl;
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

static int bbre_set_compile(bbre_set *set, const bbre **rs, size_t n);

int bbre_set_init_internal(bbre_set **pset, const bbre_alloc *palloc)
{
  int err = 0;
  bbre_set *set;
  bbre_alloc alloc = bbre_alloc_make(palloc);
  *pset = bbre_alloci(&alloc, NULL, 0, sizeof(bbre_set));
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

static int bbre_set_compile(bbre_set *set, const bbre **rs, size_t n)
{
  int err = 0;
  size_t i;
  bbre_uint prev_split = 0;
  /* add sentinel 0th instruction */
  if ((err = bbre_buf_push(
           &set->alloc, &set->prog.insts,
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
               bbre_inst_relocate(r->prog.insts[src_pc], src_pc, dst_pc),
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
  if ((err = bbre_buf_reserve(&exec->alloc, &s->dense_pc, next_size)))
    goto error;
  if ((err = bbre_buf_reserve(&exec->alloc, &s->dense_slot, next_size)))
    goto error;
  s->size = next_size, s->dense_pc_size = 0, s->dense_slot_size = 0;
error:
  return err;
}

static void bbre_sset_clear(bbre_sset *s)
{
  assert(s->dense_pc_size == s->dense_slot_size || s->dense_slot_size == 0);
  s->dense_pc_size = 0, s->dense_slot_size = 0;
}

static void bbre_sset_init(bbre_sset *s)
{
  bbre_buf_init(&s->sparse), bbre_buf_init(&s->dense_pc),
      bbre_buf_init(&s->dense_slot);
  s->size = s->dense_pc_size = s->dense_slot_size = 0;
}

static void bbre_sset_destroy(bbre_exec *exec, bbre_sset *s)
{
  bbre_buf_destroy(&exec->alloc, &s->sparse),
      bbre_buf_destroy(&exec->alloc, &s->dense_pc),
      bbre_buf_destroy(&exec->alloc, &s->dense_slot);
}

static int bbre_sset_is_memb(bbre_sset *s, bbre_uint pc)
{
  assert(pc < s->size);
  return s->sparse[pc] < s->dense_pc_size && s->dense_pc[s->sparse[pc]] == pc;
}

static void bbre_sset_add_internal(bbre_sset *s, bbre_uint pc)
{
  assert(pc < s->size);
  assert(s->dense_pc_size < s->size);
  assert(pc);
  assert(!bbre_sset_is_memb(s, pc));
  s->dense_pc[s->dense_pc_size] = pc;
  s->sparse[pc] = s->dense_pc_size++;
  return;
}

static void bbre_sset_add_k(bbre_sset *s, bbre_uint pc)
{
  bbre_sset_add_internal(s, pc);
  assert(s->dense_slot_size == 0);
}

static void bbre_sset_add_kv(bbre_sset *s, bbre_nfa_thrd spec)
{
  bbre_sset_add_internal(s, spec.pc);
  s->dense_slot[s->dense_slot_size++] = spec.slot_hdl;
  /* ensure we're only calling one of k()/kv() on each generation of the sset */
  assert(s->dense_pc_size == s->dense_slot_size);
  return;
}

static bbre_nfa_thrd bbre_sset_get_pair(bbre_sset *s, bbre_uint i)
{
  bbre_nfa_thrd thrd;
  thrd.pc = s->dense_pc[i], thrd.slot_hdl = s->dense_slot[i];
  return thrd;
}

static void bbre_save_slots_init(bbre_save_slots *s)
{
  s->slots = NULL;
  s->slots_size = s->slots_alloc = s->last_empty = s->per_thrd = 0;
}

static void bbre_save_slots_destroy(bbre_exec *exec, bbre_save_slots *s)
{
  bbre_alloci(&exec->alloc, s->slots, sizeof(size_t) * s->slots_alloc, 0);
}

static void bbre_save_slots_clear(bbre_save_slots *s, size_t per_thrd)
{
  s->slots_size = 0, s->last_empty = 0,
  s->per_thrd = per_thrd + 1 /* for refcnt */;
}

#define BBRE_UNSET_POSN (((size_t)0 - (size_t)1))

static size_t *bbre_save_slots_refcnt(bbre_save_slots *s, bbre_uint ref)
{
  return s->slots + (ref + 1) * s->per_thrd - 1;
}

static int
bbre_save_slots_new(bbre_exec *exec, bbre_save_slots *s, bbre_uint *next)
{
  bbre_uint i;
  int err = 0;
  assert(s->per_thrd);
  if (s->last_empty) {
    /* reclaim */
    *next = s->last_empty;
    s->last_empty = *bbre_save_slots_refcnt(s, *next);
  } else {
    if ((s->slots_size + 1) * (s->per_thrd + 1) > s->slots_alloc) {
      /* initial alloc / realloc */
      size_t new_alloc =
          (s->slots_alloc ? s->slots_alloc * 2 : 16) * s->per_thrd;
      size_t *new_slots = bbre_alloci(
          &exec->alloc, s->slots, s->slots_alloc * sizeof(size_t),
          new_alloc * sizeof(size_t));
      if (!new_slots) {
        err = BBRE_ERR_MEM;
        goto error;
      }
      s->slots = new_slots, s->slots_alloc = new_alloc;
    }
    *next = s->slots_size++;
    assert(s->slots_size * s->per_thrd <= s->slots_alloc);
  }
  for (i = 0; i < s->per_thrd - 1; i++)
    (s->slots + *next * s->per_thrd)[i] = BBRE_UNSET_POSN;
  *bbre_save_slots_refcnt(s, *next) = 1; /* initial refcount = 1 */
error:
  return err;
}

static bbre_uint bbre_save_slots_fork(bbre_save_slots *s, bbre_uint ref)
{
  assert(s->per_thrd);
  assert(*bbre_save_slots_refcnt(s, ref));
  (*bbre_save_slots_refcnt(s, ref))++;
  return ref;
}

static void bbre_save_slots_kill(bbre_save_slots *s, bbre_uint ref)
{
  assert(s->per_thrd);
  assert(*bbre_save_slots_refcnt(s, ref));
  if (!(--(*bbre_save_slots_refcnt(s, ref)))) {
    /* prepend to free list -- repurpose refcnt for this */
    *bbre_save_slots_refcnt(s, ref) = s->last_empty;
    s->last_empty = ref;
  }
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
  assert(*bbre_save_slots_refcnt(s, ref));
  if (v == s->slots[ref * s->per_thrd + idx]) {
    /* not changing anything */
  } else {
    if ((err = bbre_save_slots_new(exec, s, out)))
      goto error;
    bbre_save_slots_kill(s, ref); /* decrement refcount */
    assert(*bbre_save_slots_refcnt(s, *out) == 1);
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
  assert(s->per_thrd);
  return s->per_thrd - 1;
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
  bbre_buf_init(&n->thrd_stk);
  bbre_save_slots_init(&n->slots);
  bbre_buf_init(&n->pri_stk);
  bbre_buf_init(&n->pri_bmp_tmp);
  n->reversed = 0;
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

static void bbre_nfa_destroy(bbre_exec *exec, bbre_nfa *n)
{
  bbre_buf_destroy(&exec->alloc, &n->thrd_stk);
  bbre_save_slots_destroy(exec, &n->slots);
  bbre_buf_destroy(&exec->alloc, &n->pri_stk),
      bbre_buf_destroy(&exec->alloc, &n->pri_bmp_tmp);
}

static int
bbre_nfa_start(bbre_exec *exec, bbre_uint pc, bbre_uint noff, int reversed)
{
  bbre_nfa_thrd initial_thrd;
  bbre_uint i;
  int err = 0;
  if ((err = bbre_sset_reset(exec, &exec->src, bbre_prog_size(exec->prog))) ||
      (err = bbre_sset_reset(exec, &exec->dst, bbre_prog_size(exec->prog))))
    goto error;
  bbre_buf_clear(&exec->nfa.thrd_stk), bbre_buf_clear(&exec->nfa.pri_stk);
  bbre_save_slots_clear(&exec->nfa.slots, noff);
  initial_thrd.pc = pc;
  if ((err =
           bbre_save_slots_new(exec, &exec->nfa.slots, &initial_thrd.slot_hdl)))
    goto error;
  bbre_sset_add_kv(&exec->src, initial_thrd);
  for (i = 0; i < exec->prog->npat; i++)
    if ((err = bbre_buf_push(&exec->alloc, &exec->nfa.pri_stk, 0)))
      goto error;
  if ((err = bbre_bmp_init(
           exec->alloc, &exec->nfa.pri_bmp_tmp, exec->prog->npat)))
    goto error;
  exec->nfa.reversed = reversed;
error:
  return err;
}

static int bbre_nfa_eps(bbre_exec *exec, size_t pos, bbre_assert_flag ass)
{
  int err = 0;
  size_t i, j;
  bbre_sset_clear(&exec->dst);
  /* Reserve space for the threads, and then push them all in reverse, so that
   * the highest-priority threads (those at the beginning of the dense array)
   * are popped first from the stack. */
  if ((err = bbre_buf_reserve(
           &exec->alloc, &exec->nfa.thrd_stk, exec->src.dense_pc_size)))
    goto error;
  for (i = exec->src.dense_pc_size, j = 0; i > 0; j++)
    exec->nfa.thrd_stk[j] = bbre_sset_get_pair(&exec->src, --i);
  /* Clear the source set so that it can be used to track found instructions. */
  bbre_sset_clear(&exec->src);
  while (bbre_buf_size(exec->nfa.thrd_stk)) {
    bbre_nfa_thrd thrd = *bbre_buf_peek(&exec->nfa.thrd_stk, 0);
    bbre_inst op = bbre_prog_get(exec->prog, thrd.pc);
    assert(*bbre_save_slots_refcnt(&exec->nfa.slots, thrd.slot_hdl));
    assert(thrd.pc);
    if (bbre_sset_is_memb(&exec->src, thrd.pc)) {
      /* we already processed this thread */
      bbre_save_slots_kill(
          &exec->nfa.slots, bbre_buf_pop(&exec->nfa.thrd_stk).slot_hdl);
      continue;
    }
    bbre_sset_add_k(&exec->src, thrd.pc);
    switch (bbre_inst_opcode(bbre_prog_get(exec->prog, thrd.pc))) {
    case BBRE_OPCODE_MATCH: {
      bbre_uint idx = bbre_inst_match_param_idx(bbre_inst_param(op)) * 2 +
                      bbre_inst_match_param_end(bbre_inst_param(op));
      if (idx < bbre_save_slots_per_thrd(&exec->nfa.slots) &&
          (err = bbre_save_slots_set(
               exec, &exec->nfa.slots, thrd.slot_hdl, idx, pos,
               &thrd.slot_hdl)))
        goto error;
      if (bbre_inst_next(op)) {
        thrd.pc = bbre_inst_next(op);
        *bbre_buf_peek(&exec->nfa.thrd_stk, 0) = thrd;
        assert(BBRE_IMPLIES(
            bbre_inst_match_param_idx(bbre_inst_param(op)) == 0,
            !exec->nfa.pri_stk[exec->prog->set_idxs[thrd.pc] - 1]));
        break;
      }
    }
      /* fall through */
    case BBRE_OPCODE_RANGE:
      (void)(bbre_buf_pop(&exec->nfa.thrd_stk));
      assert(!bbre_sset_is_memb(&exec->dst, thrd.pc));
      bbre_sset_add_kv(&exec->dst, thrd); /* this is a range or final match */
      break;
    case BBRE_OPCODE_SPLIT: {
      bbre_nfa_thrd pri, sec;
      pri.pc = bbre_inst_next(op), pri.slot_hdl = thrd.slot_hdl;
      sec.pc = bbre_inst_param(op),
      sec.slot_hdl = bbre_save_slots_fork(&exec->nfa.slots, thrd.slot_hdl);
      /* In rare situations, the compiler will emit a SPLIT instruction with
       * one of its branch targets set to the address of the instruction
       * itself. I observed this happening after a fuzzington run that
       * produced a regexp with nested empty-width quantifiers: a{0,0}*.
       * The way that bbre works now, this is harmless. Preventing these
       * instructions from being emitted would add some complexity to the
       * program for no clear benefit. */
      /* assert(pri.pc != thrd.pc && sec.pc != thrd.pc); */
      *bbre_buf_peek(&exec->nfa.thrd_stk, 0) = sec;
      if ((err = bbre_buf_push(&exec->alloc, &exec->nfa.thrd_stk, pri)))
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
        *bbre_buf_peek(&exec->nfa.thrd_stk, 0) = thrd;
      } else {
        bbre_save_slots_kill(&exec->nfa.slots, thrd.slot_hdl);
        (void)bbre_buf_pop(&exec->nfa.thrd_stk);
      }
      break;
    }
    }
  }
  bbre_sset_clear(&exec->src);
error:
  return err;
}

static void bbre_nfa_match_end(bbre_exec *exec, bbre_nfa_thrd thrd)
{
  bbre_uint idx = exec->prog->set_idxs[thrd.pc];
  bbre_uint *memo = exec->nfa.pri_stk + idx - 1;
  assert(idx > 0);
  assert(idx - 1 < bbre_buf_size(exec->nfa.pri_stk));
  /* for now, it is only possible to call the NFA with more than one slot (the
   * engine will refuse to use it for matches with zero capturing groups) */
  assert(bbre_save_slots_per_thrd(&exec->nfa.slots) >= 2);
  if (*memo)
    bbre_save_slots_kill(&exec->nfa.slots, *memo);
  *memo = bbre_save_slots_fork(&exec->nfa.slots, thrd.slot_hdl);
}

static void bbre_nfa_chr(bbre_exec *exec, unsigned int ch)
{
  size_t i;
  bbre_bmp_clear(&exec->nfa.pri_bmp_tmp);
  for (i = 0; i < exec->dst.dense_pc_size; i++) {
    bbre_nfa_thrd thrd = bbre_sset_get_pair(&exec->dst, i);
    bbre_inst op = bbre_prog_get(exec->prog, thrd.pc);
    bbre_uint pri = bbre_bmp_get(
                  exec->nfa.pri_bmp_tmp, exec->prog->set_idxs[thrd.pc]),
              opcode = bbre_inst_opcode(op);
    assert(*bbre_save_slots_refcnt(&exec->nfa.slots, thrd.slot_hdl));
    assert(
        *bbre_save_slots_refcnt(&exec->nfa.slots, thrd.slot_hdl) <=
        bbre_prog_size(exec->prog));
    if (pri) {
      bbre_save_slots_kill(&exec->nfa.slots, thrd.slot_hdl);
      continue; /* priority exhaustion: disregard this thread */
    }
    assert(opcode == BBRE_OPCODE_RANGE || opcode == BBRE_OPCODE_MATCH);
    if (opcode == BBRE_OPCODE_RANGE) {
      bbre_byte_range br = bbre_uint_to_byte_range(bbre_inst_param(op));
      if (ch >= br.l && ch <= br.h) {
        thrd.pc = bbre_inst_next(op);
        bbre_sset_add_kv(&exec->src, thrd);
      } else
        bbre_save_slots_kill(&exec->nfa.slots, thrd.slot_hdl);
    } else /* if opcode == MATCH */ {
      assert(!bbre_inst_next(op));
      bbre_nfa_match_end(exec, thrd);
      /* don't kill the thread, it's held by pri_bmp */
      bbre_bmp_set(exec->nfa.pri_bmp_tmp, exec->prog->set_idxs[thrd.pc]);
    }
  }
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
    bbre_exec *exec, size_t pos, bbre_uint max_span, bbre_span *out_span,
    unsigned int *out_which_span, bbre_uint prev_ch)
{
  int err = 0;
  size_t j, sets = 0;
  bbre_uint slot;
  assert(out_span);
  if ((err = bbre_nfa_eps(
           exec, pos, bbre_make_assert_flag(prev_ch, BBRE_SENTINEL_CH))))
    goto error;
  bbre_nfa_chr(exec, 256);
  slot = exec->nfa.pri_stk[sets];
  for (j = 0; (j < max_span) && out_span; j++) {
    int span_good;
    out_span[j].begin = bbre_save_slots_get(&exec->nfa.slots, slot, j * 2);
    out_span[j].end = bbre_save_slots_get(&exec->nfa.slots, slot, j * 2 + 1);
    span_good =
        !(out_span[j].begin == BBRE_UNSET_POSN ||
          out_span[j].end == BBRE_UNSET_POSN);
    out_span[j].begin *= span_good, out_span[j].end *= span_good;
    if (out_which_span)
      out_which_span[j] = span_good;
    if (j == 0)
      err += span_good;
  }
error:
  return err;
}

static int
bbre_nfa_run(bbre_exec *exec, bbre_uint ch, size_t pos, bbre_uint prev_ch)
{
  int err;
  if ((err = bbre_nfa_eps(exec, pos, bbre_make_assert_flag(prev_ch, ch))))
    goto error;
  bbre_nfa_chr(exec, ch);
error:
  return err;
}

static void bbre_dfa_init(bbre_dfa *d)
{
  d->states = NULL;
  d->states_size = d->num_active_states = 0;
  memset(d->entry, 0, sizeof(d->entry));
  bbre_buf_init(&d->thrd_stk), bbre_buf_init(&d->set_buf),
      bbre_buf_init(&d->set_bmp);
}

static void bbre_dfa_destroy(bbre_exec *exec, bbre_dfa *d)
{
  size_t i;
  for (i = 0; i < d->states_size; i++)
    if (d->states[i])
      bbre_alloci(&exec->alloc, d->states[i], d->states[i]->alloc, 0);
  bbre_alloci(
      &exec->alloc, d->states, d->states_size * sizeof(bbre_dfa_state *), 0);
  bbre_buf_destroy(&exec->alloc, &d->thrd_stk),
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

static int bbre_dfa_table_cmp(
    bbre_uint size_a, bbre_uint *a, bbre_uint size_b, bbre_uint *b)
{
  return (size_a == size_b) ? memcmp(a, b, sizeof(*a) * size_a) : 1;
}

static int bbre_dfa_start(bbre_exec *exec, bbre_uint pc, int reversed)
{
  bbre_uint i;
  int err = 0;
  if ((err = bbre_sset_reset(exec, &exec->src, bbre_prog_size(exec->prog))) ||
      (err = bbre_sset_reset(exec, &exec->dst, bbre_prog_size(exec->prog))))
    goto error;
  bbre_buf_clear(&exec->dfa.thrd_stk);
  bbre_sset_add_k(&exec->src, pc);
  for (i = 0; i < exec->prog->npat; i++)
    if ((err = bbre_buf_push(&exec->alloc, &exec->nfa.pri_stk, 0)))
      goto error;
  if ((err = bbre_bmp_init(
           exec->alloc, &exec->nfa.pri_bmp_tmp, exec->prog->npat)))
    goto error;
  exec->nfa.reversed = reversed;
error:
  return err;
}

/* need: current state, but ALSO the previous state's matches */
static int bbre_dfa_construct(
    bbre_exec *exec, bbre_dfa *d, bbre_dfa_state *prev_state, unsigned int ch,
    bbre_uint prev_flag, bbre_dfa_state **out_next_state)
{
  size_t i;
  int err = 0;
  bbre_uint hash, table_pos, num_checked, *state_data, next_alloc;
  bbre_dfa_state *next_state;
  assert(!(prev_flag & BBRE_DFA_STATE_FLAG_DIRTY));
  /* check threads in n, and look them up in the dfa cache */
  hash = bbre_hash(prev_flag);
  hash = bbre_hash(hash + exec->src.dense_pc_size);
  hash = bbre_hash(hash + bbre_buf_size(d->set_buf));
  for (i = 0; i < exec->src.dense_pc_size; i++)
    hash = bbre_hash(hash + exec->src.dense_pc[i]);
  for (i = 0; i < bbre_buf_size(d->set_buf); i++)
    hash = bbre_hash(hash + d->set_buf[i]);
  if (!d->states_size) {
    /* need to allocate initial cache */
    bbre_dfa_state **next_cache = bbre_alloci(
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
    if (bbre_dfa_table_cmp(
            next_state->num_state, state_data, exec->src.dense_pc_size,
            exec->src.dense_pc))
      goto not_found;
    if (bbre_dfa_table_cmp(
            next_state->num_set, state_data + exec->src.dense_pc_size,
            bbre_buf_size(d->set_buf), d->set_buf))
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
      for (i = 0; i < d->states_size; i++) {
        assert(d->states[i]); /* if we're here, the cache is full, and thus all
                                 slots have a valid pointer in them */
        d->states[i]->flags |= BBRE_DFA_STATE_FLAG_DIRTY;
      }
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
      next_alloc = bbre_dfa_state_alloc(
          exec->src.dense_pc_size, bbre_buf_size(d->set_buf));
      if (prev_alloc < next_alloc) {
        next_state = bbre_alloci(
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
    next_state->num_state = exec->src.dense_pc_size;
    next_state->num_set = bbre_buf_size(d->set_buf);
    state_data = bbre_dfa_state_data(next_state);
    for (i = 0; i < exec->src.dense_pc_size; i++)
      state_data[i] = exec->src.dense_pc[i];
    for (i = 0; i < bbre_buf_size(d->set_buf); i++)
      state_data[exec->src.dense_pc_size + i] = d->set_buf[i];
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
    bbre_exec *exec, bbre_dfa *d, bbre_uint entry, bbre_uint prev_flag,
    bbre_dfa_state **out_next_state)
{
  int err = 0;
  /* clear the set buffer so that it can be used to compare dfa states later */
  bbre_buf_clear(&d->set_buf);
  *out_next_state = d->entry[entry][prev_flag];
  assert(!*out_next_state);
  bbre_sset_clear(&exec->src);
  bbre_sset_add_k(&exec->src, exec->prog->entry[entry]);
  if ((err = bbre_dfa_construct(exec, d, NULL, 0, prev_flag, out_next_state)))
    goto error;
  d->entry[entry][prev_flag] = *out_next_state;
error:
  return err;
}

static int bbre_dfa_eps(bbre_exec *exec, bbre_assert_flag ass)
{
  int err = 0;
  size_t i, j;
  bbre_sset_clear(&exec->dst);
  if ((err = bbre_buf_reserve(
           &exec->alloc, &exec->dfa.thrd_stk, exec->src.dense_pc_size)))
    goto error;
  for (i = exec->src.dense_pc_size, j = 0; i > 0; j++)
    exec->dfa.thrd_stk[j] = exec->src.dense_pc[--i];
  bbre_sset_clear(&exec->src);
  while (bbre_buf_size(exec->dfa.thrd_stk)) {
    bbre_uint pc = *bbre_buf_peek(&exec->dfa.thrd_stk, 0);
    bbre_inst op = bbre_prog_get(exec->prog, pc);
    assert(pc);
    if (bbre_sset_is_memb(&exec->src, pc)) {
      (void)bbre_buf_pop(&exec->dfa.thrd_stk);
      continue;
    }
    bbre_sset_add_k(&exec->src, pc);
    switch (bbre_inst_opcode(bbre_prog_get(exec->prog, pc))) {
    case BBRE_OPCODE_MATCH: {
      if (bbre_inst_next(op)) {
        pc = bbre_inst_next(op);
        *bbre_buf_peek(&exec->dfa.thrd_stk, 0) = pc;
        break;
      }
    }
      /* fall through */
    case BBRE_OPCODE_RANGE:
      (void)bbre_buf_pop(&exec->dfa.thrd_stk);
      assert(!bbre_sset_is_memb(&exec->dst, pc));
      bbre_sset_add_k(&exec->dst, pc); /* this is a range or final match */
      break;
    case BBRE_OPCODE_SPLIT: {
      bbre_uint pri, sec;
      pri = bbre_inst_next(op), sec = bbre_inst_param(op);
      *bbre_buf_peek(&exec->dfa.thrd_stk, 0) = sec;
      if ((err = bbre_buf_push(&exec->alloc, &exec->dfa.thrd_stk, pri)))
        goto error;
      break;
    }
    default: /* ASSERT */ {
      assert(
          bbre_inst_opcode(bbre_prog_get(exec->prog, pc)) ==
          BBRE_OPCODE_ASSERT);
      assert(!!(ass & BBRE_ASSERT_WORD) ^ !!(ass & BBRE_ASSERT_NOT_WORD));
      if ((bbre_inst_param(op) & ass) == bbre_inst_param(op)) {
        pc = bbre_inst_next(op);
        *bbre_buf_peek(&exec->dfa.thrd_stk, 0) = pc;
      } else
        (void)bbre_buf_pop(&exec->dfa.thrd_stk);
      break;
    }
    }
  }
  bbre_sset_clear(&exec->src);
error:
  return err;
}

static int bbre_dfa_construct_chr(
    bbre_exec *exec, bbre_dfa *d, bbre_nfa *n, bbre_dfa_state *prev_state,
    unsigned int ch, bbre_dfa_state **out_next_state, int should_pri)
{
  int err;
  size_t i;
  /* clear the set buffer so that it can be used to compare dfa states later */
  bbre_buf_clear(&d->set_buf);
  /* we only care about `ch` if `prev_state != NULL`. we only care about
   * `prev_flag` if `prev_state == NULL` */
  /* import prev_state into n */
  bbre_sset_clear(&exec->src);
  for (i = 0; i < prev_state->num_state; i++)
    bbre_sset_add_k(&exec->src, bbre_dfa_state_data(prev_state)[i]);
  /* run eps on n */
  if ((err = bbre_dfa_eps(
           exec, bbre_make_assert_flag_raw(
                     prev_state->flags & BBRE_DFA_STATE_FLAG_FROM_TEXT_BEGIN,
                     prev_state->flags & BBRE_DFA_STATE_FLAG_FROM_LINE_BEGIN,
                     prev_state->flags & BBRE_DFA_STATE_FLAG_FROM_WORD, ch))))
    goto error;
  /* collect matches and match priorities into d->set_buf */
  bbre_bmp_clear(&n->pri_bmp_tmp);
  for (i = 0; i < exec->dst.dense_pc_size; i++) {
    bbre_uint pc = exec->dst.dense_pc[i];
    bbre_inst op = bbre_prog_get(exec->prog, pc);
    bbre_uint pri = bbre_bmp_get(n->pri_bmp_tmp, exec->prog->set_idxs[pc]),
              opcode = bbre_inst_opcode(op);
    if (pri && should_pri)
      continue;
    assert(opcode == BBRE_OPCODE_RANGE || opcode == BBRE_OPCODE_MATCH);
    if (opcode == BBRE_OPCODE_RANGE) {
      bbre_byte_range br = bbre_uint_to_byte_range(bbre_inst_param(op));
      if (ch >= br.l && ch <= br.h) {
        pc = bbre_inst_next(op);
        bbre_sset_add_k(&exec->src, pc);
      }
    } else /* if opcode == MATCH */ {
      assert(!bbre_inst_next(op));
      /* NOTE: since there only exists one match instruction for a set n, we
       * don't need to check if we've already pushed the match instruction. */
      if ((err = bbre_buf_push(
               &exec->alloc, &d->set_buf, exec->prog->set_idxs[pc] - 1)))
        goto error;
      bbre_bmp_set(n->pri_bmp_tmp, exec->prog->set_idxs[pc]);
    }
  }
  /* feed ch to n -> this was accomplished by the above code */
  if ((err = bbre_dfa_construct(
           exec, d, prev_state, ch,
           (ch == BBRE_SENTINEL_CH) * BBRE_DFA_STATE_FLAG_FROM_TEXT_BEGIN |
               (ch == BBRE_SENTINEL_CH || ch == '\n') *
                   BBRE_DFA_STATE_FLAG_FROM_LINE_BEGIN |
               (bbre_is_word_char(ch) ? BBRE_DFA_STATE_FLAG_FROM_WORD : 0) |
               (should_pri ? BBRE_DFA_STATE_FLAG_PRI : 0),
           out_next_state)))
    goto error;
error:
  return err;
}

static void bbre_dfa_save_matches(bbre_dfa *dfa, bbre_dfa_state *state)
{
  bbre_uint *start, *end;
  for (start = bbre_dfa_state_data(state) + state->num_state,
      end = start + state->num_set;
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
  int exit_early = !!(flags & BBRE_DFA_MATCH_FLAG_EXIT_EARLY);
  int many = !!(flags & BBRE_DFA_MATCH_FLAG_MANY);
  int pri = !!(flags & BBRE_DFA_MATCH_FLAG_PRI);
  bbre_uint entry =
      reversed ? BBRE_PROG_ENTRY_REVERSE : BBRE_PROG_ENTRY_DOTSTAR;
  bbre_uint prev_ch = reversed ? (pos == n ? BBRE_SENTINEL_CH : s[pos])
                               : (pos == 0 ? BBRE_SENTINEL_CH : s[pos - 1]);
  bbre_uint incoming_assert_flag =
      (prev_ch == BBRE_SENTINEL_CH) * BBRE_DFA_STATE_FLAG_FROM_TEXT_BEGIN |
      (prev_ch == BBRE_SENTINEL_CH || prev_ch == '\n') *
          BBRE_DFA_STATE_FLAG_FROM_LINE_BEGIN |
      (bbre_is_word_char(prev_ch) ? BBRE_DFA_STATE_FLAG_FROM_WORD : 0) |
      (pri ? BBRE_DFA_STATE_FLAG_PRI : 0);
  assert(BBRE_IMPLIES(!out_pos, exit_early));
  assert(BBRE_IMPLIES(exit_early, !many));
  if ((err = bbre_dfa_start(exec, exec->prog->entry[entry], reversed)))
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
             exec, &exec->dfa, entry, incoming_assert_flag, &state)))
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
        if (state->num_set) {
          err = 1;
          goto error;
        }
      } else {
        if (state->num_set)
          out = start;
        if (!state->num_state) {
          *out_pos = reversed ? out - end - increment : out - s - increment;
          goto done_success;
        }
        if (many)
          bbre_dfa_save_matches(&exec->dfa, state);
      }
      start += increment;
      if (!next) {
        if ((err = bbre_dfa_construct_chr(
                 exec, &exec->dfa, &exec->nfa, state, ch, &next, pri)))
          goto error;
      }
      state = next;
    }
    if (exit_early) {
      if (state->num_set) {
        err = 1;
        goto error;
      }
    } else {
      if (state->num_set)
        out = start;
      if (!state->num_state) {
        *out_pos = reversed ? out - end - increment : out - s - increment;
        goto done_success;
      }
      if (many)
        bbre_dfa_save_matches(&exec->dfa, state);
    }
  }
  if (!state->ptrs[BBRE_SENTINEL_CH]) {
    if ((err = bbre_dfa_construct_chr(
             exec, &exec->dfa, &exec->nfa, state, BBRE_SENTINEL_CH, &state,
             pri)))
      goto error;
  } else
    state = state->ptrs[BBRE_SENTINEL_CH];
  if (many)
    bbre_dfa_save_matches(&exec->dfa, state);
  if (out_pos && state->num_set)
    *out_pos = reversed ? 0 : n;
  assert(state);
  err = !!state->num_set;
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
  bbre_exec *exec = bbre_alloci(&alloc, NULL, 0, sizeof(bbre_exec));
  *pexec = exec;
  assert(bbre_prog_size(prog));
  if (!exec) {
    err = BBRE_ERR_MEM;
    goto error;
  }
  memset(exec, 0, sizeof(bbre_exec));
  exec->alloc = alloc;
  exec->prog = prog;
  bbre_sset_init(&exec->src), bbre_sset_init(&exec->dst);
  bbre_nfa_init(&exec->nfa);
  bbre_dfa_init(&exec->dfa);
error:
  return err;
}

static void bbre_exec_destroy(bbre_exec *exec)
{
  if (!exec)
    goto done;
  bbre_sset_destroy(exec, &exec->src), bbre_sset_destroy(exec, &exec->dst);
  bbre_nfa_destroy(exec, &exec->nfa);
  bbre_dfa_destroy(exec, &exec->dfa);
  bbre_alloci(&exec->alloc, exec, sizeof(bbre_exec), 0);
done:
  return;
}

static int bbre_compile(bbre *r)
{
  int err = 0;
  assert(!bbre_prog_size(&r->prog));
  if ((err = bbre_compile_internal(r, r->ast_root_hdl, 0)) ||
      (err = bbre_compile_internal(r, r->ast_root_hdl, 1))) {
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
        exec, (bbre_byte *)s, n, pos, NULL,
        BBRE_DFA_MATCH_FLAG_EXIT_EARLY | BBRE_DFA_MATCH_FLAG_PRI);
    goto error;
  } else if (max_span == 1) {
    err = bbre_dfa_match(
        exec, (bbre_byte *)s, n, pos, &out_span[0].end,
        BBRE_DFA_MATCH_FLAG_PRI);
    if (err <= 0)
      goto error;
    err = bbre_dfa_match(
        exec, (bbre_byte *)s, n, out_span[0].end, &out_span[0].begin,
        BBRE_DFA_MATCH_FLAG_REVERSED);
    if (err < 0)
      goto error;
    assert(
        err == 1 && out_span[0].begin != BBRE_UNSET_POSN &&
        out_span[0].end != BBRE_UNSET_POSN);
    if (which_spans)
      *which_spans = 1;
    err = 1;
    goto error;
  }
  if ((err = bbre_nfa_start(exec, exec->prog->entry[entry], max_span * 2, 0)))
    goto error;
  for (i = 0; i < n; i++) {
    if ((err = bbre_nfa_run(exec, ((const bbre_byte *)s)[i], i, prev_ch)))
      goto error;
    prev_ch = ((const bbre_byte *)s)[i];
  }
  if ((err = bbre_nfa_end(exec, n, max_span, out_span, which_spans, prev_ch)) <=
      0)
    goto error;
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
        BBRE_DFA_MATCH_FLAG_EXIT_EARLY | BBRE_DFA_STATE_FLAG_PRI);
  } else {
    bbre_uint i, j;
    size_t dummy;
    err = bbre_dfa_match(
        exec, (bbre_byte *)s, n, pos, &dummy,
        BBRE_DFA_MATCH_FLAG_MANY | BBRE_DFA_MATCH_FLAG_PRI);
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

/* API */

int bbre_builder_init(
    bbre_builder **pbuild, const char *s, size_t n, const bbre_alloc *palloc)
{
  int err = 0;
  bbre_builder *build;
  bbre_alloc alloc = bbre_alloc_make(palloc);
  build = bbre_alloci(&alloc, NULL, 0, sizeof(bbre_builder));
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
  bbre_alloci(&build->alloc, build, sizeof(bbre_builder), 0);
done:
  return;
}

void bbre_builder_flags(bbre_builder *build, bbre_flags flags)
{
  build->flags = flags;
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

/* Initialize a bare `bbre` (no regexp parsed yet) */
static int bbre_init_internal(bbre **pr, const bbre_alloc *palloc)
{
  int err = 0;
  bbre *r;
  bbre_alloc alloc = bbre_alloc_make(palloc);
  r = bbre_alloci(&alloc, NULL, 0, sizeof(bbre));
  *pr = r;
  if (!r) {
    err = BBRE_ERR_MEM;
    goto error;
  }
  r->alloc = alloc;
  bbre_buf_init(&r->ast);
  r->ast_root_hdl = 0;
  bbre_buf_init(&r->group_names), bbre_buf_init(&r->op_stk),
      bbre_buf_init(&r->comp_stk);
  r->compcc.store_empty = BBRE_NIL, r->compcc.store_ops = 0;
  bbre_buf_init(&r->compcc.store), bbre_buf_init(&r->compcc.tree),
      bbre_buf_init(&r->compcc.tree_2), bbre_buf_init(&r->compcc.hash);
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

void bbre_destroy(bbre *r)
{
  size_t i;
  if (!r)
    goto done;
  bbre_buf_destroy(&r->alloc, (void **)&r->ast);
  for (i = 0; i < bbre_buf_size(r->group_names); i++)
    bbre_alloci(
        &r->alloc, r->group_names[i].name, r->group_names[i].name_size, 0);
  bbre_buf_destroy(&r->alloc, &r->group_names);
  bbre_buf_destroy(&r->alloc, &r->op_stk),
      bbre_buf_destroy(&r->alloc, &r->comp_stk);
  bbre_buf_destroy(&r->alloc, &r->compcc.store),
      bbre_buf_destroy(&r->alloc, &r->compcc.tree),
      bbre_buf_destroy(&r->alloc, &r->compcc.tree_2),
      bbre_buf_destroy(&r->alloc, &r->compcc.hash);
  bbre_prog_destroy(&r->prog);
  bbre_exec_destroy(r->exec);
  bbre_alloci(&r->alloc, r, sizeof(*r), 0);
done:
  return;
}

const char *bbre_get_err_msg(const bbre *reg) { return reg->error.msg; }

size_t bbre_get_err_pos(const bbre *reg) { return reg->error.pos; }

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

int bbre_set_builder_init(bbre_set_builder **pspec, const bbre_alloc *palloc)
{
  int err = 0;
  bbre_set_builder *spec;
  bbre_alloc alloc = bbre_alloc_make(palloc);
  spec = bbre_alloci(&alloc, NULL, 0, sizeof(bbre_builder));
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

void bbre_set_builder_destroy(bbre_set_builder *spec)
{
  if (!spec)
    goto done;
  bbre_buf_destroy(&spec->alloc, &spec->pats);
  bbre_alloci(&spec->alloc, spec, sizeof(bbre_builder), 0);
done:
  return;
}

int bbre_set_builder_add(bbre_set_builder *set, const bbre *b)
{
  return bbre_buf_push(&set->alloc, &set->pats, b);
}

bbre_set *bbre_set_init_patterns(const char *const *pats_nt, size_t num_pats)
{
  int err = 0;
  size_t i;
  bbre_alloc a = bbre_alloc_make(NULL);
  bbre **regs = bbre_alloci(&a, NULL, 0, sizeof(bbre *) * num_pats);
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
    bbre_alloci(&a, regs, sizeof(bbre *) * num_pats, 0);
  }
  return set;
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

void bbre_set_destroy(bbre_set *set)
{
  if (!set)
    goto done;
  bbre_prog_destroy(&set->prog);
  if (set->exec)
    bbre_exec_destroy(set->exec);
  bbre_alloci(&set->alloc, set, sizeof(*set), 0);
done:
  return;
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

static const char *const bbre_version_str;

const char *bbre_version(void) { return bbre_version_str; }

/* Below is a UTF-8 decoder implemented as a compact DFA. This was heavily
 * inspired by Bjoern Hoehrmann's ubiquitous "Flexible and Economical UTF-8
 * Decoder" (https://bjoern.hoehrmann.de/utf-8/decoder/dfa/). I chose to write
 * a script that would generate this DFA for me, because it was fun. The first
 * table, bbre_utf8_dfa_class[], encodes equivalence classes for every byte.
 * This helps cut down on the amount of transitions in the DFA-- rather than
 * having 256 for each state, we only need the number of equivalence classes,
 * typically in the tens. The second table, bbre_utf8_dfa_trans[], encodes, for
 * each state, the next state for each equivalence class. This encoding allows
 * the DFA to be reasonably compact while still fairly fast. The third table,
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

/* Decode one byte of UTF-8 encoded text. */
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

/* Check that the input string is well-formed UTF-8. */
static int bbre_parse_check_well_formed_utf8(bbre *r)
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
                if ((err = bbre_compile_ranges_append(
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
 * This was the best compression scheme I could come up with. */

/*{ Generated by `unicode_data.py gen_ccs impl` */
/* 4313 ranges, 8626 integers, 6360 bytes */
/* Compression ratio: 2.71 */
static const bbre_uint bbre_builtin_cc_data[1590] = {
    0x7ACF7CF7, 0xADFF7AD7, 0x7F27AD77, 0x6BD16A7D, 0xB7CF71F6, 0xFB36ECDF,
    0x0D0DF7AD, 0xF667D92B, 0x998E6FD8, 0x9DB69D8E, 0xC9596FA6, 0xF3DDEB7F,
    0xAC6DEB3D, 0x6CF7CF77, 0xA6FB6D3B, 0xDB4CCCFF, 0xBB2B0DB7, 0xCD30ECFF,
    0x26B1ADB1, 0x18CCCFFF, 0x6D2CFFEB, 0xD5ED56CD, 0xCD7ACB37, 0xF337ED4D,
    0xEDF7B5DD, 0x78CD70D1, 0x333F32ED, 0xDF30BCDF, 0x5CCD30DD, 0x7E8F6BD3,
    0x4B7DCD73, 0x29DFC62B, 0xCD5FCC7B, 0xB537FEFD, 0x5F124343, 0x501A5853,
    0x43001243, 0xD4D1D4D2, 0x1CF35F14, 0x6BCF34B5, 0xA77D9AC3, 0xCD4DF74D,
    0xACB28BAF, 0xDAF3FED8, 0x3FEDCC72, 0xC772CB33, 0xB33EAEAC, 0x78989CD6,
    0xDBACEE33, 0xB4DBB3CE, 0x2F3FBDCD, 0x3FD9D37D, 0x4C34D753, 0x4CA475AB,
    0xD30D33D3, 0xCB4369F4, 0xFDCACEB4, 0x34B74F3F, 0xCCBB4CDB, 0x8FAC30DE,
    0x7DCC370E, 0xFFF8AD7B, 0x276DB333, 0xFFF560CD, 0xFCE6BFD9, 0x61A69D9F,
    0x6959FCF6, 0xF999FFE6, 0x19BEC66B, 0xA7DC456D, 0xF56456B9, 0xCD4567B9,
    0xA166979E, 0xCFB3ECD7, 0xD2B6A6DA, 0xE7FA96B6, 0xCC37FD82, 0xE8B67E7C,
    0xB4ECB6FF, 0xCDF4B0BC, 0x3FA3CAFD, 0xC823A334, 0xCD2772A3, 0xDFB26335,
    0x5CF3AB34, 0x962BEA3B, 0xCAD7B35E, 0x34AF3FE8, 0x3FF9ACDF, 0xDB30CC6F,
    0xCCD34DF4, 0x4DAB33EB, 0x4BDECCDB, 0xBF8AD733, 0xFDCD3B3D, 0x7FA723FF,
    0x7FEE89E9, 0x49BFFFF2, 0xF1BFFFF2, 0xA76DA767, 0x65A39A3B, 0x847C7D1D,
    0x5A658E33, 0xC1935E69, 0x4B0FE642, 0xD53F452E, 0x1534464D, 0xC1DD5861,
    0x24CE98D5, 0x719A7BF5, 0x48659D86, 0x9C390E75, 0x3926ADA9, 0x669A6631,
    0x6658668D, 0xF6158E68, 0x9AB4E7F9, 0x9E6876B6, 0xD566DA1B, 0x358661D8,
    0xFFDAF5E6, 0xF69A5E66, 0xFFF9CE6A, 0x6957B766, 0x9E675895, 0x97669B6B,
    0x869D9161, 0xFDAE6555, 0xBEC59A4E, 0x7999F6BF, 0xD6F591EE, 0xEFF739AC,
    0x6FFD3BAF, 0x35AB39BF, 0x54D7DBE3, 0xAE45973F, 0x1A57C6E1, 0xAD6FBE76,
    0x69A15A13, 0x9DAF6155, 0x98669DB6, 0xBFE18EC9, 0xE5A663A3, 0x65BB6A44,
    0x59BE6679, 0x4F65B95E, 0xDCF661DB, 0x6D6669B4, 0xDB7E979B, 0x633A66D7,
    0xE7996DFA, 0xB6DD9E1B, 0x958D765F, 0xB6695B66, 0x75866359, 0xA5599C56,
    0x9261A319, 0xA66A6986, 0x69A7FA38, 0xA9DA3ABA, 0xE8E525A9, 0xA4CE9A56,
    0x7959BEE9, 0xD99A4661, 0xE91D997E, 0x9A4E6DA6, 0x8E698E6D, 0x9994E8E6,
    0xD6F7B6D6, 0xA6E3986B, 0xB98679ED, 0x7E69D5B6, 0x659E6DAD, 0xD8DE6596,
    0xA66B8F66, 0xB6999E4D, 0x3AEFBEB7, 0x1A6DDBEB, 0x695BAE66, 0x59A6D9B6,
    0xADB9E796, 0x7B6D9BE3, 0x1559E79E, 0x6F8CE37A, 0xD1C45447, 0x3F9AF66B,
    0x9535B661, 0x8E3A5E6F, 0xE47FFDB9, 0xAFE61AFE, 0x2B2FFE61, 0xABCCFFFF,
    0x1DCD6737, 0x48ECB32D, 0x6CFFFA2B, 0x2C353713, 0x797F5592, 0x7FF984E6,
    0xCD699456, 0x9EF9BD99, 0x93664935, 0xFAF67391, 0xAF66FF13, 0x986B97DB,
    0xB7EFFF17, 0xFFC8AC13, 0xFE9D7333, 0x736CF333, 0xFCCDEB4C, 0x8FD7B7ED,
    0x9CADF7FF, 0xD24C73FE, 0x0D6ED0D5, 0x7C334CD3, 0xFCFFFB2B, 0xCFFF7BB4,
    0xB2CC70DC, 0x4D37CF3C, 0xACFFFEAB, 0xFAA2B6AC, 0xFE2B59CF, 0xE331ACFB,
    0x4D38CCFF, 0x74D311D3, 0x4FB4D34E, 0x34C474D3, 0x4D3BD1CD, 0xED308CD3,
    0xE737ACB5, 0xC331AD67, 0xD1D1D1D1, 0xF1D1D1D1, 0xD36D266F, 0x1C336D36,
    0x2EAFAB1D, 0xCD0D4D1C, 0x9CFAA331, 0xD0DD2196, 0x0DDF2F74, 0xDFE23353,
    0xFED61969, 0x776BD99F, 0x79A3BF5E, 0x65A1A3A6, 0x1D9ECE45, 0x99FF6656,
    0x5A61A6BA, 0x65A1A3AD, 0x6A61A67A, 0x3A638CB2, 0x9EEE6596, 0x0D29A6A9,
    0x63FA958A, 0xCCE6B9AE, 0x65A5E5AC, 0xF335665B, 0x9B69B56F, 0xE9B69B4E,
    0x7A63D80A, 0x6D9A39A5, 0xAA615ADA, 0xB191CCE7, 0x77D6CBF1, 0x9056399A,
    0x4667D91B, 0x9EAFF9BB, 0x868EB56A, 0x9AABE996, 0x99A699E4, 0x6DE5639E,
    0x53A1AD9F, 0xEF9EDA1A, 0xB6DABFFC, 0xA3AD5A61, 0x6261A1A1, 0xC5A986D9,
    0x59E67299, 0x6BD67F9F, 0x576D99D6, 0x9E1D07BB, 0xD1F9A6B9, 0xFFAFDCE6,
    0x3BAFFC6E, 0x9B6EEFFD, 0x135FBCE6, 0x986D986F, 0x566B9119, 0x66FDAF77,
    0x776BBDC4, 0xBFE7669B, 0x9ECDE6B9, 0x3B6E6679, 0xB7466937, 0x6E6693F5,
    0xF6466386, 0xF67FD19A, 0x6BB1F9AF, 0xB7661138, 0x198F6179, 0x3DDF8F61,
    0x51599761, 0xD9A4DED6, 0x59EED8D6, 0x58F6D37D, 0xB69B69B6, 0x7FD715A9,
    0xD9BEFACE, 0x159567D3, 0x68567DD3, 0xF9759638, 0xD876F8DE, 0xF335F9B6,
    0xA1896BD6, 0xFC476FA1, 0xD6AED59B, 0x3D384EFF, 0x13A3D256, 0x898AC3B5,
    0xCCF5AB3F, 0x9D7733FE, 0x368FC31A, 0xFBB24EC3, 0xCBB6334D, 0xD422331E,
    0xA59B1D2C, 0x5FD63B0C, 0x3B0DB233, 0x3E7F3ED2, 0x30CB734C, 0x5CC676E7,
    0x3F36CDF3, 0x23249E8F, 0x8FDEC93B, 0xC6B4DB76, 0x70AD7E8C, 0xD35EC74D,
    0xB4ADFA8E, 0xEDD8AD77, 0xAD71C2B3, 0xDAB3F9D8, 0xFD9ACD74, 0xDF4DB333,
    0xFC8CAC36, 0xE4CC2333, 0xAA599FE5, 0xA65AFA35, 0xE19E9AA7, 0xAFA69A1A,
    0x59BF5476, 0x9BEF6A6F, 0xA3BBE76B, 0x45CE6B59, 0x665BAFAE, 0x3A9A5647,
    0x7A7D321A, 0xE569AE49, 0x3A799FF7, 0xD669D967, 0xB2DB9FF4, 0xD4CFFE62,
    0x2ED55C70, 0x3CF7DB53, 0xC8A7FEEB, 0xDABF2E9D, 0xBB33FDEC, 0xFDF5DF4D,
    0x8CAD7B59, 0x775F33FF, 0xF3DACCAC, 0xFCFDF1C3, 0x5AD2C437, 0xC4B4C6B1,
    0xFF4D37D1, 0x77AD77AD, 0x1AC63C8F, 0x73FBD1ED, 0xBA3732CE, 0x73DD769C,
    0xCD2CC74C, 0xFEC23368, 0x21C82F75, 0xC72B2CDF, 0xC2A2E970, 0xECEBB739,
    0xCD26B7F5, 0xC75FCB69, 0xB37ACB10, 0x4377D9CD, 0xABF9D34F, 0xB4E8AC75,
    0x89DEB5DE, 0xF5E75B19, 0xB18DEDCC, 0xFDCDB5C7, 0x732D6F3F, 0x3FE9CD2C,
    0x36D3347B, 0xB4CCA6D3, 0xB9CFFEA2, 0x336AC331, 0xFFFFF35D, 0xAD7AD4CC,
    0xD31CD0D0, 0x0FCD276C, 0xDCF3AAB3, 0x99F6B7F5, 0xC9FBD6FD, 0x02BAB586,
    0x00000000, 0x00860000, 0x00002180, 0x90000000, 0x194909A0, 0x92694936,
    0x52486240, 0x4BA98690, 0x86000092, 0x09860000, 0x00000005, 0x80000000,
    0x34869263, 0x1DA51980, 0xA5140476, 0xA1397495, 0x00002961, 0x86924960,
    0x000AEE57, 0x06400000, 0x00000000, 0x00900000, 0x00000860, 0x00000000,
    0x00000000, 0x9CEFB000, 0x986E71BB, 0x3B6F7D9A, 0x7799E915, 0x9667FA6E,
    0x00B39BF6, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x0009E000,
    0x00000000, 0x00000000, 0xF9E00000, 0xEFAE99B6, 0xAE99B6FA, 0x9B66FAEF,
    0xAEFAEFAE, 0x94B8696F, 0x1A69BE1A, 0x1AA66BBE, 0x5865254E, 0x6934D174,
    0x0DCDA6F8, 0x4AEE5B5B, 0xA18D0219, 0x000000ED, 0x00000000, 0x00000000,
    0xD0786000, 0xC32D3B64, 0x000154CF, 0x00000000, 0x00000055, 0xA0007150,
    0x00000000, 0x80000000, 0x0D00242B, 0xC0000289, 0x0D000030, 0x4537400B,
    0x8E1B8DCE, 0xCEB999E7, 0xB663BFCF, 0xF586C565, 0x6B38E756, 0x75693BC5,
    0x3A39A199, 0x7944F61A, 0xBD8E7EE1, 0xBDBFED6E, 0xF5A75D5E, 0x6F9A3A76,
    0x9A76F5A7, 0x9D8668E2, 0xBD69DBD6, 0x69DBD69D, 0xDBD69DBD, 0xD69DBD69,
    0x9DBD69DB, 0x9D6DDA76, 0x69D69DB6, 0xB69D69DB, 0xDB69D69D, 0xF4B69D69,
    0xE95AFB5C, 0xD9DFCEDA, 0xF99ED66F, 0x5AE699B6, 0xC30C541E, 0xD4B3D2F7,
    0x18E4E1B4, 0x50647D36, 0x47353F54, 0x47F93575, 0x9DDD0DC6, 0x539916E4,
    0xED6DBE7C, 0x930E63FA, 0x4175994E, 0xB966F90E, 0x17D867DF, 0xC35F1FD4,
    0x1390E596, 0xF7A3D986, 0xA4F54B53, 0x9792E4ED, 0x87E61B74, 0x4753E667,
    0x7E19686E, 0x0654B50D, 0x618D4DB9, 0xB06699CE, 0x18ECB115, 0x3ADBF7F6,
    0xC5E5E7AF, 0x99E65698, 0x1321BFE5, 0x68EA6D91, 0x7E1711D8, 0x798E19DB,
    0xB1F6543B, 0xFFA3C836, 0x27CED369, 0xDB0ECBE7, 0x7D5EC774, 0x09CD0CA7,
    0xD4CC37A9, 0xEDBB1F24, 0xA2CCEB31, 0xAC6B3EDE, 0xCF3AD376, 0x6D5AC70C,
    0xCBF39C2B, 0xCE4A8B6B, 0xDB1CDF37, 0x6AD30D35, 0x22D3291D, 0xCD431C9F,
    0x6DE4CC35, 0xD6AD30DB, 0xB0D0D0D1, 0xCD2A94CF, 0x75AB54F7, 0x2A2CB434,
    0x23AC33C9, 0xD30D35CB, 0x2D0D1D6A, 0xCD435E8B, 0x52DB02A3, 0xB0C432D3,
    0x4CCB4B0C, 0x5576B96B, 0xA2D7346B, 0xEC349353, 0x1AD55DA5, 0x3E8B2D7D,
    0xC33CC343, 0xCE754F0A, 0xD7D19F24, 0xDF31DB7A, 0xD24F56B2, 0x0D5DD3F1,
    0x0CBF6DB3, 0x7C56B4B1, 0xCB48330D, 0xFE7ED33A, 0xCBB49D5C, 0xB0DCAF32,
    0x36DB7C9A, 0xB4F0CA2D, 0xBC9B32CD, 0x4D34E370, 0x39D34C47, 0x4D3ED34D,
    0x34D311D3, 0x4D34EF47, 0x7319C233, 0x37330BCD, 0xDEB4F34D, 0xD75C3331,
    0x2B1CDF33, 0x5CDF35CC, 0x2F3CD4B3, 0x9CA3279D, 0x32CF2BD0, 0xA33197ED,
    0x0BC7B4CD, 0x2CCB4DBB, 0xBDEB6D37, 0xAF0CC6B5, 0xAC777DAC, 0xDBB5BD70,
    0x374CC31C, 0x0DD274ED, 0xBCDBB4CD, 0x2C35B530, 0xF74D3E2A, 0xDEB5BCEF,
    0x1D1C331A, 0x1D1D1D1D, 0xE6331D1D, 0x6ACDA1B8, 0x66DEB31F, 0xB6ECD0DC,
    0xCDF75EC2, 0xB9C9FFF5, 0xF8D9FE5F, 0xF2B5AB5F, 0xD6728CC6, 0x736D3277,
    0x48CC34CD, 0x6B68CC2E, 0x1CA39C83, 0x7B1AD4D5, 0x7DD734BC, 0xC30B6D7F,
    0xB4CD3B2C, 0x3CBB0EC6, 0x4CB1DC77, 0xE74B4CCF, 0x6AD753AC, 0xCA2DB573,
    0xB4C3297D, 0x2C37A84C, 0x6D723C33, 0x336D36D3, 0xC2AB1D1C, 0xBDA87B09,
    0xB1ADB249, 0xA262B3DD, 0x9CD36DDD, 0x35F0A337, 0x0D0C4B4B, 0xDC274DCD,
    0x35FD2B0D, 0x4CDE76BD, 0x8AD2DAF3, 0xDD7C3731, 0x6CB1ED32, 0x536D36D3,
    0x7AD4CCA7, 0x1CD0D0AD, 0xCD276CD3, 0x2EC62F0F, 0xECF73DCB, 0x5D4AC735,
    0xED3369D7, 0x5DB49D36, 0x36CCDFF3, 0xBDF59D27, 0x1B9DBAB4, 0xD336AC33,
    0x136DEAB5, 0xD22C3537, 0x31AD331A, 0xC2331EC3, 0xAD330D0A, 0x337AD336,
    0xF0D75BD6, 0xB5533C9F, 0x2CBB4DCB, 0xB5729CBB, 0xCDAF2ED3, 0x2B4CDAB4,
    0xDCDF31CC, 0x3BACE335, 0xE76EDD27, 0xB5CCC35D, 0x6ADE4CCB, 0xD777CD37,
    0x31ACBB2A, 0x0C3F2BDB, 0xECB71C93, 0x274ECEB7, 0x277921ED, 0x35DDB22C,
    0xA606B4D7, 0xAB3AD7CC, 0x311CFF0C, 0x73DF4735, 0x34D759C7, 0x3475AB4C,
    0xC92A2CB4, 0xAF5EACB6, 0xD6AD34AC, 0x36AD775E, 0x71DDEEA4, 0x5DDA74C3,
    0xC372F9AB, 0x0ECE321C, 0xC3EB1C67, 0x35CABB4D, 0x6B435749, 0x75EC83CD,
    0x87CC674D, 0xF59D326E, 0x6DCB21A8, 0xE334A8AB, 0xA74F389C, 0x6EC2E0AC,
    0xD0D1DF73, 0xB0E86B69, 0x5CD7B435, 0xF30ACE36, 0xCDFB4B30, 0xBCCF326F,
    0x8ED67B7A, 0xECDB3374, 0x5D8ACF33, 0x3EFF6C2B, 0xE2B18CCC, 0xF3B8CC3E,
    0xCCC2B1EC, 0x2B6EC2B1, 0x2ACAF5DD, 0xF7730AC7, 0xDA870CCD, 0x796FFB23,
    0xE4DDABAB, 0x673BECA8, 0x347A3CC2, 0x2F7D35C9, 0x736899D3, 0xF2CB31C3,
    0xDCCADF3C, 0x72DC6FE7, 0xDBB08D82, 0x69FD374A, 0x71BECC3B, 0x47343534,
    0x2F9ACA3B, 0x24343B53, 0xA58535F1, 0x01243501, 0x1D4D2430, 0x35F14D4D,
    0xF34B51CF, 0xB268D8CC, 0x27E97BBA, 0xBA59EE23, 0xFF3B249B, 0xF66F25C9,
    0x9B7323C8, 0xBA3349B9, 0x73249FAD, 0xB2321833, 0x924D1F97, 0x357792CC,
    0xAEFAEFAE, 0xC7B1E4D9, 0x19CDEB7F, 0x009C746B, 0x00000000, 0x00480000,
    0x00000480, 0x0C000000, 0xD4310CA1, 0x32D43534, 0x12430434, 0x38B0C543,
    0x00012492, 0x24800012, 0x00000051, 0x00000000, 0x3130D0CE, 0x28099805,
    0x3431459E, 0x5229CF4F, 0x6000000B, 0x0BD30C48, 0x000001F7, 0x0000C800,
    0x00000000, 0x20010C00, 0x00000001, 0x00000000, 0x00000000, 0x337769D2,
    0xBB21969C, 0xAA76ACD2, 0xE7530DD3, 0x0000001F, 0x00000000, 0x00000000,
    0x00000000, 0xC8000000, 0x00000000, 0x00000000, 0x00000000, 0x6DF5C320,
    0xF5DF5D33, 0xDE00B36D, 0xB34DE335, 0xB34DB34D, 0x274CB32D, 0x3534A696,
    0x4C05CB29, 0x70D334D3, 0xDBF361F8, 0x04D1F75D, 0x015E494C, 0x00000000,
    0x00000000, 0x78000000, 0x07367E68, 0x00000000, 0x0002A800, 0x038A8000,
    0x00000A00, 0x00000000, 0x4304C800, 0x02848680, 0x4B4B0000, 0x6594C000,
    0xD9ED9BA0, 0x18EADEB2, 0x2778AD67, 0x34336EAD, 0xEEC34747, 0xDFDC2F4D,
    0xFDADD7B1, 0xEBABD7B7, 0xEB4EDEB7, 0x4EDEB4ED, 0x4C34930C, 0xEB4ED753,
    0x4D3434ED, 0x432EC757, 0xB1CA4B53, 0xAD3B7ACB, 0x3B7AD3B7, 0x7AD3B7AD,
    0xD7B7AD3B, 0x73AC273A, 0xAC273AC2, 0x273AC273, 0xFB1B98C8, 0xB3FCC8AD,
    0x3E998ACB, 0xC6561DEB, 0xE56339E6, 0x5E759F77, 0x7AA599FF, 0xB9B6DAA1,
    0xFC4EF5A6, 0x62B269D9, 0xDB19CFEB, 0xF72F2B4C, 0xD6AD35EC, 0xFFAF2B6C,
    0xB4DD0D1C, 0xDF7CF430, 0x48EE4899, 0x4BC3537D, 0xC35D4FC3, 0x8B64CC34,
    0x3E48CD4F, 0x31BC31F5, 0x4C3584FC, 0xD6724CC3, 0x3354B0D0, 0xD31FD0D9,
    0x2C4FC31F, 0xC330D0D3, 0xC35C9BB0, 0x4CD51D4F, 0x4B330D36, 0x70D2B5D7,
    0xA8FF0D33, 0x4966C32D, 0x4CC30EC3, 0xC31AC74D, 0xB5324DB4, 0x2A5E9EF3,
    0xDC357382, 0x36D4D34E, 0xC37EEDB4, 0xF0C0C84F, 0x7D82AB6D, 0x1FC34B06,
    0xE4C3697A, 0x70CA549B, 0x6B0DF5DF, 0xE7321A8B, 0xAFFBF0D6, 0x37AC930C,
    0xCAD734BC, 0xDF63DC35, 0x73530DB0, 0xEB0D30D7, 0x21DC81D9, 0x31DE870D,
    0x2AE43434, 0xD8FF20AA, 0x2BCC36D1, 0xD8BF0DEA, 0x1CC30CD7, 0x90CB47B2,
    0xC33ED4DA, 0x34D3434F, 0xD320CD4C, 0x0DF42BB0, 0xC5D4DC8B, 0x5D1DE934,
    0xF42F24D3, 0x0C1DC90D, 0x6C30DC97, 0xE8334626, 0x26C35B3B, 0x4DF572A1,
    0xC7A6AC9B, 0x23AB97F0, 0x48E4DC97, 0x0DB2C6BA, 0x6CC35ED9, 0x90DF0DF6,
    0xC6F3C88D, 0xD8BC379C, 0xADB5C32B, 0x8ECC338A, 0x4D7A3A6B, 0x4B2EA335,
    0xCCFE3EEB, 0xFBB6B30E, 0xDC33B1AC, 0xFAFB7D36, 0xD328ECFF, 0xFAE62B5C,
    0x34ADB5AC, 0xF662B6DD, 0xBEEB5ECF, 0xDB0CCCFF, 0xB33CCF3B, 0xA75DCCFF,
    0xDC3272CA, 0x32434312, 0xADF70CDE, 0x719C9F32, 0x3434DB4C, 0x0ED7A29D,
    0x3F0CCBB3, 0x37A8333D, 0x2DCB54F5, 0xB4DD76FD, 0x83BD7B56, 0x31CA6D76,
    0x4F87B0D3, 0x36A9F4DA, 0x3F0D24EC, 0x4C36C368, 0x8B0D7A2D, 0xDA0FC32C,
    0x36A9B0D2, 0x93E5B5AC, 0xC339F4C4, 0x7E5EC32C, 0xE292E6C8, 0x3D351D0E,
    0x1EC32CC3, 0x3196493E, 0x36EC36AC, 0xD36C30FC, 0x87B0DAA7, 0xEC94E78C,
    0x5DB31D24, 0xCCF49273, 0xC30CCC72, 0x6CCEE02E, 0x0CC70D2D, 0x9C83349D,
    0x4C35B535, 0xD6C30EC3, 0xD21CD37C, 0xEB23C970, 0xB52EF34F, 0xB0D7B0C7,
    0xD0DFF0D7, 0xCC3349F1, 0x1BC94760, 0x56F249C3, 0xD58330DB, 0x3E4C32EE,
    0x5D748471, 0x6CDF64DF, 0x74C2F5CD, 0x79864B1F, 0x7EC36CCF, 0x7BD434D3,
    0x74FD0B0C, 0x57AAC34D, 0x966C74B3, 0x7F58EC32, 0xCB37CECD, 0xFF74CCA6,
    0xEC872B57, 0x4D8CD7B7, 0xFC32DCD3, 0xB7DA6AFA, 0x0DF330DF, 0xE9A29F27,
    0xCEAA1C30, 0x737CD3B0, 0x30ED7598, 0x27DD5DC3, 0x8E70D34D, 0xC34DB28C,
    0xD9E6CC34, 0xC34D0AE3, 0xF0D36431, 0x66925DE9, 0x9EC9F67E, 0x737CD730,
    0x27A1CFCD, 0xAECB1AA9, 0xD31C3558, 0xC66A6D79, 0xF4C7E330, 0x5F330CA2,
    0x2F0CD633, 0x5B8BF34C, 0x0D20DC73, 0x34C2F533, 0x9D1F8F0D, 0x25FD74B6,
    0x33DAF0DB, 0x3EC934D3, 0xA4970C4D, 0x1AD7287A, 0x62C30FC3, 0x3B2CB1C6,
    0x3A9535CA, 0x3696DAB2, 0xD35DEC34, 0x32EC3435, 0xC4D71ACC, 0x6D213730,
    0x534D19C9, 0x34F289CB, 0x9A437FEC, 0xC34D37CA, 0xDE77DFA6, 0x0C9F4D36,
    0xB35DD4DB, 0x475ABC34, 0x6AD2B25B, 0x30D0D1D3, 0x430B6D3F, 0xB0DE3247,
    0xB30CBB60, 0x072DAF0C, 0x3587FAB2, 0xB4EAEEC7, 0xA8AC72FC, 0x2B34CFE7,
    0xC37BAB98, 0xDB709CCC, 0x7E8CC6B4, 0xC74D70AD, 0xD6AAD35E, 0x6C6F2FBE,
    0xA9727DF7, 0xDAC734B5, 0x4CF3477C, 0x9CCB4347, 0xF71DFAA6, 0xFFD31F8E,
    0x77EFCD36, 0x8EC71DCC, 0x77B1BBEC, 0x33FFACAD, 0xCDF2CCA3, 0xC4C33FFE,
    0xF3ACD74A, 0xEEFF30DC, 0x36EB2CC6, 0xB7D1ECFE, 0xFF332B0D, 0x4735311C,
    0xB3FFFC33, 0xF99CCD7A, 0xB09CC7B7, 0x3FC98AD7, 0xBECF7C7B, 0xADE73CEA,
    0x4D73EB9C, 0xDC334DB7, 0xF598EDF3, 0x8EDF58AD, 0xDF6EBDF5, 0x5BCDF5BC,
    0xCDF5BCDF, 0xF5BCDF5B, 0xBCDF5BCD, 0xDF5BCDF5, 0x7ECDF5BC, 0xCDF5BCDF,
    0xF5A9DF58, 0xDEDF58CD, 0xDF59DF58, 0x7FCDF6D9, 0x5DF59ADF, 0xCDF5BADF,
    0xF58ADF5A, 0xF98CDF5D, 0x59ACDF58, 0x8EDF59DF, 0xCDF5ADF5, 0xF5ABDF5A,
    0xDF5A9CDD, 0xA9DF58BA, 0x6D9CDF58, 0xFDF7FCDF, 0xDF7CADF6, 0x5ADDF5A9,
    0xDDF5BCDF, 0xF59CDF5B, 0x9BDF59CD, 0xDF59CDF5, 0xBEDF5BEC, 0xDF58CDF5,
    0x9D9DF59B, 0xF5ACDF58, 0xBBDF58AD, 0x99DF76BC, 0xF59BDF7F, 0xCADF5BFD,
    0xAACCDF5A, 0x3FD9CDF5, 0x5DEB6D37, 0xCAC32C33, 0x53B33FFC, 0x3F3FBECB,
    0x1DEECD4C, 0xC273DCDD, 0xA5FCFD34, 0xBF5733C3, 0x3777CB6B, 0xB3F2BDF3,
    0xB2D62A79, 0x1DCD3622, 0x4870C2EB, 0xDDB1B99D, 0xD7BCDB7B, 0x0EEC718A,
    0xBBCF0AC7, 0xB1B8ADF0, 0xDF2BCAD2, 0x86ABA7EF, 0x8EDF5DB2, 0xB20DD735,
    0x7334FD6B, 0xD6F336AD, 0xA8376B6E, 0x4CAD36AA, 0x73575EDF, 0x339DF7EC,
    0xB7DDAFC7, 0xB70AE9DD, 0x0AD308CC, 0xC3B1ADC3, 0x6B9AD369, 0x39C70ED7,
    0xACB2CCCF, 0xC37EADB5, 0xDB74D734, 0xC36BCF7F, 0xCB2CCD5E, 0x77AD779C,
    0x4CDC70DD, 0xC7B7EDDB, 0x34DDF5EA, 0x8AC77DCD, 0xB2FDD2B5, 0xC318DAD2,
    0x9DCCF5DB, 0x2ADCC2B3, 0x58BD9CAB, 0x6B5E9CC7, 0x2B0D8ABC, 0xDCD2B6CD,
    0xCDACCEB6, 0xF09BCCF5, 0x6CCD3543, 0xFCC734B7, 0xFBACB348, 0x72E267EF,
    0xA2FB4CBD, 0xCCB2DCFF, 0x30DB7D36, 0x32ECFF3B, 0xB5DCF32F, 0x0BCFF2E2,
    0x6CF0BC73, 0x9CFFB22B, 0x362B4334, 0x22B5ECFF, 0x2B0DCF37, 0xB49CFAF2,
    0xFBE2B6CD, 0x362B59CF, 0x62B5ECFB, 0xB38CCFFF, 0x7ACF77E2, 0x35D5FFB7,
    0x1D6AD30D, 0x33D32D0D, 0xDB4F530D, 0xB7CD32D0, 0x49CF6AA2, 0x2A2B49DB,
    0x7D36ECFF, 0xCCFFB6EB, 0x1D7D3368, 0xB0AC72AD, 0x5ECFB262, 0xBCFEB72B,
    0xFFC97B33, 0x722AC33E, 0xEB0D7BEF, 0x4DB8F7B5, 0x7C57376D, 0xC3115046,
    0x47ED8644, 0x619F4904, 0x52FDCDD3, 0x7391EE45, 0x43386F97, 0x5FC1B526,
    0xA2B9E71F, 0xE81FAF8F, 0x836E65ED, 0xFCC8F23B, 0x7E2A5E84, 0xA7CC8001,
    0x06AB801F, 0x61FE0000, 0x80198A82, 0x06DB806D, 0x30D200A0, 0xEE97A6E7,
    0xA00007A0, 0x936A00A8, 0x9248FA2B, 0xF6FE49F5, 0x1F737450, 0x47924D0F,
    0xCFE26B31, 0xFFA62B5B, 0x9B58B4EC, 0x6936EFE4, 0x1F707498, 0x47924D0F,
    0xC1355FB1, 0x0CB0D330, 0x8668C8BB, 0xEB23C35C, 0x6D2BE797, 0x4925B837,
    0x0DAB0DB6, 0xCCD0730D, 0xB659CD34, 0xF437B6CC, 0x98FB1CD6, 0x2A4CC318,
    0x3F27BC9B, 0xD9B258B8, 0x4C93B23D, 0x47379AC3, 0xB4CC9F72, 0xB3DCC36C,
    0xA7322DAD, 0xC862733D, 0xC338CD6F, 0xB19D51EA, 0xC30F9D35, 0x7FCC37AE,
    0x76DADB47, 0x1FCC36EC, 0x5FCB2FD3, 0x2CD77FC3, 0xDF0D2372, 0x34D33DF5,
    0xDF10CCB5, 0xC3534EAB, 0x0CF2A7DC, 0x34F4935B, 0x2D330D24, 0xB314D37D,
    0xFD6DBD4C, 0x8AF87EA0, 0xD1C9C348, 0xBC93229C, 0xD36FDDB2, 0x579C35AC,
    0xC8F70C2E, 0x37CCB309, 0xFCD36FCC, 0xEC37CC35, 0xDA63360F, 0xDAA5A931,
    0x4D4B4D30, 0xAAC3174F, 0xCC304D51, 0x2EC32C34, 0xEBC349A6, 0xF66EACD4,
    0xE7B25EB9, 0x98FA38E8, 0x7259CF7C, 0x1D2331DF, 0xEF34C3B3, 0xB4DB72DE,
    0xC7731C7E, 0x4D7F34D0, 0xCF330DF7, 0xB341C9B4, 0xB8B736DE, 0x434CCB09,
    0xB4FE9E72, 0x6ED0DCC6, 0x2A6CCCB3, 0x899BFB52, 0xBB22EAD7, 0x2D4AB35D,
    0xEE77C7B3, 0xB30D372C, 0xD3330C62, 0xCA8F6B2C, 0x6FDDCB7D, 0x32FCDEC3,
    0xC23218AC, 0x34ADC9F2, 0xEAE638DD, 0xB39FBC9B, 0x9C34AEFC, 0xBE3E92E3,
    0x97B7A17E, 0x598A5FD9, 0xF323C8EE, 0xF8A97A13, 0x9F320005, 0x1AAE007E,
    0x87F80000, 0x00662A09, 0xB804A83A, 0x200A006D, 0xA099B9C9, 0x0001E8EB,
    0xDA802A28, 0x8A3E92E4, 0x9FEEC564, 0xB6699EF9, 0x9ECCD663, 0xBB316693,
    0xCB0CCCFA, 0xDCFFFB0C, 0x6B31CD36, 0xF68CCFF2, 0xFC8A74CD, 0x20DEAD31,
    0xC34BF8BF, 0xFA3C34BF, 0x33238986, 0xA62EB986, 0xA333EDA3, 0x8FAD8EF7,
    0x4EA9B722, 0x0CB0CBBA, 0x34D6FFF3, 0xB997A727, 0xFEC6567D, 0x5456BD99,
    0x656BB9E6, 0xA6D79FED, 0xFFF6F6D3, 0x9E699599, 0xFEDE39A5, 0xB596F9AB,
    0x458E927A, 0xBEBAE2DB, 0xDBF915A9, 0x903D9A56, 0x914D2C71, 0x6D9A6191,
    0x7988E3B6, 0x86B90DE6, 0xCF649135, 0x39A59A35, 0x8639A39A, 0xF86DD519,
    0x98D6539D, 0x86739861, 0x1AE4F9F9, 0x79AC646E, 0x4D417EE6, 0x67515F92,
    0xFEBE49B9, 0x0CCD0EC0, 0x92FF647D, 0xF1B9A791, 0x9A730E45, 0x9CC595A3,
    0x96D192E5, 0xC924D863, 0xD09867D1, 0x6FDA64E7, 0x5AF49D98, 0xD7EDBCE7,
    0x6BADC190, 0x96F9B1EE, 0xE6998F69, 0x8456FFDA, 0xF6D8FEB5, 0xFBBFF69A,
    0x39B69956, 0xDCE4DDFF, 0xBE4D35A3, 0xB14540FE, 0xD5DDB9A6, 0x0747D074,
    0x47D0747D, 0x90747D07, 0x3586DB3D, 0x5F90D243, 0xE61A64C1, 0x92E7619F,
    0xDF619549, 0xDEC51191, 0x54B69150, 0x06C79D34, 0x6879A717, 0x150356DA,
    0x386B6AE3, 0x98631DA6, 0x5D9BEFBD, 0xD5257645, 0xE13BBF63, 0x1759E19B,
    0x986A6865, 0x02DAE189, 0x2E61964D, 0x661A7C86, 0xA1A9A658, 0xA63DA3A1,
    0xD938F621, 0xE9A56DAE, 0x769E6698, 0x6BACE1DB, 0x8661D946, 0x5B666159,
    0xE9E8DD6B, 0x68EE6FB5, 0xA6EDBADF, 0xFFAFF6FF, 0x8635AEEF, 0xAF698CEB,
    0x633D9CE6, 0xBB8633BB, 0x99D66BD6, 0x69DB576D, 0x618E4DAE, 0x6B863536,
    0xED86F9B8, 0x59A4EFDB, 0x9663DBE4, 0xF6793EDD, 0x798CE99A, 0xF739AFCE,
    0x95DBAFEF, 0x13B98DEF, 0x648699A6, 0xC766E8FC, 0xB1FE6B9A, 0xD14D3FA3,
    0xF3863986, 0x9E61F9E1, 0xEC5966A9, 0xA7E765B9, 0x971E6661, 0xB8D54CB7,
    0x6ECE79B6, 0xB1B0E9A6, 0x95D664B5, 0x7DB7E979, 0xA633A66D, 0x1AD68E9F,
    0x5FB6DD9E, 0x516FF8D6, 0x558D669F, 0x77AFFE1B, 0x66AE97A6, 0xCF1DD86B,
    0x4115376E, 0xB69B8576, 0x39B66939, 0xA39A39A6, 0x7D59D653, 0x8E65DBDE,
    0x19E7B69B, 0xA756DAE6, 0x5D98E1FD, 0x99679B6B, 0xB6379965, 0x699AE3D9,
    0xEDA66793, 0xCEBBEFAD, 0x869B76FA, 0x9A56EB99, 0x9669B66D, 0xEB6E79E5,
    0x9EDB66F8, 0x855679E7, 0xB3F158DE, 0xD195BCE7, 0xBE79D679, 0x66799B95,
    0xE7FBB985, 0x9AEFFDAF, 0x96E7FFD5, 0xEB667FDD, 0x6F93A9A7, 0x67FDD986,
    0xDECC19B5, 0xC354B33E, 0xDBB3CD9C, 0x3E8DCCB4, 0x34CBB47F, 0xB35DF5C3,
    0x33FCDACD, 0xACB7AC23, 0xDEF3FCEC, 0x308BDDF5, 0x2D352DB4, 0xB0CB0C43,
    0x2DB4CCB4, 0x25934D4B, 0xF32B2AD7, 0x8737DC63, 0x667B9B75, 0xFF75BE8E,
    0xFD99F47D, 0xBFD9BEB7, 0xFEE7BFFE, 0x35AA599F, 0xAA7A6B9A, 0x926A19E9,
    0x9E7BE9A6, 0x7BEE7FBD, 0x63BDEFFF, 0x667FDFA7, 0xCEDA4EAC, 0xE8E6A4E8,
    0xB37586D8, 0x9867ADE7, 0x3FCACACB, 0xEDF7D633, 0xC7B3CACB, 0xBB3FDC8A,
    0x9FF55665, 0xED4569B3, 0xA39A199E, 0x9A19A1A3, 0x5F61A3A3, 0x0EF79FD6,
    0xCCFAA72B, 0xF159B30A, 0x9ABCE7F9, 0x7FFF9986, 0xDE596556, 0x67FF3958,
    0x73115AC6, 0xF67988AC, 0x7D647F91, 0x667FB31F, 0x7F1ECD38, 0x000000FD};
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
static const bbre_builtin_cc bbre_builtin_ccs_unicode_property[200] = {
    {5,  3,   464,   "Adlam"                 },
    {4,  3,   528,   "Ahom"                  },
    {21, 1,   596,   "Anatolian_Hieroglyphs" },
    {6,  58,  640,   "Arabic"                },
    {8,  4,   1286,  "Armenian"              },
    {7,  2,   1370,  "Avestan"               },
    {8,  2,   1418,  "Balinese"              },
    {5,  2,   1470,  "Bamum"                 },
    {9,  2,   1554,  "Bassa_Vah"             },
    {5,  2,   1602,  "Batak"                 },
    {7,  14,  1646,  "Bengali"               },
    {9,  4,   1806,  "Bhaiksuki"             },
    {8,  3,   1882,  "Bopomofo"              },
    {6,  3,   1962,  "Brahmi"                },
    {7,  1,   2029,  "Braille"               },
    {8,  2,   2065,  "Buginese"              },
    {5,  1,   2109,  "Buhid"                 },
    {19, 3,   2141,  "Canadian_Aboriginal"   },
    {6,  1,   2249,  "Carian"                },
    {18, 2,   2285,  "Caucasian_Albanian"    },
    {2,  2,   2332,  "Cc"                    },
    {2,  21,  2366,  "Cf"                    },
    {6,  2,   2774,  "Chakma"                },
    {4,  4,   2822,  "Cham"                  },
    {8,  3,   2902,  "Cherokee"              },
    {10, 1,   2990,  "Chorasmian"            },
    {2,  6,   3026,  "Co"                    },
    {6,  173, 3163,  "Common"                },
    {6,  3,   5939,  "Coptic"                },
    {2,  4,   6015,  "Cs"                    },
    {9,  4,   6104,  "Cuneiform"             },
    {7,  6,   6208,  "Cypriot"               },
    {12, 1,   6279,  "Cypro_Minoan"          },
    {8,  10,  6319,  "Cyrillic"              },
    {7,  1,   6570,  "Deseret"               },
    {10, 5,   6610,  "Devanagari"            },
    {11, 8,   6738,  "Dives_Akuru"           },
    {5,  1,   6848,  "Dogra"                 },
    {8,  5,   6884,  "Duployan"              },
    {20, 1,   6976,  "Egyptian_Hieroglyphs"  },
    {7,  1,   7020,  "Elbasan"               },
    {7,  1,   7056,  "Elymaic"               },
    {8,  36,  7092,  "Ethiopic"              },
    {8,  10,  7556,  "Georgian"              },
    {10, 6,   7697,  "Glagolitic"            },
    {6,  1,   7805,  "Gothic"                },
    {7,  15,  7841,  "Grantha"               },
    {5,  36,  8013,  "Greek"                 },
    {8,  14,  8483,  "Gujarati"              },
    {13, 6,   8621,  "Gunjala_Gondi"         },
    {8,  16,  8701,  "Gurmukhi"              },
    {3,  22,  8859,  "Han"                   },
    {6,  14,  9443,  "Hangul"                },
    {15, 2,   9767,  "Hanifi_Rohingya"       },
    {7,  1,   9815,  "Hanunoo"               },
    {6,  3,   9847,  "Hatran"                },
    {6,  9,   9903,  "Hebrew"                },
    {8,  6,   10029, "Hiragana"              },
    {16, 2,   10158, "Imperial_Aramaic"      },
    {9,  29,  10202, "Inherited"             },
    {21, 2,   10794, "Inscriptional_Pahlavi" },
    {22, 2,   10842, "Inscriptional_Parthian"},
    {8,  3,   10890, "Javanese"              },
    {6,  2,   10954, "Kaithi"                },
    {7,  13,  11005, "Kannada"               },
    {8,  14,  11137, "Katakana"              },
    {4,  3,   11381, "Kawi"                  },
    {8,  2,   11445, "Kayah_Li"              },
    {10, 8,   11484, "Kharoshthi"            },
    {19, 2,   11584, "Khitan_Small_Script"   },
    {5,  4,   11646, "Khmer"                 },
    {6,  2,   11730, "Khojki"                },
    {9,  2,   11778, "Khudawadi"             },
    {3,  11,  11826, "Lao"                   },
    {5,  39,  11928, "Latin"                 },
    {6,  3,   12594, "Lepcha"                },
    {5,  5,   12650, "Limbu"                 },
    {8,  3,   12732, "Linear_A"              },
    {8,  7,   12808, "Linear_B"              },
    {4,  2,   12928, "Lisu"                  },
    {2,  658, 12987, "Ll"                    },
    {2,  71,  16005, "Lm"                    },
    {2,  524, 17116, "Lo"                    },
    {2,  10,  24327, "Lt"                    },
    {2,  646, 24446, "Lu"                    },
    {6,  1,   27234, "Lycian"                },
    {6,  2,   27270, "Lydian"                },
    {8,  1,   27313, "Mahajani"              },
    {7,  1,   27349, "Makasar"               },
    {9,  7,   27385, "Malayalam"             },
    {7,  2,   27473, "Mandaic"               },
    {10, 2,   27508, "Manichaean"            },
    {7,  3,   27560, "Marchen"               },
    {13, 7,   27624, "Masaram_Gondi"         },
    {2,  182, 27710, "Mc"                    },
    {2,  5,   29850, "Me"                    },
    {11, 1,   29952, "Medefaidrin"           },
    {12, 3,   29992, "Meetei_Mayek"          },
    {13, 2,   30064, "Mende_Kikakui"         },
    {16, 3,   30120, "Meroitic_Cursive"      },
    {20, 1,   30188, "Meroitic_Hieroglyphs"  },
    {4,  3,   30224, "Miao"                  },
    {2,  346, 30296, "Mn"                    },
    {4,  2,   34658, "Modi"                  },
    {9,  6,   34714, "Mongolian"             },
    {3,  3,   34832, "Mro"                   },
    {7,  5,   34888, "Multani"               },
    {7,  3,   34954, "Myanmar"               },
    {9,  2,   35046, "Nabataean"             },
    {11, 1,   35094, "Nag_Mundari"           },
    {11, 3,   35130, "Nandinagari"           },
    {2,  64,  35194, "Nd"                    },
    {11, 4,   36522, "New_Tai_Lue"           },
    {4,  2,   36598, "Newa"                  },
    {3,  2,   36646, "Nko"                   },
    {2,  12,  36682, "Nl"                    },
    {2,  72,  36928, "No"                    },
    {5,  2,   38354, "Nushu"                 },
    {22, 4,   38416, "Nyiakeng_Puachue_Hmong"},
    {5,  1,   38492, "Ogham"                 },
    {8,  1,   38524, "Ol_Chiki"              },
    {13, 3,   38556, "Old_Hungarian"         },
    {10, 2,   38624, "Old_Italic"            },
    {17, 1,   38672, "Old_North_Arabian"     },
    {10, 1,   38708, "Old_Permic"            },
    {11, 2,   38744, "Old_Persian"           },
    {11, 1,   38796, "Old_Sogdian"           },
    {17, 1,   38832, "Old_South_Arabian"     },
    {10, 1,   38868, "Old_Turkic"            },
    {10, 1,   38908, "Old_Uyghur"            },
    {5,  14,  38944, "Oriya"                 },
    {5,  2,   39100, "Osage"                 },
    {7,  2,   39152, "Osmanya"               },
    {12, 5,   39200, "Pahawh_Hmong"          },
    {9,  1,   39292, "Palmyrene"             },
    {11, 1,   39328, "Pau_Cin_Hau"           },
    {2,  6,   39364, "Pc"                    },
    {2,  19,  39475, "Pd"                    },
    {2,  76,  39752, "Pe"                    },
    {2,  10,  40223, "Pf"                    },
    {8,  1,   40324, "Phags_Pa"              },
    {10, 2,   40360, "Phoenician"            },
    {2,  11,  40403, "Pi"                    },
    {2,  187, 40516, "Po"                    },
    {2,  79,  43162, "Ps"                    },
    {15, 3,   43653, "Psalter_Pahlavi"       },
    {6,  2,   43717, "Rejang"                },
    {5,  2,   43764, "Runic"                 },
    {9,  2,   43816, "Samaritan"             },
    {10, 2,   43860, "Saurashtra"            },
    {2,  21,  43916, "Sc"                    },
    {7,  1,   44297, "Sharada"               },
    {7,  1,   44337, "Shavian"               },
    {7,  2,   44373, "Siddham"               },
    {11, 3,   44425, "SignWriting"           },
    {7,  13,  44497, "Sinhala"               },
    {2,  31,  44651, "Sk"                    },
    {2,  64,  45123, "Sm"                    },
    {2,  185, 45975, "So"                    },
    {7,  1,   48843, "Sogdian"               },
    {12, 2,   48879, "Sora_Sompeng"          },
    {7,  1,   48927, "Soyombo"               },
    {9,  2,   48967, "Sundanese"             },
    {12, 1,   49019, "Syloti_Nagri"          },
    {6,  4,   49055, "Syriac"                },
    {7,  2,   49127, "Tagalog"               },
    {8,  3,   49170, "Tagbanwa"              },
    {6,  2,   49214, "Tai_Le"                },
    {8,  5,   49258, "Tai_Tham"              },
    {8,  2,   49346, "Tai_Viet"              },
    {5,  2,   49402, "Takri"                 },
    {5,  18,  49450, "Tamil"                 },
    {6,  2,   49663, "Tangsa"                },
    {6,  4,   49711, "Tangut"                },
    {6,  13,  49813, "Telugu"                },
    {6,  1,   49951, "Thaana"                },
    {4,  2,   49979, "Thai"                  },
    {7,  7,   50023, "Tibetan"               },
    {8,  3,   50127, "Tifinagh"              },
    {7,  2,   50182, "Tirhuta"               },
    {4,  1,   50234, "Toto"                  },
    {8,  2,   50270, "Ugaritic"              },
    {3,  1,   50309, "Vai"                   },
    {8,  8,   50349, "Vithkuqi"              },
    {6,  2,   50453, "Wancho"                },
    {11, 2,   50496, "Warang_Citi"           },
    {6,  3,   50547, "Yezidi"                },
    {2,  2,   50599, "Yi"                    },
    {16, 1,   50659, "Zanabazar_Square"      },
    {2,  1,   50699, "Zl"                    },
    {2,  1,   50722, "Zp"                    },
    {2,  7,   50745, "Zs"                    },
    {1,  0,   0,     "CCc,Cf,Cs,Co"          },
    {1,  0,   0,     "LLu,Ll,Lo,Lt,Lm"       },
    {1,  0,   0,     "MMn,Me,Mc"             },
    {1,  0,   0,     "NNd,No,Nl"             },
    {1,  0,   0,     "PPo,Ps,Pe,Pd,Pc,Pi,Pf" },
    {1,  0,   0,     "SSc,Sm,Sk,So"          },
    {1,  0,   0,     "ZZs,Zl,Zp"             },
    {0,  0,   0,     ""                      }
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
    const bbre_builtin_cc *start, bbre_uint *out_hdl)
{
  const bbre_builtin_cc *p = NULL, *found = NULL;
  int err = 0;
  *out_hdl = 0;
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
             r, out_hdl, BBRE_AST_TYPE_CC_BUILTIN, found->start_bit_offset,
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
      if (!*out_hdl)
        *out_hdl = subcls;
      else if ((err = bbre_ast_make(
                    r, out_hdl, BBRE_AST_TYPE_CC_OR, *out_hdl, subcls)))
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
    if ((err = bbre_compile_ranges_append(
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
    bbre *r, const bbre_byte *name, size_t name_len, bbre_uint *out_hdl)
{
  return bbre_builtin_cc_make(
      r, name, name_len, bbre_builtin_ccs_unicode_property, out_hdl);
}

static int bbre_builtin_cc_ascii(
    bbre *r, const bbre_byte *name, size_t name_len, bbre_uint *out_hdl)
{
  return bbre_builtin_cc_make(
      r, name, name_len, bbre_builtin_ccs_ascii, out_hdl);
}

static int bbre_builtin_cc_perl(
    bbre *r, const bbre_byte *name, size_t name_len, bbre_uint *out_hdl)
{
  return bbre_builtin_cc_make(
      r, name, name_len, bbre_builtin_ccs_perl, out_hdl);
}

/*{ Generated by `versioner.py` */
static const char *const bbre_version_str = "0.0.2";
/*} Generated by `versioner.py` */

#ifdef BBRE_DEBUG_UTILS
/* Inject a header file after everything. This is used during development for
 * tools that need access to ABI-unstable internal structures. */
  #include BBRE_DEBUG_UTILS
#endif

/* Copyright 2024-2025 Max Nurzia
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

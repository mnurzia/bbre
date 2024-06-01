#include "mptest.h"
/* bits/util/exports */
#if !defined(MPTEST__SPLIT_BUILD)
#define MPTEST_INTERNAL static
#else
#define MPTEST_INTERNAL extern
#endif

#if !defined(MPTEST__SPLIT_BUILD)
#define MPTEST_INTERNAL_DATA_DECL static
#define MPTEST_INTERNAL_DATA static
#else
#define MPTEST_INTERNAL_DATA_DECL extern
#define MPTEST_INTERNAL_DATA 
#endif

#if MPTEST_USE_APARSE
/* bits/util/ntstr/strstr_n */
MPTEST_INTERNAL const char*
mptest__strstr_n(const char* s, const char* sub, mptest_size sub_size);
#endif /* MPTEST_USE_APARSE */

/* bits/util/preproc/token_paste */
#define MPTEST__PASTE_0(a, b) a ## b
#define MPTEST__PASTE(a, b) MPTEST__PASTE_0(a, b)

/* bits/util/static_assert */
#define MPTEST__STATIC_ASSERT(name, expr) char MPTEST__PASTE(mptest__, name)[(expr)==1]

/* bits/container/str */
typedef struct mptest__str {
    mptest_size _size_short; /* does not include \0 */
    mptest_size _alloc;      /* does not include \0 */
    mptest_char* _data;
} mptest__str;

void mptest__str_init(mptest__str* str);
int mptest__str_init_s(mptest__str* str, const mptest_char* s);
int mptest__str_init_n(mptest__str* str, const mptest_char* chrs, mptest_size n);
int mptest__str_init_copy(mptest__str* str, const mptest__str* in);
void mptest__str_init_move(mptest__str* str, mptest__str* old);
void mptest__str_destroy(mptest__str* str);
mptest_size mptest__str_size(const mptest__str* str);
int mptest__str_cat(mptest__str* str, const mptest__str* other);
int mptest__str_cat_s(mptest__str* str, const mptest_char* s);
int mptest__str_cat_n(mptest__str* str, const mptest_char* chrs, mptest_size n);
int mptest__str_push(mptest__str* str, mptest_char chr);
int mptest__str_insert(mptest__str* str, mptest_size index, mptest_char chr);
const mptest_char* mptest__str_get_data(const mptest__str* str);
int mptest__str_cmp(const mptest__str* str_a, const mptest__str* str_b);
mptest_size mptest__str_slen(const mptest_char* chars);
void mptest__str_clear(mptest__str* str);
void mptest__str_cut_end(mptest__str* str, mptest_size new_size);

#if MPTEST_USE_DYN_ALLOC
#if MPTEST_USE_SYM
/* bits/container/str_view */
typedef struct mptest__str_view {
    const mptest_char* _data;
    mptest_size _size;
} mptest__str_view;

void mptest__str_view_init(mptest__str_view* view, const mptest__str* other);
void mptest__str_view_init_s(mptest__str_view* view, const mptest_char* chars);
void mptest__str_view_init_n(mptest__str_view* view, const mptest_char* chars, mptest_size n);
void mptest__str_view_init_null(mptest__str_view* view);
mptest_size mptest__str_view_size(const mptest__str_view* view);
const mptest_char* mptest__str_view_get_data(const mptest__str_view* view);
int mptest__str_view_cmp(const mptest__str_view* a, const mptest__str_view* b);
#endif /* MPTEST_USE_DYN_ALLOC */
#endif /* MPTEST_USE_SYM */

/* bits/util/unused */
#define MPTEST__UNUSED(x) ((void)(x))

#if MPTEST_USE_DYN_ALLOC
#if MPTEST_USE_SYM
/* bits/container/vec */
#define MPTEST__VEC_TYPE(T) \
    MPTEST__PASTE(T, _vec)

#define MPTEST__VEC_IDENT(T, name) \
    MPTEST__PASTE(T, MPTEST__PASTE(_vec_, name))

#define MPTEST__VEC_IDENT_INTERNAL(T, name) \
    MPTEST__PASTE(T, MPTEST__PASTE(_vec__, name))

#define MPTEST__VEC_DECL_FUNC(T, func) \
    MPTEST__PASTE(MPTEST__VEC_DECL_, func)(T)

#define MPTEST__VEC_IMPL_FUNC(T, func) \
    MPTEST__PASTE(MPTEST__VEC_IMPL_, func)(T)

#if MPTEST_DEBUG

#define MPTEST__VEC_CHECK(vec) \
    do { \
        /* ensure size is not greater than allocation size */ \
        MPTEST_ASSERT(vec->_size <= vec->_alloc); \
        /* ensure that data is not null if size is greater than 0 */ \
        MPTEST_ASSERT(vec->_size ? vec->_data != MPTEST_NULL : 1); \
    } while (0)

#else

#define MPTEST__VEC_CHECK(vec) MPTEST__UNUSED(vec)

#endif

#define MPTEST__VEC_DECL(T) \
    typedef struct MPTEST__VEC_TYPE(T) { \
        mptest_size _size; \
        mptest_size _alloc; \
        T* _data; \
    } MPTEST__VEC_TYPE(T)

#define MPTEST__VEC_DECL_init(T) \
    void MPTEST__VEC_IDENT(T, init)(MPTEST__VEC_TYPE(T)* vec)

#define MPTEST__VEC_IMPL_init(T) \
    void MPTEST__VEC_IDENT(T, init)(MPTEST__VEC_TYPE(T)* vec) { \
        vec->_size = 0; \
        vec->_alloc = 0; \
        vec->_data = MPTEST_NULL; \
    } 

#define MPTEST__VEC_DECL_destroy(T) \
    void MPTEST__VEC_IDENT(T, destroy)(MPTEST__VEC_TYPE(T)* vec)

#define MPTEST__VEC_IMPL_destroy(T) \
    void MPTEST__VEC_IDENT(T, destroy)(MPTEST__VEC_TYPE(T)* vec) { \
        MPTEST__VEC_CHECK(vec); \
        if (vec->_data != MPTEST_NULL) { \
            MPTEST_FREE(vec->_data); \
        } \
    }

#define MPTEST__VEC_GROW_ONE(T, vec) \
    do { \
        void* new_ptr; \
        mptest_size new_alloc; \
        if (vec->_size + 1 > vec->_alloc) { \
            if (vec->_data == MPTEST_NULL) { \
                new_alloc = 1; \
                new_ptr = (T*)MPTEST_MALLOC(sizeof(T) * new_alloc); \
            } else { \
                new_alloc = vec->_alloc * 2; \
                new_ptr = (T*)MPTEST_REALLOC(vec->_data, sizeof(T) * new_alloc); \
            } \
            if (new_ptr == MPTEST_NULL) { \
                return -1; \
            } \
            vec->_alloc = new_alloc; \
            vec->_data = new_ptr; \
        } \
        vec->_size = vec->_size + 1; \
    } while (0)

#define MPTEST__VEC_GROW(T, vec, n) \
    do { \
        void* new_ptr; \
        mptest_size new_alloc = vec->_alloc; \
        mptest_size new_size = vec->_size + n; \
        if (new_size > new_alloc) { \
            if (new_alloc == 0) { \
                new_alloc = 1; \
            } \
            while (new_alloc < new_size) { \
                new_alloc *= 2; \
            } \
            if (vec->_data == MPTEST_NULL) { \
                new_ptr = (T*)MPTEST_MALLOC(sizeof(T) * new_alloc); \
            } else { \
                new_ptr = (T*)MPTEST_REALLOC(vec->_data, sizeof(T) * new_alloc); \
            } \
            if (new_ptr == MPTEST_NULL) { \
                return -1; \
            } \
            vec->_alloc = new_alloc; \
            vec->_data = new_ptr; \
        } \
        vec->_size += n; \
    } while (0)

#define MPTEST__VEC_SETSIZE(T, vec, n) \
    do { \
        void* new_ptr; \
        if (vec->_alloc < n) { \
            if (vec->_data == MPTEST_NULL) { \
                new_ptr = (T*)MPTEST_MALLOC(sizeof(T) * n); \
            } else { \
                new_ptr = (T*)MPTEST_REALLOC(vec->_data, sizeof(T) * n); \
            } \
            if (new_ptr == MPTEST_NULL) { \
                return -1; \
            } \
            vec->_alloc = n; \
            vec->_data = new_ptr; \
        } \
    } while (0)

#define MPTEST__VEC_DECL_push(T) \
    int MPTEST__VEC_IDENT(T, push)(MPTEST__VEC_TYPE(T)* vec, T elem)

#define MPTEST__VEC_IMPL_push(T) \
    int MPTEST__VEC_IDENT(T, push)(MPTEST__VEC_TYPE(T)* vec, T elem) { \
        MPTEST__VEC_CHECK(vec); \
        MPTEST__VEC_GROW_ONE(T, vec); \
        vec->_data[vec->_size - 1] = elem; \
        MPTEST__VEC_CHECK(vec); \
        return 0; \
    }

#if MPTEST_DEBUG

#define MPTEST__VEC_CHECK_POP(vec) \
    do { \
        /* ensure that there is an element to pop */ \
        MPTEST_ASSERT(vec->_size > 0); \
    } while (0)

#else

#define MPTEST__VEC_CHECK_POP(vec) MPTEST__UNUSED(vec)

#endif

#define MPTEST__VEC_DECL_pop(T) \
    T MPTEST__VEC_IDENT(T, pop)(MPTEST__VEC_TYPE(T)* vec)

#define MPTEST__VEC_IMPL_pop(T) \
    T MPTEST__VEC_IDENT(T, pop)(MPTEST__VEC_TYPE(T)* vec) { \
        MPTEST__VEC_CHECK(vec); \
        MPTEST__VEC_CHECK_POP(vec); \
        return vec->_data[--vec->_size]; \
    }

#define MPTEST__VEC_DECL_cat(T) \
    T MPTEST__VEC_IDENT(T, cat)(MPTEST__VEC_TYPE(T)* vec, MPTEST__VEC_TYPE(T)* other)

#define MPTEST__VEC_IMPL_cat(T) \
    int MPTEST__VEC_IDENT(T, cat)(MPTEST__VEC_TYPE(T)* vec, MPTEST__VEC_TYPE(T)* other) { \
        re_size i; \
        re_size old_size = vec->_size; \
        MPTEST__VEC_CHECK(vec); \
        MPTEST__VEC_CHECK(other); \
        MPTEST__VEC_GROW(T, vec, other->_size); \
        for (i = 0; i < other->_size; i++) { \
            vec->_data[old_size + i] = other->_data[i]; \
        } \
        MPTEST__VEC_CHECK(vec); \
        return 0; \
    }

#define MPTEST__VEC_DECL_insert(T) \
    int MPTEST__VEC_IDENT(T, insert)(MPTEST__VEC_TYPE(T)* vec, mptest_size index, T elem)

#define MPTEST__VEC_IMPL_insert(T) \
    int MPTEST__VEC_IDENT(T, insert)(MPTEST__VEC_TYPE(T)* vec, mptest_size index, T elem) { \
        mptest_size i; \
        mptest_size old_size = vec->_size; \
        MPTEST__VEC_CHECK(vec); \
        MPTEST__VEC_GROW_ONE(T, vec); \
        if (old_size != 0) { \
            for (i = old_size; i >= index + 1; i--) { \
                vec->_data[i] = vec->_data[i - 1]; \
            } \
        } \
        vec->_data[index] = elem; \
        return 0; \
    }

#define MPTEST__VEC_DECL_peek(T) \
    T MPTEST__VEC_IDENT(T, peek)(const MPTEST__VEC_TYPE(T)* vec)

#define MPTEST__VEC_IMPL_peek(T) \
    T MPTEST__VEC_IDENT(T, peek)(const MPTEST__VEC_TYPE(T)* vec) { \
        MPTEST__VEC_CHECK(vec); \
        MPTEST__VEC_CHECK_POP(vec); \
        return vec->_data[vec->_size - 1]; \
    }

#define MPTEST__VEC_DECL_clear(T) \
    void MPTEST__VEC_IDENT(T, clear)(MPTEST__VEC_TYPE(T)* vec)

#define MPTEST__VEC_IMPL_clear(T) \
    void MPTEST__VEC_IDENT(T, clear)(MPTEST__VEC_TYPE(T)* vec) { \
        MPTEST__VEC_CHECK(vec); \
        vec->_size = 0; \
    }

#define MPTEST__VEC_DECL_size(T) \
    mptest_size MPTEST__VEC_IDENT(T, size)(const MPTEST__VEC_TYPE(T)* vec)

#define MPTEST__VEC_IMPL_size(T) \
    mptest_size MPTEST__VEC_IDENT(T, size)(const MPTEST__VEC_TYPE(T)* vec) { \
        return vec->_size; \
    }

#if MPTEST_DEBUG

#define MPTEST__VEC_CHECK_BOUNDS(vec, idx) \
    do { \
        /* ensure that idx is within bounds */ \
        MPTEST_ASSERT(idx < vec->_size); \
    } while (0)

#else

#define MPTEST__VEC_CHECK_BOUNDS(vec, idx) \
    do { \
        MPTEST__UNUSED(vec); \
        MPTEST__UNUSED(idx); \
    } while (0) 

#endif

#define MPTEST__VEC_DECL_get(T) \
    T MPTEST__VEC_IDENT(T, get)(const MPTEST__VEC_TYPE(T)* vec, mptest_size idx)

#define MPTEST__VEC_IMPL_get(T) \
    T MPTEST__VEC_IDENT(T, get)(const MPTEST__VEC_TYPE(T)* vec, mptest_size idx) { \
        MPTEST__VEC_CHECK(vec); \
        MPTEST__VEC_CHECK_BOUNDS(vec, idx); \
        return vec->_data[idx]; \
    }

#define MPTEST__VEC_DECL_getref(T) \
    T* MPTEST__VEC_IDENT(T, getref)(MPTEST__VEC_TYPE(T)* vec, mptest_size idx)

#define MPTEST__VEC_IMPL_getref(T) \
    T* MPTEST__VEC_IDENT(T, getref)(MPTEST__VEC_TYPE(T)* vec, mptest_size idx) { \
        MPTEST__VEC_CHECK(vec); \
        MPTEST__VEC_CHECK_BOUNDS(vec, idx); \
        return &vec->_data[idx]; \
    }

#define MPTEST__VEC_DECL_getcref(T) \
    const T* MPTEST__VEC_IDENT(T, getcref)(const MPTEST__VEC_TYPE(T)* vec, mptest_size idx)

#define MPTEST__VEC_IMPL_getcref(T) \
    const T* MPTEST__VEC_IDENT(T, getcref)(const MPTEST__VEC_TYPE(T)* vec, mptest_size idx) { \
        MPTEST__VEC_CHECK(vec); \
        MPTEST__VEC_CHECK_BOUNDS(vec, idx); \
        return &vec->_data[idx]; \
    }

#define MPTEST__VEC_DECL_set(T) \
    void MPTEST__VEC_IDENT(T, set)(MPTEST__VEC_TYPE(T)* vec, mptest_size idx, T elem)

#define MPTEST__VEC_IMPL_set(T) \
    void MPTEST__VEC_IDENT(T, set)(MPTEST__VEC_TYPE(T)* vec, mptest_size idx, T elem) { \
        MPTEST__VEC_CHECK(vec); \
        MPTEST__VEC_CHECK_BOUNDS(vec, idx); \
        vec->_data[idx] = elem; \
    }

#define MPTEST__VEC_DECL_capacity(T) \
    mptest_size MPTEST__VEC_IDENT(T, capacity)(MPTEST__VEC_TYPE(T)* vec)

#define MPTEST__VEC_IMPL_capacity(T) \
    mptest_size MPTEST__VEC_IDENT(T, capacity)(MPTEST__VEC_TYPE(T)* vec) { \
        return vec->_alloc; \
    }

#define MPTEST__VEC_DECL_get_data(T) \
    T* MPTEST__VEC_IDENT(T, get_data)(MPTEST__VEC_TYPE(T)* vec)

#define MPTEST__VEC_IMPL_get_data(T) \
    T* MPTEST__VEC_IDENT(T, get_data)(MPTEST__VEC_TYPE(T)* vec) { \
        return vec->_data; \
    }

#define MPTEST__VEC_DECL_move(T) \
    void MPTEST__VEC_IDENT(T, move)(MPTEST__VEC_TYPE(T)* vec, MPTEST__VEC_TYPE(T)* old);

#define MPTEST__VEC_IMPL_move(T) \
    void MPTEST__VEC_IDENT(T, move)(MPTEST__VEC_TYPE(T)* vec, MPTEST__VEC_TYPE(T)* old) { \
        MPTEST__VEC_CHECK(old); \
        *vec = *old; \
        MPTEST__VEC_IDENT(T, init)(old); \
    }

#define MPTEST__VEC_DECL_reserve(T) \
    int MPTEST__VEC_IDENT(T, reserve)(MPTEST__VEC_TYPE(T)* vec, mptest_size cap);

#define MPTEST__VEC_IMPL_reserve(T) \
    int MPTEST__VEC_IDENT(T, reserve)(MPTEST__VEC_TYPE(T)* vec, mptest_size cap) { \
        MPTEST__VEC_CHECK(vec); \
        MPTEST__VEC_SETSIZE(T, vec, cap); \
        return 0; \
    }
#endif /* MPTEST_USE_DYN_ALLOC */
#endif /* MPTEST_USE_SYM */

/* mptest */
#ifndef MPTEST_INTERNAL_H
#define MPTEST_INTERNAL_H
/* How assert checking works (and why we need longjmp for it):
 * 1. You use the function ASSERT_ASSERT(statement) in your test code.
 * 2. Under the hood, ASSERT_ASSERT setjmps the current test, and runs the
 *    statement until an assert within the program fails.
 * 3. The assert hook longjmps out of the code into the previous setjmp from
 *    step (2).
 * 4. mptest recognizes this jump back and passes the test.
 * 5. If the jump back doesn't happen, mptest recognizes this too and fails the
 *    test, expecting an assertion failure. */
#if MPTEST_USE_TIME
#include <time.h>
#endif

#define MPTEST__RESULT_SKIPPED -3

/* The different ways a test can fail. */
typedef enum mptest__fail_reason {
  /* No failure. */
  MPTEST__FAIL_REASON_NONE,
  /* ASSERT_XX(...) statement failed. */
  MPTEST__FAIL_REASON_ASSERT_FAILURE,
  /* FAIL() statement issued. */
  MPTEST__FAIL_REASON_FAIL_EXPR,
#if MPTEST_USE_LONGJMP
  /* Program caused an assert() failure *within its code*. */
  MPTEST__FAIL_REASON_UNCAUGHT_PROGRAM_ASSERT,
#endif
#if MPTEST_USE_DYN_ALLOC
  /* Fatal error: mptest (not the program) ran out of memory. */
  MPTEST__FAIL_REASON_NOMEM,
#endif
#if MPTEST_USE_LEAKCHECK
  /* Program tried to call realloc() on null pointer. */
  MPTEST__FAIL_REASON_REALLOC_OF_NULL,
  /* Program tried to call realloc() on invalid pointer. */
  MPTEST__FAIL_REASON_REALLOC_OF_INVALID,
  /* Program tried to call realloc() on an already freed pointer. */
  MPTEST__FAIL_REASON_REALLOC_OF_FREED,
  /* Program tried to call realloc() on an already reallocated pointer. */
  MPTEST__FAIL_REASON_REALLOC_OF_REALLOCED,
  /* Program tried to call free() on a null pointer. */
  MPTEST__FAIL_REASON_FREE_OF_NULL,
  /* Program tried to call free() on an invalid pointer. */
  MPTEST__FAIL_REASON_FREE_OF_INVALID,
  /* Program tried to call free() on an already freed pointer. */
  MPTEST__FAIL_REASON_FREE_OF_FREED,
  /* Program tried to call free() on an already reallocated pointer. */
  MPTEST__FAIL_REASON_FREE_OF_REALLOCED,
  /* End-of-test memory check found unfreed blocks. */
  MPTEST__FAIL_REASON_LEAKED,
  /* Test did not detect an OOM condition. */
  MPTEST__FAIL_REASON_OOM_FALSE_NEGATIVE,
  /* Test erroneously signaled OOM. */
  MPTEST__FAIL_REASON_OOM_FALSE_POSITIVE,
#endif
#if MPTEST_USE_SYM
  /* Syms compared unequal. */
  MPTEST__FAIL_REASON_SYM_INEQUALITY,
  /* Syntax error occurred in a sym. */
  MPTEST__FAIL_REASON_SYM_SYNTAX,
  /* Couldn't parse a sym into an object. */
  MPTEST__FAIL_REASON_SYM_DESERIALIZE,
#endif
  MPTEST__FAIL_REASON_LAST
} mptest__fail_reason;

/* Type representing a function to be called whenever a suite is set up or torn
 * down. */
typedef void (*mptest__suite_callback)(void *data);

#if MPTEST_USE_SYM
typedef struct mptest__sym_fail_data {
  mptest_sym *sym_actual;
  mptest_sym *sym_expected;
} mptest__sym_fail_data;

typedef struct mptest__sym_syntax_error_data {
  const char *err_msg;
  mptest_size err_pos;
} mptest__sym_syntax_error_data;
#endif

/* Data describing how the test failed. */
typedef union mptest__fail_data {
  const char *string_data;
#if MPTEST_USE_LEAKCHECK
  void *memory_block;
#endif
#if MPTEST_USE_SYM
  mptest__sym_fail_data sym_fail_data;
  mptest__sym_syntax_error_data sym_syntax_error_data;
#endif
} mptest__fail_data;

#if MPTEST_USE_APARSE
typedef struct mptest__aparse_name mptest__aparse_name;

struct mptest__aparse_name {
  const char *name;
  mptest_size name_len;
  mptest__aparse_name *next;
};

typedef struct mptest__aparse_state {
  ap *aparse;
  /*     --leak-check : whether to enable leak checking or not */
  int opt_leak_check;
  /* -t, --test : the test name(s) to search for and run */
  mptest__aparse_name *opt_test_name_head;
  mptest__aparse_name *opt_test_name_tail;
  /* -s, --suite : the suite name(s) to search for and run */
  mptest__aparse_name *opt_suite_name_head;
  mptest__aparse_name *opt_suite_name_tail;
  /*     --fault-check : whether to enable fault checking */
  int opt_fault_check;
  /*     --leak-check-pass : whether to enable leak check malloc passthrough */
  int opt_leak_check_pass;
} mptest__aparse_state;
#endif

#if MPTEST_USE_LONGJMP
typedef struct mptest__longjmp_state {
  /* Saved setjmp context (used for testing asserts, etc.) */
  MPTEST_JMP_BUF assert_context;
  /* Saved setjmp context (used to catch actual errors during testing) */
  MPTEST_JMP_BUF test_context;
  /* 1 if we are checking for a jump, 0 if not. Used so that if an assertion
   * *accidentally* goes off, we can catch it. */
  mptest__fail_reason checking;
  /* Reason for jumping (assertion failure, malloc/free failure, etc) */
  mptest__fail_reason reason;
} mptest__longjmp_state;
#endif

#if MPTEST_USE_LEAKCHECK
typedef struct mptest__leakcheck_state {
  /* 1 if current test should be audited for leaks, 0 otherwise. */
  mptest__leakcheck_mode test_leak_checking;
  /* First and most recent blocks allocated. */
  struct mptest__leakcheck_block *first_block;
  struct mptest__leakcheck_block *top_block;
  /* Total number of allocations in use. */
  int total_allocations;
  /* Total number of calls to malloc() or realloc(). */
  int total_calls;
  /* Whether or not to let allocations fall through */
  int fall_through;
  /* Whether or not an OOM was generated on this test iteration */
  int oom_generated;
} mptest__leakcheck_state;
#endif

#if MPTEST_USE_TIME
typedef struct mptest__time_state {
  /* Start times that will be compared against later */
  clock_t program_start_time;
  clock_t suite_start_time;
  clock_t test_start_time;
} mptest__time_state;
#endif

#if MPTEST_USE_FUZZ
typedef struct mptest__fuzz_state {
  /* State of the random number generator */
  mptest_rand rand_state;
  /* Whether or not the current test should be fuzzed */
  int fuzz_active;
  /* Whether or not the current test failed on a fuzz */
  int fuzz_failed;
  /* Number of iterations to run the next test for */
  int fuzz_iterations;
  /* Fuzz failure context */
  int fuzz_fail_iteration;
  mptest_rand fuzz_fail_seed;
} mptest__fuzz_state;
#endif

struct mptest__state {
  /* Total number of assertions */
  int assertions;
  /* Total number of tests */
  int total;
  /* Total number of passes, fails, and errors */
  int passes;
  int fails;
  int errors;
  /* Total number of suite passes and fails */
  int suite_passes;
  int suite_fails;
  /* 1 if the current suite failed, 0 if not */
  int suite_failed;
  /* Suite setup/teardown callbacks */
  mptest__suite_callback suite_test_setup_cb;
  mptest__suite_callback suite_test_teardown_cb;
  /* Names of the current running test/suite */
  const char *current_test;
  const char *current_suite;
  /* Reason for failing a test */
  mptest__fail_reason fail_reason;
  /* Fail diagnostics */
  const char *fail_msg;
  const char *fail_file;
  int fail_line;
  /* Stores information about the failure. */
  /* Assert expression that caused the fail, if `fail_reason` ==
   * `MPTEST__FAIL_REASON_ASSERT_FAILURE` */
  /* Pointer to offending allocation, if `longjmp_reason` is one of the
   * malloc fail reasons */
  mptest__fail_data fail_data;
  /* Indentation level (used for output) */
  int indent_lvl;
  /* Fault checking mode */
  int fault_checking;
  /* Number of possible fault calls */
  int fault_calls;
  /* Iteration that the fault failed on */
  int fault_fail_call_idx;
  /* Whether or not a fault caused a failure */
  int fault_failed;

#if MPTEST_USE_LONGJMP
  mptest__longjmp_state longjmp_state;
#endif

#if MPTEST_USE_LEAKCHECK
  mptest__leakcheck_state leakcheck_state;
#endif

#if MPTEST_USE_TIME
  mptest__time_state time_state;
#endif

#if MPTEST_USE_APARSE
  mptest__aparse_state aparse_state;
#endif

#if MPTEST_USE_FUZZ
  mptest__fuzz_state fuzz_state;
#endif
};

#include <stdio.h>

MPTEST_INTERNAL mptest__result mptest__state_do_run_test(
    struct mptest__state *state, mptest__test_func test_func);
MPTEST_INTERNAL void mptest__state_print_indent(struct mptest__state *state);
MPTEST_INTERNAL int mptest__fault(struct mptest__state *state, const char *cls);

#if MPTEST_USE_LONGJMP

MPTEST_INTERNAL void mptest__longjmp_init(struct mptest__state *state);
MPTEST_INTERNAL void mptest__longjmp_destroy(struct mptest__state *state);
MPTEST_INTERNAL void mptest__longjmp_exec(struct mptest__state *state,
                                      mptest__fail_reason reason,
                                      const char *file, int line,
                                      const char *msg);

#endif

#if MPTEST_USE_LEAKCHECK
/* Number of guard bytes to put at the top of each block. */
#define MPTEST__LEAKCHECK_GUARD_BYTES_COUNT 16

/* Flags kept for each block. */
enum mptest__leakcheck_block_flags {
  /* The block was allocated with malloc(). */
  MPTEST__LEAKCHECK_BLOCK_FLAG_INITIAL = 1,
  /* The block was freed with free(). */
  MPTEST__LEAKCHECK_BLOCK_FLAG_FREED = 2,
  /* The block was the *input* of a reallocation with realloc(). */
  MPTEST__LEAKCHECK_BLOCK_FLAG_REALLOC_OLD = 4,
  /* The block was the *result* of a reallocation with realloc(). */
  MPTEST__LEAKCHECK_BLOCK_FLAG_REALLOC_NEW = 8
};

/* Header kept in memory before each allocation. */
struct mptest__leakcheck_header {
  /* Guard bytes (like a magic number, signifies proper allocation) */
  unsigned char guard_bytes[MPTEST__LEAKCHECK_GUARD_BYTES_COUNT];
  /* Block reference */
  struct mptest__leakcheck_block *block;
};

/* Structure that keeps track of a header's properties. */
struct mptest__leakcheck_block {
  /* Pointer to the header that exists right before the memory. */
  struct mptest__leakcheck_header *header;
  /* Size of block as passed to malloc() or realloc() */
  size_t block_size;
  /* Previous and next block records */
  struct mptest__leakcheck_block *prev;
  struct mptest__leakcheck_block *next;
  /* Realloc chain previous and next */
  struct mptest__leakcheck_block *realloc_prev;
  struct mptest__leakcheck_block *realloc_next;
  /* Flags (see `enum mptest__leakcheck_block_flags`) */
  enum mptest__leakcheck_block_flags flags;
  /* Source location where the malloc originated */
  const char *file;
  int line;
};

#define MPTEST__LEAKCHECK_HEADER_SIZEOF                                        \
  (sizeof(struct mptest__leakcheck_header))

MPTEST_INTERNAL void mptest__leakcheck_init(struct mptest__state *state);
MPTEST_INTERNAL void mptest__leakcheck_destroy(struct mptest__state *state);
MPTEST_INTERNAL void mptest__leakcheck_reset(struct mptest__state *state);
MPTEST_INTERNAL int mptest__leakcheck_has_leaks(struct mptest__state *state);
MPTEST_INTERNAL int
mptest__leakcheck_block_has_freeable(struct mptest__leakcheck_block *block);
MPTEST_INTERNAL int mptest__leakcheck_after_test(struct mptest__state *state,
                                             mptest__result res);
#endif

#if MPTEST_USE_COLOR
#define MPTEST__COLOR_PASS "\x1b[1;32m"       /* Pass messages */
#define MPTEST__COLOR_FAIL "\x1b[1;31m"       /* Fail messages */
#define MPTEST__COLOR_TEST_NAME "\x1b[1;36m"  /* Test names */
#define MPTEST__COLOR_SUITE_NAME "\x1b[1;35m" /* Suite names */
#define MPTEST__COLOR_EMPHASIS "\x1b[1m"      /* Important numbers */
#define MPTEST__COLOR_RESET "\x1b[0m"         /* Regular text */
#define MPTEST__COLOR_SYM_INT "\x1b[1;36m"    /* Sym integer highlight */
#define MPTEST__COLOR_SYM_STR "\x1b[1;33m"    /* Sym string highlight */
#else
#define MPTEST__COLOR_PASS ""
#define MPTEST__COLOR_FAIL ""
#define MPTEST__COLOR_TEST_NAME ""
#define MPTEST__COLOR_SUITE_NAME ""
#define MPTEST__COLOR_EMPHASIS ""
#define MPTEST__COLOR_RESET ""
#define MPTEST__COLOR_SYM_INT ""
#define MPTEST__COLOR_SYM_STR ""
#endif

#if MPTEST_USE_TIME
MPTEST_INTERNAL void mptest__time_init(struct mptest__state *state);
MPTEST_INTERNAL void mptest__time_destroy(struct mptest__state *state);
#endif

#if MPTEST_USE_APARSE
MPTEST_INTERNAL int mptest__aparse_init(struct mptest__state *state);
MPTEST_INTERNAL void mptest__aparse_destroy(struct mptest__state *state);
MPTEST_INTERNAL int mptest__aparse_match_test_name(struct mptest__state *state,
                                               const char *test_name);
MPTEST_INTERNAL int mptest__aparse_match_suite_name(struct mptest__state *state,
                                                const char *suite_name);
#endif

#if MPTEST_USE_FUZZ
MPTEST_INTERNAL void mptest__fuzz_init(struct mptest__state *state);
MPTEST_INTERNAL mptest__result mptest__fuzz_run_test(struct mptest__state *state,
                                                 mptest__test_func test_func);
MPTEST_INTERNAL void mptest__fuzz_print(struct mptest__state *state);
#endif

#if MPTEST_USE_SYM
MPTEST_INTERNAL void mptest__sym_dump(mptest_sym *sym, mptest_int32 parent_ref,
                                  mptest_int32 indent);
MPTEST_INTERNAL int mptest__sym_parse_do(mptest_sym_build *build_in,
                                     const mptest__str_view in,
                                     const char **err_msg, mptest_size *err_pos);
#endif

#endif

#if MPTEST_USE_APARSE
/* aparse */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* argument flags */
#define AP_ARG_FLAG_OPT        0x1 /* optional argument */
#define AP_ARG_FLAG_REQUIRED   0x2 /* required positional argument */
#define AP_ARG_FLAG_SUB        0x4 /* subparser argument */
#define AP_ARG_FLAG_COALESCE   0x8 /* coalesce short opt in usage */
#define AP_ARG_FLAG_DESTRUCTOR 0x10 /* arg callback has embedded dtor */

typedef struct ap_arg ap_arg;

/* internal argument structure */
struct ap_arg {
  int flags; /* bitset of AP_ARG_FLAG_xxx */
  ap_arg* next; /* next argument in list */
  ap_cb cb; /* callback */
  const char* metavar; /* metavar */
  const char* help; /* help text */
  const char* opt_long; /* long opt */
  char opt_short; /* if short option, option character */
  void* user; /* user pointer */
  void* user1; /* second user pointer (used for subparser) */
};

/* subparser linked list used in subparser search order */
typedef struct ap_sub ap_sub;
struct ap_sub {
  const char* identifier; /* command name */
  ap* par; /* the subparser itself*/
  ap_sub* next;
};

/* argument parser */
struct ap {
  const ap_ctxcb* ctxcb; /* context callbacks (replicated in subparsers) */
  const char* progname; /* argv[0] */
  ap_arg* args; /* argument list */
  ap_arg* args_tail; /* end of argument list */
  ap_arg* current; /* current arg under modification */
  ap* parent; /* parent for subparser arg search */
  const char* description; /* help description */
  const char* epilog; /* help epilog */
};

/* callback wrappers */
void* ap_cb_malloc(ap* parser, size_t n)
{
  return parser->ctxcb->alloc
             ? parser->ctxcb->alloc(parser->ctxcb->uptr, NULL, 0, n)
             : malloc(n);
}

void ap_cb_free(ap* parser, void* ptr, size_t n)
{
  if (parser->ctxcb->alloc)
    parser->ctxcb->alloc(parser->ctxcb->uptr, ptr, n, 0);
  else
    free(ptr);
}

void* ap_cb_realloc(ap* parser, void* ptr, size_t o, size_t n)
{
  return parser->ctxcb->alloc
             ? parser->ctxcb->alloc(parser->ctxcb->uptr, ptr, o, n)
             : realloc(ptr, n);
}

int ap_cb_out(ap* parser, const char* text, size_t n)
{
  return parser->ctxcb->print
             ? parser->ctxcb->print(parser->ctxcb->uptr, AP_FD_OUT, text, n)
             : (fwrite(text, 1, n, stdout) < n ? AP_ERR_IO : AP_ERR_NONE);
}

int ap_cb_err(ap* parser, const char* text, size_t n)
{
  return parser->ctxcb->print
             ? parser->ctxcb->print(parser->ctxcb->uptr, AP_FD_ERR, text, n)
             : (fwrite(text, 1, n, stderr) < n ? AP_ERR_IO : AP_ERR_NONE);
}

typedef int (*ap_print_func)(ap* par, const char* string, size_t n);

/* printf-like implementation */
int ap_pstrs(ap* par, ap_print_func out, const char* fmt, ...)
{
  int err = AP_ERR_NONE;
  va_list args;
  va_start(args, fmt);
  while (*fmt) {
    if (*fmt == '%') {
      ++fmt;
      if (*fmt == 's') {
        const char* arg = va_arg(args, const char*);
        assert(arg);
        if ((err = out(par, arg, strlen(arg))))
          goto done;
      } else if (*fmt == 'c') {
        int _arg = va_arg(args, int);
        char arg = (char)_arg;
        if (arg && (err = out(par, &arg, 1)))
          goto done;
      } else {
        assert(0); /* internal error */
      }
    } else {
      const char* begin = fmt;
      while (*(fmt + 1) && (*(fmt + 1) != '%'))
        fmt++;
      if ((err = out(par, begin, (size_t)(fmt - begin) + 1)))
        goto done;
    }
    fmt++;
  }
done:
  va_end(args);
  return err;
}

int ap_usage(ap* par, ap_print_func out)
{
  /* print usage without a newline */
  int err = AP_ERR_NONE;
  ap_arg* arg = par->args;
  assert(par->progname);
  if ((err = ap_pstrs(par, out, "usage: %s", par->progname)))
    return err;
  {
    /* coalesce short args */
    int any = 0;
    for (arg = par->args; arg; arg = arg->next) {
      if (!((arg->flags & AP_ARG_FLAG_OPT) &&
            (arg->flags & AP_ARG_FLAG_COALESCE) && arg->opt_short))
        continue;
      if ((err = ap_pstrs(
               par, out, "%s%c", !(any++) ? " [-" : "", arg->opt_short)))
        return err;
    }
    if (any && (err = ap_pstrs(par, out, "]")))
      return err;
  }
  {
    /* print options and possibly metavars */
    for (arg = par->args; arg; arg = arg->next) {
      if (!((arg->flags & AP_ARG_FLAG_OPT) &&
            !((arg->flags & AP_ARG_FLAG_COALESCE) && arg->opt_short)))
        continue;
      assert(arg->opt_long || arg->opt_short);
      if (arg->opt_short && (err = ap_pstrs(par, out, " [-%c", arg->opt_short)))
        return err;
      else if (
          !arg->opt_short &&
          (err = ap_pstrs(par, out, " [--%s", arg->opt_long)))
        return err;
      if (arg->metavar && (err = ap_pstrs(par, out, " %s", arg->metavar)))
        return err;
      if ((err = ap_pstrs(par, out, "]")))
        return err;
    }
  }
  {
    /* print positionals */
    for (arg = par->args; arg; arg = arg->next) {
      if (arg->flags & AP_ARG_FLAG_OPT)
        continue;
      assert(arg->metavar);
      if ((err = ap_pstrs(par, out, " %s", arg->metavar)))
        return err;
    }
  }
  return err;
}

int ap_show_argspec(ap* par, ap_arg* arg, ap_print_func out, int with_metavar)
{
  int err;
  if (arg->flags & AP_ARG_FLAG_OPT) {
    /* optionals */
    if (arg->opt_short && (err = ap_pstrs(par, out, "-%c", arg->opt_short)))
      return err;
    if (with_metavar && arg->metavar &&
        (err = ap_pstrs(par, out, " %s", arg->metavar)))
      return err;
    if (arg->opt_long && arg->opt_short && (err = ap_pstrs(par, out, ",")))
      return err;
    if (arg->opt_long && (err = ap_pstrs(par, out, "--%s", arg->opt_long)))
      return err;
    if (with_metavar && arg->metavar &&
        (err = ap_pstrs(par, out, " %s", arg->metavar)))
      return err;
  } else if ((err = ap_pstrs(par, out, "%s", arg->metavar)))
    /* positionals */
    return err;
  return AP_ERR_NONE;
}

int ap_error_prefix(ap* par)
{
  int err;
  if ((err = ap_usage(par, ap_cb_err)))
    return err;
  if ((err = ap_pstrs(par, ap_cb_err, "\n%s: error: ", par->progname)))
    return err;
  return err;
}

int ap_error(ap* par, const char* error_string)
{
  int err;
  if ((err = ap_error_prefix(par)) ||
      (err = ap_pstrs(par, ap_cb_err, "%s\n", error_string)))
    return err;
  return 1;
}

int ap_arg_error_internal(ap* par, ap_arg* arg, const char* error_string)
{
  int err;
  if ((err = ap_error_prefix(par)) ||
      (err = ap_pstrs(par, ap_cb_err, "argument ")) ||
      (err = ap_show_argspec(par, arg, ap_cb_err, 0)) ||
      (err = ap_pstrs(par, ap_cb_err, ": %s\n", error_string)))
    return err;
  return AP_ERR_PARSE;
}

int ap_arg_error(ap_cb_data* cbd, const char* error_string)
{
  ap* par = cbd->parser;
  ap_arg* arg = cbd->reserved;
  /* if this fails, you tried to call ap_arg_error from a destructor callback */
  assert(!arg || cbd->destroy);
  return ap_arg_error_internal(par, arg, error_string);
}

/* default callbacks (stubbed to NULL so that we know to use default funcs) */
static const ap_ctxcb ap_default_ctxcb = {NULL, NULL, NULL};

ap* ap_init(const char* progname)
{
  ap* out;
  /* just wrap `ap_init_full` for convenience */
  return (ap_init_full(&out, progname, NULL) == AP_ERR_NONE) ? out : NULL;
}

int ap_init_full(ap** out, const char* progname, const ap_ctxcb* pctxcb)
{
  ap* par;
  /* do a little dance to use the correct malloc callback before we've actually
   * allocated memory for the parser */
  pctxcb = pctxcb ? pctxcb : &ap_default_ctxcb;
  par = pctxcb->alloc ? pctxcb->alloc(pctxcb->uptr, NULL, 0, sizeof(ap))
                      : malloc(sizeof(ap));
  memset(par, 0, sizeof(*par));
  if (!par)
    return AP_ERR_NOMEM;
  par->ctxcb = pctxcb;
  par->progname = progname;
  par->args = NULL;
  par->args_tail = NULL;
  par->current = NULL;
  par->parent = NULL;
  *out = par;
  return AP_ERR_NONE;
}

void ap_destroy(ap* par)
{
  while (par->args) {
    ap_arg* prev = par->args;
    if (prev->flags & AP_ARG_FLAG_SUB) {
      /* destroy subparser */
      ap_sub* sub = (ap_sub*)prev->user;
      while (sub) {
        ap_sub* prev_sub = sub;
        ap_destroy(prev_sub->par);
        sub = sub->next;
        ap_cb_free(par, prev_sub, sizeof(*prev_sub));
      }
    } else if (prev->flags & AP_ARG_FLAG_DESTRUCTOR) {
      /* destroy arguments that requested it */
      ap_cb_data data = {0};
      data.destroy = 1;
      data.parser = par;
      prev->cb(prev->user, &data);
    }
    par->args = par->args->next;
    ap_cb_free(par, prev, sizeof(*prev));
  }
  ap_cb_free(par, par, sizeof(*par));
}

void ap_description(ap* par, const char* description)
{
  par->description = description;
}

void ap_epilog(ap* par, const char* epilog) { par->epilog = epilog; }

int ap_begin(ap* par)
{
  ap_arg* next = (ap_arg*)ap_cb_malloc(par, sizeof(ap_arg));
  if (!next)
    return AP_ERR_NOMEM;
  memset(next, 0, sizeof(*next));
  if (!par->args) /* first argument, initialize list */
    par->args = next, par->args_tail = next;
  else /* next argument, link to end */
    par->args_tail->next = next, par->args_tail = next;
  par->current = next;
  return AP_ERR_NONE;
}

int ap_pos(ap* par, const char* metavar)
{
  int err = 0;
  if ((err = ap_begin(par)))
    return err;
  par->current->flags = 0;
  par->current->metavar = metavar;
  return 0;
}

int ap_opt(ap* par, char short_opt, const char* long_opt)
{
  int err = 0;
  if ((err = ap_begin(par)))
    return err;
  /* if this fails, you didn't specify a short or long opt */
  assert(short_opt != 0 || long_opt != NULL);
  par->current->flags = AP_ARG_FLAG_OPT;
  par->current->opt_short = short_opt;
  par->current->opt_long = long_opt;
  return 0;
}

void ap_check_arg(ap* par)
{
  /* if this fails, you forgot to call ap_pos or ap_opt */
  (void)par, assert(par->current);
}

void ap_help(ap* par, const char* help)
{
  ap_check_arg(par);
  par->current->help = help;
}

void ap_metavar(ap* par, const char* metavar)
{
  ap_check_arg(par);
  par->current->metavar = metavar;
}

void ap_type_sub(ap* par, const char* metavar, int* out_idx)
{
  ap_check_arg(par);
  /* if this fails, you called ap_type_sub() twice */
  assert(!(par->current->flags & AP_ARG_FLAG_SUB));
  par->current->flags |= AP_ARG_FLAG_SUB;
  par->current->metavar = metavar;
  par->current->user1 = (void*)out_idx;
}

int ap_sub_add(ap* par, const char* name, ap** subpar)
{
  int err = 0;
  ap_sub* sub = ap_cb_malloc(par, sizeof(ap_sub));
  ap_check_arg(par);
  if (!sub)
    return AP_ERR_NOMEM;
  if ((err = ap_init_full(subpar, NULL, par->ctxcb))) {
    ap_cb_free(par, sub, sizeof(*sub));
    return err;
  }
  sub->identifier = name;
  sub->next = par->current->user;
  sub->par = *subpar;
  par->current->user = sub;
  return 0;
}

void ap_end(ap* par)
{
  ap_check_arg(par);
  if (par->current->flags & AP_ARG_FLAG_SUB)
    /* if this fails, then you didn't add any subparsers with ap_sub_add() */
    assert(par->current->user);
  else
    /* if this fails, there wasn't an ap_type_xxx call on the argument */
    assert(!!par->current->cb);
  par->current = NULL;
}

void ap_type_custom(ap* par, ap_cb callback, void* user)
{
  ap_check_arg(par);
  par->current->cb = callback;
  par->current->user = user;
}

void ap_custom_dtor(ap* par, int enable)
{
  int flag = enable * AP_ARG_FLAG_DESTRUCTOR;
  ap_check_arg(par);
  assert(enable == 0 || enable == 1);
  par->current->flags = (par->current->flags & ~AP_ARG_FLAG_DESTRUCTOR) | flag;
}

int ap_flag_cb(void* uptr, ap_cb_data* pdata)
{
  int* out = (int*)uptr;
  (void)(pdata);
  *out = 1;
  return 0;
}

void ap_type_flag(ap* par, int* out)
{
  ap_type_custom(par, ap_flag_cb, (void*)out);
  par->current->flags |= AP_ARG_FLAG_COALESCE;
}

int ap_int_cb(void* uptr, ap_cb_data* pdata)
{
  if (!sscanf(pdata->arg, "%i", (int*)uptr))
    return ap_arg_error(pdata, "invalid integer argument");
  return pdata->arg_len;
}

void ap_type_int(ap* par, int* out)
{
  ap_type_custom(par, ap_int_cb, (void*)out);
  ap_metavar(par, "NUM");
}

int ap_str_cb(void* uptr, ap_cb_data* pdata)
{
  const char** out = (const char**)uptr;
  if (!pdata->arg)
    return ap_arg_error(pdata, "expected an argument");
  *out = pdata->arg;
  return pdata->arg_len;
}

void ap_type_str(ap* par, const char** out)
{
  ap_type_custom(par, ap_str_cb, (void*)out);
}

typedef struct ap_enum {
  const char** choices;
  int* out;
  char* metavar;
} ap_enum;

int ap_enum_cb(void* uptr, ap_cb_data* pdata)
{
  ap_enum* e = (ap_enum*)uptr;
  const char** cur;
  int i;
  if (pdata->destroy) {
    ap_cb_free(pdata->parser, e->metavar, strlen(e->metavar));
    ap_cb_free(pdata->parser, e, sizeof(*e));
    return AP_ERR_NONE;
  }
  for (cur = e->choices, i = 0; *cur; cur++, i++) {
    if (!strcmp(*cur, pdata->arg)) {
      *e->out = i;
      return pdata->arg_len;
    }
  }
  return ap_arg_error(pdata, "invalid choice for argument");
}

int ap_type_enum(ap* par, int* out, const char** choices)
{
  ap_enum* e;
  /* don't pass NULL in */
  assert(choices);
  /* you must pass at least one choice */
  assert(choices[0]);
  e = ap_cb_malloc(par, sizeof(ap_enum));
  if (!e)
    return AP_ERR_NOMEM;
  memset(e, 0, sizeof(*e));
  e->choices = choices;
  e->out = out;
  {
    /* build metavar */
    size_t mvs = 2;
    const char** cur;
    char* metavar_ptr;
    for (cur = choices; *cur; cur++) {
      /* make space for comma + length of string */
      mvs += (mvs != 2) + strlen(*cur);
    }
    e->metavar = malloc(sizeof(char) * mvs + 1);
    if (!e->metavar) {
      ap_cb_free(par, e, sizeof(*e));
      return AP_ERR_NOMEM;
    }
    metavar_ptr = e->metavar;
    *(metavar_ptr++) = '{';
    for (cur = choices; *cur; cur++) {
      size_t l = strlen(*cur);
      if (metavar_ptr != e->metavar + 1)
        *(metavar_ptr++) = ',';
      memcpy(metavar_ptr, *cur, l);
      metavar_ptr += l;
    }
    *(metavar_ptr++) = '}';
    *(metavar_ptr++) = '\0';
  }
  ap_type_custom(par, ap_enum_cb, (void*)e);
  ap_metavar(par, e->metavar);
  ap_custom_dtor(par, 1);
  return AP_ERR_NONE;
}

int ap_help_cb(void* uptr, ap_cb_data* pdata)
{
  int err;
  (void)uptr;
  (void)pdata;
  if ((err = ap_show_help(pdata->parser)))
    return err;
  return AP_ERR_EXIT;
}

void ap_type_help(ap* par)
{
  ap_type_custom(par, ap_help_cb, NULL);
  ap_help(par, "show this help text and exit");
}

int ap_version_cb(void* uptr, ap_cb_data* pdata)
{
  int err;
  if ((err = ap_pstrs(pdata->parser, ap_cb_err, "%s\n", (const char*)uptr)))
    return err;
  return AP_ERR_EXIT;
}

void ap_type_version(ap* par, const char* version)
{
  ap_type_custom(par, ap_version_cb, (void*)version);
  ap_help(par, "show version text and exit");
}

typedef struct ap_parser {
  int argc;
  const char* const* argv;
  int idx;
  int arg_idx;
  int arg_len;
} ap_parser;

void ap_parser_init(ap_parser* ctx, int argc, const char* const* argv)
{
  ctx->argc = argc;
  ctx->argv = argv;
  ctx->idx = 0;
  ctx->arg_idx = 0;
  ctx->arg_len = (ctx->idx == ctx->argc) ? 0 : (int)strlen(ctx->argv[ctx->idx]);
}

void ap_parser_advance(ap_parser* ctx, int amt)
{
  if (!amt)
    return;
  /* if this fails, you tried to run the parser backwards. this isn't possible
   * at the moment. */
  assert(amt > 0);
  /* if this fails, you tried to get more chars after exhausting input args. */
  assert(ctx->idx < ctx->argc);
  /* if this fails, you asked for too many characters from the same argument. */
  assert(amt <= (ctx->arg_len - ctx->arg_idx));
  ctx->arg_idx += amt;
  if (ctx->arg_idx == ctx->arg_len) {
    ctx->idx++;
    ctx->arg_idx = 0;
    ctx->arg_len =
        (ctx->idx == ctx->argc) ? 0 : (int)strlen(ctx->argv[ctx->idx]);
  }
}

const char* ap_parser_cur(ap_parser* ctx)
{
  return (ctx->idx == ctx->argc || ctx->arg_idx == ctx->arg_len)
             ? NULL
             : ctx->argv[ctx->idx] + ctx->arg_idx;
}

int ap_parse_internal(ap* par, ap_parser* ctx);

int ap_parse_internal_part(ap* par, ap_arg* arg, ap_parser* ctx)
{
  int cb_ret, cb_sub_idx = 0;
  if (!(arg->flags & AP_ARG_FLAG_SUB)) {
    ap_cb_data cbd = {0};
    do {
      cbd.arg = ap_parser_cur(ctx);
      cbd.arg_len = cbd.arg ? ctx->arg_len : 0;
      cbd.idx = cb_sub_idx++;
      cbd.more = 0;
      cbd.reserved = arg;
      cbd.parser = par;
      cb_ret = arg->cb(arg->user, &cbd);
      if (cb_ret < 0)
        /* callback encountered error in parse */
        return cb_ret;
      /* callbacks should always only parse up to end of string */
      assert(cb_ret <= cbd.arg_len);
      cbd.idx++;
      ap_parser_advance(ctx, cb_ret);
    } while (cbd.more);
  } else {
    ap_sub* sub = arg->user;
    /* if this fails, then you forgot to call ap_sub_add */
    assert(sub);
    if (!sub->identifier) {
      /* immediately trigger parsing */
      return ap_parse_internal(sub->par, ctx);
    } else {
      const char* cmp = ap_parser_cur(ctx);
      if (!cmp)
        return AP_ERR_PARSE;
      while (sub) {
        if (!strcmp(sub->identifier, cmp))
          goto found;
        sub = sub->next;
      }
      /* (error) couldn't find subparser */
      return AP_ERR_PARSE;
    found:
      ap_parser_advance(ctx, (int)strlen(sub->identifier));
      return ap_parse_internal(sub->par, ctx);
    }
  }
  return AP_ERR_NONE;
}

ap_arg* ap_find_next_positional(ap_arg* arg)
{
  while (arg && (arg->flags & AP_ARG_FLAG_OPT)) {
    arg = arg->next;
  }
  return arg;
}

typedef struct ap_iter {
  ap_arg* arg;
  ap* parent;
} ap_iter;

ap_iter ap_iter_init(ap* parent)
{
  ap_iter out;
  while (parent && !parent->args)
    parent = parent->parent;
  out.arg = parent ? parent->args : NULL;
  out.parent = parent;
  return out;
}

void ap_iter_next(ap_iter* iter)
{
  assert(iter->arg);
  if (!(iter->arg = iter->arg->next))
    *iter = ap_iter_init(iter->parent->parent);
}

int ap_parse_internal(ap* par, ap_parser* ctx)
{
  int err;
  ap_arg* next_positional = ap_find_next_positional(par->args);
  while (ctx->idx < ctx->argc) {
    if (ap_parser_cur(ctx)[0] == '-' &&
        (ap_parser_cur(ctx)[1] && ap_parser_cur(ctx)[1] != '-')) {
      /* optional "-O..." */
      int saved_idx = ctx->idx;
      ap_parser_advance(ctx, 1);
      while (ctx->idx == saved_idx && ap_parser_cur(ctx) &&
             *ap_parser_cur(ctx)) {
        /* accumulate chained short opts */
        ap_iter iter;
        char opt_short = *ap_parser_cur(ctx);
        for (iter = ap_iter_init(par); iter.arg; ap_iter_next(&iter)) {
          ap_arg* search = iter.arg;
          if ((search->flags & AP_ARG_FLAG_OPT) &&
              search->opt_short == opt_short) {
            /* found arg with matching short opt */
            /* step over option char */
            ap_parser_advance(ctx, 1);
            if ((err = ap_parse_internal_part(par, search, ctx)) < 0)
              return err;
            /* if this fails, your callback advanced to the next argument, but
             * did not fully consume that argument */
            assert(ctx->idx != saved_idx ? !ctx->arg_idx : 1);
            break;
          }
        }
        if (!iter.arg)
          /* arg not found */
          return AP_ERR_PARSE;
        /* arg found and parsing must continue */
        continue;
      }
    } else if (
        ap_parser_cur(ctx)[0] == '-' && ap_parser_cur(ctx)[1] == '-' &&
        ap_parser_cur(ctx)[2]) {
      /* long optional "--option..."*/
      ap_iter iter;
      ap_parser_advance(ctx, 2);
      for (iter = ap_iter_init(par); iter.arg; ap_iter_next(&iter)) {
        ap_arg* search = iter.arg;
        if ((search->flags & AP_ARG_FLAG_OPT) &&
            !strcmp(search->opt_long, ap_parser_cur(ctx))) {
          /* found arg with matching long opt */
          int prev_idx = ctx->idx;
          /* step over long opt name */
          ap_parser_advance(ctx, (int)strlen(search->opt_long));
          if ((err = ap_parse_internal_part(par, search, ctx)) < 0)
            return err;
          /* if this fails, your callback did not consume every character of the
           * argument (it returned a value less than the argument length) */
          (void)prev_idx, assert(ctx->idx != prev_idx);
          break;
        }
      }
      if (!iter.arg)
        /* arg not found */
        return AP_ERR_PARSE;
      /* arg found and parsing must continue */
      continue;
    } else if (!next_positional) {
      /* no more positional args */
      return AP_ERR_PARSE;
    } else {
      /* positional, includes "-" and "--" and "" */
      int part_ret = 0, prev_idx = ctx->idx;
      if ((part_ret = ap_parse_internal_part(par, next_positional, ctx)) < 0)
        return part_ret;
      /* if this fails, your callback did not consume every character of the
       * argument (it returned a value less than the argument length) */
      (void)prev_idx, assert(ctx->idx != prev_idx);
      next_positional = ap_find_next_positional(next_positional->next);
    }
  }
  if (next_positional)
    return ap_arg_error_internal(par, next_positional, "expected an argument");
  return AP_ERR_NONE;
}

int ap_parse(ap* par, int argc, const char* const* argv)
{
  ap_parser parser;
  ap_parser_init(&parser, argc, argv);
  return ap_parse_internal(par, &parser);
}

int ap_show_usage(ap* par) { return ap_usage(par, ap_cb_out); }

int ap_show_help(ap* par)
{
  int err = AP_ERR_NONE;
  if ((err = ap_show_usage(par)))
    return err;
  if ((err = ap_pstrs(par, ap_cb_out, "\n")))
    return err;
  if (par->description &&
      (err = ap_pstrs(par, ap_cb_out, "\n%s\n", par->description)))
    return err;
  {
    int any = 0;
    ap_arg* arg;
    for (arg = par->args; arg; arg = arg->next) {
      /* positional arguments */
      if (arg->flags & AP_ARG_FLAG_OPT)
        continue;
      if (!(any++) &&
          (err = ap_pstrs(par, ap_cb_out, "\npositional arguments:\n")))
        return err;
      if ((err = ap_pstrs(par, ap_cb_out, "  ")) ||
          (err = ap_show_argspec(par, arg, ap_cb_out, 1)) ||
          (err = ap_pstrs(par, ap_cb_out, "\n")))
        return err;
      if (arg->help && (err = ap_pstrs(par, ap_cb_out, "    %s\n", arg->help)))
        return err;
    }
    for (any = 0, arg = par->args; arg; arg = arg->next) {
      /* optional arguments */
      if (!(arg->flags & AP_ARG_FLAG_OPT))
        continue;
      assert(arg->opt_long || arg->opt_short);
      if (!(any++) &&
          (err = ap_pstrs(par, ap_cb_out, "\noptional arguments:\n")))
        return err;
      if ((err = ap_pstrs(par, ap_cb_out, "  ")) ||
          (err = ap_show_argspec(par, arg, ap_cb_out, 1)) ||
          (err = ap_pstrs(par, ap_cb_out, "\n")))
        return err;
      if (arg->help && (err = ap_pstrs(par, ap_cb_out, "    %s\n", arg->help)))
        return err;
    }
  }
  if (par->epilog && (err = ap_pstrs(par, ap_cb_out, "\n%s\n", par->epilog)))
    return err;
  return err;
}
#endif /* MPTEST_USE_APARSE */

#if MPTEST_USE_APARSE
/* bits/util/ntstr/strstr_n */
MPTEST_INTERNAL const char*
mptest__strstr_n(const char* s, const char* sub, mptest_size sub_size) {
    while (*s) {
        const char* sa = s;
        mptest_size pos = 0;
        while (*sa && (pos != sub_size)) {
            if (*sa != sub[pos]) {
                break;
            }
            sa++;
            pos++;
        }
        if (pos == sub_size) {
            return s;
        }
        s++;
    }
    return MPTEST_NULL;
}
#endif /* MPTEST_USE_APARSE */

/* bits/types/char */
MPTEST__STATIC_ASSERT(mptest__char_is_one_byte, sizeof(mptest_char) == 1);

/* bits/container/str */
/* Maximum size, without null terminator */
#define MPTEST__STR_SHORT_SIZE_MAX                                                \
    (((sizeof(mptest__str) - sizeof(mptest_size)) / (sizeof(mptest_char)) - 1))

#define MPTEST__STR_GET_SHORT(str) !((str)->_size_short & 1)
#define MPTEST__STR_SET_SHORT(str, short)                                         \
    do {                                                                      \
        mptest_size temp = short;                                                 \
        (str)->_size_short &= ~((mptest_size)1);                                  \
        (str)->_size_short |= !temp;                                          \
    } while (0)
#define MPTEST__STR_GET_SIZE(str) ((str)->_size_short >> 1)
#define MPTEST__STR_SET_SIZE(str, size)                                           \
    do {                                                                      \
        mptest_size temp = size;                                                  \
        (str)->_size_short &= 1;                                              \
        (str)->_size_short |= temp << 1;                                      \
    } while (0)
#define MPTEST__STR_DATA(str)                                                     \
    (MPTEST__STR_GET_SHORT(str) ? ((mptest_char*)&((str)->_alloc)) : (str)->_data)

/* Round up to multiple of 32 */
#define MPTEST__STR_ROUND_ALLOC(alloc) (((alloc + 1) + 32) & (~((mptest_size)32)))

#if MPTEST_DEBUG

#define MPTEST__STR_CHECK(str)                                                    \
    do {                                                                      \
        if (MPTEST__STR_GET_SHORT(str)) {                                         \
            /* If string is short, the size must always be less than */       \
            /* MPTEST__STR_SHORT_SIZE_MAX. */                                     \
            MPTEST_ASSERT(MPTEST__STR_GET_SIZE(str) <= MPTEST__STR_SHORT_SIZE_MAX);       \
        } else {                                                              \
            /* If string is long, the size can still be less, but the other   \
             */                                                               \
            /* fields must be valid. */                                       \
            /* Ensure there is enough space */                                \
            MPTEST_ASSERT((str)->_alloc >= MPTEST__STR_GET_SIZE(str));                \
            /* Ensure that the _data field isn't NULL if the size is 0 */     \
            if (MPTEST__STR_GET_SIZE(str) > 0) {                                  \
                MPTEST_ASSERT((str)->_data != MPTEST_NULL);                           \
            }                                                                 \
            /* Ensure that if _alloc is 0 then _data is NULL */               \
            if ((str)->_alloc == 0) {                                         \
                MPTEST_ASSERT((str)->_data == MPTEST_NULL);                           \
            }                                                                 \
        }                                                                     \
        /* Ensure that there is a null-terminator */                          \
        MPTEST_ASSERT(MPTEST__STR_DATA(str)[MPTEST__STR_GET_SIZE(str)] == '\0');          \
    } while (0)

#else

#define MPTEST__STR_CHECK(str) MPTEST__UNUSED(str)

#endif

void mptest__str_init(mptest__str* str) {
    str->_size_short = 0;
    MPTEST__STR_DATA(str)[0] = '\0';
}

void mptest__str_destroy(mptest__str* str) {
    if (!MPTEST__STR_GET_SHORT(str)) {
        if (str->_data != MPTEST_NULL) {
            MPTEST_FREE(str->_data);
        }
    }
}

mptest_size mptest__str_size(const mptest__str* str) { return MPTEST__STR_GET_SIZE(str); }

MPTEST_INTERNAL int mptest__str_grow(mptest__str* str, mptest_size new_size) {
    mptest_size old_size = MPTEST__STR_GET_SIZE(str);
    MPTEST__STR_CHECK(str);
    if (MPTEST__STR_GET_SHORT(str)) {
        if (new_size <= MPTEST__STR_SHORT_SIZE_MAX) {
            /* Can still be a short str */
            MPTEST__STR_SET_SIZE(str, new_size);
        } else {
            /* Needs allocation */
            mptest_size new_alloc =
              MPTEST__STR_ROUND_ALLOC(new_size + (new_size >> 1));
            mptest_char* new_data =
              (mptest_char*)MPTEST_MALLOC(sizeof(mptest_char) * (new_alloc + 1));
            mptest_size i;
            if (new_data == MPTEST_NULL) {
                return -1;
            }
            /* Copy data from old string */
            for (i = 0; i < old_size; i++) {
                new_data[i] = MPTEST__STR_DATA(str)[i];
            }
            /* Fill in the remaining fields */
            MPTEST__STR_SET_SHORT(str, 0);
            MPTEST__STR_SET_SIZE(str, new_size);
            str->_data = new_data;
            str->_alloc = new_alloc;
        }
    } else {
        if (new_size > str->_alloc) {
            /* Needs allocation */
            mptest_size new_alloc =
              MPTEST__STR_ROUND_ALLOC(new_size + (new_size >> 1));
            mptest_char* new_data;
            if (str->_alloc == 0) {
                new_data =
                  (mptest_char*)MPTEST_MALLOC(sizeof(mptest_char) * (new_alloc + 1));
            } else {
                new_data = (mptest_char*)MPTEST_REALLOC(
                  str->_data, sizeof(mptest_char) * (new_alloc + 1));
            }
            if (new_data == MPTEST_NULL) {
                return -1;
            }
            str->_data = new_data;
            str->_alloc = new_alloc;
        }
        MPTEST__STR_SET_SIZE(str, new_size);
    }
    /* Null terminate */
    MPTEST__STR_DATA(str)[MPTEST__STR_GET_SIZE(str)] = '\0';
    MPTEST__STR_CHECK(str);
    return 0;
}

int mptest__str_push(mptest__str* str, mptest_char chr) {
    int err = 0;
    mptest_size old_size = MPTEST__STR_GET_SIZE(str);
    if ((err = mptest__str_grow(str, old_size + 1))) {
        return err;
    }
    MPTEST__STR_DATA(str)[old_size] = chr;
    MPTEST__STR_CHECK(str);
    return err;
}

mptest_size mptest__str_slen(const mptest_char* s) {
    mptest_size out = 0;
    while (*(s++)) {
        out++;
    }
    return out;
}

int mptest__str_init_s(mptest__str* str, const mptest_char* s) {
    int err = 0;
    mptest_size i;
    mptest_size sz = mptest__str_slen(s);
    mptest__str_init(str);
    if ((err = mptest__str_grow(str, sz))) {
        return err;
    }
    for (i = 0; i < sz; i++) {
        MPTEST__STR_DATA(str)[i] = s[i];
    }
    return err;
}

int mptest__str_init_n(mptest__str* str, const mptest_char* chrs, mptest_size n) {
    int err = 0;
    mptest_size i;
    mptest__str_init(str);
    if ((err = mptest__str_grow(str, n))) {
        return err;
    }
    for (i = 0; i < n; i++) {
        MPTEST__STR_DATA(str)[i] = chrs[i];
    }
    return err;
}

int mptest__str_cat(mptest__str* str, const mptest__str* other) {
    int err = 0;
    mptest_size i;
    mptest_size n = MPTEST__STR_GET_SIZE(other);
    mptest_size old_size = MPTEST__STR_GET_SIZE(str);
    if ((err = mptest__str_grow(str, old_size + n))) {
        return err;
    }
    /* Copy data */
    for (i = 0; i < n; i++) {
        MPTEST__STR_DATA(str)[old_size + i] = MPTEST__STR_DATA(other)[i];
    }
    MPTEST__STR_CHECK(str);
    return err;
}

int mptest__str_cat_n(mptest__str* str, const mptest_char* chrs, mptest_size n) {
    int err = 0;
    mptest_size i;
    mptest_size old_size = MPTEST__STR_GET_SIZE(str);
    if ((err = mptest__str_grow(str, old_size + n))) {
        return err;
    }
    /* Copy data */
    for (i = 0; i < n; i++) {
        MPTEST__STR_DATA(str)[old_size + i] = chrs[i];
    }
    MPTEST__STR_CHECK(str);
    return err;
}

int mptest__str_cat_s(mptest__str* str, const mptest_char* chrs) {
    mptest_size chrs_size = mptest__str_slen(chrs);
    return mptest__str_cat_n(str, chrs, chrs_size);
}

int mptest__str_insert(mptest__str* str, mptest_size index, mptest_char chr) {
    int err = 0;
    mptest_size i;
    mptest_size old_size = MPTEST__STR_GET_SIZE(str);
    /* bounds check */
    MPTEST_ASSERT(index <= MPTEST__STR_GET_SIZE(str));
    if ((err = mptest__str_grow(str, old_size + 1))) {
        return err;
    }
    /* Shift data */
    if (old_size != 0) {
        for (i = old_size; i >= index + 1; i--) {
            MPTEST__STR_DATA(str)[i] = MPTEST__STR_DATA(str)[i - 1];
        }
    }
    MPTEST__STR_DATA(str)[index] = chr;
    MPTEST__STR_CHECK(str);
    return err;
}

const mptest_char* mptest__str_get_data(const mptest__str* str) {
    return MPTEST__STR_DATA(str);
}

int mptest__str_init_copy(mptest__str* str, const mptest__str* in) {
    mptest_size i;
    int err = 0;
    mptest__str_init(str);
    if ((err = mptest__str_grow(str, mptest__str_size(in)))) {
        return err;
    }
    for (i = 0; i < mptest__str_size(str); i++) {
        MPTEST__STR_DATA(str)[i] = MPTEST__STR_DATA(in)[i];
    }
    return err;
}

void mptest__str_init_move(mptest__str* str, mptest__str* old) {
    MPTEST__STR_CHECK(old);
    *str = *old;
    mptest__str_init(old);
}

int mptest__str_cmp(const mptest__str* str_a, const mptest__str* str_b) {
    mptest_size a_len = mptest__str_size(str_a);
    mptest_size b_len = mptest__str_size(str_b);
    mptest_size i = 0;
    const mptest_char* a_data = mptest__str_get_data(str_a);
    const mptest_char* b_data = mptest__str_get_data(str_b);
    while (1) {
        if (i == a_len || i == b_len) {
            break;
        }
        if (a_data[i] < b_data[i]) {
            return -1;
        } else if (a_data[i] > b_data[i]) {
            return 1;
        }
        i++;
    }
    if (i == a_len) {
        if (i == b_len) {
            return 0;
        } else {
            return -1;
        }
    }
    return 1;
}

void mptest__str_clear(mptest__str* str) {
    MPTEST__STR_SET_SIZE(str, 0);
    MPTEST__STR_DATA(str)[0] = '\0';
}

void mptest__str_cut_end(mptest__str* str, mptest_size new_size) {
    MPTEST_ASSERT(new_size <= MPTEST__STR_GET_SIZE(str));
    MPTEST__STR_SET_SIZE(str, new_size);
    MPTEST__STR_DATA(str)[new_size] = '\0';
}

#if MPTEST_USE_DYN_ALLOC
#if MPTEST_USE_SYM
/* bits/container/str_view */
void mptest__str_view_init(mptest__str_view* view, const mptest__str* other) {
    view->_size = mptest__str_size(other);
    view->_data = mptest__str_get_data(other);
}

void mptest__str_view_init_s(mptest__str_view* view, const mptest_char* chars) {
    view->_size = mptest__str_slen(chars);
    view->_data = chars;
}

void mptest__str_view_init_n(mptest__str_view* view, const mptest_char* chars, mptest_size n) {
    view->_size = n;
    view->_data = chars;
}

void mptest__str_view_init_null(mptest__str_view* view) {
    view->_size = 0;
    view->_data = MPTEST_NULL;
}

mptest_size mptest__str_view_size(const mptest__str_view* view) {
    return view->_size;
}

const mptest_char* mptest__str_view_get_data(const mptest__str_view* view) {
    return view->_data;
}

int mptest__str_view_cmp(const mptest__str_view* view_a, const mptest__str_view* view_b) {
    mptest_size a_len = mptest__str_view_size(view_a);
    mptest_size b_len = mptest__str_view_size(view_b);
    const mptest_char* a_data = mptest__str_view_get_data(view_a);
    const mptest_char* b_data = mptest__str_view_get_data(view_b);
    mptest_size i;
    if (a_len < b_len) {
        return -1;
    } else if (a_len > b_len) {
        return 1;
    }
    for (i = 0; i < a_len; i++) {
        if (a_data[i] != b_data[i]) {
            if (a_data[i] < b_data[i]) {
                return -1;
            } else {
                return 1;
            }
        }
    }
    return 0;
}
#endif /* MPTEST_USE_DYN_ALLOC */
#endif /* MPTEST_USE_SYM */

#if MPTEST_USE_SYM
/* bits/types/fixed/int32 */
/* If this fails, you need to define MPTEST_INT32_TYPE to a signed integer type
 * that is 32 bits wide. */
MPTEST__STATIC_ASSERT(mptest__int32_is_4_bytes, sizeof(mptest_int32) == 4);
#endif /* MPTEST_USE_SYM */

/* mptest */
#if MPTEST_USE_APARSE

const char* mptest__aparse_help = "Runs tests.";

const char* mptest__aparse_version = "0.1.0";

MPTEST_INTERNAL int mptest__aparse_opt_test_cb(void* user, ap_cb_data* pdata)
{
  mptest__aparse_state* test_state = (mptest__aparse_state*)user;
  mptest__aparse_name* name;
  if (!pdata->arg_len && !pdata->idx) {
    pdata->more = 1;
    return 0;
  }
  name = MPTEST_MALLOC(sizeof(mptest__aparse_name));
  if (name == MPTEST_NULL) {
    return AP_ERR_NOMEM;
  }
  if (test_state->opt_test_name_head == MPTEST_NULL) {
    test_state->opt_test_name_head = name;
    test_state->opt_test_name_tail = name;
  } else {
    test_state->opt_test_name_tail->next = name;
    test_state->opt_test_name_tail = name;
  }
  name->name = pdata->arg;
  name->name_len = (mptest_size)pdata->arg_len;
  name->next = MPTEST_NULL;
  return pdata->arg_len;
}

MPTEST_INTERNAL int mptest__aparse_opt_suite_cb(void* user, ap_cb_data* pdata)
{
  mptest__aparse_state* test_state = (mptest__aparse_state*)user;
  mptest__aparse_name* name;
  if (!pdata->arg_len && !pdata->idx) {
    pdata->more = 1;
    return 0;
  }
  name = MPTEST_MALLOC(sizeof(mptest__aparse_name));
  if (name == MPTEST_NULL) {
    return AP_ERR_NOMEM;
  }
  if (test_state->opt_suite_name_head == MPTEST_NULL) {
    test_state->opt_suite_name_head = name;
    test_state->opt_suite_name_tail = name;
  } else {
    test_state->opt_suite_name_tail->next = name;
    test_state->opt_suite_name_tail = name;
  }
  name->name = pdata->arg;
  name->name_len = (mptest_size)pdata->arg_len;
  name->next = MPTEST_NULL;
  return pdata->arg_len;
}

MPTEST_INTERNAL int mptest__aparse_init(struct mptest__state* state)
{
  int err = 0;
  mptest__aparse_state* test_state = &state->aparse_state;
  ap* aparse = (state->aparse_state.aparse = ap_init("prog"));
  if (!aparse)
    return MPTEST__RESULT_ERROR;
  test_state->opt_test_name_head = MPTEST_NULL;
  test_state->opt_test_name_tail = MPTEST_NULL;
  test_state->opt_suite_name_tail = MPTEST_NULL;
  test_state->opt_suite_name_tail = MPTEST_NULL;
  test_state->opt_leak_check = 0;

  if ((err = ap_opt(aparse, 't', "test")))
    return err;
  ap_type_custom(aparse, mptest__aparse_opt_test_cb, test_state);
  ap_help(aparse, "Run tests that match the substring NAME");
  ap_metavar(aparse, "NAME");

  if ((err = ap_opt(aparse, 's', "suite")))
    return err;
  ap_type_custom(aparse, mptest__aparse_opt_suite_cb, test_state);
  ap_help(aparse, "Run suites that match the substring NAME");
  ap_metavar(aparse, "NAME");

  if ((err = ap_opt(aparse, 0, "fault-check"))) {
    return err;
  }
  ap_type_flag(aparse, &test_state->opt_fault_check);
  ap_help(aparse, "Instrument tests by simulating faults");

#if MPTEST_USE_LEAKCHECK
  if ((err = ap_opt(aparse, 0, "leak-check"))) {
    return err;
  }
  ap_type_flag(aparse, &test_state->opt_leak_check);
  ap_help(aparse, "Instrument tests with memory leak checking");

  if ((err = ap_opt(aparse, 0, "leak-check-pass"))) {
    return err;
  }
  ap_type_flag(aparse, &test_state->opt_leak_check_pass);
  ap_help(
      aparse, "Pass memory allocations without recording, useful with ASAN");
#endif

  if ((err = ap_opt(aparse, 'h', "help"))) {
    return err;
  }
  ap_type_help(aparse);

  if ((err = ap_opt(aparse, 0, "version"))) {
    return err;
  }
  ap_type_version(aparse, mptest__aparse_version);
  return 0;
}

MPTEST_INTERNAL void mptest__aparse_destroy(struct mptest__state* state)
{
  mptest__aparse_state* test_state = &state->aparse_state;
  mptest__aparse_name* name = test_state->opt_test_name_head;
  while (name) {
    mptest__aparse_name* next = name->next;
    MPTEST_FREE(name);
    name = next;
  }
  name = test_state->opt_suite_name_head;
  while (name) {
    mptest__aparse_name* next = name->next;
    MPTEST_FREE(name);
    name = next;
  }
  ap_destroy(test_state->aparse);
}

MPTEST_API int mptest__state_init_argv(
    struct mptest__state* state, int argc, const char* const* argv)
{
  int stat = 0;
  mptest__state_init(state);
  stat = ap_parse(state->aparse_state.aparse, argc - 1, argv + 1);
  if (stat == AP_ERR_EXIT) {
    return 1;
  } else if (stat != 0) {
    return stat;
  }
  if (state->aparse_state.opt_fault_check) {
    state->fault_checking = MPTEST__FAULT_MODE_SET;
  }
#if MPTEST_USE_LEAKCHECK
  if (state->aparse_state.opt_leak_check) {
    state->leakcheck_state.test_leak_checking = MPTEST__LEAKCHECK_MODE_ON;
  }
  if (state->aparse_state.opt_leak_check_pass) {
    state->leakcheck_state.fall_through = 1;
  }
#endif
  return stat;
}

MPTEST_INTERNAL int mptest__aparse_match_test_name(
    struct mptest__state* state, const char* test_name)
{
  mptest__aparse_name* name = state->aparse_state.opt_test_name_head;
  if (name == MPTEST_NULL) {
    return 1;
  }
  while (name) {
    if (mptest__strstr_n(test_name, name->name, name->name_len)) {
      return 1;
    }
    name = name->next;
  }
  return 0;
}

MPTEST_INTERNAL int mptest__aparse_match_suite_name(
    struct mptest__state* state, const char* suite_name)
{
  mptest__aparse_name* name = state->aparse_state.opt_suite_name_head;
  if (name == MPTEST_NULL) {
    return 1;
  }
  while (name) {
    if (mptest__strstr_n(suite_name, name->name, name->name_len)) {
      return 1;
    }
    name = name->next;
  }
  return 0;
}

#endif

/* mptest */
#if MPTEST_USE_FUZZ

MPTEST_INTERNAL void mptest__fuzz_init(struct mptest__state* state)
{
  mptest__fuzz_state* fuzz_state = &state->fuzz_state;
  fuzz_state->rand_state = 0xDEADBEEF;
  fuzz_state->fuzz_active = 0;
  fuzz_state->fuzz_iterations = 1;
  fuzz_state->fuzz_fail_iteration = 0;
  fuzz_state->fuzz_fail_seed = 0;
}

MPTEST_API mptest_rand mptest__fuzz_rand(struct mptest__state* state)
{
  /* ANSI C LCG (wikipedia) */
  static const mptest_rand a = 1103515245;
  static const mptest_rand m = ((mptest_rand)1) << 31;
  static const mptest_rand c = 12345;
  mptest__fuzz_state* fuzz_state = &state->fuzz_state;
  return (
      fuzz_state->rand_state =
          ((a * fuzz_state->rand_state + c) % m) & 0xFFFFFFFF);
}

MPTEST_API void mptest__fuzz_next_test(struct mptest__state* state, int iterations)
{
  mptest__fuzz_state* fuzz_state = &state->fuzz_state;
  fuzz_state->fuzz_iterations = iterations;
  fuzz_state->fuzz_active = 1;
}

MPTEST_INTERNAL mptest__result
mptest__fuzz_run_test(struct mptest__state* state, mptest__test_func test_func)
{
  int i = 0;
  int iters = 1;
  mptest__result res = MPTEST__RESULT_PASS;
  mptest__fuzz_state* fuzz_state = &state->fuzz_state;
  /* Reset fail variables */
  fuzz_state->fuzz_fail_iteration = 0;
  fuzz_state->fuzz_fail_seed = 0;
  if (fuzz_state->fuzz_active) {
    iters = fuzz_state->fuzz_iterations;
  }
  for (i = 0; i < iters; i++) {
    /* Save the start state */
    mptest_rand start_state = fuzz_state->rand_state;
    int should_finish = 0;
    res = mptest__state_do_run_test(state, test_func);
    /* Note: we don't handle MPTEST__RESULT_SKIPPED because it is handled in
     * the calling function. */
    if (res != MPTEST__RESULT_PASS) {
      should_finish = 1;
    }
    if (should_finish) {
      /* Save fail context */
      fuzz_state->fuzz_fail_iteration = i;
      fuzz_state->fuzz_fail_seed = start_state;
      fuzz_state->fuzz_failed = 1;
      break;
    }
  }
  fuzz_state->fuzz_active = 0;
  return res;
}

MPTEST_INTERNAL void mptest__fuzz_print(struct mptest__state* state)
{
  mptest__fuzz_state* fuzz_state = &state->fuzz_state;
  if (fuzz_state->fuzz_failed) {
    mptest__state_print_indent(state);
    printf(
        "    ...on fuzz iteration " MPTEST__COLOR_EMPHASIS
        "%i" MPTEST__COLOR_RESET " with seed " MPTEST__COLOR_EMPHASIS
        "%lX" MPTEST__COLOR_RESET "\n",
        fuzz_state->fuzz_fail_iteration, fuzz_state->fuzz_fail_seed);
  }
  fuzz_state->fuzz_failed = 0;
  /* Reset fuzz iterations, needs to be done after every fuzzed test */
  fuzz_state->fuzz_iterations = 1;
}

#endif

/* mptest */
#if MPTEST_USE_LEAKCHECK

/* Set the guard bytes in `header`. */
MPTEST_INTERNAL void
mptest__leakcheck_header_set_guard(struct mptest__leakcheck_header* header)
{
  /* Currently we choose 0xCC as the guard byte, it's a stripe of ones and
   * zeroes that looks like 11001100b */
  size_t i;
  for (i = 0; i < MPTEST__LEAKCHECK_GUARD_BYTES_COUNT; i++) {
    header->guard_bytes[i] = 0xCC;
  }
}

/* Ensure that `header` has valid guard bytes. */
MPTEST_INTERNAL int
mptest__leakcheck_header_check_guard(struct mptest__leakcheck_header* header)
{
  size_t i;
  for (i = 0; i < MPTEST__LEAKCHECK_GUARD_BYTES_COUNT; i++) {
    if (header->guard_bytes[i] != 0xCC) {
      return 0;
    }
  }
  return 1;
}

/* Determine if `block` contains a `free()`able pointer. */
MPTEST_INTERNAL int
mptest__leakcheck_block_has_freeable(struct mptest__leakcheck_block* block)
{
  /* We can free the pointer if it was not freed or was not reallocated
   * earlier. */
  return !(
      block->flags & (MPTEST__LEAKCHECK_BLOCK_FLAG_FREED |
                      MPTEST__LEAKCHECK_BLOCK_FLAG_REALLOC_OLD));
}

/* Initialize a `struct mptest__leakcheck_block`.
 * If `prev` is NULL, then this function will not attempt to link `block` to
 * any previous element in the malloc linked list. */
MPTEST_INTERNAL void mptest__leakcheck_block_init(
    struct mptest__leakcheck_block* block, size_t size,
    struct mptest__leakcheck_block* prev,
    enum mptest__leakcheck_block_flags flags, const char* file, int line)
{
  block->block_size = size;
  /* Link current block to previous block */
  block->prev = prev;
  /* Link previous block to current block */
  if (prev) {
    block->prev->next = block;
  }
  block->next = NULL;
  /* Keep `realloc()` fields unpopulated for now */
  block->realloc_next = NULL;
  block->realloc_prev = NULL;
  block->flags = flags;
  /* Save source info */
  block->file = file;
  block->line = line;
}

/* Link a block to its respective header. */
MPTEST_INTERNAL void mptest__leakcheck_block_link_header(
    struct mptest__leakcheck_block* block,
    struct mptest__leakcheck_header* header)
{
  block->header = header;
  header->block = block;
}

/* Initialize malloc-checking state. */
MPTEST_INTERNAL void mptest__leakcheck_init(struct mptest__state* state)
{
  mptest__leakcheck_state* leakcheck_state = &state->leakcheck_state;
  leakcheck_state->test_leak_checking = 0;
  leakcheck_state->first_block = NULL;
  leakcheck_state->top_block = NULL;
  leakcheck_state->total_allocations = 0;
  leakcheck_state->total_calls = 0;
  leakcheck_state->fall_through = 0;
}

/* Destroy malloc-checking state. */
MPTEST_INTERNAL void mptest__leakcheck_destroy(struct mptest__state* state)
{
  /* Walk the malloc list, destroying everything */
  struct mptest__leakcheck_block* current = state->leakcheck_state.first_block;
  while (current) {
    struct mptest__leakcheck_block* prev = current;
    if (mptest__leakcheck_block_has_freeable(current)) {
      MPTEST_FREE(current->header);
    }
    current = current->next;
    MPTEST_FREE(prev);
  }
}

/* Reset (NOT destroy) malloc-checking state. */
/* For now, this is equivalent to a destruction. This may not be the case in
 * the future. */
MPTEST_INTERNAL void mptest__leakcheck_reset(struct mptest__state* state)
{
  /* Preserve `test_leak_checking` */
  mptest__leakcheck_mode test_leak_checking =
      state->leakcheck_state.test_leak_checking;
  /* Preserve fall_through */
  int fall_through = state->leakcheck_state.fall_through;
  mptest__leakcheck_destroy(state);
  mptest__leakcheck_init(state);
  state->leakcheck_state.test_leak_checking = test_leak_checking;
  state->leakcheck_state.fall_through = fall_through;
  state->leakcheck_state.oom_generated = 0;
}

/* Check the block record for leaks, returning 1 if there are any. */
MPTEST_INTERNAL int mptest__leakcheck_has_leaks(struct mptest__state* state)
{
  struct mptest__leakcheck_block* current = state->leakcheck_state.first_block;
  while (current) {
    if (mptest__leakcheck_block_has_freeable(current)) {
      return 1;
    }
    current = current->next;
  }
  return 0;
}

MPTEST_INTERNAL int
mptest__leakcheck_after_test(struct mptest__state* state, int res)
{
  if (state->leakcheck_state.test_leak_checking &&
      mptest__leakcheck_has_leaks(state)) {
    state->fail_reason = MPTEST__FAIL_REASON_LEAKED;
    return MPTEST__RESULT_FAIL;
  } else if (
      res == MPTEST__RESULT_OOM_DETECTED &&
      !state->leakcheck_state.oom_generated) {
    state->fail_reason = MPTEST__FAIL_REASON_OOM_FALSE_POSITIVE;
    return MPTEST__RESULT_ERROR;
  } else if (
      res == MPTEST__RESULT_OOM_DETECTED &&
      state->leakcheck_state.oom_generated) {
    return MPTEST__RESULT_PASS;
  } else if (
      res == MPTEST__RESULT_PASS && state->leakcheck_state.oom_generated) {
    state->fail_reason = MPTEST__FAIL_REASON_OOM_FALSE_NEGATIVE;
    return MPTEST__RESULT_ERROR;
  }
  return res;
}

MPTEST_API void* mptest__leakcheck_hook_malloc(
    struct mptest__state* state, const char* file, int line, size_t size)
{
  /* Header + actual memory block */
  char* base_ptr;
  /* Identical to `base_ptr` */
  struct mptest__leakcheck_header* header;
  /* Current block*/
  struct mptest__leakcheck_block* block_info;
  /* Pointer to return to the user */
  char* out_ptr;
  struct mptest__leakcheck_state* leakcheck_state = &state->leakcheck_state;
  if (!leakcheck_state->test_leak_checking) {
    return (char*)MPTEST_MALLOC(size);
  }
  if (mptest__fault(state, "malloc")) {
    state->leakcheck_state.oom_generated = 1;
    mptest_ex_oom_inject();
    return NULL;
  }
  if (leakcheck_state->fall_through) {
    leakcheck_state->total_calls++;
    return (char*)MPTEST_MALLOC(size);
  }
  /* Allocate the memory the user requested + space for the header */
  base_ptr = (char*)MPTEST_MALLOC(size + MPTEST__LEAKCHECK_HEADER_SIZEOF);
  if (base_ptr == NULL) {
    state->fail_data.memory_block = NULL;
    mptest_ex_nomem();
    mptest__longjmp_exec(state, MPTEST__FAIL_REASON_NOMEM, file, line, NULL);
  }
  /* Allocate memory for the block_info structure */
  block_info = (struct mptest__leakcheck_block*)MPTEST_MALLOC(
      sizeof(struct mptest__leakcheck_block));
  if (block_info == NULL) {
    state->fail_data.memory_block = NULL;
    mptest_ex_nomem();
    mptest__longjmp_exec(state, MPTEST__FAIL_REASON_NOMEM, file, line, NULL);
  }
  /* Setup the header */
  header = (struct mptest__leakcheck_header*)base_ptr;
  mptest__leakcheck_header_set_guard(header);
  /* Setup the block_info */
  if (leakcheck_state->first_block == NULL) {
    /* If `state->first_block == NULL`, then this is the first allocation.
     * Use NULL as the previous value, and then set the `first_block` and
     * `top_block` to the new block. */
    mptest__leakcheck_block_init(
        block_info, size, NULL, MPTEST__LEAKCHECK_BLOCK_FLAG_INITIAL, file,
        line);
    leakcheck_state->first_block = block_info;
    leakcheck_state->top_block = block_info;
  } else {
    /* If this isn't the first allocation, use `state->top_block` as the
     * previous block. */
    mptest__leakcheck_block_init(
        block_info, size, leakcheck_state->top_block,
        MPTEST__LEAKCHECK_BLOCK_FLAG_INITIAL, file, line);
    leakcheck_state->top_block = block_info;
  }
  /* Link the header and block_info together */
  mptest__leakcheck_block_link_header(block_info, header);
  /* Return the base pointer offset by the header amount */
  out_ptr = base_ptr + MPTEST__LEAKCHECK_HEADER_SIZEOF;
  /* Increment the total number of allocations */
  leakcheck_state->total_allocations++;
  /* Increment the total number of calls */
  leakcheck_state->total_calls++;
  return out_ptr;
}

MPTEST_API void mptest__leakcheck_hook_free(
    struct mptest__state* state, const char* file, int line, void* ptr)
{
  struct mptest__leakcheck_header* header;
  struct mptest__leakcheck_block* block_info;
  struct mptest__leakcheck_state* leakcheck_state = &state->leakcheck_state;
  if (!leakcheck_state->test_leak_checking || leakcheck_state->fall_through) {
    MPTEST_FREE(ptr);
    return;
  }
  if (ptr == NULL) {
    state->fail_data.memory_block = NULL;
    mptest_ex_bad_alloc();
    mptest__longjmp_exec(
        state, MPTEST__FAIL_REASON_FREE_OF_NULL, file, line, NULL);
  }
  /* Retrieve header by subtracting header size from pointer */
  header = (struct mptest__leakcheck_header*)((char*)ptr -
                                              MPTEST__LEAKCHECK_HEADER_SIZEOF);
  /* TODO: check for SIGSEGV here */
  if (!mptest__leakcheck_header_check_guard(header)) {
    state->fail_data.memory_block = ptr;
    mptest_ex_bad_alloc();
    mptest__longjmp_exec(
        state, MPTEST__FAIL_REASON_FREE_OF_INVALID, file, line, NULL);
  }
  block_info = header->block;
  /* Ensure that the pointer has not been freed or reallocated already */
  if (block_info->flags & MPTEST__LEAKCHECK_BLOCK_FLAG_FREED) {
    state->fail_data.memory_block = ptr;
    mptest_ex_bad_alloc();
    mptest__longjmp_exec(
        state, MPTEST__FAIL_REASON_REALLOC_OF_FREED, file, line, NULL);
  }
  if (block_info->flags & MPTEST__LEAKCHECK_BLOCK_FLAG_REALLOC_OLD) {
    state->fail_data.memory_block = ptr;
    mptest_ex_bad_alloc();
    mptest__longjmp_exec(
        state, MPTEST__FAIL_REASON_FREE_OF_REALLOCED, file, line, NULL);
  }
  /* We can finally `free()` the pointer */
  MPTEST_FREE(header);
  block_info->flags |= MPTEST__LEAKCHECK_BLOCK_FLAG_FREED;
  /* Decrement the total number of allocations */
  leakcheck_state->total_allocations--;
}

MPTEST_API void* mptest__leakcheck_hook_realloc(
    struct mptest__state* state, const char* file, int line, void* old_ptr,
    size_t new_size)
{
  /* New header + memory */
  char* base_ptr;
  struct mptest__leakcheck_header* old_header;
  struct mptest__leakcheck_header* new_header;
  struct mptest__leakcheck_block* old_block_info;
  struct mptest__leakcheck_block* new_block_info;
  /* Pointer to return to the user */
  char* out_ptr;
  struct mptest__leakcheck_state* leakcheck_state = &state->leakcheck_state;
  if (!old_ptr) {
    return mptest__leakcheck_hook_malloc(state, file, line, new_size);
  }
  if (!leakcheck_state->test_leak_checking) {
    return (void*)MPTEST_REALLOC(old_ptr, new_size);
  }
  if (mptest__fault(state, "realloc")) {
    state->leakcheck_state.oom_generated = 1;
    mptest_ex_oom_inject();
    return NULL;
  }
  if (leakcheck_state->fall_through) {
    leakcheck_state->total_calls++;
    return (char*)MPTEST_REALLOC(old_ptr, new_size);
  }
  old_header =
      (struct mptest__leakcheck_header*)((char*)old_ptr -
                                         MPTEST__LEAKCHECK_HEADER_SIZEOF);
  old_block_info = old_header->block;
  if (old_ptr == NULL) {
    state->fail_data.memory_block = NULL;
    mptest_ex_bad_alloc();
    mptest__longjmp_exec(
        state, MPTEST__FAIL_REASON_REALLOC_OF_NULL, file, line, NULL);
  }
  if (!mptest__leakcheck_header_check_guard(old_header)) {
    state->fail_data.memory_block = old_ptr;
    mptest_ex_bad_alloc();
    mptest__longjmp_exec(
        state, MPTEST__FAIL_REASON_REALLOC_OF_INVALID, file, line, NULL);
  }
  if (old_block_info->flags & MPTEST__LEAKCHECK_BLOCK_FLAG_FREED) {
    state->fail_data.memory_block = old_ptr;
    mptest_ex_bad_alloc();
    mptest__longjmp_exec(
        state, MPTEST__FAIL_REASON_REALLOC_OF_FREED, file, line, NULL);
  }
  if (old_block_info->flags & MPTEST__LEAKCHECK_BLOCK_FLAG_REALLOC_OLD) {
    state->fail_data.memory_block = old_ptr;
    mptest_ex_bad_alloc();
    mptest__longjmp_exec(
        state, MPTEST__FAIL_REASON_REALLOC_OF_REALLOCED, file, line, NULL);
  }
  /* Allocate the memory the user requested + space for the header */
  base_ptr =
      (char*)MPTEST_REALLOC(old_header, new_size + MPTEST__LEAKCHECK_HEADER_SIZEOF);
  if (base_ptr == NULL) {
    state->fail_data.memory_block = old_ptr;
    mptest_ex_nomem();
    mptest__longjmp_exec(state, MPTEST__FAIL_REASON_NOMEM, file, line, NULL);
  }
  /* Allocate memory for the new block_info structure */
  new_block_info = (struct mptest__leakcheck_block*)MPTEST_MALLOC(
      sizeof(struct mptest__leakcheck_block));
  if (new_block_info == NULL) {
    state->fail_data.memory_block = old_ptr;
    mptest_ex_nomem();
    mptest__longjmp_exec(state, MPTEST__FAIL_REASON_NOMEM, file, line, NULL);
  }
  /* Setup the header */
  new_header = (struct mptest__leakcheck_header*)base_ptr;
  /* Set the guard again (double bag it per se) */
  mptest__leakcheck_header_set_guard(new_header);
  /* Setup the block_info */
  if (leakcheck_state->first_block == NULL) {
    mptest__leakcheck_block_init(
        new_block_info, new_size, NULL,
        MPTEST__LEAKCHECK_BLOCK_FLAG_REALLOC_NEW, file, line);
    leakcheck_state->first_block = new_block_info;
    leakcheck_state->top_block = new_block_info;
  } else {
    mptest__leakcheck_block_init(
        new_block_info, new_size, leakcheck_state->top_block,
        MPTEST__LEAKCHECK_BLOCK_FLAG_REALLOC_NEW, file, line);
    leakcheck_state->top_block = new_block_info;
  }
  /* Mark `old_block_info` as reallocation target */
  old_block_info->flags |= MPTEST__LEAKCHECK_BLOCK_FLAG_REALLOC_OLD;
  /* Link the block with its respective header */
  mptest__leakcheck_block_link_header(new_block_info, new_header);
  /* Finally, indicate the new allocation in the realloc chain */
  old_block_info->realloc_next = new_block_info;
  new_block_info->realloc_prev = old_block_info;
  out_ptr = base_ptr + MPTEST__LEAKCHECK_HEADER_SIZEOF;
  /* Increment the total number of calls */
  leakcheck_state->total_calls++;
  return out_ptr;
}

MPTEST_API void mptest__leakcheck_set(struct mptest__state* state, int on)
{
  state->leakcheck_state.test_leak_checking = on;
}

MPTEST_API void mptest_ex_nomem(void) { mptest_ex(); }
MPTEST_API void mptest_ex_oom_inject(void) { mptest_ex(); }
MPTEST_API void mptest_ex_bad_alloc(void) { mptest_ex(); }

MPTEST_API void mptest_malloc_dump(void)
{
  struct mptest__state* state = &mptest__state_g;
  struct mptest__leakcheck_state* leakcheck_state = &state->leakcheck_state;
  struct mptest__leakcheck_block* block = leakcheck_state->first_block;
  while (block) {
    printf(
        "%p: %u bytes at %s:%i: %s%s%s%s",
        (void*)(((char*)block->header) + MPTEST__LEAKCHECK_HEADER_SIZEOF),
        (unsigned int)block->block_size, block->file, block->line,
        (block->flags & MPTEST__LEAKCHECK_BLOCK_FLAG_INITIAL) ? "I" : "-",
        (block->flags & MPTEST__LEAKCHECK_BLOCK_FLAG_FREED) ? "F" : "-",
        (block->flags & MPTEST__LEAKCHECK_BLOCK_FLAG_REALLOC_OLD) ? "O" : "-",
        (block->flags & MPTEST__LEAKCHECK_BLOCK_FLAG_REALLOC_NEW) ? "N" : "-");
    if (block->realloc_prev) {
      printf(
          " from %p", (void*)(((char*)block->realloc_prev->header) +
                              MPTEST__LEAKCHECK_HEADER_SIZEOF));
    }
    printf("\n");
    block = block->next;
  }
}

#endif

/* mptest */
#if MPTEST_USE_LONGJMP
/* Initialize longjmp state. */
MPTEST_INTERNAL void mptest__longjmp_init(struct mptest__state* state)
{
  state->longjmp_state.checking = MPTEST__FAIL_REASON_NONE;
  state->longjmp_state.reason = MPTEST__FAIL_REASON_NONE;
}

/* Destroy longjmp state. */
MPTEST_INTERNAL void mptest__longjmp_destroy(struct mptest__state* state)
{
  (void)(state);
}

/* Jumps back to either the out-of-test context or the within-assertion context
 * depending on if we wanted `reason` to happen or not. In other words, this
 * will fail the test if we weren't explicitly checking for `reason` to happen,
 * meaning `reason` was unexpected and thus an error. */
MPTEST_INTERNAL void mptest__longjmp_exec(
    struct mptest__state* state, mptest__fail_reason reason, const char* file,
    int line, const char* msg)
{
  state->longjmp_state.reason = reason;
  if (state->longjmp_state.checking == reason) {
    MPTEST_LONGJMP(state->longjmp_state.assert_context, 1);
  } else {
    state->fail_file = file;
    state->fail_line = line;
    state->fail_msg = msg;
    state->fail_reason = reason;
    MPTEST_LONGJMP(state->longjmp_state.test_context, 1);
  }
}

#else

/* TODO: write `mptest__longjmp_exec` for when longjmp isn't on
 */

#endif

/* mptest */
/* Initialize a test runner state. */
MPTEST_API void mptest__state_init(struct mptest__state* state)
{
  state->assertions = 0;
  state->total = 0;
  state->passes = 0;
  state->fails = 0;
  state->errors = 0;
  state->suite_passes = 0;
  state->suite_fails = 0;
  state->suite_failed = 0;
  state->suite_test_setup_cb = NULL;
  state->suite_test_teardown_cb = NULL;
  state->current_test = NULL;
  state->current_suite = NULL;
  state->fail_reason = (enum mptest__fail_reason)0;
  state->fail_msg = NULL;
  /* we do not initialize state->fail_data */
  state->fail_file = NULL;
  state->fail_line = 0;
  state->indent_lvl = 0;
  state->fault_checking = 0;
  state->fault_calls = 0;
  state->fault_fail_call_idx = -1;
  state->fault_failed = 0;
#if MPTEST_USE_LONGJMP
  mptest__longjmp_init(state);
#endif
#if MPTEST_USE_LEAKCHECK
  mptest__leakcheck_init(state);
#endif
#if MPTEST_USE_TIME
  mptest__time_init(state);
#endif
#if MPTEST_USE_APARSE
  mptest__aparse_init(state);
#endif
#if MPTEST_USE_FUZZ
  mptest__fuzz_init(state);
#endif
}

/* Destroy a test runner state. */
MPTEST_API void mptest__state_destroy(struct mptest__state* state)
{
  (void)(state);
#if MPTEST_USE_APARSE
  mptest__aparse_destroy(state);
#endif
#if MPTEST_USE_TIME
  mptest__time_destroy(state);
#endif
#if MPTEST_USE_LEAKCHECK
  mptest__leakcheck_destroy(state);
#endif
#if MPTEST_USE_LONGJMP
  mptest__longjmp_destroy(state);
#endif
}

/* Actually define (create storage space for) the global state */
struct mptest__state mptest__state_g;

/* Print report at the end of testing. */
MPTEST_API void mptest__state_report(struct mptest__state* state)
{
  if (state->suite_fails + state->suite_passes) {
    printf(
        MPTEST__COLOR_SUITE_NAME
        "%i" MPTEST__COLOR_RESET " suites: " MPTEST__COLOR_PASS
        "%i" MPTEST__COLOR_RESET " passed, " MPTEST__COLOR_FAIL
        "%i" MPTEST__COLOR_RESET " failed\n",
        state->suite_fails + state->suite_passes, state->suite_passes,
        state->suite_fails);
  }
  if (state->errors) {
    printf(
        MPTEST__COLOR_TEST_NAME
        "%i" MPTEST__COLOR_RESET " tests (" MPTEST__COLOR_EMPHASIS
        "%i" MPTEST__COLOR_RESET " assertions): " MPTEST__COLOR_PASS
        "%i" MPTEST__COLOR_RESET " passed, " MPTEST__COLOR_FAIL
        "%i" MPTEST__COLOR_RESET " failed, " MPTEST__COLOR_FAIL
        "%i" MPTEST__COLOR_RESET " errors",
        state->total, state->assertions, state->passes, state->fails,
        state->errors);
  } else {
    printf(
        MPTEST__COLOR_TEST_NAME
        "%i" MPTEST__COLOR_RESET " tests (" MPTEST__COLOR_EMPHASIS
        "%i" MPTEST__COLOR_RESET " assertions): " MPTEST__COLOR_PASS
        "%i" MPTEST__COLOR_RESET " passed, " MPTEST__COLOR_FAIL
        "%i" MPTEST__COLOR_RESET " failed",
        state->fails + state->passes, state->assertions, state->passes,
        state->fails);
  }
#if MPTEST_USE_TIME
  {
    clock_t program_end_time = clock();
    double elapsed_time =
        ((double)(program_end_time - state->time_state.program_start_time)) /
        CLOCKS_PER_SEC;
    printf(" in %f seconds", elapsed_time);
  }
#endif
  printf("\n");
}

/* Helper to indent to the current level if nested suites/tests are used. */
MPTEST_INTERNAL void mptest__state_print_indent(struct mptest__state* state)
{
  int i;
  for (i = 0; i < state->indent_lvl; i++) {
    printf("  ");
  }
}

/* Print a formatted source location. */
MPTEST_INTERNAL void mptest__print_source_location(const char* file, int line)
{
  printf(
      MPTEST__COLOR_EMPHASIS "%s" MPTEST__COLOR_RESET ":" MPTEST__COLOR_EMPHASIS
                             "%i" MPTEST__COLOR_RESET,
      file, line);
}

/* fuck string.h */
MPTEST_INTERNAL int mptest__streq(const char* a, const char* b)
{
  while (1) {
    if (*a == '\0') {
      if (*b == '\0') {
        return 1;
      } else {
        return 0;
      }
    } else if (*b == '\0') {
      return 0;
    }
    if (*a != *b) {
      return 0;
    }
    a++;
    b++;
  }
}

MPTEST_INTERNAL int mptest__fault(struct mptest__state* state, const char* class)
{
  MPTEST__UNUSED(class);
  if (state->fault_checking == MPTEST__FAULT_MODE_ONE &&
      state->fault_calls == state->fault_fail_call_idx) {
    state->fault_calls++;
    return 1;
  } else if (
      state->fault_checking == MPTEST__FAULT_MODE_SET &&
      state->fault_calls == state->fault_fail_call_idx) {
    return 1;
  } else {
    state->fault_calls++;
  }
  return 0;
}

MPTEST_API int mptest_fault(const char* class)
{
  return mptest__fault(&mptest__state_g, class);
}

MPTEST_INTERNAL void mptest__fault_reset(struct mptest__state* state)
{
  state->fault_calls = 0;
  state->fault_failed = 0;
  state->fault_fail_call_idx = -1;
}

MPTEST_INTERNAL mptest__result
mptest__fault_run_test(struct mptest__state* state, mptest__test_func test_func)
{
  int max_iter = 0;
  int i;
  mptest__result res = MPTEST__RESULT_PASS;
  /* Suspend fault checking */
  int fault_prev = state->fault_checking;
  state->fault_checking = MPTEST__FAULT_MODE_OFF;
  mptest__fault_reset(state);
  res = mptest__state_do_run_test(state, test_func);
  /* Reinstate fault checking */
  state->fault_checking = fault_prev;
  max_iter = state->fault_calls;
  if (res != MPTEST__RESULT_PASS) {
    /* Initial test failed. */
    return res;
  }
  for (i = 0; i < max_iter; i++) {
    mptest__fault_reset(state);
    state->fault_fail_call_idx = i;
    res = mptest__state_do_run_test(state, test_func);
    if (res != MPTEST__RESULT_PASS) {
      /* Save fail context */
      state->fault_failed = 1;
      break;
    }
  }
  return res;
}

MPTEST_API void mptest__fault_set(struct mptest__state* state, int on)
{
  state->fault_checking = on;
}

/* Ran when setting up for a test before it is run. */
MPTEST_INTERNAL mptest__result mptest__state_before_test(
    struct mptest__state* state, mptest__test_func test_func,
    const char* test_name)
{
  state->current_test = test_name;
#if MPTEST_USE_LEAKCHECK
  if (state->leakcheck_state.test_leak_checking) {
    mptest__leakcheck_reset(state);
  }
#endif
  /* indent if we are running a suite */
  mptest__state_print_indent(state);
  printf(
      "test " MPTEST__COLOR_TEST_NAME "%s" MPTEST__COLOR_RESET "... ",
      state->current_test);
  fflush(stdout);
#if MPTEST_USE_APARSE
  if (!mptest__aparse_match_test_name(state, test_name)) {
    return MPTEST__RESULT_SKIPPED;
  }
#endif
  if (state->fault_checking == MPTEST__FAULT_MODE_OFF) {
#if MPTEST_USE_FUZZ
    return mptest__fuzz_run_test(state, test_func);
#else
    return mptest__state_do_run_test(state, test_func);
#endif
  } else {
    return mptest__fault_run_test(state, test_func);
  }
}

MPTEST_INTERNAL mptest__result mptest__state_do_run_test(
    struct mptest__state* state, mptest__test_func test_func)
{
  mptest__result res;
#if MPTEST_USE_LEAKCHECK
  mptest__leakcheck_reset(state);
#endif
#if MPTEST_USE_LONGJMP
  if (MPTEST_SETJMP(state->longjmp_state.test_context) == 0) {
    res = test_func();
  } else {
    res = MPTEST__RESULT_ERROR;
  }
#else
  res = test_func();
#endif
#if MPTEST_USE_LEAKCHECK
  if ((res = mptest__leakcheck_after_test(state, res))) {
    return res;
  }
#endif
  return res;
}

/* Ran when a test is over. */
MPTEST_INTERNAL void
mptest__state_after_test(struct mptest__state* state, mptest__result res)
{
#if MPTEST_USE_LEAKCHECK
  int has_leaks = 0;
  if (state->leakcheck_state.test_leak_checking) {
    has_leaks = mptest__leakcheck_has_leaks(state);
    if (has_leaks && res == MPTEST__RESULT_PASS) {
      res = MPTEST__RESULT_FAIL;
      state->fail_reason = MPTEST__FAIL_REASON_LEAKED;
    }
  }
#endif
  if (res == MPTEST__RESULT_PASS) {
    /* Test passed -> print pass message */
    state->passes++;
    state->total++;
    printf(MPTEST__COLOR_PASS "passed" MPTEST__COLOR_RESET "\n");
  }
  if (res == MPTEST__RESULT_FAIL) {
    /* Test failed -> fail the current suite, print diagnostics */
    state->fails++;
    state->total++;
    if (state->current_suite) {
      state->suite_failed = 1;
    }
    printf(MPTEST__COLOR_FAIL "failed" MPTEST__COLOR_RESET "\n");
    if (state->fail_reason == MPTEST__FAIL_REASON_ASSERT_FAILURE) {
      /* Assertion failure -> show expression, message, source */
      mptest__state_print_indent(state);
      printf(
          "  " MPTEST__COLOR_FAIL "assertion failure" MPTEST__COLOR_RESET
          ": " MPTEST__COLOR_EMPHASIS "%s" MPTEST__COLOR_RESET "\n",
          state->fail_msg);
      /* If the message and expression are the same, don't print the
       * expression */
      if (!mptest__streq(
              state->fail_msg, (const char*)state->fail_data.string_data)) {
        mptest__state_print_indent(state);
        printf(
            "    expression: " MPTEST__COLOR_EMPHASIS "%s" MPTEST__COLOR_RESET
            "\n",
            (const char*)state->fail_data.string_data);
      }
      mptest__state_print_indent(state);
      /* Print source location */
      printf("    ...at ");
      mptest__print_source_location(state->fail_file, state->fail_line);
      printf("\n");
    }
#if MPTEST_USE_SYM
    if (state->fail_reason == MPTEST__FAIL_REASON_SYM_INEQUALITY) {
      /* Sym inequality -> show both syms, message, source */
      mptest__state_print_indent(state);
      printf(
          "  " MPTEST__COLOR_FAIL
          "assertion failure: s-expression inequality" MPTEST__COLOR_RESET
          ": " MPTEST__COLOR_EMPHASIS "%s" MPTEST__COLOR_RESET "\n",
          state->fail_msg);
      mptest__state_print_indent(state);
      printf("    actual:\n");
      mptest__sym_dump(
          state->fail_data.sym_fail_data.sym_actual, 0, state->indent_lvl + 6);
      printf("\n");
      mptest__state_print_indent(state);
      printf("    expected:\n");
      mptest__sym_dump(
          state->fail_data.sym_fail_data.sym_expected, 0,
          state->indent_lvl + 6);
      printf("\n");
      mptest__sym_check_destroy();
    }
#endif
#if MPTEST_USE_LEAKCHECK
    if (state->fail_reason == MPTEST__FAIL_REASON_LEAKED || has_leaks) {
      struct mptest__leakcheck_block* current =
          state->leakcheck_state.first_block;
      mptest__state_print_indent(state);
      printf("  " MPTEST__COLOR_FAIL
             "memory leak(s) detected" MPTEST__COLOR_RESET ":\n");
      while (current) {
        if (mptest__leakcheck_block_has_freeable(current)) {
          mptest__state_print_indent(state);
          printf(
              "    " MPTEST__COLOR_FAIL "leak" MPTEST__COLOR_RESET
              " of " MPTEST__COLOR_EMPHASIS "%lu" MPTEST__COLOR_RESET
              " bytes at " MPTEST__COLOR_EMPHASIS "%p" MPTEST__COLOR_RESET
              ":\n",
              (long unsigned int)current->block_size, (void*)current->header);
          mptest__state_print_indent(state);
          if (current->flags & MPTEST__LEAKCHECK_BLOCK_FLAG_INITIAL) {
            printf("      allocated with " MPTEST__COLOR_EMPHASIS
                   "malloc()" MPTEST__COLOR_RESET "\n");
          } else if (
              current->flags & MPTEST__LEAKCHECK_BLOCK_FLAG_REALLOC_NEW) {
            printf("      reallocated with " MPTEST__COLOR_EMPHASIS
                   "realloc()" MPTEST__COLOR_RESET ":\n");
            printf(
                "        ...from " MPTEST__COLOR_EMPHASIS
                "%p" MPTEST__COLOR_RESET "\n",
                (void*)current->realloc_prev);
          }
          mptest__state_print_indent(state);
          printf("      ...at ");
          mptest__print_source_location(current->file, current->line);
          printf("\n");
        }
        current = current->next;
      }
    }
#endif
  } else if (res == MPTEST__RESULT_ERROR) {
    state->errors++;
    state->total++;
    if (state->current_suite) {
      state->suite_failed = 1;
    }
    printf(MPTEST__COLOR_FAIL "error!" MPTEST__COLOR_RESET "\n");
    if (0) {
    }
#if MPTEST_USE_DYN_ALLOC
    if (state->fail_reason == MPTEST__FAIL_REASON_NOMEM) {
      mptest__state_print_indent(state);
      printf(
          "  " MPTEST__COLOR_FAIL "out of memory: " MPTEST__COLOR_RESET
          ": " MPTEST__COLOR_EMPHASIS "%s" MPTEST__COLOR_RESET,
          state->fail_msg);
    }
#endif
#if MPTEST_USE_SYM
    if (state->fail_reason == MPTEST__FAIL_REASON_SYM_SYNTAX) {
      /* Sym syntax error -> show message, source, error info */
      mptest__state_print_indent(state);
      printf(
          "  " MPTEST__COLOR_FAIL
          "s-expression syntax error" MPTEST__COLOR_RESET
          ": " MPTEST__COLOR_EMPHASIS "%s" MPTEST__COLOR_RESET
          ":" MPTEST__COLOR_EMPHASIS "%s" MPTEST__COLOR_RESET
          "at position %i\n",
          state->fail_msg, state->fail_data.sym_syntax_error_data.err_msg,
          (int)state->fail_data.sym_syntax_error_data.err_pos);
    }
#endif
#if MPTEST_USE_LONGJMP
    if (state->fail_reason == MPTEST__FAIL_REASON_UNCAUGHT_PROGRAM_ASSERT) {
      mptest__state_print_indent(state);
      printf(
          "  " MPTEST__COLOR_FAIL
          "uncaught assertion failure" MPTEST__COLOR_RESET
          ": " MPTEST__COLOR_EMPHASIS "%s" MPTEST__COLOR_RESET "\n",
          state->fail_msg);
      if (!mptest__streq(
              state->fail_msg, (const char*)state->fail_data.string_data)) {
        mptest__state_print_indent(state);
        printf(
            "    expression: " MPTEST__COLOR_EMPHASIS "%s" MPTEST__COLOR_RESET
            "\n",
            (const char*)state->fail_data.string_data);
      }
      mptest__state_print_indent(state);
      printf("    ...at ");
      mptest__print_source_location(state->fail_file, state->fail_line);
    }
#if MPTEST_USE_LEAKCHECK
    if (state->fail_reason == MPTEST__FAIL_REASON_NOMEM) {
      mptest__state_print_indent(state);
      printf("  " MPTEST__COLOR_FAIL "internal error: malloc() returned "
             "a null pointer" MPTEST__COLOR_RESET "\n");
      mptest__state_print_indent(state);
      printf("    ...at ");
      mptest__print_source_location(state->fail_file, state->fail_line);
      printf("\n");
    }
    if (state->fail_reason == MPTEST__FAIL_REASON_REALLOC_OF_NULL) {
      mptest__state_print_indent(state);
      printf("  " MPTEST__COLOR_FAIL "attempt to call realloc() on a NULL "
             "pointer" MPTEST__COLOR_RESET "\n");
      mptest__state_print_indent(state);
      printf("    ...at ");
      mptest__print_source_location(state->fail_file, state->fail_line);
      printf("\n");
    }
    if (state->fail_reason == MPTEST__FAIL_REASON_FREE_OF_NULL) {
      mptest__state_print_indent(state);
      printf("  " MPTEST__COLOR_FAIL "attempt to call free() on a NULL "
             "pointer" MPTEST__COLOR_RESET "\n");
      mptest__state_print_indent(state);
      printf("    ...at ");
      mptest__print_source_location(state->fail_file, state->fail_line);
      printf("\n");
    }
    if (state->fail_reason == MPTEST__FAIL_REASON_REALLOC_OF_INVALID) {
      mptest__state_print_indent(state);
      printf("  " MPTEST__COLOR_FAIL "attempt to call realloc() on an "
             "invalid pointer (pointer was not "
             "returned by malloc() or realloc())" MPTEST__COLOR_RESET ":\n");
      mptest__state_print_indent(state);
      printf("    pointer: %p\n", state->fail_data.memory_block);
      mptest__state_print_indent(state);
      printf("    ...at ");
      mptest__print_source_location(state->fail_file, state->fail_line);
      printf("\n");
    }
    if (state->fail_reason == MPTEST__FAIL_REASON_REALLOC_OF_FREED) {
      mptest__state_print_indent(state);
      printf("  " MPTEST__COLOR_FAIL
             "attempt to call realloc() on a pointer that was already "
             "freed" MPTEST__COLOR_RESET ":\n");
      mptest__state_print_indent(state);
      printf("    pointer: %p\n", state->fail_data.memory_block);
      mptest__state_print_indent(state);
      printf("    ...at ");
      mptest__print_source_location(state->fail_file, state->fail_line);
      printf("\n");
    }
    if (state->fail_reason == MPTEST__FAIL_REASON_REALLOC_OF_REALLOCED) {
      mptest__state_print_indent(state);
      printf("  " MPTEST__COLOR_FAIL
             "attempt to call realloc() on a pointer that was already "
             "reallocated" MPTEST__COLOR_RESET ":\n");
      mptest__state_print_indent(state);
      printf("    pointer: %p\n", state->fail_data.memory_block);
      mptest__state_print_indent(state);
      printf("    ...at ");
      mptest__print_source_location(state->fail_file, state->fail_line);
      printf("\n");
    }
    if (state->fail_reason == MPTEST__FAIL_REASON_FREE_OF_INVALID) {
      mptest__state_print_indent(state);
      printf("  " MPTEST__COLOR_FAIL "attempt to call free() on an "
             "invalid pointer (pointer was not "
             "returned by malloc() or free())" MPTEST__COLOR_RESET ":\n");
      mptest__state_print_indent(state);
      printf("    pointer: %p\n", state->fail_data.memory_block);
      mptest__state_print_indent(state);
      printf("    ...at ");
      mptest__print_source_location(state->fail_file, state->fail_line);
      printf("\n");
    }
    if (state->fail_reason == MPTEST__FAIL_REASON_FREE_OF_FREED) {
      mptest__state_print_indent(state);
      printf("  " MPTEST__COLOR_FAIL
             "attempt to call free() on a pointer that was already "
             "freed" MPTEST__COLOR_RESET ":\n");
      mptest__state_print_indent(state);
      printf("    pointer: %p\n", state->fail_data.memory_block);
      mptest__state_print_indent(state);
      printf("    ...at ");
      mptest__print_source_location(state->fail_file, state->fail_line);
      printf("\n");
    }
    if (state->fail_reason == MPTEST__FAIL_REASON_FREE_OF_FREED) {
      mptest__state_print_indent(state);
      printf("  " MPTEST__COLOR_FAIL
             "attempt to call free() on a pointer that was already "
             "freed" MPTEST__COLOR_RESET ":\n");
      mptest__state_print_indent(state);
      printf("    pointer: %p\n", state->fail_data.memory_block);
      mptest__state_print_indent(state);
      printf("    ...at ");
      mptest__print_source_location(state->fail_file, state->fail_line);
      printf("\n");
    }
    if (state->fail_reason == MPTEST__FAIL_REASON_OOM_FALSE_NEGATIVE) {
      mptest__state_print_indent(state);
      printf("  " MPTEST__COLOR_FAIL
             "test did not detect injected OOM" MPTEST__COLOR_RESET "\n");
    }
    if (state->fail_reason == MPTEST__FAIL_REASON_OOM_FALSE_POSITIVE) {
      mptest__state_print_indent(state);
      printf("  " MPTEST__COLOR_FAIL
             "test erroneously signaled OOM" MPTEST__COLOR_RESET "\n");
    }
#endif
#endif
  } else if (res == MPTEST__RESULT_SKIPPED) {
    printf("skipped\n");
  }
  if (res == MPTEST__RESULT_FAIL || res == MPTEST__RESULT_ERROR || has_leaks ||
      state->fail_reason == MPTEST__FAIL_REASON_LEAKED) {
#if MPTEST_USE_FUZZ
    /* Print fuzz information, if any */
    mptest__fuzz_print(state);
#endif
    if (state->fault_fail_call_idx != -1) {
      printf(
          "    ...at fault iteration " MPTEST__COLOR_EMPHASIS
          "%i" MPTEST__COLOR_RESET "\n",
          state->fault_fail_call_idx);
    }
  }
#if MPTEST_USE_LEAKCHECK
  /* Reset leak-checking state (IMPORTANT!) */
  mptest__leakcheck_reset(state);
#endif
}

MPTEST_API void mptest__run_test(
    struct mptest__state* state, mptest__test_func test_func,
    const char* test_name)
{
  mptest__result res = mptest__state_before_test(state, test_func, test_name);
  mptest__state_after_test(state, res);
}

/* Ran before a suite is executed. */
MPTEST_INTERNAL void mptest__state_before_suite(
    struct mptest__state* state, mptest__suite_func suite_func,
    const char* suite_name)
{
  state->current_suite = suite_name;
  state->suite_failed = 0;
  state->suite_test_setup_cb = NULL;
  state->suite_test_teardown_cb = NULL;
  mptest__state_print_indent(state);
  printf(
      "suite " MPTEST__COLOR_SUITE_NAME "%s" MPTEST__COLOR_RESET ":\n",
      state->current_suite);
  state->indent_lvl++;
#if MPTEST_USE_APARSE
  if (mptest__aparse_match_suite_name(state, suite_name)) {
    suite_func();
  }
#endif
}

/* Ran after a suite is executed. */
MPTEST_INTERNAL void mptest__state_after_suite(struct mptest__state* state)
{
  if (!state->suite_failed) {
    state->suite_passes++;
  } else {
    state->suite_fails++;
  }
  state->current_suite = NULL;
  state->suite_failed = 0;
  state->indent_lvl--;
}

MPTEST_API void mptest__run_suite(
    struct mptest__state* state, mptest__suite_func suite_func,
    const char* suite_name)
{
  mptest__state_before_suite(state, suite_func, suite_name);
  mptest__state_after_suite(state);
}

/* Fills state with information on pass. */
MPTEST_API void mptest__assert_pass(
    struct mptest__state* state, const char* msg, const char* assert_expr,
    const char* file, int line)
{
  MPTEST__UNUSED(msg);
  MPTEST__UNUSED(assert_expr);
  MPTEST__UNUSED(file);
  MPTEST__UNUSED(line);
  state->assertions++;
}

/* Fills state with information on failure. */
MPTEST_API void mptest__assert_fail(
    struct mptest__state* state, const char* msg, const char* assert_expr,
    const char* file, int line)
{
  state->fail_reason = MPTEST__FAIL_REASON_ASSERT_FAILURE;
  state->fail_msg = msg;
  state->fail_data.string_data = assert_expr;
  state->fail_file = file;
  state->fail_line = line;
  mptest_ex_assert_fail();
}

/* Dummy function to break on for test assert failures */
MPTEST_API void mptest_ex_assert_fail(void) { mptest_ex(); }

/* Dummy function to break on for program assert failures */
MPTEST_API void mptest_ex_uncaught_assert_fail(void) { mptest_ex(); }

MPTEST_API MPTEST_JMP_BUF* mptest__catch_assert_begin(struct mptest__state* state)
{
  state->longjmp_state.checking = MPTEST__FAIL_REASON_UNCAUGHT_PROGRAM_ASSERT;
  return &state->longjmp_state.assert_context;
}

MPTEST_API void mptest__catch_assert_end(struct mptest__state* state)
{
  state->longjmp_state.checking = 0;
}

MPTEST_API void mptest__catch_assert_fail(
    struct mptest__state* state, const char* msg, const char* assert_expr,
    const char* file, int line)
{
  state->fail_data.string_data = assert_expr;
  mptest__longjmp_exec(
      state, MPTEST__FAIL_REASON_UNCAUGHT_PROGRAM_ASSERT, file, line, msg);
}

MPTEST_API void mptest_ex(void) { return; }

/* mptest */
#if MPTEST_USE_SYM

typedef enum mptest__sym_type {
  MPTEST__SYM_TYPE_EXPR,
  MPTEST__SYM_TYPE_ATOM_STRING,
  MPTEST__SYM_TYPE_ATOM_NUMBER
} mptest__sym_type;

typedef union mptest__sym_data {
  mptest__str str;
  mptest_int32 num;
} mptest__sym_data;

typedef struct mptest__sym_tree {
  mptest__sym_type type;
  mptest_int32 first_child_ref;
  mptest_int32 next_sibling_ref;
  mptest__sym_data data;
} mptest__sym_tree;

void mptest__sym_tree_init(mptest__sym_tree* tree, mptest__sym_type type)
{
  tree->type = type;
  tree->first_child_ref = MPTEST__SYM_NONE;
  tree->next_sibling_ref = MPTEST__SYM_NONE;
}

void mptest__sym_tree_destroy(mptest__sym_tree* tree)
{
  if (tree->type == MPTEST__SYM_TYPE_ATOM_STRING) {
    mptest__str_destroy(&tree->data.str);
  }
}

MPTEST__VEC_DECL(mptest__sym_tree);
MPTEST__VEC_IMPL_FUNC(mptest__sym_tree, init)
MPTEST__VEC_IMPL_FUNC(mptest__sym_tree, destroy)
MPTEST__VEC_IMPL_FUNC(mptest__sym_tree, push)
MPTEST__VEC_IMPL_FUNC(mptest__sym_tree, size)
MPTEST__VEC_IMPL_FUNC(mptest__sym_tree, getref)
MPTEST__VEC_IMPL_FUNC(mptest__sym_tree, getcref)

struct mptest_sym {
  mptest__sym_tree_vec tree_storage;
};

void mptest__sym_init(mptest_sym* sym)
{
  mptest__sym_tree_vec_init(&sym->tree_storage);
}

void mptest__sym_destroy(mptest_sym* sym)
{
  mptest_size i;
  for (i = 0; i < mptest__sym_tree_vec_size(&sym->tree_storage); i++) {
    mptest__sym_tree_destroy(
        mptest__sym_tree_vec_getref(&sym->tree_storage, i));
  }
  mptest__sym_tree_vec_destroy(&sym->tree_storage);
}

MPTEST_INTERNAL mptest__sym_tree* mptest__sym_get(mptest_sym* sym, mptest_int32 ref)
{
  MPTEST_ASSERT(ref != MPTEST__SYM_NONE);
  return mptest__sym_tree_vec_getref(&sym->tree_storage, (mptest_size)ref);
}

MPTEST_INTERNAL const mptest__sym_tree*
mptest__sym_getcref(const mptest_sym* sym, mptest_int32 ref)
{
  MPTEST_ASSERT(ref != MPTEST__SYM_NONE);
  return mptest__sym_tree_vec_getcref(&sym->tree_storage, (mptest_size)ref);
}

MPTEST_INTERNAL int mptest__sym_new(
    mptest_sym* sym, mptest_int32 parent_ref, mptest_int32 prev_sibling_ref,
    mptest__sym_tree new_tree, mptest_int32* new_ref)
{
  int err = 0;
  mptest_int32 next_ref = (mptest_int32)mptest__sym_tree_vec_size(&sym->tree_storage);
  if ((err = mptest__sym_tree_vec_push(&sym->tree_storage, new_tree))) {
    return err;
  }
  *new_ref = next_ref;
  if (parent_ref != MPTEST__SYM_NONE) {
    if (prev_sibling_ref == MPTEST__SYM_NONE) {
      mptest__sym_tree* parent = mptest__sym_get(sym, parent_ref);
      parent->first_child_ref = *new_ref;
    } else {
      mptest__sym_tree* sibling = mptest__sym_get(sym, prev_sibling_ref);
      sibling->next_sibling_ref = *new_ref;
    }
  }
  return err;
}

MPTEST__VEC_DECL(mptest_sym_build);
MPTEST__VEC_IMPL_FUNC(mptest_sym_build, init)
MPTEST__VEC_IMPL_FUNC(mptest_sym_build, destroy)
MPTEST__VEC_IMPL_FUNC(mptest_sym_build, push)
MPTEST__VEC_IMPL_FUNC(mptest_sym_build, pop)
MPTEST__VEC_IMPL_FUNC(mptest_sym_build, getref)

#define MPTEST__SYM_PARSE_ERROR -1

typedef struct mptest__sym_parse {
  const char* str;
  mptest_size str_pos;
  mptest_size str_size;
  mptest_sym_build_vec stk;
  mptest_size stk_ptr;
  const char* error;
  mptest__str build_str;
} mptest__sym_parse;

void mptest__sym_parse_init(mptest__sym_parse* parse, const mptest__str_view in)
{
  parse->str = mptest__str_view_get_data(&in);
  parse->str_pos = 0;
  parse->str_size = mptest__str_view_size(&in);
  mptest_sym_build_vec_init(&parse->stk);
  parse->stk_ptr = 0;
  parse->error = MPTEST_NULL;
  mptest__str_init(&parse->build_str);
}

void mptest__sym_parse_destroy(mptest__sym_parse* parse)
{
  mptest_sym_build_vec_destroy(&parse->stk);
  mptest__str_destroy(&parse->build_str);
}

int mptest__sym_parse_next(mptest__sym_parse* parse)
{
  MPTEST_ASSERT(parse->str_pos <= parse->str_size);
  if (parse->str_pos == parse->str_size) {
    parse->str_pos++;
    return -1;
  } else {
    return parse->str[parse->str_pos++];
  }
}

MPTEST_INTERNAL int mptest__sym_parse_expr_begin(
    mptest__sym_parse* parse, mptest_sym_build* base_build)
{
  int err = 0;
  mptest_sym_build next_build;
  if (parse->stk_ptr == 0) {
    if ((err = mptest_sym_build_expr(base_build, &next_build))) {
      return err;
    }
  } else {
    if ((err = mptest_sym_build_expr(
             mptest_sym_build_vec_getref(&parse->stk, parse->stk_ptr - 1),
             &next_build))) {
      return err;
    }
  }
  if ((err = mptest_sym_build_vec_push(&parse->stk, next_build))) {
    return err;
  }
  parse->stk_ptr++;
  return err;
}

MPTEST_INTERNAL int mptest__sym_parse_expr_end(mptest__sym_parse* parse)
{
  if (parse->stk_ptr == 0) {
    parse->error = "unmatched ')'";
    return MPTEST__SYM_PARSE_ERROR;
  }
  parse->stk_ptr--;
  mptest_sym_build_vec_pop(&parse->stk);
  return 0;
}

MPTEST_INTERNAL int mptest__sym_parse_isblank(int ch)
{
  return (ch == '\n') || (ch == '\t') || (ch == '\r') || (ch == ' ');
}

MPTEST_INTERNAL int mptest__sym_parse_ispunc(int ch)
{
  return (ch == '(') || (ch == ')');
}

MPTEST_INTERNAL int mptest__sym_parse_hexdig(int ch)
{
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  } else if (ch >= 'A' && ch <= 'F') {
    return ch - 'A' + 10;
  } else if (ch >= 'a' && ch <= 'f') {
    return ch - 'a' + 10;
  } else {
    return -1;
  }
}

MPTEST_INTERNAL int mptest__sym_parse_esc(mptest__sym_parse* parse)
{
  int ch = mptest__sym_parse_next(parse);
  if (ch == -1) {
    parse->error = "unfinished escape sequence";
    return MPTEST__SYM_PARSE_ERROR;
  } else if (ch == 't') {
    return '\t';
  } else if (ch == 'r') {
    return '\r';
  } else if (ch == '0') {
    return '\0';
  } else if (ch == 'n') {
    return '\n';
  } else if (ch == 'x') {
    int out_ch = 0;
    int dig;
    ch = mptest__sym_parse_next(parse);
    if ((dig = mptest__sym_parse_hexdig(ch)) == -1) {
      parse->error = "invalid hex escape";
      return MPTEST__SYM_PARSE_ERROR;
    }
    out_ch = dig;
    ch = mptest__sym_parse_next(parse);
    if ((dig = mptest__sym_parse_hexdig(ch)) == -1) {
      parse->error = "invalid hex escape";
      return MPTEST__SYM_PARSE_ERROR;
    }
    out_ch *= 16;
    out_ch += dig;
    return out_ch;
  } else if (ch == 'u') {
    int out_ch = 0;
    int dig;
    ch = mptest__sym_parse_next(parse);
    if ((dig = mptest__sym_parse_hexdig(ch)) == -1) {
      parse->error = "invalid unicode escape";
      return MPTEST__SYM_PARSE_ERROR;
    }
    out_ch = dig;
    ch = mptest__sym_parse_next(parse);
    if ((dig = mptest__sym_parse_hexdig(ch)) == -1) {
      parse->error = "invalid unicode escape";
      return MPTEST__SYM_PARSE_ERROR;
    }
    out_ch *= 16;
    out_ch += dig;
    ch = mptest__sym_parse_next(parse);
    if ((dig = mptest__sym_parse_hexdig(ch)) == -1) {
      parse->error = "invalid unicode escape";
      return MPTEST__SYM_PARSE_ERROR;
    }
    out_ch *= 16;
    out_ch += dig;
    ch = mptest__sym_parse_next(parse);
    if ((dig = mptest__sym_parse_hexdig(ch)) == -1) {
      parse->error = "invalid unicode escape";
      return MPTEST__SYM_PARSE_ERROR;
    }
    out_ch *= 16;
    out_ch += dig;
    return out_ch;
  } else if (ch == '"') {
    return '"';
  } else {
    parse->error = "invalid escape character";
    return MPTEST__SYM_PARSE_ERROR;
  }
}

MPTEST_INTERNAL int mptest__sym_parse_gen_utf8(int codep, unsigned char* out_buf)
{
  if (codep <= 0x7F) {
    out_buf[0] = codep & 0x7F;
    return 1;
  } else if (codep <= 0x07FF) {
    out_buf[0] = (unsigned char)(((codep >> 6) & 0x1F) | 0xC0);
    out_buf[1] = (unsigned char)(((codep >> 0) & 0x3F) | 0x80);
    return 2;
  } else if (codep <= 0xFFFF) {
    out_buf[0] = (unsigned char)(((codep >> 12) & 0x0F) | 0xE0);
    out_buf[1] = (unsigned char)(((codep >> 6) & 0x3F) | 0x80);
    out_buf[2] = (unsigned char)(((codep >> 0) & 0x3F) | 0x80);
    return 3;
  } else if (codep <= 0x10FFFF) {
    out_buf[0] = (unsigned char)(((codep >> 18) & 0x07) | 0xF0);
    out_buf[1] = (unsigned char)(((codep >> 12) & 0x3F) | 0x80);
    out_buf[2] = (unsigned char)(((codep >> 6) & 0x3F) | 0x80);
    out_buf[3] = (unsigned char)(((codep >> 0) & 0x3F) | 0x80);
    return 4;
  } else {
    return -1;
  }
}

MPTEST_INTERNAL int mptest__sym_parse_do(
    mptest_sym_build* build_in, const mptest__str_view in, const char** err_msg,
    mptest_size* err_pos)
{
  int err = 0;
  mptest__sym_parse parse;
  mptest__sym_parse_init(&parse, in);
  while (1) {
    int ch = mptest__sym_parse_next(&parse);
    mptest_sym_build* build;
    if (parse.stk_ptr) {
      build = mptest_sym_build_vec_getref(&parse.stk, parse.stk_ptr - 1);
    } else {
      build = build_in;
    }
    mptest__str_clear(&parse.build_str);
    if (ch == -1) {
      break;
    } else if (ch == '(') {
      /* ( | Begin expression */
      if ((err = mptest__sym_parse_expr_begin(&parse, build_in))) {
        goto error;
      }
    } else if (ch == ')') {
      /* ) | End expression */
      if ((err = mptest__sym_parse_expr_end(&parse))) {
        goto error;
      }
    } else if (mptest__sym_parse_isblank(ch)) {
      /* <\s> | Whitespace */
      continue;
    } else if (ch == '0') {
      /* 0 | Start of hex literal, or just a zero */
      mptest_int32 num = 0;
      mptest_size saved_pos = parse.str_pos;
      int n = 0;
      ch = mptest__sym_parse_next(&parse);
      if (mptest__sym_parse_ispunc(ch) || mptest__sym_parse_isblank(ch) ||
          ch == -1) {
        /* 0 | Just a zero */
        parse.str_pos = saved_pos;
        if ((err = mptest_sym_build_num(build, 0))) {
          goto error;
        }
        continue;
      }
      if (ch != 'x') {
        parse.error = "invalid hex literal";
        err = MPTEST__SYM_PARSE_ERROR;
        goto error;
      }
      while (1) {
        int dig;
        saved_pos = parse.str_pos;
        ch = mptest__sym_parse_next(&parse);
        if (n == 8) {
          parse.error = "hex literal too long";
          err = MPTEST__SYM_PARSE_ERROR;
          goto error;
        }
        if ((dig = mptest__sym_parse_hexdig(ch)) != -1) {
          /* [0-9A-Fa-f] | Hex digit */
          num *= 16;
          num += dig;
        } else {
          if ((mptest__sym_parse_isblank(ch) || mptest__sym_parse_ispunc(ch) ||
               ch == -1) &&
              n != 0) {
            /* [\s)] | Continue */
            parse.str_pos = saved_pos;
            if ((err = mptest_sym_build_num(build, num))) {
              goto error;
            }
            break;
          } else {
            /* Everything else | Error */
            parse.error = "expected hex digits for hex literal";
            err = MPTEST__SYM_PARSE_ERROR;
            goto error;
          }
        }
        n++;
      }
    } else if (ch > '0' && ch <= '9') {
      /* 1-9 | Integer literal */
      mptest_int32 num = ch - '0';
      mptest_size saved_pos;
      int n = 1;
      while (1) {
        saved_pos = parse.str_pos;
        ch = mptest__sym_parse_next(&parse);
        if (n == 10) {
          parse.error = "decimal literal too long";
          err = MPTEST__SYM_PARSE_ERROR;
          goto error;
        }
        if (ch >= '0' && ch <= '9') {
          num *= 10;
          num += ch - '0';
        } else {
          if (mptest__sym_parse_isblank(ch) || mptest__sym_parse_ispunc(ch) ||
              ch == -1) {
            parse.str_pos = saved_pos;
            if ((err = mptest_sym_build_num(build, num))) {
              goto error;
            }
            break;
          } else {
            parse.error = "expected decimal digits for decimal literal";
            err = MPTEST__SYM_PARSE_ERROR;
            goto error;
          }
        }
        n++;
      }
    } else if (ch == '"') {
      /* " | String starter */
      while (1) {
        ch = mptest__sym_parse_next(&parse);
        if (ch == -1) {
          /* "<EOF> | Invalid, error */
          parse.error = "unfinished string literal";
          err = MPTEST__SYM_PARSE_ERROR;
          goto error;
        } else if (ch == '\\') {
          /* "\ | Escape sequence starter */
          int rune = mptest__sym_parse_esc(&parse);
          unsigned char ubuf[8];
          int ubuf_sz = 0;
          if (rune < 0) {
            err = rune;
            goto error;
          }
          if ((ubuf_sz = mptest__sym_parse_gen_utf8(rune, ubuf)) < 0) {
            parse.error = "invalid UTF-8 character number";
            err = MPTEST__SYM_PARSE_ERROR;
            goto error;
          }
          if ((err = mptest__str_cat_n(
                   &parse.build_str, (char*)ubuf, (mptest_size)ubuf_sz))) {
            goto error;
          }
        } else if (ch == '"') {
          /* "" | Finish string */
          if ((err = mptest_sym_build_str(
                   build, (const char*)mptest__str_get_data(&parse.build_str),
                   mptest__str_size(&parse.build_str)))) {
            goto error;
          }
          break;
        } else {
          /* <*> | Add to string */
          char ch_char = (char)ch;
          if ((err = mptest__str_cat_n(&parse.build_str, &ch_char, 1))) {
            goto error;
          }
        }
      }
    } else if (ch == '\'') {
      /* ' | Char starter */
      int rune;
      unsigned char ubuf[8];
      int ubuf_sz = 0;
      ch = mptest__sym_parse_next(&parse);
      if (ch == -1) {
        parse.error = "expected character for character literal";
        err = MPTEST__SYM_PARSE_ERROR;
        goto error;
      } else if (ch == '\\') {
        rune = mptest__sym_parse_esc(&parse);
      } else {
        rune = ch;
      }
      if (rune < 0) {
        err = rune;
        goto error;
      }
      if ((ubuf_sz = mptest__sym_parse_gen_utf8(rune, ubuf)) < 0) {
        parse.error = "invalid UTF-8 character number";
        err = MPTEST__SYM_PARSE_ERROR;
        goto error;
      }
      ch = mptest__sym_parse_next(&parse);
      if (ch == -1 || ch != '\'') {
        parse.error = "expected ' to close character literal";
        err = MPTEST__SYM_PARSE_ERROR;
        goto error;
      }
      if ((err = mptest_sym_build_num(build, rune))) {
        goto error;
      }
    } else {
      /* <*> | Add to atom */
      char ch_char = (char)ch;
      if ((err = mptest__str_cat_n(&parse.build_str, &ch_char, 1))) {
        goto error;
      }
      while (1) {
        mptest_size saved_pos = parse.str_pos;
        ch = mptest__sym_parse_next(&parse);
        if (mptest__sym_parse_isblank(ch) || mptest__sym_parse_ispunc(ch) ||
            ch == -1) {
          /* [\s()<EOF>] | Build string */
          if ((err = mptest_sym_build_str(
                   build, (const char*)mptest__str_get_data(&parse.build_str),
                   mptest__str_size(&parse.build_str)))) {
            goto error;
          }
          parse.str_pos = saved_pos;
          break;
        } else {
          /* <*> | Add to string */
          ch_char = (char)ch;
          if ((err = mptest__str_cat_n(&parse.build_str, &ch_char, 1))) {
            goto error;
          }
        }
      }
    }
  }
  if (parse.stk_ptr) {
    parse.error = "unmatched '('";
    err = MPTEST__SYM_PARSE_ERROR;
    goto error;
  }
error:
  *err_pos = parse.str_pos;
  *err_msg = parse.error;
  mptest__sym_parse_destroy(&parse);
  return err;
}

MPTEST_INTERNAL void mptest__sym_dump_r(
    mptest_sym* sym, mptest_int32 parent_ref, mptest_int32 begin, mptest_int32 indent)
{
  mptest__sym_tree* tree;
  mptest_int32 child_ref;
  mptest_int32 i;
  if (parent_ref == MPTEST__SYM_NONE) {
    return;
  }
  tree = mptest__sym_get(sym, parent_ref);
  if (tree->first_child_ref == MPTEST__SYM_NONE) {
    if (tree->type == MPTEST__SYM_TYPE_ATOM_NUMBER) {
      printf(MPTEST__COLOR_SYM_INT "%i" MPTEST__COLOR_RESET, tree->data.num);
    } else if (tree->type == MPTEST__SYM_TYPE_ATOM_STRING) {
      int has_special = 0;
      const char* sbegin = mptest__str_get_data(&tree->data.str);
      const char* end = sbegin + mptest__str_size(&tree->data.str);
      while (sbegin != end) {
        if (*sbegin < 32 || *sbegin > 126) {
          has_special = 1;
          break;
        }
        sbegin++;
      }
      printf(MPTEST__COLOR_SYM_STR);
      if (has_special) {
        printf("\"");
        sbegin = mptest__str_get_data(&tree->data.str);
        while (sbegin != end) {
          if (*sbegin < 32 || *sbegin > 126) {
            printf("\\x%02X", *sbegin);
          } else {
            printf("%c", *sbegin);
          }
          sbegin++;
        }
        printf("\"");
      } else {
        printf("%s", mptest__str_get_data(&tree->data.str));
      }
      printf(MPTEST__COLOR_RESET);
    } else if (tree->type == MPTEST__SYM_TYPE_EXPR) {
      printf("()");
    }
  } else {
    if (begin != indent) {
      printf("\n");
      for (i = 0; i < indent; i++) {
        printf(" ");
      }
    }
    printf("(");
    child_ref = tree->first_child_ref;
    while (child_ref != MPTEST__SYM_NONE) {
      mptest__sym_tree* child = mptest__sym_get(sym, child_ref);
      mptest__sym_dump_r(sym, child_ref, begin, indent + 2);
      child_ref = child->next_sibling_ref;
      if (child_ref != MPTEST__SYM_NONE) {
        printf(" ");
      }
    }
    printf(")");
  }
}

MPTEST_INTERNAL void
mptest__sym_dump(mptest_sym* sym, mptest_int32 parent_ref, mptest_int32 indent)
{
  mptest_int32 i;
  for (i = 0; i < indent; i++) {
    printf(" ");
  }
  mptest__sym_dump_r(sym, parent_ref, indent, indent);
}

MPTEST_INTERNAL int mptest__sym_equals(
    mptest_sym* sym, mptest_sym* other, mptest_int32 sym_ref, mptest_int32 other_ref)
{
  mptest__sym_tree* parent_tree;
  mptest__sym_tree* other_tree;
  if ((sym_ref == other_ref) && sym_ref == MPTEST__SYM_NONE) {
    return 1;
  } else if (sym_ref == MPTEST__SYM_NONE || other_ref == MPTEST__SYM_NONE) {
    return 0;
  }
  parent_tree = mptest__sym_get(sym, sym_ref);
  other_tree = mptest__sym_get(other, other_ref);
  if (parent_tree->type != other_tree->type) {
    return 0;
  } else {
    if (parent_tree->type == MPTEST__SYM_TYPE_ATOM_NUMBER) {
      if (parent_tree->data.num != other_tree->data.num) {
        return 0;
      }
      return 1;
    } else if (parent_tree->type == MPTEST__SYM_TYPE_ATOM_STRING) {
      if (mptest__str_cmp(&parent_tree->data.str, &other_tree->data.str) != 0) {
        return 0;
      }
      return 1;
    } else if (parent_tree->type == MPTEST__SYM_TYPE_EXPR) {
      mptest_int32 parent_child_ref = parent_tree->first_child_ref;
      mptest_int32 other_child_ref = other_tree->first_child_ref;
      mptest__sym_tree* parent_child;
      mptest__sym_tree* other_child;
      while (parent_child_ref != MPTEST__SYM_NONE &&
             other_child_ref != MPTEST__SYM_NONE) {
        if (!mptest__sym_equals(
                sym, other, parent_child_ref, other_child_ref)) {
          return 0;
        }
        parent_child = mptest__sym_get(sym, parent_child_ref);
        other_child = mptest__sym_get(other, other_child_ref);
        parent_child_ref = parent_child->next_sibling_ref;
        other_child_ref = other_child->next_sibling_ref;
      }
      return parent_child_ref == other_child_ref;
    }
    return 0;
  }
}

MPTEST_API void mptest_sym_build_init(
    mptest_sym_build* build, mptest_sym* sym, mptest_int32 parent_ref,
    mptest_int32 prev_child_ref)
{
  build->sym = sym;
  build->parent_ref = parent_ref;
  build->prev_child_ref = prev_child_ref;
}

MPTEST_API void mptest_sym_build_destroy(mptest_sym_build* build)
{
  MPTEST__UNUSED(build);
}

MPTEST_API int mptest_sym_build_expr(mptest_sym_build* build, mptest_sym_build* sub)
{
  mptest__sym_tree new_tree;
  mptest_int32 new_child_ref;
  int err = 0;
  mptest__sym_tree_init(&new_tree, MPTEST__SYM_TYPE_EXPR);
  if ((err = mptest__sym_new(
           build->sym, build->parent_ref, build->prev_child_ref, new_tree,
           &new_child_ref))) {
    return err;
  }
  build->prev_child_ref = new_child_ref;
  mptest_sym_build_init(sub, build->sym, new_child_ref, MPTEST__SYM_NONE);
  return err;
}

MPTEST_API int
mptest_sym_build_str(mptest_sym_build* build, const char* str, mptest_size str_size)
{
  mptest__sym_tree new_tree;
  mptest_int32 new_child_ref;
  int err = 0;
  mptest__sym_tree_init(&new_tree, MPTEST__SYM_TYPE_ATOM_STRING);
  if ((err =
           mptest__str_init_n(&new_tree.data.str, (const mptest_char*)str, str_size))) {
    return err;
  }
  if ((err = mptest__sym_new(
           build->sym, build->parent_ref, build->prev_child_ref, new_tree,
           &new_child_ref))) {
    return err;
  }
  build->prev_child_ref = new_child_ref;
  return err;
}

MPTEST_API int mptest_sym_build_cstr(mptest_sym_build* build, const char* cstr)
{
  return mptest_sym_build_str(build, cstr, mptest__str_slen((const mptest_char*)cstr));
}

MPTEST_API int mptest_sym_build_num(mptest_sym_build* build, mptest_int32 num)
{
  mptest__sym_tree new_tree;
  mptest_int32 new_child_ref;
  int err = 0;
  mptest__sym_tree_init(&new_tree, MPTEST__SYM_TYPE_ATOM_NUMBER);
  new_tree.data.num = num;
  if ((err = mptest__sym_new(
           build->sym, build->parent_ref, build->prev_child_ref, new_tree,
           &new_child_ref))) {
    return err;
  }
  build->prev_child_ref = new_child_ref;
  return err;
}

MPTEST_API int mptest_sym_build_type(mptest_sym_build* build, const char* type)
{
  mptest_sym_build new;
  int err = 0;
  if ((err = mptest_sym_build_expr(build, &new))) {
    return err;
  }
  if ((err = mptest_sym_build_cstr(&new, type))) {
    return err;
  }
  *build = new;
  return err;
}

MPTEST_API void mptest_sym_walk_init(
    mptest_sym_walk* walk, const mptest_sym* sym, mptest_int32 parent_ref,
    mptest_int32 prev_child_ref)
{
  walk->sym = sym;
  walk->parent_ref = parent_ref;
  walk->prev_child_ref = prev_child_ref;
}

MPTEST_API int
mptest__sym_walk_peeknext(mptest_sym_walk* walk, mptest_int32* out_child_ref)
{
  const mptest__sym_tree* prev;
  mptest_int32 child_ref;
  if (walk->parent_ref == MPTEST__SYM_NONE) {
    if (!mptest__sym_tree_vec_size(&walk->sym->tree_storage)) {
      return SYM_EMPTY;
    }
    child_ref = 0;
  } else if (walk->prev_child_ref == MPTEST__SYM_NONE) {
    prev = mptest__sym_getcref(walk->sym, walk->parent_ref);
    child_ref = prev->first_child_ref;
  } else {
    prev = mptest__sym_getcref(walk->sym, walk->prev_child_ref);
    child_ref = prev->next_sibling_ref;
  }
  if (child_ref == MPTEST__SYM_NONE) {
    return SYM_NO_MORE;
  }
  *out_child_ref = child_ref;
  return 0;
}

MPTEST_API int
mptest__sym_walk_getnext(mptest_sym_walk* walk, mptest_int32* out_child_ref)
{
  int err = 0;
  if ((err = mptest__sym_walk_peeknext(walk, out_child_ref))) {
    return err;
  }
  walk->prev_child_ref = *out_child_ref;
  return err;
}

MPTEST_API int mptest_sym_walk_getexpr(mptest_sym_walk* walk, mptest_sym_walk* sub)
{
  int err = 0;
  const mptest__sym_tree* child;
  mptest_int32 child_ref;
  if ((err = mptest__sym_walk_getnext(walk, &child_ref))) {
    return err;
  }
  child = mptest__sym_getcref(walk->sym, child_ref);
  if (child->type != MPTEST__SYM_TYPE_EXPR) {
    return SYM_WRONG_TYPE;
  } else {
    mptest_sym_walk_init(sub, walk->sym, child_ref, MPTEST__SYM_NONE);
    return 0;
  }
}

MPTEST_API int mptest_sym_walk_getstr(
    mptest_sym_walk* walk, const char** str, mptest_size* str_size)
{
  int err = 0;
  const mptest__sym_tree* child;
  mptest_int32 child_ref;
  if ((err = mptest__sym_walk_getnext(walk, &child_ref))) {
    return err;
  }
  child = mptest__sym_getcref(walk->sym, child_ref);
  if (child->type != MPTEST__SYM_TYPE_ATOM_STRING) {
    return SYM_WRONG_TYPE;
  } else {
    *str = (const char*)mptest__str_get_data(&child->data.str);
    *str_size = mptest__str_size(&child->data.str);
    return 0;
  }
}

MPTEST_API int mptest_sym_walk_getnum(mptest_sym_walk* walk, mptest_int32* num)
{
  int err = 0;
  const mptest__sym_tree* child;
  mptest_int32 child_ref;
  if ((err = mptest__sym_walk_getnext(walk, &child_ref))) {
    return err;
  }
  child = mptest__sym_getcref(walk->sym, child_ref);
  if (child->type != MPTEST__SYM_TYPE_ATOM_NUMBER) {
    return SYM_WRONG_TYPE;
  } else {
    *num = child->data.num;
    return 0;
  }
}

MPTEST_API int
mptest_sym_walk_checktype(mptest_sym_walk* walk, const char* expected_type)
{
  const char* str;
  int err = 0;
  mptest_size str_size;
  mptest_size expected_size = mptest__str_slen(expected_type);
  mptest__str_view expected, actual;
  mptest__str_view_init_n(&expected, expected_type, expected_size);
  if ((err = mptest_sym_walk_getstr(walk, &str, &str_size))) {
    return err;
  }
  mptest__str_view_init_n(&actual, str, str_size);
  if (mptest__str_view_cmp(&expected, &actual) != 0) {
    return SYM_WRONG_TYPE;
  }
  return 0;
}

MPTEST_API int mptest_sym_walk_hasmore(mptest_sym_walk* walk)
{
  const mptest__sym_tree* prev;
  if (walk->parent_ref == MPTEST__SYM_NONE) {
    if (mptest__sym_tree_vec_size(&walk->sym->tree_storage) == 0) {
      return 0;
    } else {
      return 1;
    }
  } else if (walk->prev_child_ref == MPTEST__SYM_NONE) {
    prev = mptest__sym_getcref(walk->sym, walk->parent_ref);
    if (prev->first_child_ref == MPTEST__SYM_NONE) {
      return 0;
    } else {
      return 1;
    }
  } else {
    prev = mptest__sym_getcref(walk->sym, walk->prev_child_ref);
    if (prev->next_sibling_ref == MPTEST__SYM_NONE) {
      return 0;
    } else {
      return 1;
    }
  }
}

MPTEST_API int mptest_sym_walk_peekstr(mptest_sym_walk* walk)
{
  int err = 0;
  const mptest__sym_tree* child;
  mptest_int32 child_ref;
  if ((err = mptest__sym_walk_peeknext(walk, &child_ref))) {
    return err;
  }
  child = mptest__sym_getcref(walk->sym, child_ref);
  return child->type == MPTEST__SYM_TYPE_ATOM_STRING;
}

MPTEST_API int mptest_sym_walk_peekexpr(mptest_sym_walk* walk)
{
  int err = 0;
  const mptest__sym_tree* child;
  mptest_int32 child_ref;
  if ((err = mptest__sym_walk_peeknext(walk, &child_ref))) {
    return err;
  }
  child = mptest__sym_getcref(walk->sym, child_ref);
  return child->type == MPTEST__SYM_TYPE_EXPR;
}

MPTEST_API int mptest_sym_walk_peeknum(mptest_sym_walk* walk)
{
  int err = 0;
  const mptest__sym_tree* child;
  mptest_int32 child_ref;
  if ((err = mptest__sym_walk_peeknext(walk, &child_ref))) {
    return err;
  }
  child = mptest__sym_getcref(walk->sym, child_ref);
  return child->type == MPTEST__SYM_TYPE_ATOM_NUMBER;
}

MPTEST_API int mptest__sym_check_init(
    mptest_sym_build* build_out, const char* str, const char* file, int line,
    const char* msg)
{
  int err = 0;
  mptest_sym* sym_actual = MPTEST_NULL;
  mptest_sym* sym_expected = MPTEST_NULL;
  mptest__str_view in_str_view;
  const char* err_msg;
  mptest_size err_pos;
  mptest_sym_build parse_build;
  sym_actual = (mptest_sym*)MPTEST_MALLOC(sizeof(mptest_sym));
  if (sym_actual == MPTEST_NULL) {
    err = 1;
    goto error;
  }
  mptest__sym_init(sym_actual);
  sym_expected = (mptest_sym*)MPTEST_MALLOC(sizeof(mptest_sym));
  if (sym_expected == MPTEST_NULL) {
    err = 1;
    goto error;
  }
  mptest__sym_init(sym_expected);
  mptest_sym_build_init(
      build_out, sym_actual, MPTEST__SYM_NONE, MPTEST__SYM_NONE);
  mptest__str_view_init_n(&in_str_view, str, mptest__str_slen(str));
  mptest_sym_build_init(
      &parse_build, sym_expected, MPTEST__SYM_NONE, MPTEST__SYM_NONE);
  if ((err = mptest__sym_parse_do(
           &parse_build, in_str_view, &err_msg, &err_pos))) {
    goto error;
  }
  mptest__state_g.fail_data.sym_fail_data.sym_actual = sym_actual;
  mptest__state_g.fail_data.sym_fail_data.sym_expected = sym_expected;
  return err;
error:
  if (sym_actual != MPTEST_NULL) {
    mptest__sym_destroy(sym_actual);
    MPTEST_FREE(sym_actual);
  }
  if (sym_expected != MPTEST_NULL) {
    mptest__sym_destroy(sym_expected);
    MPTEST_FREE(sym_expected);
  }
  if (err == MPTEST__SYM_PARSE_ERROR) { /* parse error */
    mptest__state_g.fail_reason = MPTEST__FAIL_REASON_SYM_SYNTAX;
    mptest__state_g.fail_file = file;
    mptest__state_g.fail_line = line;
    mptest__state_g.fail_msg = msg;
    mptest__state_g.fail_data.sym_syntax_error_data.err_msg = err_msg;
    mptest__state_g.fail_data.sym_syntax_error_data.err_pos = err_pos;
  } else if (err == -1) { /* no mem */
    mptest__state_g.fail_reason = MPTEST__FAIL_REASON_NOMEM;
    mptest__state_g.fail_file = file;
    mptest__state_g.fail_line = line;
    mptest__state_g.fail_msg = msg;
  }
  return err;
}

MPTEST_API int mptest__sym_check(const char* file, int line, const char* msg)
{
  if (!mptest__sym_equals(
          mptest__state_g.fail_data.sym_fail_data.sym_actual,
          mptest__state_g.fail_data.sym_fail_data.sym_expected, 0, 0)) {
    mptest__state_g.fail_reason = MPTEST__FAIL_REASON_SYM_INEQUALITY;
    mptest__state_g.fail_file = file;
    mptest__state_g.fail_line = line;
    mptest__state_g.fail_msg = msg;
    return 1;
  } else {
    return 0;
  }
}

MPTEST_API void mptest__sym_check_destroy(void)
{
  mptest__sym_destroy(mptest__state_g.fail_data.sym_fail_data.sym_actual);
  mptest__sym_destroy(mptest__state_g.fail_data.sym_fail_data.sym_expected);
  MPTEST_FREE(mptest__state_g.fail_data.sym_fail_data.sym_actual);
  MPTEST_FREE(mptest__state_g.fail_data.sym_fail_data.sym_expected);
}

MPTEST_API int mptest__sym_make_init(
    mptest_sym_build* build_out, mptest_sym_walk* walk_out, const char* str,
    const char* file, int line, const char* msg)
{
  mptest__str_view in_str_view;
  const char* err_msg;
  mptest_size err_pos;
  int err = 0;
  mptest_sym* sym_out;
  sym_out = (mptest_sym*)MPTEST_MALLOC(sizeof(mptest_sym));
  if (sym_out == MPTEST_NULL) {
    err = 1;
    goto error;
  }
  mptest__sym_init(sym_out);
  mptest_sym_build_init(build_out, sym_out, MPTEST__SYM_NONE, MPTEST__SYM_NONE);
  mptest__str_view_init_n(&in_str_view, str, mptest__str_slen(str));
  if ((err =
           mptest__sym_parse_do(build_out, in_str_view, &err_msg, &err_pos))) {
    goto error;
  }
  mptest_sym_walk_init(walk_out, sym_out, MPTEST__SYM_NONE, MPTEST__SYM_NONE);
  return err;
error:
  if (sym_out) {
    mptest__sym_destroy(sym_out);
    MPTEST_FREE(sym_out);
  }
  if (err == MPTEST__SYM_PARSE_ERROR) { /* parse error */
    mptest__state_g.fail_reason = MPTEST__FAIL_REASON_SYM_SYNTAX;
    mptest__state_g.fail_file = file;
    mptest__state_g.fail_line = line;
    mptest__state_g.fail_msg = msg;
    mptest__state_g.fail_data.sym_syntax_error_data.err_msg = err_msg;
    mptest__state_g.fail_data.sym_syntax_error_data.err_pos = err_pos;
  } else if (err == -1) { /* no mem */
    mptest__state_g.fail_reason = MPTEST__FAIL_REASON_NOMEM;
    mptest__state_g.fail_file = file;
    mptest__state_g.fail_line = line;
    mptest__state_g.fail_msg = msg;
  }
  return err;
}

MPTEST_API void mptest__sym_make_destroy(mptest_sym_build* build)
{
  mptest__sym_destroy(build->sym);
  MPTEST_FREE(build->sym);
}

#endif

/* mptest */
#if MPTEST_USE_TIME

MPTEST_INTERNAL void mptest__time_init(struct mptest__state* state)
{
  state->time_state.program_start_time = clock();
  state->time_state.suite_start_time = 0;
  state->time_state.test_start_time = 0;
}

MPTEST_INTERNAL void mptest__time_destroy(struct mptest__state* state)
{
  (void)(state);
}

#endif


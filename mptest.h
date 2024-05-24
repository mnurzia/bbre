#ifdef __cplusplus
extern "C" {
#endif
#if !defined(MPTEST_H)
#define MPTEST_H

/* Set to 1 in order to define setjmp(), longjmp(), and jmp_buf replacements. */
#if !defined(MPTEST_USE_CUSTOM_LONGJMP)
#include <setjmp.h>
#define MPTEST_SETJMP setjmp
#define MPTEST_LONGJMP longjmp
#define MPTEST_JMP_BUF jmp_buf
#endif

/* bits/hooks/malloc */
/* Set to 1 in order to define malloc(), free(), and realloc() replacements. */
#if !defined(MPTEST_USE_CUSTOM_ALLOCATOR)
#include <stdlib.h>
#define MPTEST_MALLOC malloc
#define MPTEST_REALLOC realloc
#define MPTEST_FREE free
#endif

/* bits/types/size */
/* desc */
/* cppreference */
#if !defined(MPTEST_SIZE_TYPE)
#include <stdlib.h>
#define MPTEST_SIZE_TYPE size_t
#endif

/* bits/util/debug */
/* Set to 1 in order to override the setting of the NDEBUG variable. */
#if !defined(MPTEST_DEBUG)
#define MPTEST_DEBUG 0
#endif

/* bits/hooks/assert */
/* desc */
/* cppreference */
#if !defined(MPTEST_ASSERT)
#include <assert.h>
#define MPTEST_ASSERT assert
#endif

/* bits/util/exports */
/* Set to 1 in order to define all symbols with static linkage (local to the
 * including source file) as opposed to external linkage. */
#if !defined(MPTEST_STATIC)
#define MPTEST_STATIC 0
#endif

/* bits/types/char */
/* desc */
/* cppreference */
#if !defined(MPTEST_CHAR_TYPE)
#define MPTEST_CHAR_TYPE char
#endif

#if MPTEST_USE_SYM
/* bits/types/fixed/int32 */
/* desc */
/* cppreference */
#if !defined(MPTEST_INT32_TYPE)
#endif
#endif /* MPTEST_USE_SYM */

/* mptest */
/* Help text */
#if !defined(MPTEST_USE_DYN_ALLOC)
#define MPTEST_USE_DYN_ALLOC 1
#endif

/* mptest */
/* Help text */
#if !defined(MPTEST_USE_LONGJMP)
#define MPTEST_USE_LONGJMP 1
#endif

/* mptest */
/* Help text */
#if !defined(MPTEST_USE_SYM)
#define MPTEST_USE_SYM 1
#endif

/* mptest */
/* Help text */
#if !defined(MPTEST_USE_LEAKCHECK)
#define MPTEST_USE_LEAKCHECK 1
#endif

/* mptest */
/* Help text */
#if !defined(MPTEST_USE_COLOR)
#define MPTEST_USE_COLOR 1
#endif

/* mptest */
/* Help text */
#if !defined(MPTEST_USE_TIME)
#define MPTEST_USE_TIME 1
#endif

/* mptest */
/* Help text */
#if !defined(MPTEST_USE_APARSE)
#define MPTEST_USE_APARSE 1
#endif

/* mptest */
/* Help text */
#if !defined(MPTEST_USE_FUZZ)
#define MPTEST_USE_FUZZ 1
#endif

/* mptest */
/* Help text */
#if !defined(MPTEST_DETECT_UNCAUGHT_ASSERTS)
#define MPTEST_DETECT_UNCAUGHT_ASSERTS 1
#endif

#if MPTEST_USE_APARSE
/* aparse */
#ifndef APARSE_H
#define APARSE_H

#include <stddef.h> /* size_t */

#define AP_ERR_NONE 0   /* no error */
#define AP_ERR_NOMEM -1 /* out of memory */
#define AP_ERR_PARSE -2 /* error when parsing */
#define AP_ERR_IO -3    /* error when printing */
#define AP_ERR_EXIT -4  /* exit main() immediately for -h and -v-like opts */

typedef struct ap ap;

/* "file descriptors" passed to ap_ctxcb->print */
#define AP_FD_OUT 0 /* stdout */
#define AP_FD_ERR 1 /* stderr */

/* customizable callbacks for ap instances */
typedef struct ap_ctxcb {
  /* user pointer */
  void *uptr;
  /* general-purpose allocator callback
   *   ptr == NULL, new_size != 0 ->  malloc(new_size)
   *   ptr != NULL, new_size != 0 -> realloc(ptr, new_size)
   *   ptr != NULL, new_size == 0 ->    free(ptr) [return NULL] */
  void *(*alloc)(void *uptr, void *ptr, size_t old_size, size_t new_size);
  /* print to stdout/stderr
   *   fd == 0 -> fwrite(text, 1, size, stdout)
   *   fd == 1 -> fwrite(text, 1, size, stderr) */
  int (*print)(void *uptr, int fd, const char *text, size_t size);
} ap_ctxcb;

/* callback data passed to argument callbacks */
typedef struct ap_cb_data {
  const char *arg; /* pointer to argument (may be NULL)*/
  int arg_len;     /* strlen() of arg */
  int idx;         /* number of times callback has been called in a row */
  int more;        /* set this to 1 to have your callback called again */
  int destroy;     /* 1 if ap_custom_dtor() was called & arg being destroyed */
  ap *parser;      /* pointer to the parser */
  void *reserved;
} ap_cb_data;

/* callback function for custom argument types
 * - uptr: user pointer
 * - pdata: pointer to callback data
 * return:
 * - 0 or any positive value: "i consumed N chars of the argument"
 * - AP_ERR_xxx: error occurred */
typedef int (*ap_cb)(void *uptr, ap_cb_data *pdata);

/* initialize parser
 * - progname: argv[0] */
ap *ap_init(const char *progname);

/* initialize parser (extended)
 * - out: set to the parser
 * - progname: argv[0]
 * - pctxcb: library callbacks (see `ap_ctxcb`)
 * return:
 * - AP_ERR_NONE: no error
 * - AP_ERR_NOMEM: out of memory
 *
 * If `pctxcb` is NULL, default values are used (stdlib malloc, fread, fwrite,
 * etc.)*/
int ap_init_full(ap **out, const char *progname, const ap_ctxcb *pctxcb);

/* destroy parser
 * - parser: the parser to destroy */
void ap_destroy(ap *parser);

/* set parser description for help text
 * - parser: the parser to set the description of
 * - description: the description to set */
void ap_description(ap *parser, const char *description);

/* set parser epilog for help text
 * - parser: the parser to set the epilog of
 * - epilog: the epilog to set */
void ap_epilog(ap *parser, const char *epilog);

/* begin positional argument
 * - parser: the parser to add a positional argument to
 * - metavar: the placeholder text for this argument (required)
 * return:
 * - AP_ERR_NONE: no error
 * - AP_ERR_NOMEM: out of memory */
int ap_pos(ap *parser, const char *metavar);

/* begin optional argument
 * - parser: the parser to add an optional argument to
 * - short_opt: short option char (like -o, may be '\0' for no short opt)
 * - long_opt: long option string (like --option, may be NULL for no long opt)
 * return:
 * - AP_ERR_NONE: no error
 * - AP_ERR_NOMEM: out of memory
 *
 * Either `short_opt` or `long_opt` may be '\0' or NULL, respectively, but both
 * may not. */
int ap_opt(ap *parser, char short_opt, const char *long_opt);

/* specify current argument as flag type argument
 * - parser: the parser to set the argument type of
 * - out: pointer to an integer that will be set to 1 when argument is specified
 *        in argv */
void ap_type_flag(ap *parser, int *out);

/* specify current argument as integer type argument
 * - parser: the parser to set the argument type of
 * - out: pointer to an integer that will be set to the integer value of the
 *        argument specified in argv */
void ap_type_int(ap *parser, int *out);

/* specify current argument as string type argument
 * - parser: the parser to set the argument type of
 * - out: pointer to a string that will be set to argument specified in argv */
void ap_type_str(ap *parser, const char **out);

/* specify current argument as enum type argument
 * - parser: the parser to set the argument type of
 * - out: pointer to an integer that will hold the index in `choices` of the
 *        argument specified in argv
 * - choices: NULL-terminated array of string choices for the argument
 * return:
 * - AP_ERR_NONE: no error
 * - AP_ERR_NOMEM: out of memory */
int ap_type_enum(ap *parser, int *out, const char **choices);

/* specify current argument as one that shows help text immediately
 * - parser: the parser to set the argument type of
 *
 * If this option is specified in `argv`, `ap_parse` will return AP_ERR_EXIT. */
void ap_type_help(ap *parser);

/* specify current argument as one that shows version text immediately
 * - parser: the parser to set the argument type of
 * - version: the version text to show
 *
 * If this option is specified in `argv`, `ap_parse` will return AP_ERR_EXIT. */
void ap_type_version(ap *parser, const char *version);

/* specify current argument as subparser
 * - parser: the parser to set the argument type of
 * - metavar: the metavar to set for the subparser
 * - out_idx: set to the index of the subparser that was selected for parsing */
void ap_type_sub(ap *parser, const char *metavar, int *out_idx);

/* add subparser selection to subparser argument
 * - parser: the parser that will have a new subparser added to its current
 *           subparser argument
 * - name: value specified in `argv` to trigger this subparser
 * - subpar: location of a newly-constructed `ap` object that represents the
 *           subparser itself
 * return:
 * - AP_ERR_NONE: no error
 * - AP_ERR_NOMEM: out of memory
 *
 * Setting `name` to the empty string "" is valid, but is really only useful for
 * triggering a subparser immediately on an option specification. */
int ap_sub_add(ap *parser, const char *name, ap **subpar);

/* specify current argument as a custom argument
 * - parser: the parser to set the argument type of
 * - callback: function called when this argument is specified in `argv`
 *             (see `ap_cb`)
 * - user: user pointer passed to `callback` */
void ap_type_custom(ap *parser, ap_cb callback, void *user);

/* signal that the current custom argument should be destroyed when the parser
 * is destroyed
 * - parser: the parser that will have its current argument's destructor status
 *           modified
 * - enable: 1 if the current argument's callback should be called with
 *           `ap_cb_data.destroy == 1` when `ap_destroy` is called, 0 if not */
void ap_custom_dtor(ap *parser, int enable);

/* specify help text for the current argument
 * - parser: the parser to set the help text of the current argument for
 * - help: the help text to set */
void ap_help(ap *parser, const char *help);

/* specify metavar for the current argument
 * - parser: the parser to set the metavar of the current argument for
 * - metavar: the metavar to set */
void ap_metavar(ap *parser, const char *metavar);

/* parse arguments
 * - parser: the parser to use for parsing `argc` and `argv`
 * - argc: the number of arguments in `argv`
 * - argv: an array of the arguments themselves
 * return:
 * - AP_ERR_NONE: no error
 * - AP_ERR_PARSE: parsing error, message was printed using `ap_ctxcb.err`
 * - AP_ERR_IO: I/O error when writing output
 * - AP_ERR_EXIT: argument specified exiting early (like -h or -v)
 *
 * Note that this function is not supposed to accept the program name (typically
 * argv[0] in `main`). So, a typical usage in `main` looks like:
 * `parser = ap_init(argv[0]);`
 * `ap_parse(parser, argc - 1, argv + 1);` */
int ap_parse(ap *parser, int argc, const char *const *argv);

/* show help text
 * - parser: the parser to show the help text of
 * return:
 * - AP_ERR_NONE: no error
 * - AP_ERR_IO: I/O error when writing output */
int ap_show_help(ap *parser);

/* show usage text
 * - parser: the parser to show the usage text of
 * return:
 * - AP_ERR_NONE: no error
 * - AP_ERR_IO: I/O error when writing output */
int ap_show_usage(ap *parser);

/* display an error with usage text
 * - parser: the parser to display the error for
 * - error_string: the error message
 * return:
 * - 1: no [internal] error -- so you can call exit(ap_error(...))
 * - AP_ERR_IO: I/O error when writing output */
int ap_error(ap *parser, const char *error_string);

/* display an error with additional context about an argument when in a callback
 * - parser: the parser to show the help text of
 * - error_string: the error message
 * return:
 * - AP_ERR_PARSE: no error (intended to be used as a direct return value)
 * - AP_ERR_IO: I/O error when writing output */
int ap_arg_error(ap_cb_data *cbd, const char *error_string);

#endif
#endif /* MPTEST_USE_APARSE */

/* bits/types/size */
typedef MPTEST_SIZE_TYPE mptest_size;

/* bits/util/cstd */
/* If __STDC__ is not defined, assume C89. */
#ifndef __STDC__
#define MPTEST__CSTD 1989
#else
#if defined(__STDC_VERSION__)
#if __STDC_VERSION__ >= 201112L
#define MPTEST__CSTD 2011
#elif __STDC_VERSION__ >= 199901L
#define MPTEST__CSTD 1999
#else
#define MPTEST__CSTD 1989
#endif
#else
#define MPTEST__CSTD_1989
#endif
#endif

/* bits/util/debug */
#if !MPTEST_DEBUG
#if defined(NDEBUG)
#if NDEBUG == 0
#define MPTEST_DEBUG 1
#else
#define MPTEST_DEBUG 0
#endif
#endif
#endif

/* bits/hooks/assert */
#ifndef MPTEST__HOOKS_ASSERT_INTERNAL_H
#define MPTEST__HOOKS_ASSERT_INTERNAL_H
#if defined(MPTEST__COVERAGE) || !MPTEST_DEBUG
#undef MPTEST_ASSERT
#define MPTEST_ASSERT(e) ((void)0)
#endif

#endif /* MPTEST__HOOKS_ASSERT_INTERNAL_H */

/* bits/util/exports */
#if !defined(MPTEST__SPLIT_BUILD)
#if MPTEST_STATIC
#define MPTEST_API static
#else
#define MPTEST_API extern
#endif
#else
#define MPTEST_API extern
#endif

/* bits/util/null */
#define MPTEST_NULL 0

/* bits/types/char */
#if !defined(MPTEST_CHAR_TYPE)
#define MPTEST_CHAR_TYPE char
#endif

typedef MPTEST_CHAR_TYPE mptest_char;

#if MPTEST_USE_SYM
/* bits/types/fixed/int32 */
#if !defined(MPTEST_INT32_TYPE)
#if MPTEST__CSTD >= 1999
#include <stdint.h>
#define MPTEST_INT32_TYPE int32_t
#else
#define MPTEST_INT32_TYPE signed int
#endif
#endif

typedef MPTEST_INT32_TYPE mptest_int32;
#endif /* MPTEST_USE_SYM */

/* mptest */
#ifndef MPTEST_API_H
#define MPTEST_API_H

/* Plan:
 * Name  | longjmp | fuzz | time | leakcheck | sym | aparse |
 *-------+---------+------+------+-----------+-----+--------+
 * tiny  |         |      |      |           |     |        |
 * small |    X    |  X   |  X   |           |     |        |
 * big   |    X    |  X   |  X   |     X     |  X  |   X    | */
/* Forward declaration */
struct mptest__state;

/* Global state object, used in all macros. */
extern struct mptest__state mptest__state_g;

typedef int mptest__result;

#define MPTEST__RESULT_PASS 0
#define MPTEST__RESULT_FAIL -1
/* an uncaught error that caused a `longjmp()` out of the test */
/* or a miscellaneous error like a sym syntax error */
#define MPTEST__RESULT_ERROR -2

#define MPTEST__FAULT_MODE_OFF 0
#define MPTEST__FAULT_MODE_SET 1
#define MPTEST__FAULT_MODE_ONE 2

#if MPTEST_USE_LEAKCHECK
typedef int mptest__leakcheck_mode;

#define MPTEST__LEAKCHECK_MODE_OFF 0
#define MPTEST__LEAKCHECK_MODE_ON 1

#define MPTEST__RESULT_OOM_DETECTED -1000
#endif

/* Test function signature */
typedef mptest__result (*mptest__test_func)(void);
typedef void (*mptest__suite_func)(void);

/* Internal functions that API macros call */
MPTEST_API void mptest__state_init(struct mptest__state *state);
MPTEST_API void mptest__state_destroy(struct mptest__state *state);
MPTEST_API void mptest__state_report(struct mptest__state *state);
MPTEST_API void mptest__run_test(struct mptest__state *state,
                             mptest__test_func test_func,
                             const char *test_name);
MPTEST_API void mptest__run_suite(struct mptest__state *state,
                              mptest__suite_func suite_func,
                              const char *suite_name);

MPTEST_API void mptest__assert_fail(struct mptest__state *state, const char *msg,
                                const char *assert_expr, const char *file,
                                int line);
MPTEST_API void mptest__assert_pass(struct mptest__state *state, const char *msg,
                                const char *assert_expr, const char *file,
                                int line);

MPTEST_API void mptest_ex(void);

MPTEST_API void mptest_ex_assert_fail(void);
MPTEST_API void mptest_ex_uncaught_assert_fail(void);

MPTEST_API MPTEST_JMP_BUF *mptest__catch_assert_begin(struct mptest__state *state);
MPTEST_API void mptest__catch_assert_end(struct mptest__state *state);
MPTEST_API void mptest__catch_assert_fail(struct mptest__state *state,
                                      const char *msg, const char *assert_expr,
                                      const char *file, int line);

MPTEST_API void mptest__fault_set(struct mptest__state *state, int on);

#if MPTEST_USE_LEAKCHECK
MPTEST_API void *mptest__leakcheck_hook_malloc(struct mptest__state *state,
                                           const char *file, int line,
                                           size_t size);
MPTEST_API void mptest__leakcheck_hook_free(struct mptest__state *state,
                                        const char *file, int line, void *ptr);
MPTEST_API void *mptest__leakcheck_hook_realloc(struct mptest__state *state,
                                            const char *file, int line,
                                            void *old_ptr, size_t new_size);
MPTEST_API void mptest__leakcheck_set(struct mptest__state *state, int on);

MPTEST_API void mptest_ex_nomem(void);
MPTEST_API void mptest_ex_fault(void);
MPTEST_API void mptest_ex_oom_inject(void);
MPTEST_API void mptest_ex_bad_alloc(void);
MPTEST_API void mptest_malloc_dump(void);
MPTEST_API int mptest_fault(const char *cls);
#endif

#if MPTEST_USE_APARSE
/* declare argv as pointer to const pointer to const char */
/* can change argv, can't change *argv, can't change **argv */
MPTEST_API int mptest__state_init_argv(struct mptest__state *state, int argc,
                                   const char *const *argv);
#endif

#if MPTEST_USE_FUZZ
typedef unsigned long mptest_rand;
MPTEST_API void mptest__fuzz_next_test(struct mptest__state *state, int iterations);
MPTEST_API mptest_rand mptest__fuzz_rand(struct mptest__state *state);
#endif

#define _ASSERT_PASS_BEHAVIOR(expr, msg)                                       \
  do {                                                                         \
    mptest__assert_pass(&mptest__state_g, msg, #expr, __FILE__, __LINE__);     \
  } while (0)

#define _ASSERT_FAIL_BEHAVIOR(expr, msg)                                       \
  do {                                                                         \
    mptest__assert_fail(&mptest__state_g, msg, #expr, __FILE__, __LINE__);     \
    return MPTEST__RESULT_FAIL;                                                \
  } while (0)

#define _STRIFY(expr) #expr

/* Used for binary assertions (<, >, <=, >=, ==, !=) in order to format error
 * messages correctly. */
#define _ASSERT_BINOPm(lhs, rhs, op, msg)                                      \
  do {                                                                         \
    if (!((lhs)op(rhs))) {                                                     \
      _ASSERT_FAIL_BEHAVIOR(lhs op rhs, msg);                                  \
    } else {                                                                   \
      _ASSERT_PASS_BEHAVIOR(lhs op rhs, msg);                                  \
    }                                                                          \
  } while (0)

#define _ASSERT_BINOP(lhs, rhs, op)                                            \
  do {                                                                         \
    if (!((lhs)op(rhs))) {                                                     \
      _ASSERT_FAIL_BEHAVIOR(lhs op rhs, _STRIFY(lhs op rhs));                  \
    } else {                                                                   \
      _ASSERT_PASS_BEHAVIOR(lhs op rhs, _STRIFY(lhs op rhs));                  \
    }                                                                          \
  } while (0)

/* Define a test. */
/* Usage:
 * TEST(test_name) {
 *     ASSERT(...);
 *     PASS();
 * } */
#define TEST(name) mptest__result mptest__test_##name(void)

/* Define a suite. */
/* Usage:
 * SUITE(suite_name) {
 *     RUN_TEST(test_1_name);
 *     RUN_TEST(test_2_name);
 * } */
#define SUITE(name) void mptest__suite_##name(void)

/* `TEST()` and `SUITE()` macros are declared `static` because otherwise
 * -Wunused will not notice if a test is defined but not called. */

/* Run a test. Should only be used from within a suite. */
#define RUN_TEST(test)                                                         \
  do {                                                                         \
    mptest__run_test(&mptest__state_g, mptest__test_##test, #test);            \
  } while (0)

/* Run a suite. */
#define RUN_SUITE(suite)                                                       \
  do {                                                                         \
    mptest__run_suite(&mptest__state_g, mptest__suite_##suite, #suite);        \
  } while (0)

#if MPTEST_USE_FUZZ

#define MPTEST__FUZZ_DEFAULT_ITERATIONS 500

/* Run a test a number of times, changing the RNG state each time. */
#define FUZZ_TEST(test)                                                        \
  do {                                                                         \
    mptest__fuzz_next_test(&mptest__state_g, MPTEST__FUZZ_DEFAULT_ITERATIONS); \
    RUN_TEST(test);                                                            \
  } while (0)

#endif

/* Unconditionally pass a test. */
#define PASS()                                                                 \
  do {                                                                         \
    return MPTEST__RESULT_PASS;                                                \
  } while (0)

#define ASSERTm(expr, msg)                                                     \
  do {                                                                         \
    if (!(expr)) {                                                             \
      _ASSERT_FAIL_BEHAVIOR(expr, msg);                                        \
    } else {                                                                   \
      _ASSERT_PASS_BEHAVIOR(lhs op rhs, msg);                                  \
    }                                                                          \
  } while (0)

/* Unconditionally fail a test. */
#define FAIL()                                                                 \
  do {                                                                         \
    _ASSERT_FAIL_BEHAVIOR("0", "FAIL() called");                               \
  } while (0)

#define ASSERT(expr) ASSERTm(expr, #expr)

#define ASSERT_EQm(lhs, rhs, msg) _ASSERT_BINOPm(lhs, rhs, ==, msg)
#define ASSERT_NEQm(lhs, rhs, msg) _ASSERT_BINOPm(lhs, rhs, !=, msg)
#define ASSERT_GTm(lhs, rhs, msg) _ASSERT_BINOPm(lhs, rhs, >, msg)
#define ASSERT_LTm(lhs, rhs, msg) _ASSERT_BINOPm(lhs, rhs, <, msg)
#define ASSERT_GTEm(lhs, rhs, msg) _ASSERT_BINOPm(lhs, rhs, >=, msg)
#define ASSERT_LTEm(lhs, rhs, msg) _ASSERT_BINOPm(lhs, rhs, <=, msg)

#define ASSERT_EQ(lhs, rhs) _ASSERT_BINOP(lhs, rhs, ==)
#define ASSERT_NEQ(lhs, rhs) _ASSERT_BINOP(lhs, rhs, !=)
#define ASSERT_GT(lhs, rhs) _ASSERT_BINOP(lhs, rhs, >)
#define ASSERT_LT(lhs, rhs) _ASSERT_BINOP(lhs, rhs, <)
#define ASSERT_GTE(lhs, rhs) _ASSERT_BINOP(lhs, rhs, >=)
#define ASSERT_LTE(lhs, rhs) _ASSERT_BINOP(lhs, rhs, <=)

#define PROPAGATE(expr)                                                        \
  do {                                                                         \
    int _mptest_err = (expr);                                                  \
    if (_mptest_err != MPTEST__RESULT_PASS) {                                  \
      return _mptest_err;                                                      \
    }                                                                          \
  } while (0)

#if MPTEST_USE_LONGJMP

/* Assert that an assertion failure will occur within statement `stmt`. */
#define ASSERT_ASSERTm(stmt, msg)                                              \
  do {                                                                         \
    if (MPTEST_SETJMP(*mptest__catch_assert_begin(&mptest__state_g)) == 0) {       \
      stmt;                                                                    \
      mptest__catch_assert_end(&mptest__state_g);                              \
      _ASSERT_FAIL_BEHAVIOR("<runtime-assert-checked-function> " #stmt, msg);  \
    } else {                                                                   \
      mptest__catch_assert_end(&mptest__state_g);                              \
      _ASSERT_PASS_BEHAVIOR("<runtime-assert-checked-function> " #stmt, msg);  \
    }                                                                          \
  } while (0)

#define ASSERT_ASSERT(stmt) ASSERT_ASSERTm(stmt, #stmt)

#if MPTEST_DETECT_UNCAUGHT_ASSERTS

#define MPTEST_INJECT_ASSERTm(expr, msg)                                       \
  do {                                                                         \
    if (!(expr)) {                                                             \
      mptest_ex_uncaught_assert_fail();                                        \
      mptest__catch_assert_fail(&mptest__state_g, msg, #expr, __FILE__,        \
                                __LINE__);                                     \
    }                                                                          \
  } while (0)

#else

#define MPTEST_INJECT_ASSERTm(expr, msg)                                       \
  do {                                                                         \
    if (mptest__state_g.longjmp_checking &                                     \
        MPTEST__LONGJMP_REASON_ASSERT_FAIL) {                                  \
      if (!(expr)) {                                                           \
        mptest_ex_uncaught_assert_fail();                                      \
        mptest__catch_assert_fail(&mptest__state_g, msg, #expr, __FILE__,      \
                                  __LINE__);                                   \
      }                                                                        \
    } else {                                                                   \
      MPTEST_ASSERT(expr);                                                         \
    }                                                                          \
  } while (0)

#endif

#else

#define MPTEST_INJECT_ASSERTm(expr, msg) MPTEST_ASSERT(expr)

#endif

#define MPTEST_INJECT_ASSERT(expr) MPTEST_INJECT_ASSERTm(expr, #expr)

#if MPTEST_USE_LEAKCHECK

#define MPTEST_INJECT_MALLOC_FL(size, file, line)                                             \
  mptest__leakcheck_hook_malloc(&mptest__state_g, file, line, (size))
#define MPTEST_INJECT_MALLOC(size) MPTEST_INJECT_MALLOC_FL(size, __FILE__, __LINE__)
#define MPTEST_INJECT_FREE_FL(ptr, file, line)                                                \
  mptest__leakcheck_hook_free(&mptest__state_g, file, line, (ptr))
#define MPTEST_INECT_FREE(ptr) MPTEST_INJECT_FREE_FL(ptr, __FILE__, __LINE__)
#define MPTEST_INJECT_REALLOC_FL(old_ptr, new_size, file, line)                               \
  mptest__leakcheck_hook_realloc(&mptest__state_g, file, line,         \
                                 (old_ptr), (new_size))
#define MPTEST_INJECT_REALLOC(old_ptr, new_size) MPTEST_INJECT_REALLOC_FL(old_ptr, new_size, __FILE__, __LINE__)
#define MPTEST_ENABLE_LEAK_CHECKING()                                          \
  mptest__leakcheck_set(&mptest__state_g, MPTEST__LEAKCHECK_MODE_ON)

#define MPTEST_ENABLE_OOM_ONE()                                                \
  mptest__leakcheck_set(&mptest__state_g, MPTEST__LEAKCHECK_MODE_OOM_ONE)

#define MPTEST_ENABLE_OOM_SET()                                                \
  mptest__leakcheck_set(&mptest__state_g, MPTEST__LEAKCHECK_MODE_OOM_SET)

#define MPTEST_DISABLE_LEAK_CHECKING()                                         \
  mptest__leakcheck_set(&mptest__state_g, MPTEST__LEAKCHECK_MODE_OFF)

#define OOM()                                                                  \
  do {                                                                         \
    return MPTEST__RESULT_OOM_DETECTED;                                        \
  } while (0)

#else

#define MPTEST_INJECT_MALLOC(size) MPTEST_MALLOC(size)
#define MPTEST_INJECT_FREE(ptr) MPTEST_FREE(ptr)
#define MPTEST_INJECT_REALLOC(old_ptr, new_size)                               \
  MPTEST_REALLOC(old_ptr, new_size)

#endif

#define MPTEST_MAIN_BEGIN() mptest__state_init(&mptest__state_g)

#define MPTEST_MAIN_BEGIN_ARGS(argc, argv)                                     \
  do {                                                                         \
    int res = mptest__state_init_argv(&mptest__state_g, argc,                  \
                                      (char const *const *)(argv));            \
    if (res == AP_ERR_EXIT) {                                                  \
      return 1;                                                                \
    } else if (res != 0) {                                                     \
      return (int)res;                                                         \
    }                                                                          \
  } while (0)

#define MPTEST_MAIN_END()                                                      \
  do {                                                                         \
    mptest__state_report(&mptest__state_g);                                    \
    mptest__state_destroy(&mptest__state_g);                                   \
  } while (0)

#define MPTEST_ENABLE_FAULT_CHECKING()                                         \
  mptest__fault_set(&mptest__state_g, MPTEST__FAULT_MODE_ONE)

#define MPTEST_DISABLE_FAULT_CHECKING()                                        \
  mptest__fault_set(&mptest__state_g, MPTEST__FAULT_MODE_OFF)

#if MPTEST_USE_FUZZ

#define RAND_PARAM(mod) (mptest__fuzz_rand(&mptest__state_g) % (mod))

#endif

#if MPTEST_USE_SYM

typedef struct mptest_sym mptest_sym;

typedef struct mptest_sym_build {
  mptest_sym *sym;
  mptest_int32 parent_ref;
  mptest_int32 prev_child_ref;
} mptest_sym_build;

typedef struct mptest_sym_walk {
  const mptest_sym *sym;
  mptest_int32 parent_ref;
  mptest_int32 prev_child_ref;
} mptest_sym_walk;

typedef mptest_sym_build sym_build;
typedef mptest_sym_walk sym_walk;

MPTEST_API void mptest_sym_build_init(mptest_sym_build *build, mptest_sym *sym,
                                  mptest_int32 parent_ref, mptest_int32 prev_child_ref);
MPTEST_API int mptest_sym_build_expr(mptest_sym_build *build,
                                 mptest_sym_build *sub);
MPTEST_API int mptest_sym_build_str(mptest_sym_build *build, const char *str,
                                mptest_size str_size);
MPTEST_API int mptest_sym_build_cstr(mptest_sym_build *build, const char *cstr);
MPTEST_API int mptest_sym_build_num(mptest_sym_build *build, mptest_int32 num);
MPTEST_API int mptest_sym_build_type(mptest_sym_build *build, const char *type);

MPTEST_API void mptest_sym_walk_init(mptest_sym_walk *walk, const mptest_sym *sym,
                                 mptest_int32 parent_ref, mptest_int32 prev_child_ref);
MPTEST_API int mptest_sym_walk_getexpr(mptest_sym_walk *walk, mptest_sym_walk *sub);
MPTEST_API int mptest_sym_walk_getstr(mptest_sym_walk *walk, const char **str,
                                  mptest_size *str_size);
MPTEST_API int mptest_sym_walk_getnum(mptest_sym_walk *walk, mptest_int32 *num);
MPTEST_API int mptest_sym_walk_checktype(mptest_sym_walk *walk,
                                     const char *expected_type);
MPTEST_API int mptest_sym_walk_hasmore(mptest_sym_walk *walk);
MPTEST_API int mptest_sym_walk_peekstr(mptest_sym_walk *walk);
MPTEST_API int mptest_sym_walk_peeknum(mptest_sym_walk *walk);
MPTEST_API int mptest_sym_walk_peekexpr(mptest_sym_walk *walk);

MPTEST_API int mptest__sym_check_init(mptest_sym_build *build_out, const char *str,
                                  const char *file, int line, const char *msg);
MPTEST_API int mptest__sym_check(const char *file, int line, const char *msg);
MPTEST_API void mptest__sym_check_destroy(void);
MPTEST_API int mptest__sym_make_init(mptest_sym_build *build_out,
                                 mptest_sym_walk *walk_out, const char *str,
                                 const char *file, int line, const char *msg);
MPTEST_API void mptest__sym_make_destroy(mptest_sym_build *build_out);

#define MPTEST__SYM_NONE (-1)

#define ASSERT_SYMEQm(type, in_var, chexpr, msg)                               \
  do {                                                                         \
    mptest_sym_build temp_build;                                               \
    if (mptest__sym_check_init(&temp_build, chexpr, __FILE__, __LINE__,        \
                               msg)) {                                         \
      return MPTEST__RESULT_ERROR;                                             \
    }                                                                          \
    if (type##_to_sym(&temp_build, in_var)) {                                  \
      return MPTEST__RESULT_ERROR;                                             \
    }                                                                          \
    if (mptest__sym_check(__FILE__, __LINE__, msg)) {                          \
      return MPTEST__RESULT_FAIL;                                              \
    }                                                                          \
    mptest__sym_check_destroy();                                               \
  } while (0);

#define ASSERT_SYMEQ(type, var, chexpr)                                        \
  ASSERT_SYMEQm(type, var, chexpr, #chexpr)

#define SYM_PUT_TYPE(build, type)                                              \
  do {                                                                         \
    int _sym_err;                                                              \
    if ((_sym_err = mptest_sym_build_cstr(build, (type)))) {                   \
      return _sym_err;                                                         \
    }                                                                          \
  } while (0)

#define SYM_PUT_NUM(build, num)                                                \
  do {                                                                         \
    int _sym_err;                                                              \
    if ((_sym_err = mptest_sym_build_num(build, (num)))) {                     \
      return _sym_err;                                                         \
    }                                                                          \
  } while (0)

#define SYM_PUT_STR(build, str)                                                \
  do {                                                                         \
    int _sym_err;                                                              \
    if ((_sym_err = mptest_sym_build_cstr(build, (str)))) {                    \
      return _sym_err;                                                         \
    }                                                                          \
  } while (0)

#define SYM_PUT_STRN(build, str, str_size)                                     \
  do {                                                                         \
    int _sym_err;                                                              \
    if ((_sym_err = mptest_sym_build_str(build, (str), (str_size)))) {         \
      return _sym_err;                                                         \
    }                                                                          \
  } while (0)

#define SYM_PUT_EXPR(build, new_build)                                         \
  do {                                                                         \
    int _sym_err;                                                              \
    if ((_sym_err = mptest_sym_build_expr(build, new_build))) {                \
      return _sym_err;                                                         \
    }                                                                          \
  } while (0)

#define SYM_PUT_SUB(build, type, in_var)                                       \
  do {                                                                         \
    int _sym_err;                                                              \
    if ((_sym_err = type##_to_sym((build), in_var))) {                         \
      return _sym_err;                                                         \
    }                                                                          \
  } while (0)

#define SYM(type, str, out_var)                                                \
  do {                                                                         \
    mptest_sym_build temp_build;                                               \
    mptest_sym_walk temp_walk;                                                 \
    int _sym_err;                                                              \
    if (mptest__sym_make_init(&temp_build, &temp_walk, str, __FILE__,          \
                              __LINE__, MPTEST_NULL)) {                            \
      return MPTEST__RESULT_ERROR;                                             \
    }                                                                          \
    if ((_sym_err = type##_from_sym(&temp_walk, out_var))) {                   \
      if (_sym_err == SYM_NOMEM) {                                             \
        return MPTEST__RESULT_PASS;                                            \
      }                                                                        \
      return MPTEST__RESULT_ERROR;                                             \
    }                                                                          \
    mptest__sym_make_destroy(&temp_build);                                     \
  } while (0)

#define SYM_CHECK_TYPE(walk, type_name)                                        \
  do {                                                                         \
    int _sym_err;                                                              \
    if ((_sym_err = mptest_sym_walk_checktype(walk, type_name))) {             \
      return _sym_err;                                                         \
    }                                                                          \
  } while (0)

#define SYM_GET_STR(walk, str_out, size_out)                                   \
  do {                                                                         \
    int _sym_err;                                                              \
    if ((_sym_err = mptest_sym_walk_getstr(walk, str_out, size_out))) {        \
      return _sym_err;                                                         \
    }                                                                          \
  } while (0)

#define SYM_GET_NUM(walk, num_out)                                             \
  do {                                                                         \
    int _sym_err;                                                              \
    if ((_sym_err = mptest_sym_walk_getnum(walk, num_out))) {                  \
      return _sym_err;                                                         \
    }                                                                          \
  } while (0)

#define SYM_GET_EXPR(walk, walk_out)                                           \
  do {                                                                         \
    int _sym_err;                                                              \
    if ((_sym_err = mptest_sym_walk_getexpr(walk, walk_out))) {                \
      return _sym_err;                                                         \
    }                                                                          \
  } while (0)

#define SYM_GET_SUB(walk, type, out_var)                                       \
  do {                                                                         \
    int _sym_err;                                                              \
    if ((_sym_err = type##_from_sym((walk), (out_var)))) {                     \
      return _sym_err;                                                         \
    }                                                                          \
  } while (0)

#define SYM_MORE(walk) (mptest_sym_walk_hasmore((walk)))

#define SYM_PEEK_STR(walk) (mptest_sym_walk_peekstr((walk)))
#define SYM_PEEK_NUM(walk) (mptest_sym_walk_peeknum((walk)))
#define SYM_PEEK_EXPR(walk) (mptest_sym_walk_peekexpr((walk)))

#define SYM_OK 0
#define SYM_EMPTY 5
#define SYM_WRONG_TYPE 6
#define SYM_NO_MORE 7
#define SYM_INVALID 8
#define SYM_NOMEM 9

#endif

#endif

#endif /* MPTEST_H */
#ifdef __cplusplus
}
#endif

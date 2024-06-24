#ifndef MN_BBRE_H
#define MN_BBRE_H
#include <stddef.h> /* size_t */

/* Self-plagiarism from rv. */
#if __STDC__ && __STDC_VERSION__ >= 199901L /* Attempt to load stdint.h. */
  #include <stdint.h>
  #define BBRE_U8_TYPE  uint8_t
  #define BBRE_U16_TYPE uint16_t
  #define BBRE_S32_TYPE int32_t
  #define BBRE_U32_TYPE uint32_t
#else
  #ifdef __UINT8_TYPE__
    #define BBRE_U8_TYPE  __UINT8_TYPE__
    #define BBRE_U16_TYPE __UINT16_TYPE__
    #define BBRE_S32_TYPE __INT32_TYPE__
    #define BBRE_U32_TYPE __UINT32_TYPE__
  #else
    #define BBRE_U8_TYPE  unsigned char
    #define BBRE_U16_TYPE unsigned short
    #define BBRE_S32_TYPE signed int
    #define BBRE_U32_TYPE unsigned int
  #endif /* (slight) deviations from c89. Sorry {TI, Cray, DEC, et. al.} */
#endif

typedef BBRE_U8_TYPE bbre_u8;
typedef BBRE_U16_TYPE bbre_u16;
typedef BBRE_S32_TYPE bbre_s32;
typedef BBRE_U32_TYPE bbre_u32;

/** Enumeration of error types. */
#define BBRE_ERR_MEM   (-1) /* Out of memory. */
#define BBRE_ERR_PARSE (-2) /* Parsing failed. */
#define BBRE_ERR_LIMIT (-3) /* Hard limit reached (program size, etc.) */

/** Memory allocator callback.
 ** This is a little different from the three-callback option provided by most
 ** libraries. If you are confused, this might help you understand:
 ** ```c
 ** alloc_cb(user,    NULL,        0, new_size) = malloc(new_size)
 ** alloc_cb(user, old_ptr, old_size, new_size) = realloc(old_ptr, new_size)
 ** alloc_cb(user, old_ptr, old_size,        0) = free(old_ptr)
 ** ````
 ** Of course, the library uses stdlib malloc if possible, so chances are you
 ** don't need to worry about this part of the API. */
typedef void *(*bbre_alloc_cb)(void *user, void *ptr, size_t prev, size_t next);

typedef struct bbre_alloc {
  void *user;
  bbre_alloc_cb cb;
} bbre_alloc;

/** Regular expression flags.
 ** These mirror the flags used in the regular expression syntax, but can be
 ** given to bbre_spec_flags() in order to enable them out-of-band. */
typedef enum bbre_flags {
  BBRE_FLAG_INSENSITIVE = 1, /* (?i) Case insensitive matching */
  BBRE_FLAG_MULTILINE = 2,   /* (?m) Multiline matching */
  BBRE_FLAG_DOTNEWLINE = 4,  /* (?s) '.' matches '\\n' */
  BBRE_FLAG_UNGREEDY = 8     /* (?U) Quantifiers become ungreedy */
} bbre_flags;

/** Builder class for regular expressions.
 ** This is intended to be used for nontrivial usage of the library, for
 ** example, if you want to use a non-null-terminated regex. */
typedef struct bbre_spec bbre_spec;

/** Initialize a bbre_spec.
 ** - `pspec` is a pointer to a pointer that will contain the newly-constructed
 **   bbre_spec object.
 ** - `pat` is the pattern string to use for the bbre_spec object.
 ** - `pat_size` is the size (in bytes) of `pat`.
 ** - `alloc` is the memory allocator to use. Pass NULL to use the default.
 **
 ** Returns BBRE_ERR_NOMEM if there is not enough memory to represent the
 ** object, 0 otherwise. If there was not enough memory, `*pspec` is NULL. */
int bbre_spec_init(
    bbre_spec **pspec, const char *pat, size_t pat_size,
    const bbre_alloc *alloc);
/* Set flags for a bbre_spec. */
void bbre_spec_flags(bbre_spec *spec, bbre_flags flags);
/* Destroy a bbre_spec. */
void bbre_spec_destroy(bbre_spec *spec);

/** An object that matches a single regular expression. */
typedef struct bbre bbre;

/** Initialize a bbre.
 ** `pat_nt` is a null-terminated string containing the pattern.
 **
 ** Returns a newly-constructed bbre object, or NULL if there was not enough
 ** memory to store the object. Internally, this function calls
 ** bbre_init_spec(), which can return more than one error code if the pattern
 ** is malformed: this function assumes the pattern is correct and will abort
 ** if these errors occur. If you require more robust error checking, use
 ** bbre_init_spec() directly. */
bbre *bbre_init(const char *pat_nt);

/** Initialize a bbre from a bbre_spec.
 ** - `preg` is a pointer to a pointer that will contain the newly-constucted
 **   bbre object.
 ** - `spec` is a bbre_spec used for initializing the `*preg`.
 ** - `alloc` is the memory allocator to use. Pass NULL to use the default.
 **
 ** Returns BBRE_ERR_PARSE if the pattern in `spec` contains a parsing error,
 ** BBRE_ERR_MEM if there was not enough memory to parse or compile the
 ** pattern, BBRE_ERR_LIMIT if the pattern's compiled size is too large, or 0
 ** if there was no error.
 ** If this function returns BBRE_ERR_PARSE, you can use the bbre_get_error()
 ** function to retrieve a detailed error message, and an index into the pattern
 ** where the error occurred. */
int bbre_init_spec(bbre **preg, const bbre_spec *spec, const bbre_alloc *alloc);

/** Destroy a bbre. */
void bbre_destroy(bbre *reg);

/** Retrieve a parsing error from a \ref bbre.
 ** - `reg` is the bbre to check the error of.
 ** - `pmsg` is a pointer to the output message. `*pmsg` will be set to the
 **   error message. `*pmsg` is always null-terminated if an error occurred.
 ** - `ppos` is a pointer to the output position. `*ppos` will be set to
 **   the index in the input pattern where the error occurred.
 **
 ** Returns the length (in bytes) of `*pmsg`, not including its null terminator.
 ** If the preceding call to bbre_init() did not cause a parse error (i.e., it
 ** did not return BBRE_ERR_PARSE) then `*pmsg` is NULL, `*ppos` is 0, and the
 ** function returns 0. */
size_t bbre_get_error(bbre *reg, const char **pmsg, size_t *pos);

/** Substring bounds record.
 ** This structure records the bounds of a capture recorded by bbre_captures().
 ** `begin` is the start of the match, `end` is the end. */
typedef struct bbre_span {
  size_t begin; /* Begin index */
  size_t end;   /* End index */
} bbre_span;

/** Match text against a bbre.
 ** These functions perform matching operations using a bbre object. All of them
 ** take two parameters, `text` and `text_size`, which denote the string to
 ** match against.
 **
 ** bbre_is_match() checks if `reg`'s pattern occurs anywhere within `text`.
 ** Like the rest of these functions, bbre_is_match() returns 0 if the pattern
 ** did not match anywhere in the string, or 1 if it did.
 **
 ** bbre_find() locates the position in `text` where `reg`'s pattern occurs, if
 ** it occurs. `out_bounds` points to a bbre_span where the boundaries of the
 ** match will be stored should a match be found.
 **
 ** bbre_captures() works like bbre_find(), but it also extracts capturing
 ** groups. `num_captures` is the amount of groups to capture, and
 ** `out_captures` points to an array of bbre_span where the boundaries of each
 ** capture will be stored. Note that capture group 0 denotes the boundaries of
 ** the entire match (i.e., those retrieved by bbre_find()), so to retrieve the
 ** first capturing group, pass 2 for `num_captures`; to retrieve the second,
 ** pass 3, and so on.
 **
 ** Returns 0 if a match was not found anywhere in `text`, 1 if a match was
 ** found, in which case the relevant `out_bounds` or `out_captures` variable
 ** will be written to, or BBRE_ERR_MEM if there was not enough memory to
 ** successfully perform the match. */
int bbre_is_match(bbre *reg, const char *text, size_t text_size);
int bbre_find(
    bbre *reg, const char *text, size_t text_size, bbre_span *out_bounds);
int bbre_captures(
    bbre *reg, const char *text, size_t text_size, bbre_u32 num_captures,
    bbre_span *out_captures);

/** Match text against a bbre, starting the match from a given position.
 ** These functions behave identically to the bbre_is_match(), bbre_find(), and
 ** bbre_captures() functions, but they take an additional `pos` parameter that
 ** describes an offset in `text` to start the match from.
 ** The utility of these functions is that they take into account empty-width
 ** assertions active at `pos`. For example, matching `\b` against "A " at
 ** position 1 would return a match, because these functions look at the
 ** surrounding characters for empty-width assertion context. */
int bbre_is_match_at(bbre *reg, const char *text, size_t text_size, size_t pos);
int bbre_find_at(
    bbre *reg, const char *text, size_t text_size, size_t pos,
    bbre_span *out_bounds);
int bbre_captures_at(
    bbre *reg, const char *text, size_t text_size, size_t pos,
    bbre_u32 num_captures, bbre_span *out_captures);

/** Builder class for regular expression sets. */
typedef struct bbre_set_spec bbre_set_spec;

/** Initialize a bbre_set_spec.
 ** - `pspec` is a pointer to a pointer that will contain the newly-constructed
 **   bbre_set_spec object.
 ** - `alloc` is the bbre_alloc memory allocator to use. Pass NULL to use the
 **   default.
 **
 ** Returns BBRE_ERR_MEM if there was not enough memory to store the object,
 ** 0 otherwise. */
int bbre_set_spec_init(bbre_set_spec **pspec, const bbre_alloc *alloc);

/** Destroy a bbre_set_spec. */
void bbre_set_spec_destroy(bbre_set_spec *b);

/** Add a pattern to a bbre_set_spec.
 ** - `set` is the set to add the pattern to
 ** - `reg` is the pattern to add
 **
 ** Returns BBRE_ERR_MEM if there was not enough memory to add `reg` to `set`,
 ** 0 otherwise. */
int bbre_set_spec_add(bbre_set_spec *set, const bbre *reg);

int bbre_set_spec_config(bbre_set_spec *b, int option, ...);

typedef struct bbre_set bbre_set;
bbre_set *bbre_set_init(const char *const *regexes_nt, size_t num_regexes);
int bbre_set_init_spec(
    bbre_set **pset, const bbre_set_spec *set_spec, const bbre_alloc *alloc);
void bbre_set_destroy(bbre_set *set);
int bbre_set_match(
    bbre_set *set, const char *s, size_t n, size_t pos, bbre_u32 idxs_size,
    bbre_u32 *out_idxs, bbre_u32 *out_num_idxs);
/** Duplicate a \ref bbre without re-compiling it.
 * \param reg The \ref bbre to fork
 * \param[out] pout A pointer to the output \ref bbre object. *\p pout will be
 *   set to the newly-constructed \ref bbre object.
 * \return BBRE_ERR_MEM if there was not enough memory to represent the new \ref
 *   bbre, 0 otherwise */
int bbre_fork(bbre *reg, bbre **pout);
int bbre_set_fork(bbre_set *s, bbre_set **out);

#endif /* MN_BBRE_H */

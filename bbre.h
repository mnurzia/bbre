/* bbre.h - non-backtracking regular expression library */
/* Originally written by Max Nurzia, Jan-Dec 2024 */

#ifndef MN_BBRE_H
  #define MN_BBRE_H
  #include <stddef.h> /* size_t */

  /** Error codes. */
  #define BBRE_ERR_MEM   (-1) /* Out of memory. */
  #define BBRE_ERR_PARSE (-2) /* Parsing failed. */
  #define BBRE_ERR_LIMIT (-3) /* Hard limit reached (program size, etc.) */

/** Memory allocator callback.
 ** The bbre_alloc type can be used with most of the bbre_*_init() functions
 ** provided with the library, to define a custom allocator for specific
 ** objects.
 **
 ** To use, set `alloc->cb` to a function with the bbre_alloc_cb signature, and
 ** optionally set `alloc->user` to a context pointer. The library will pass
 ** `alloc->user` to any call of `alloc->cb` that it makes.
 **
 ** The callback itself takes four parameters:
 ** - `user` is the the pointer in `alloc->user`
 ** - `old_ptr` is the pointer to the previous allocation (may be NULL)
 ** - `old_size` is the size of the previous allocation
 ** - `new_size` is the requested size for the next allocation
 **
 ** This is a little different from the three-callback option provided by most
 ** libraries. If you are confused, this might help you understand:
 ** ```
 ** alloc_cb(user,    NULL,        0, new_size) = malloc(new_size)
 ** alloc_cb(user, old_ptr, old_size, new_size) = realloc(old_ptr, new_size)
 ** alloc_cb(user, old_ptr, old_size,        0) = free(old_ptr)
 ** ````
 **
 ** This approach was adapted from Lua's memory allocator API.
 ** Of course, the library uses stdlib malloc if possible, so chances are you
 ** don't need to worry about this part of the API. */
typedef void *(*bbre_alloc_cb)(void *user, void *ptr, size_t prev, size_t next);

typedef struct bbre_alloc {
  void *user;       /* User pointer */
  bbre_alloc_cb cb; /* Allocator callback */
} bbre_alloc;

/** Regular expression flags.
 ** These mirror the flags used in the regular expression syntax, but can be
 ** given to bbre_builder_flags() in order to enable them out-of-band. */
typedef enum bbre_flags {
  BBRE_FLAG_INSENSITIVE = 1, /* (?i) Case insensitive matching */
  BBRE_FLAG_MULTILINE = 2,   /* (?m) Multiline ('^'/'$' match line start/end) */
  BBRE_FLAG_DOTNEWLINE = 4,  /* (?s) '.' matches '\n' */
  BBRE_FLAG_UNGREEDY = 8     /* (?U) Quantifiers become ungreedy */
} bbre_flags;

/** Builder class for regular expressions.
 ** This is intended to be used for nontrivial usage of the library, for
 ** example, if you want to use a non-null-terminated regex. */
typedef struct bbre_builder bbre_builder;

/** Initialize a bbre_builder.
 ** - `pbuild` is a pointer to a pointer that will contain the newly-constructed
 **   bbre_builder object.
 ** - `pat` is the pattern string to use for the bbre_builder object.
 ** - `pat_size` is the size (in bytes) of `pat`.
 ** - `alloc` is the memory allocator to use. Pass NULL to use the default.
 **
 ** Returns BBRE_ERR_NOMEM if there is not enough memory to represent the
 ** object, 0 otherwise. If there was not enough memory, `*pbuild` is NULL. */
int bbre_builder_init(
    bbre_builder **pbuild, const char *pat, size_t pat_size,
    const bbre_alloc *alloc);

/** Destroy a bbre_builder. */
void bbre_builder_destroy(bbre_builder *build);

/** Set flags for a bbre_builder.
 ** - `pbuild` is a pointer to a bbre_builder object.
 ** - `flags` is a bitset of bbre_flags that will become the new flags of the
 **   `*pbuild`. */
void bbre_builder_flags(bbre_builder *build, bbre_flags flags);

/** An object that is able to match a single regular expression. */
typedef struct bbre bbre;

/** Initialize a bbre.
 ** `pat_nt` is a null-terminated string containing the pattern.
 **
 ** Returns a newly-constructed bbre object, or NULL if there was not enough
 ** memory to store the object. Internally, this function calls
 ** bbre_init(), which can return more than one error code if the pattern is
 ** malformed: this function still just returns NULL if these errors occur.
 **
 ** If you require more robust error checking, use bbre_init() directly. */
bbre *bbre_init_pattern(const char *pat_nt);

/** Initialize a bbre from a bbre_builder.
 ** - `preg` is a pointer to a pointer that will contain the newly-constucted
 **   bbre object.
 ** - `build` is a bbre_builder used for initializing the `*preg`.
 ** - `alloc` is the memory allocator to use. Pass NULL to use the default.
 **
 ** Returns BBRE_ERR_PARSE if the pattern in `build` contains a parsing error,
 ** BBRE_ERR_MEM if there was not enough memory to parse or compile the
 ** pattern, BBRE_ERR_LIMIT if the pattern's compiled size is too large, or 0
 ** if there was no error.
 **
 ** If this function returns BBRE_ERR_PARSE, you can use the bbre_get_error()
 ** function to retrieve a detailed error message, and an index into the pattern
 ** where the error occurred. */
int bbre_init(bbre **preg, const bbre_builder *build, const bbre_alloc *alloc);

/** Destroy a bbre. */
void bbre_destroy(bbre *reg);

/** Retrieve an error message from a \ref bbre after it generates an error.
 ** Some error codes, BBRE_ERR_PARSE and BBRE_ERR_LIMIT, may have an additional
 ** string describing the specific error in detail. bbre_get_err_msg() can be
 ** used to retrieve this null-terminated string. This function may return NULL,
 ** meaning there is no extra error message data.
 **
 ** The bbre_get_err_pos() function is relevant for BBRE_ERR_PARSE. It returns
 ** the index into the input string at which the error occurred. */
const char *bbre_get_err_msg(const bbre *reg);
size_t bbre_get_err_pos(const bbre *reg);

/** Substring bounds record.
 ** This structure records the bounds of a capture recorded by bbre_captures().
 ** `begin` is the start of the match, `end` is the end.
 **
 ** The range of characters in the input text that a span refers to is
 ** [`start`, `end`). So, an empty span at position `x` has `begin = x` and
 ** `end = x`. This is a good representation for many programming languages,
 ** especially C, because it intuitively aligns with how for-loops work. */
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
 ** groups. `out_captures_size` is the amount of groups to capture, and
 ** `out_captures` points to an array of bbre_span where the boundaries of each
 ** capture will be stored. Note that capture group 0 denotes the boundaries of
 ** the entire match (i.e., those retrieved by bbre_find()), so to retrieve the
 ** first capturing group, pass 2 for `out_captures_size`; to retrieve the
 ** second, pass 3, and so on.
 **
 ** Finally, bbre_which_captures() works like bbre_captures(), but accepts an
 ** additional argument `out_captures_did_match` that points to an array of
 ** `out_captures_size` integers. Element `n` of `out_captures_did_match` will
 ** be set to 1 if capture group `n` appeared in the match, and 0 otherwise.
 ** Like bbre_captures(), there is an implicit 0th group that represents the
 ** bounds of the entire match. Consequently, `out_captures_did_match[0]` will
 ** always be set to 1, assuming `out_captures_size >= 1`. This function is
 ** only useful when a particular pattern can match one but not another group,
 ** such as the pattern `(a)|(b)`.
 **
 ** All functions return 0 if a match was not found anywhere in `text`, 1 if a
 ** match was found, in which case the relevant `out_bounds`, `out_captures`,
 ** and/or `out_captures_did_match` variable(s) will be written to, or
 ** BBRE_ERR_MEM if there was not enough memory to successfully perform the
 ** match. */
int bbre_is_match(bbre *reg, const char *text, size_t text_size);
int bbre_find(
    bbre *reg, const char *text, size_t text_size, bbre_span *out_bounds);
int bbre_captures(
    bbre *reg, const char *text, size_t text_size, bbre_span *out_captures,
    unsigned int out_captures_size);
int bbre_which_captures(
    bbre *reg, const char *text, size_t text_size, bbre_span *out_captures,
    unsigned int *out_captures_did_match, unsigned int out_captures_size);

/** Match text against a bbre, starting the match from a given position.
 ** These functions behave identically to the bbre_is_match(), bbre_find(),
 ** bbre_captures(), and bbre_captures_at() functions, but they take an
 ** additional `pos` parameter that describes an offset in `text` to start the
 ** match from.
 **
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
    bbre_span *out_captures, unsigned int out_captures_size);
int bbre_which_captures_at(
    bbre *reg, const char *text, size_t text_size, size_t pos,
    bbre_span *out_captures, unsigned int *out_captures_did_match,
    unsigned int out_captures_size);

/** Get the number of capture groups in the given regex.
 ** This will always return 1 or more. */
unsigned int bbre_capture_count(const bbre *reg);

/** Get the name of the given capture group index.
 ** Returns a constant null-terminated string with the capture group name. For
 ** capture group 0, returns the empty string "", and for any capture group with
 ** `capture_idx >= bbre_capture_count(reg)`, returns NULL.
 ** `capture_idx` is the index of the capture group, and `out_name_size` points
 ** to a `size_t` that will hold the length (in bytes) of the return value.
 ** `out_name_size` may be NULL, in which case the length is not written.
 ** The return value of this function, if non-NULL, is guaranteed to be
 ** null-terminated. */
const char *bbre_capture_name(
    const bbre *reg, unsigned int capture_idx, size_t *out_name_size);

/** Builder class for regular expression sets. */
typedef struct bbre_set_builder bbre_set_builder;

/** Initialize a bbre_set_builder.
 ** - `pbuild` is a pointer to a pointer that will contain the newly-constructed
 **   bbre_set_builder object.
 ** - `alloc` is the bbre_alloc memory allocator to use. Pass NULL to use the
 **   default.
 **
 ** Returns BBRE_ERR_MEM if there was not enough memory to store the object,
 ** 0 otherwise. */
int bbre_set_builder_init(bbre_set_builder **pbuild, const bbre_alloc *alloc);

/** Destroy a bbre_set_builder. */
void bbre_set_builder_destroy(bbre_set_builder *build);

/** Add a pattern to a bbre_set_builder.
 ** - `build` is the set to add the pattern to
 ** - `reg` is the pattern to add
 **
 ** Returns BBRE_ERR_MEM if there was not enough memory to add `reg` to `set`,
 ** 0 otherwise. */
int bbre_set_builder_add(bbre_set_builder *build, const bbre *reg);

/** An object that concurrently matches sets of regular expressions.
 ** A bbre_set is not able to extract bounds or capture information about its
 ** individual patterns, but it can match many patterns at once very efficiently
 ** and compute which pattern(s) match a given text. */
typedef struct bbre_set bbre_set;
/** Initialize a bbre_set.
 ** - `ppats_nt` is an array of null-terminated patterns to initialize the
 **   set with.
 ** - `num_pats` is the number of patterns in `ppats_nt`.
 **
 ** Returns a newly-constructed bbre_set object, or NULL if there was not enough
 ** memory to store the object. Internally, this function calls
 ** bbre_set_init(), which can return more than one error code: this function
 ** assumes that input patterns are correct and will return NULL if any of these
 ** errors occur.
 **
 ** If you require more robust error checking, use bbre_set_init() directly. */
bbre_set *bbre_set_init_patterns(const char *const *ppats_nt, size_t num_pats);
/** Initialize a bbre_set from a bbre_set_builder.
 ** - `pset` is a pointer to a pointer that will contain the newly-constructed
 **   bbre_set_builder object.
 ** - `build` is the bbre_set_builder to initialize this object with.
 ** - `alloc` is the bbre_alloc memory allocator to use. Pass NULL to use the
 **   default.
 **
 ** Returns BBRE_ERR_MEM if there was not enough memory to construct the object,
 ** 0 otherwise. */
int bbre_set_init(
    bbre_set **pset, const bbre_set_builder *build, const bbre_alloc *alloc);
/** Destroy a bbre_set. */
void bbre_set_destroy(bbre_set *set);

/** Match text against a bbre_set.
 ** These functions perform multi-matching of patterns. They both take two
 ** parameters, `text` and `text_size`, which denote the string to match
 ** against.
 **
 ** bbre_set_is_match() simply checks if any of the individual patterns in `set`
 ** match within `text`, returning 1 if so and 0 if not.
 **
 ** bbre_set_matches() checks which patterns in `set` matched within `text`.
 ** - `out_idxs` is a pointer to an array that will hold the indices of the
 **   patterns found in `text`.
 ** - `out_idxs_size` is the maximum number of indices able to be written to
 **   `out_idxs`.
 ** - `out_num_idxs` is a pointer to an integer that will hold the number of
 **   indices written to `out_idxs`.
 **
 ** Returns 1 if any pattern in `set` matched within `text`, 0 if not, or
 ** BBRE_ERR_MEM if there was not enough memory to perform the match. */
int bbre_set_is_match(bbre_set *set, const char *text, size_t text_size);
int bbre_set_matches(
    bbre_set *set, const char *text, size_t text_size, unsigned int *out_idxs,
    unsigned int out_idxs_size, unsigned int *out_num_idxs);

/** Match text against a bbre_set, starting the match from a given position.
 ** These functions perform identically to the bbre_set_is_match() and
 ** bbre_set_matches() functions, except they take an additional `pos` argument
 ** that denotes where to start matching from.
 **
 ** See bbre_is_match_at() and its related functions for an explanation as to
 ** why these functions are needed. */
int bbre_set_is_match_at(
    bbre_set *set, const char *text, size_t text_size, size_t pos);
int bbre_set_matches_at(
    bbre_set *set, const char *text, size_t text_size, size_t pos,
    unsigned int *out_idxs, unsigned int out_idxs_size,
    unsigned int *out_num_idxs);

/** Duplicate a bbre or bbre_set without recompiling it.
 ** - `pout` is a pointer to a pointer that will contain the newly-cloned bbre
 **   or bbre_set object
 ** - `reg` and `set` are the input bbre and bbre_set objects, respectively
 ** - `alloc` is the memory allocator to use. Pass NULL to use the default.
 **
 ** If you want to match a pattern using multiple threads, you will need to call
 ** this function once per thread to obtain exclusive bbre/bbre_set objects to
 ** use, as bbre and bbre_set objects cannot be used concurrently.
 **
 ** Returns BBRE_ERR_MEM if there was not enough memory to clone the object, 0
 ** otherwise. */
int bbre_clone(bbre **pout, const bbre *reg, const bbre_alloc *alloc);
int bbre_set_clone(
    bbre_set **pout, const bbre_set *set, const bbre_alloc *alloc);

/** Returns the null-terminated version string of this library.
 **
 ** The version string matches the regex `(\d*)[.](\d*)[.](\d*)-?(.*)`, with the
 ** groups denoting major, minor, patch, and extra git information (tag offset)
 ** respectively. */
const char *bbre_version(void);

#endif /* MN_BBRE_H */

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

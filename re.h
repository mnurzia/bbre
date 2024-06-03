#ifndef MN_RE_H
#define MN_RE_H

#include <stddef.h> /* size_t */

/* Self-plagiarism from rv. */
#if __STDC__ && __STDC_VERSION__ >= 199901L /* Attempt to load stdint.h. */
  #include <stdint.h>
  #define RE_U8_TYPE  uint8_t
  #define RE_U16_TYPE uint16_t
  #define RE_S32_TYPE int32_t
  #define RE_U32_TYPE uint32_t
#else
  #ifdef __UINT8_TYPE__
    #define RE_U8_TYPE  __UINT8_TYPE__
    #define RE_U16_TYPE __UINT16_TYPE__
    #define RE_S32_TYPE __INT32_TYPE__
    #define RE_U32_TYPE __UINT32_TYPE__
  #else
    #define RE_U8_TYPE  unsigned char
    #define RE_U16_TYPE unsigned short
    #define RE_S32_TYPE signed int
    #define RE_U32_TYPE unsigned int
  #endif /* (slight) deviations from c89. Sorry {TI, Cray, DEC, et. al.} */
#endif

#define RE_ERR_MEM   (-1) /* Out of memory. */
#define RE_ERR_PARSE (-2) /* Parsing failed. */
#define RE_ERR_LIMIT (-3) /* Some hard limit was reached. */

typedef RE_U8_TYPE re_u8;
typedef RE_U16_TYPE re_u16;
typedef RE_S32_TYPE re_s32;
typedef RE_U32_TYPE re_u32;

/* These are purposefully opaque. */
typedef struct re re;
typedef struct re_exec re_exec;

/* Allocator callback.
 * `prev` is the previous size of the allocation, `next` is the requested
 * allocation size, and `ptr` is the allocation itself.
 * Returns the new allocation.
 * This is a little different from the three-callback option provided by most
 * libraries. If you are confused, this might help you understand:
 *   re_alloc(       0, new_size,    NULL) = malloc(new_size)
 *   re_alloc(old_size, new_size, old_ptr) = realloc(old_ptr, new_size)
 *   re_alloc(old_size,        0, old_ptr) = free(old_ptr)
 * Of course, the library uses stdlib malloc if possible, so chances are you
 * don't need to worry about this part of the API. */
typedef void *(*re_alloc)(size_t prev, size_t next, void *ptr);

/* Initialize a regular expression. `regex_nt` is the null-terminated regexp.
 * Returns the regex object on success, NULL on failure.
 * This function is intended for quick use, so it does not provide robust error
 * handling or customization properties. See `re_init_full` for a better
 * solution. */
re *re_init(const char *regex_nt);

/* Initialize a regular expression at `*r`. `s` is the regexp, `n` is the length
 * of the regexp, in chars, and `alloc` is the allocator function, or NULL if
 * you want to use the stdlib.
 * Returns 0 on success, RE_ERR_MEM if out of memory, or RE_ERR_PARSE if the
 * regexp was ill-formed. */
int re_init_full(re **r, const char *s, size_t n, re_alloc alloc);

/* Add another regexp to the set of regular expressions that `r` matches. */
int re_union(re *r, const char *s, size_t n);

/* Compile the regular expression so that it can be used to match text. */
int re_compile(re *r);

/* Destroy the regular expression. */
void re_destroy(re *r);

int re_get_error(re *r, const char **out, size_t *pos);

typedef struct span {
  size_t begin, end;
} span;

typedef enum anchor_type {
  RE_ANCHOR_BOTH = 'B',
  RE_ANCHOR_START = 'S',
  RE_ANCHOR_END = 'E',
  RE_UNANCHORED = 'U'
} anchor_type;

/* max_span: 1 means match bounds, 2+ means match group n */
int re_match(
    const re *r, const char *s, size_t n, re_u32 max_span, re_u32 max_set,
    span *out_span, re_u32 *out_set, anchor_type anchor);

int re_exec_init(const re *r, re_exec **exec);
void re_exec_destroy(re_exec *exec);
int re_exec_match(
    re_exec *exec, const char *s, size_t n, re_u32 max_span, re_u32 max_set,
    span *out_span, re_u32 *out_set, anchor_type anchor);

#endif /* MN_RE_H */

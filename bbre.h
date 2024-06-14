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

#define BBRE_ERR_MEM   (-1) /* Out of memory. */
#define BBRE_ERR_PARSE (-2) /* Parsing failed. */
#define BBRE_ERR_LIMIT (-3) /* Some hard limit was reached. */

typedef BBRE_U8_TYPE bbre_u8;
typedef BBRE_U16_TYPE bbre_u16;
typedef BBRE_S32_TYPE bbre_s32;
typedef BBRE_U32_TYPE bbre_u32;

/* These are purposefully opaque. */
typedef struct bbre bbre;
typedef struct bbre_prog bbre_prog;
typedef struct bbre_exec bbre_exec;

/* Allocator callback.
 * `prev` is the previous size of the allocation, `next` is the requested
 * allocation size, and `ptr` is the allocation itself.
 * Returns the new allocation.
 * This is a little different from the three-callback option provided by most
 * libraries. If you are confused, this might help you understand:
 *   bbre_alloc(       0, new_size,    NULL) = malloc(new_size)
 *   bbre_alloc(old_size, new_size, old_ptr) = realloc(old_ptr, new_size)
 *   bbre_alloc(old_size,        0, old_ptr) = free(old_ptr)
 * Of course, the library uses stdlib malloc if possible, so chances are you
 * don't need to worry about this part of the API. */
typedef void *(*bbre_alloc)(size_t prev, size_t next, void *ptr);

/* Initialize a regular expression. `regex_nt` is the null-terminated regexp.
 * Returns the regex object on success, NULL on failure.
 * This function is intended for quick use, so it does not provide robust error
 * handling or customization properties. See `bbre_init_full` for a better
 * solution. */
bbre *bbre_init(const char *regex_nt);

/* Initialize a regular expression at `*r`. `s` is the regexp, `n` is the length
 * of the regexp, in chars, and `alloc` is the allocator function, or NULL if
 * you want to use the stdlib.
 * Returns 0 on success, BBRE_ERR_MEM if out of memory, or BBRE_ERR_PARSE if the
 * regexp was ill-formed. */
int bbre_init_full(bbre **r, const char *s, size_t n, bbre_alloc alloc);

/* Add another regexp to the set of regular expressions that `r` matches. */
int bbre_union(bbre *r, const char *s, size_t n);

/* Compile the regular expression so that it can be used to match text. */
int bbre_compile(bbre *r);

/* Destroy the regular expression. */
void bbre_destroy(bbre *r);

size_t bbre_get_error(bbre *r, const char **out, size_t *pos);

typedef struct span {
  size_t begin, end;
} span;

typedef enum anchor_type {
  BBRE_ANCHOR_BOTH = 'B',
  BBRE_ANCHOR_START = 'S',
  BBRE_ANCHOR_END = 'E',
  BBRE_UNANCHORED = 'U'
} anchor_type;

/* max_span: 1 means match bounds, 2+ means match group n */
int bbre_match(
    const bbre *r, const char *s, size_t n, bbre_u32 max_span, bbre_u32 max_set,
    span *out_span, bbre_u32 *out_set, anchor_type anchor);

int bbre_exec_init(const bbre *r, bbre_exec **exec);
void bbre_exec_destroy(bbre_exec *exec);
int bbre_exec_match(
    bbre_exec *exec, const char *s, size_t n, bbre_u32 max_span,
    bbre_u32 max_set, span *out_span, bbre_u32 *out_set, anchor_type anchor);

#endif /* MN_BBRE_H */

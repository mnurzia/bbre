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
typedef struct bbre_spec bbre_spec;
typedef struct bbre bbre;
typedef struct bbre_set_spec bbre_set_spec;
typedef struct bbre_set bbre_set;

typedef struct span {
  size_t begin, end;
} span;

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

typedef enum bbre_flags {
  BBRE_FLAG_INSENSITIVE = 1,
  BBRE_FLAG_MULTILINE = 2,
  BBRE_FLAG_DOTNEWLINE = 4,
  BBRE_FLAG_UNGREEDY = 8
} bbre_flags;

int bbre_spec_init(
    bbre_spec **b, const char *pat, size_t pat_size, bbre_alloc alloc);
void bbre_spec_flags(bbre_spec *b, bbre_flags flags);
void bbre_spec_destroy(bbre_spec *b);

/* Initialize a regular expression. `regex_nt` is the null-terminated regexp.
 * Returns the regex object on success, NULL on failure.
 * This function is intended for quick use, so it does not provide robust error
 * handling or customization properties. See `bbre_init_full` for a better
 * solution. */
bbre *bbre_init(const char *regex_nt);

int bbre_init_spec(bbre **pr, const bbre_spec *spec, bbre_alloc alloc);

size_t bbre_get_error(bbre *r, const char **msg, size_t *pos);

/* Destroy the regular expression. */
void bbre_destroy(bbre *r);
int bbre_fork(bbre *r, bbre **out);

int bbre_match(
    bbre *r, const char *s, size_t n, size_t pos, bbre_u32 num_captures,
    span *captures);

int bbre_set_spec_init(bbre_set_spec **pspec, bbre_alloc alloc);
int bbre_set_spec_add(bbre_set_spec *set, const bbre *b);
int bbre_set_spec_config(bbre_set_spec *b, int option, ...);
void bbre_set_spec_destroy(bbre_set_spec *b);
bbre_set *bbre_set_init(const char *const *regexes_nt, size_t num_regexes);
int bbre_set_init_spec(
    bbre_set **pset, const bbre_set_spec *set_spec, bbre_alloc alloc);
void bbre_set_destroy(bbre_set *set);
int bbre_set_match(
    bbre_set *set, const char *s, size_t n, size_t pos, bbre_u32 idxs_size,
    bbre_u32 *out_idxs, bbre_u32 *out_num_idxs);
int bbre_set_fork(bbre_set *s, bbre_set **out);

#endif /* MN_BBRE_H */

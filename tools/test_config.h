#include "mptest.h"

extern int test_alloc_last_was_null;

void *bbre_default_alloc(void *user, void *ptr, size_t prev, size_t next)
{
  void *out_ptr = NULL;
  (void)user;
  if (next) {
    (void)prev, assert((prev || !ptr));
    out_ptr = MPTEST_INJECT_REALLOC(ptr, next);
  } else if (ptr) {
    MPTEST_INJECT_FREE(ptr);
  }
  if (next && !out_ptr)
    test_alloc_last_was_null = 1;
  else if (next)
    test_alloc_last_was_null = 0;
  return out_ptr;
}

#define BBRE_DEFAULT_ALLOC bbre_default_alloc

#include "mptest.h"

void *bbre_default_alloc(void *user, void *ptr, size_t prev, size_t next)
{
  (void)user;
  if (next) {
    (void)prev, assert((prev || !ptr));
    return MPTEST_INJECT_REALLOC(ptr, next);
  } else if (ptr) {
    MPTEST_INJECT_FREE(ptr);
  }
  return NULL;
}

#define BBRE_DEFAULT_ALLOC bbre_default_alloc

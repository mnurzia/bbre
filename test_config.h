#include "mptest.h"

void *re_default_alloc(
    size_t prev, size_t next, void *ptr)
{
  if (next) {
    (void)prev, assert((prev || !ptr));
    return MPTEST_INJECT_REALLOC(ptr, next);
  } else if (ptr) {
    MPTEST_INJECT_FREE(ptr);
  }
  return NULL;
}

#define RE_DEFAULT_ALLOC re_default_alloc

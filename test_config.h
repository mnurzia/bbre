#include "mptest.h"

void *re_default_alloc(size_t prev, size_t next, void *ptr, const char* file, int line) {
  if (next) {
    (void)prev, assert((prev || !ptr));
    return MPTEST_INJECT_REALLOC_FL(ptr, next, file, line);
  } else if (ptr) {
    MPTEST_INJECT_FREE_FL(ptr, file, line);
  }
  return NULL;
}

#define RE_DEFAULT_ALLOC re_default_alloc

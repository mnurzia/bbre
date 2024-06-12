#include "re.h"
#include <assert.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
  re *r;
  int err;
  if ((err = re_init_full(&r, (const char *)Data, Size, NULL))) {
    re_destroy(r);
    return 0;
  }
  if ((err = re_compile(r))) {
    re_destroy(r);
    return 0;
  }
  assert(re_match(r, "", 0, 0, 0, NULL, NULL, 'U') >= 0);
  re_destroy(r);
  return 0;
}

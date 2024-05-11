#include "re.h"
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
  re *r;
  int err;
  if ((err = re_init_full(&r, (const char *)Data, Size, NULL))) {
    re_destroy(r);
    return 0;
  }
  re_match(r, "", 0, 0, 0, NULL, NULL, 'U');
  re_destroy(r);
  return 0;
}

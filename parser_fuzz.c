#include "re.h"
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
  re *r;
  re_init_full(&r, (const char *)Data, Size, NULL);
  re_destroy(r);
  return 0;
}

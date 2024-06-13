#include "../re.h
#include <assert.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
  re *r;
  int err;
  if ((err = bbre_init_full(&r, (const char *)Data, Size, NULL))) {
    bbre_destroy(r);
    return 0;
  }
  if ((err = bbre_compile(r))) {
    bbre_destroy(r);
    return 0;
  }
  assert(bbre_match(r, "", 0, 0, 0, NULL, NULL, 'U') >= 0);
  bbre_destroy(r);
  return 0;
}

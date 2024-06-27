#include "../bbre.h"
#include <assert.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
  bbre *regex = NULL;
  bbre_spec *spec = NULL;
  int err = 0;
  if ((err = bbre_spec_init(&spec, (const char *)Data, Size, NULL)))
    goto done;
  if ((err = bbre_init_spec(&regex, spec, NULL)))
    goto done;
  assert(bbre_is_match(regex, "", 0) >= 0);
done:
  bbre_spec_destroy(spec);
  bbre_destroy(regex);
  return 0;
}

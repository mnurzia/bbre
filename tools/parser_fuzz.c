#include "../bbre.h"
#include <assert.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
  bbre *regex = NULL;
  bbre_builder *build = NULL;
  int err = 0;
  if ((err = bbre_builder_init(&build, (const char *)Data, Size, NULL)))
    goto done;
  if ((err = bbre_init(&regex, build, NULL)))
    goto done;
  assert(bbre_is_match(regex, "", 0) >= 0);
done:
  bbre_builder_destroy(build);
  bbre_destroy(regex);
  return 0;
}

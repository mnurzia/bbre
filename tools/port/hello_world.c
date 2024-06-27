#include <assert.h>

#include "bbre.h"

int main(void)
{
  bbre *reg = bbre_init_pattern("Hel*o (?i)[w]orld!");
  assert(bbre_is_match(reg, "Hello WorLd!", 12));
  bbre_destroy(reg);
  return 0;
}

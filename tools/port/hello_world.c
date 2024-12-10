#include <assert.h>
#include <string.h>

#include "bbre.h"

int main(void)
{
  const char *text = "Hello WorLd!";
  bbre *reg = bbre_init_pattern("Hel*o (?i)[w]orld!");
  assert(bbre_is_match(reg, text, strlen(text)) == 1);
  bbre_destroy(reg);
  return 0;
}

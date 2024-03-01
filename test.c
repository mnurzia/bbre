#include "re.h"

#include <stdio.h>
#include <stdlib.h>

int main(void) {
  re *r;
  u32 match;
  int ret;
  r = re_init("(a|)*");
  ret = re_fullmatch(r, "aaab", 4, &match);
  printf("%i %u\n", ret, match);
  re_destroy(r);
  return EXIT_SUCCESS;
}

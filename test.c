#include "re.h"

#include <stdio.h>
#include <stdlib.h>

int main(void) {
  re *r;
  span spans[64] = {0};
  u32 sets[10] = {0};
  int ret;
  r = re_init("a*b*");
  re_union(r, "b*a");
  ret = re_match(r, "a", 1, 2, 3, spans, sets, 'A');
  printf("%i %u %u %u %lu %lu\n", ret, sets[0], sets[1], sets[2],
         spans[0].begin, spans[0].end);
  re_destroy(r);
  return EXIT_SUCCESS;
}

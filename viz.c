#include "re.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

void progdump_gv(re *r);
void astdump_gv(re *r);

int main(int argc, const char *const *argv)
{
  re *r;
  char buf[BUFSIZ];
  size_t sz = 0;
  int ast;
  assert(argc > 1);
  ast = !strcmp(argv[1], "ast");
  while (fread(buf + sz, 1, 1, stdin) == 1 && buf[sz] != '\n')
    sz++;
  assert(!re_init_full(&r, buf, sz, NULL));
  if (ast)
    astdump_gv(r);
  else {
    re_match(r, "", 0, 0, 0, NULL, NULL, 'U');
    progdump_gv(r);
  }
  re_destroy(r);
  return 0;
}

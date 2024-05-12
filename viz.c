#include "re.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

void progdump_gv(re *r);
void astdump_gv(re *r);

const char *escape(const char *regex, char *buf)
{
  const char *out = buf;
  while (*regex) {
    if (*regex == '\\' || *regex == '"')
      *(buf++) = '\\', *(buf++) = '\\';
    if (*regex == '\\')
      *(buf++) = *(regex);
    *(buf++) = *(regex++);
  }
  *(buf++) = '\0';
  return out;
}

int main(int argc, const char *const *argv)
{
  re *r;
  char buf[BUFSIZ] = {0}, esc_buf[BUFSIZ] = {0};
  int ast;
  assert(argc > 1);
  ast = !strcmp(argv[1], "ast");
  fgets(buf, sizeof(buf), stdin);
  assert(!re_init_full(&r, buf, strlen(buf), NULL));
  printf(
      "digraph D { label=\"%s for \\\"%s\\\"\"; labelloc=\"t\";\n",
      ast ? "ast" : "program", escape(buf, esc_buf));
  if (ast)
    astdump_gv(r);
  else {
    re_match(r, "", 0, 0, 0, NULL, NULL, 'U');
    progdump_gv(r);
  }
  (void)(esc_buf);
  re_destroy(r);
  printf("}\n");
  return 0;
}

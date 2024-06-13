#include "../bbre.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

void d_prog_gv(bbre *r);
void d_ast_gv(bbre *r);

/* these Graphviz escaping rules are really confusing... */
const char *escape(const char *regex, char *buf)
{
  const char *out = buf;
  while (*regex) {
    if (strchr("\\\"\n\r\v\t[]", *regex)) {
      *(buf++) = '&';
      *(buf++) = '#';
      if (*regex > 100)
        *(buf++) = '0' + *regex / 100;
      *(buf++) = '0' + (*regex / 10) % 10;
      *(buf++) = '0' + *regex % 10;
      *(buf++) = ';';
      regex++;
    } else {
      *(buf++) = *(regex++);
    }
  }
  *(buf++) = '\0';
  return out;
}

int main(int argc, const char *const *argv)
{
  bbre *r;
  char buf[BUFSIZ] = {0}, esc_buf[BUFSIZ] = {0}, *res;
  int ast, err;
  assert(argc > 1);
  ast = !strcmp(argv[1], "ast");
  res = fgets(buf, sizeof(buf), stdin);
  assert(res);
  err = bbre_init_full(&r, buf, strlen(buf), NULL);
  assert(!err);
  printf(
      "digraph D { label=\"%s for \\\"%s\\\"\"; labelloc=\"t\";\n",
      ast ? "ast" : "program", escape(buf, esc_buf));
  if (ast)
    d_ast_gv(r);
  else {
    bbre_compile(r);
    d_prog_gv(r);
  }
  (void)(esc_buf);
  bbre_destroy(r);
  printf("}\n");
  return 0;
}

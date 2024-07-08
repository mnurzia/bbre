#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../bbre.h"

enum tokens { OP, NUM, WS };

const char *patterns[] = {"^[\\+\\-\\*/]", "^\\d+", "^\\s+"};

typedef unsigned int val;

int main(int argc, const char *const *argv)
{
  int err = EXIT_SUCCESS;
  bbre_set *set = bbre_set_init_patterns(patterns, WS + 1);
  bbre *pats[WS + 1] = {0};
  size_t n = 0, pos = 0, i = 0, args = 0;
  val stk[64];
  for (i = 0; i < WS + 1; i++)
    pats[i] = bbre_init_pattern(patterns[i]);
  if (argc < 2) {
    fprintf(stderr, "expected expression\n");
    err = EXIT_FAILURE;
    goto error;
  }
  n = strlen(argv[1]);
  while (pos < n) {
    unsigned int idx, num_idx, tok_size;
    bbre_span span;
    const char *tok = argv[1] + pos;
    if (bbre_set_matches(set, argv[1] + pos, n - pos, &idx, 1, &num_idx) != 1 ||
        bbre_find(pats[idx], argv[1] + pos, n - pos, &span) != 1) {
      fprintf(stderr, "invalid token at position %u\n", (unsigned int)pos);
      err = EXIT_FAILURE;
      goto error;
    }
    tok_size = span.end - span.begin;
    switch (idx) {
    case OP: {
      val p1, p2, res;
      if (args < 2) {
        fprintf(stderr, "expected two arguments for operator\n");
        err = EXIT_FAILURE;
        goto error;
      }
      p2 = stk[--args], p1 = stk[--args];
      if (*tok == '+')
        res = p1 + p2;
      else if (*tok == '-')
        res = p1 - p2;
      else if (*tok == '*')
        res = p1 * p2;
      else if (*tok == '/')
        res = p1 / p2;
      stk[args++] = res;
      break;
    }
    case NUM: {
      char buf[64]; /* i know */
      memcpy(buf, tok, tok_size);
      buf[tok_size] = '\0';
      stk[args++] = atoi(buf);
      break;
    }
    }
    pos += tok_size + (span.end == span.begin);
  }
  printf("%u\n", stk[0]);
error:
  bbre_set_destroy(set);
  for (i = 0; i < WS + 1; i++)
    bbre_destroy(pats[i]);
  return err;
}

#include "../bbre.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

int load_file(FILE *file, char **contents, size_t *contents_size)
{
  long pos = 0;
  fseek(file, 0, SEEK_END);
  pos = ftell(file);
  assert(pos >= 0);
  *contents_size = pos;
  fseek(file, 0, SEEK_SET);
  *contents = malloc(*contents_size);
  assert(*contents);
  fread(*contents, 1, *contents_size, file);
  return 0;
}

int main(int argc, const char *const *argv)
{
  int err = EXIT_SUCCESS;
  bbre *r = NULL;
  char *contents = NULL;
  FILE *f = NULL;
  if (argc < 2) {
    err = EXIT_FAILURE;
    printf("expected regexp\n");
    goto error;
  }
  if (argc < 3) {
    err = EXIT_FAILURE;
    printf("expected file name\n");
    goto error;
  }
  if (!(r = bbre_init_pattern(argv[1]))) {
    err = EXIT_FAILURE;
    printf("invalid regexp\n");
    goto error;
  }
  if (!(f = fopen(argv[2], "rb"))) {
    printf("unable to read file\n");
    goto error;
  }
  {
    size_t contents_size = 0, pos = 0;
    int re_err = 1;
    bbre_span bounds = {0};
    load_file(f, &contents, &contents_size);
    printf("%u\n", (unsigned int)contents_size);
    while (re_err) {
      if ((re_err = bbre_find_at(r, contents, contents_size, pos, &bounds)) < 0)
        goto error;
      if (re_err) {
        printf(
            "%u:%.*s\n", (unsigned int)pos,
            (unsigned int)(bounds.end - bounds.begin), contents + bounds.begin);
      }
      pos = bounds.end + (bounds.begin == bounds.end);
    }
  }
error:
  if (contents)
    free(contents);
  if (f)
    fclose(f);
  bbre_destroy(r);
  return err;
}

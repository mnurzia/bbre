#include "re.h"
#include <assert.h>
#include <stdio.h>

#include <unistd.h>

u32 read_u32_le(void)
{
  u8 bytes[4];
  size_t nread = read(STDIN_FILENO, bytes, 4);
  assert(nread == 4);
  return bytes[0] | bytes[1] << 8 | bytes[2] << 16 | bytes[3] << 24;
}

void read_n(char *out, u32 n)
{
  size_t nread = read(STDIN_FILENO, out, n);
  assert(nread == n);
}

int main(int argc, const char *const *argv)
{
  int err;
  char regex[1024];
  char example[4096];
  u32 num_regexes = read_u32_le();
  (void)argv;
  assert(argc == 1);
  while (num_regexes--) {
    u32 regex_size = read_u32_le();
    u32 example_size = read_u32_le();
    re *r;
    assert(regex_size < sizeof(regex));
    assert(example_size < sizeof(example));
    read_n(regex, regex_size);
    read_n(example, example_size);
    regex[regex_size] = '\0';
    example[example_size] = '\0';
    printf("> \"%s\"\n", regex);
    printf("> \"%s\"\n", example);
    err = re_init_full(&r, regex, regex_size, NULL);
    assert(err == 0);
    err = re_match(r, example, example_size, 0, 0, NULL, NULL, 'B');
    assert(err == 1);
    re_destroy(r);
    printf("OK\n");
  }
}

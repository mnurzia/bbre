/* Benchmarks. */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "re.h"

u32 xorshift32(u32 *state)
{
  u32 x = *state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  return *state = x;
}

void fill_rand(char *buf, size_t buf_size)
{
  u32 rng_state = 5;
  size_t i;
  u32 *buf_4 = (u32 *)buf;
  assert(!(buf_size % 4));
  for (i = 0; i < buf_size / 4; i++) {
    buf_4[i] = xorshift32(&rng_state);
  }
}

char *rand_buf(size_t buf_size)
{
  char *obuf = malloc(buf_size);
  assert(obuf);
  fill_rand(obuf, buf_size);
  return obuf;
}

clock_t start_time = 0, end_time = 0;
size_t num_units = 0;

void bench_start(void) { start_time = clock(); }

void bench_end(size_t num_units_in)
{
  end_time = clock();
  num_units = num_units_in;
}

typedef void (*bench_func)(void);

void bench_run(bench_func f, const char *bench_name)
{
  double sec, ups;
  f();
  sec = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
  ups = ((double)num_units) / sec;
  printf("%s:\t%.2f s\t %.2f MB/s\n", bench_name, sec, ups / (1000.0 * 1000.0));
}

char run_pointer_chase(char *buf, size_t buf_size)
{
  u32 state = 10;
  static void *pointers[256];
  size_t i;
  char *end = buf + buf_size;
  void **current = pointers + 0;
  for (i = 0; i < 256; i++) {
    pointers[i] = pointers + i;
  }
  for (i = 0; i < 65536; i++) {
    u32 a = xorshift32(&state) & 0xFF;
    u32 b = xorshift32(&state) & 0xFF;
    void *temp = pointers[a];
    pointers[a] = pointers[b];
    pointers[b] = temp;
  }
  while (buf < end) {
    current = *current;
    buf++;
  }
  return (char)(current - pointers);
}

void pointer_chase(void)
{
  char *buf = rand_buf(1048576 * 4 * 4);
  bench_start();
  run_pointer_chase(buf, 1048576 * 4 * 4);
  bench_end(1048576 * 4 * 4);
  free(buf);
}

void bool_match(void)
{
  re *r = re_init("123456789123456789");
  re_exec *e;
  char *buf = rand_buf(1048576 * 4 * 4);
  re_compile(r);
  re_exec_init(r, &e);
  bench_start();
  re_exec_match(e, buf, 1048576 * 4 * 4, 0, 0, NULL, NULL, 'U');
  bench_end(1048576 * 4 * 4);
  re_exec_destroy(e);
  re_destroy(r);
  free(buf);
}

int main(void)
{
  bench_run(pointer_chase, "pointer_chase");
  bench_run(bool_match, "bool_match");
}

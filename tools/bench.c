/* Benchmarks. */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../bbre.h"

bbre_u32 xorshift32(bbre_u32 *state)
{
  bbre_u32 x = *state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  return *state = x;
}

void fill_rand(char *buf, size_t buf_size)
{
  bbre_u32 rng_state = 5;
  size_t i;
  bbre_u32 *buf_4 = (bbre_u32 *)buf;
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
  printf("%30s: %.2fs %7.2fMB/s\n", bench_name, sec, ups / (1000.0 * 1000.0));
}

char run_pointer_chase(char *buf, size_t buf_size)
{
  bbre_u32 state = 10;
  static char *pointers[256];
  size_t i;
  char *end = buf + buf_size;
  char **current = pointers + 0;
  for (i = 0; i < 256; i++) {
    pointers[i] = (char *)(pointers + i);
  }
  for (i = 0; i < 65536; i++) {
    bbre_u32 a = xorshift32(&state) & 0xFF;
    bbre_u32 b = xorshift32(&state) & 0xFF;
    char *temp = pointers[a];
    pointers[a] = pointers[b];
    pointers[b] = temp;
  }
  while (buf < end) {
    current = (char **)*current;
    buf++;
  }
  return (char)(current - pointers);
}

#define BENCH_SIZE 1048576 * 64 * 16

int use(int val)
{
  /* the compiler was REALLY trying to get me not to do this... */
  const char fmt[] = {0, '%', 'i'};
  fprintf(stdout, fmt, val);
  return 0;
}

void pointer_chase(void)
{
  char *buf = rand_buf(BENCH_SIZE);
  bench_start();
  use(run_pointer_chase(buf, BENCH_SIZE));
  bench_end(BENCH_SIZE);
  free(buf);
}

void bool_match_full(void)
{
  bbre *r = bbre_init("123456789123456789*");
  char *buf = rand_buf(BENCH_SIZE);
  bench_start();
  bbre_match(r, buf, BENCH_SIZE, 0, 0, NULL);
  bench_end(BENCH_SIZE);
  bbre_destroy(r);
  free(buf);
}

#define BENCH_RUN(b) bench_run(b, #b)

int main(void)
{
  BENCH_RUN(pointer_chase);
  BENCH_RUN(bool_match_full);
  return 0;
}

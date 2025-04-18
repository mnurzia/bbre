/* Benchmarks. */

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../bbre.h"

unsigned int xorshift32(unsigned int *state)
{
  unsigned int x = *state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  return *state = x;
}

void fill_rand(char *buf, size_t buf_size)
{
  unsigned int rng_state = 5;
  size_t i;
  unsigned int *buf_4 = (unsigned int *)buf;
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
size_t num_units = 0, num_thrds = 0;

const char *bench_select = NULL;
const char *bench_current = NULL;

void bench_start(void)
{
  start_time = clock();
  printf("\r\x1b[K%30s: run...", bench_current);
  fflush(stdout);
}

void bench_end_thrds(size_t num_units_in, size_t num_thrds_in)
{
  end_time = clock();
  num_units = num_units_in;
  num_thrds = num_thrds_in;
}

void bench_end(size_t num_units_in) { bench_end_thrds(num_units_in, 1); }

typedef void (*bench_func)(void);

void bench_run(bench_func f, const char *bench_name)
{
  double sec, ups;
  if (bench_select && strcmp(bench_name, bench_select))
    return;
  bench_current = bench_name;
  printf("%30s: setup...", bench_name);
  fflush(stdout);
  f();
  sec = ((double)(end_time - start_time)) / CLOCKS_PER_SEC / num_thrds;
  ups = ((double)num_units) / sec;
  printf(
      "\r\x1b[K%30s: %.2fs %7.2fMB/s\n", bench_name, sec,
      ups / (1000.0 * 1000.0));
}

char run_pointer_chase(char *buf, size_t buf_size)
{
  unsigned int state = 10;
  static char *pointers[256];
  size_t i;
  char *end = buf + buf_size;
  char **current = pointers + 0;
  for (i = 0; i < 256; i++) {
    pointers[i] = (char *)(pointers + i);
  }
  for (i = 0; i < 65536; i++) {
    unsigned int a = xorshift32(&state) & 0xFF;
    unsigned int b = xorshift32(&state) & 0xFF;
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
  const char real_fmt[] = {0, '%', 'i', 0};
  const char *fmt = real_fmt;
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

void bool_match(void)
{
  bbre *r = bbre_init_pattern("123456789123456789*");
  char *buf = rand_buf(BENCH_SIZE);
  bench_start();
  bbre_is_match(r, buf, BENCH_SIZE);
  bench_end(BENCH_SIZE);
  bbre_destroy(r);
  free(buf);
}

void bounds_match(void)
{
  bbre *r = bbre_init_pattern("123456789123456789*");
  char *buf = rand_buf(BENCH_SIZE);
  bbre_span capture;
  bench_start();
  bbre_find(r, buf, BENCH_SIZE, &capture);
  bench_end(BENCH_SIZE);
  bbre_destroy(r);
  free(buf);
}

#define arrsize(a) (sizeof(a) / sizeof((a)[0]))

void set_match(void)
{
  bbre *regs[20] = {0};
  unsigned int idxs[20] = {0};
  unsigned int nidx;
  bbre_set_builder *spec = NULL;
  bbre_set *set = NULL;
  char *buf = rand_buf(BENCH_SIZE);
  size_t i;
  for (i = 0; i < arrsize(regs); i++) {
    regs[i] = bbre_init_pattern("123456789123456789*");
  }
  bbre_set_builder_init(&spec, NULL);
  for (i = 0; i < sizeof(regs) / sizeof(regs[0]); i++) {
    bbre_set_builder_add(spec, regs[i]);
  }
  bbre_set_init(&set, spec, NULL);
  bench_start();
  bbre_set_matches(set, buf, BENCH_SIZE, idxs, arrsize(idxs), &nidx);
  bench_end(BENCH_SIZE);
  bbre_set_destroy(set);
  bbre_set_builder_destroy(spec);
  for (i = 0; i < arrsize(regs); i++)
    bbre_destroy(regs[i]);
}

typedef struct thread_arg {
  bbre *reg;
  int write_pipe, read_pipe;
} thread_arg;

void *threaded_bool_match_main(void *a)
{
  thread_arg *arg = (thread_arg *)a;
  bbre *newreg = NULL;
  char dummy = 0;
  char *buf = rand_buf(BENCH_SIZE);
  int err = 0;
  err = bbre_clone(&newreg, arg->reg, NULL);
  assert(!err);
  (void)err;
  assert(newreg && arg->reg);
  write(arg->write_pipe, "R", 1);
  read(arg->read_pipe, &dummy, 1);
  bbre_is_match(newreg, buf, BENCH_SIZE);
  bbre_destroy(newreg);
  free(buf);
  return NULL;
}

#define NTHREAD 8

void threaded_bool_match(void)
{
  pthread_t threads[NTHREAD] = {0};
  thread_arg arg;
  int i;
  char dummy;
  int to_threads[2] = {0};
  int from_threads[2] = {0};
  bbre *reg = bbre_init_pattern("123456789123456789*");
  pipe(to_threads);
  pipe(from_threads);
  arg.read_pipe = to_threads[0];
  arg.write_pipe = from_threads[1];
  arg.reg = reg;
  for (i = 0; i < NTHREAD; i++)
    pthread_create(&threads[i], NULL, threaded_bool_match_main, &arg);
  for (i = 0; i < NTHREAD; i++)
    read(from_threads[0], &dummy, 1);
  for (i = 0; i < NTHREAD; i++)
    write(to_threads[1], "R", 1);
  bench_start();
  for (i = 0; i < NTHREAD; i++)
    pthread_join(threads[i], NULL);
  bench_end_thrds((size_t)NTHREAD * (size_t)BENCH_SIZE, NTHREAD);
  bbre_destroy(reg);
  close(from_threads[0]), close(from_threads[1]);
  close(to_threads[0]), close(to_threads[1]);
}

#define BENCH_RUN(b) bench_run(b, #b)

int main(int argc, const char *const *argv)
{
  if (argc > 1)
    bench_select = argv[1];
  BENCH_RUN(pointer_chase);
  BENCH_RUN(bool_match);
  BENCH_RUN(bounds_match);
  BENCH_RUN(set_match);
  BENCH_RUN(threaded_bool_match);
  return 0;
}

#include "../bbre.h"
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>

typedef struct color {
  const char *regex;
  const char *sgr;
} color;

static const color COLORS[] = {
    {".*\\.c",   "38;5;117"   },
    {".*\\.h",   "38;5;105"   },
    {".*\\.md",  "38;5;161"   },
    {".*\\.txt", "38;5;181;21"}
};

int main(int argc, const char *const *argv)
{
  const char *regexes[128];
  bbre_set *set = NULL;
  size_t nregex = sizeof(COLORS) / sizeof(COLORS[0]);
  size_t i;
  for (i = 0; i < nregex; i++)
    regexes[i] = COLORS[i].regex;
  set = bbre_set_init_patterns(regexes, nregex);
  assert(set);
  {
    DIR *d = opendir(argc < 2 ? "." : argv[1]);
    struct dirent *ent = NULL;
    while ((ent = readdir(d))) {
      unsigned int top = 0, any;
      const char *color_str = "0";
      if (bbre_set_matches(set, ent->d_name, ent->d_namlen, &top, 1, &any) == 1)
        color_str = COLORS[top].sgr;
      printf("\x1b[%sm%s\x1b[0m\n", color_str, ent->d_name);
    }
    closedir(d);
  }
  bbre_set_destroy(set);
}

CFLAGS=-Wall -Werror -pedantic -std=c89 

all: test testoom 

bbre_test: tools/mptest.c bbre.c tools/test_gen.c tools/test.c tools/test_config.h bbre.h
	$(CC) $(CFLAGS) -DBBRE_CONFIG_HEADER_FILE=\"tools/test_config.h\" tools/mptest.c bbre.c tools/test_gen.c tools/test.c -o $@

test: bbre_test 
	./bbre_test

testoom: bbre_test
	./bbre_test --fault-check --leak-check

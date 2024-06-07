CFLAGS=-Wall -Werror -pedantic -std=c89 

all: re-test

re-test: mptest.c re.c test-gen.c test.c test-config.h re.h
	$(CC) $(CFLAGS) -DRE_CONFIG_HEADER_FILE=\"test-config.h\" mptest.c re.c test-gen.c test.c -o $@

test: re-test
	./re-test

testoom: re-test
	./re-test --fault-check --leak-check

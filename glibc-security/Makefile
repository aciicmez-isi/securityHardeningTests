CFLAGS=-Wall -Werror -Wformat -Wformat-security -D_FORTIFY_SOURCE=2
NOOPT=-O0 -g3
OPT=-O2
LDLIBS=-ldl

EXECS=guard heap ptr-enc sprintf select env-is-defined env-is-defined-setuid

all: $(EXECS)

guard: guard.c
	STACK=-fstack-protector; \
	$(CC) $(NOOPT) $$STACK -o $@ $< $(LDLIBS)

heap: heap.c
	$(CC) $(CFLAGS) $(OPT) -o $@ $< $(LDLIBS)

ptr-enc: ptr-enc.c
	$(CC) $(CFLAGS) $(OPT) -o $@ $< $(LDLIBS)

sprintf: sprintf.c
	$(CC) $(CFLAGS) $(OPT) -o $@ $< $(LDLIBS)

select: select.c
	$(CC) $(CFLAGS) $(OPT) -o $@ $< $(LDLIBS)

env-is-defined: env-is-defined.c
	$(CC) $(CFLAGS) $(OPT) -o $@ $< $(LDLIBS)

env-is-defined-setuid: env-is-defined
	cp $< $@
	chmod 4755 $@

clean:
	rm -f $(EXECS)

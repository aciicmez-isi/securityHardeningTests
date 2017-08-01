export LIBC_FATAL_STDERR_=1
export LANG=C
export LC_CTYPE=C
export LC_MESSAGES=C
export LC_ALL=C

CC=gcc
CFLAGS=-O2

STACK_PROTECTOR=stack-protector-on stack-protector-off stack-protector-default stack-protector-all
STACK_PROTECTOR_STRONG=stack-protector-strong-on stack-protector-strong-off stack-protector-strong-default
FORMAT_SECURITY=format-security-on format-security-off format-security-equal2 format-security-default
FORMAT=format-on format-off format-equal0 format-equal1 format-equal2 format-extra-args-on format-default
BUFFER_OVERFLOW=buffer-overflow-on buffer-overflow-off buffer-overflow-default
RELRO=relro-on relro-off relro-default
PIE=pie-on pie-off pie-default
BIND_NOW=bind-now-on bind-now-off bind-now-default bind-now-pie-default

EXE=$(STACK_PROTECTOR) $(STACK_PROTECTOR_STRONG) $(FORMAT_SECURITY) $(FORMAT) \
    $(BUFFER_OVERFLOW) $(RELRO) $(PIE) $(BIND_NOW) 
all: $(EXE)

PIE_DISABLE_FLAGS=$(shell if $(CC) -no-pie -S -o /dev/null -xc /dev/null >/dev/null 2>&1 ; then \
                                echo '-no-pie' ; else echo '-fno-PIE' ; fi)
PIE_ENABLE_FLAGS=-pie $(shell if ! $(CC) -pie -o /dev/null -xc hello.c >/dev/null 2>&1 ; then echo '-fPIC' ; fi)

# Test ONLY stack protector, so disable FORTIFY
stack-protector-on: stack-protector.c
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -o $@ $< -fstack-protector

stack-protector-off: stack-protector.c
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -o $@ $< -fno-stack-protector

stack-protector-default: stack-protector.c
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -o $@ $<

stack-protector-all: stack-protector-all.c
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -o $@ $< -fstack-protector-all


# stack-protector-strong
stack-protector-strong-on: stack-protector-strong.c
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -o $@ $< -fstack-protector-strong

stack-protector-strong-off: stack-protector-strong.c
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -o $@ $< -fno-stack-protector

stack-protector-strong-default: stack-protector-strong.c
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -o $@ $<


# Test FORTIFY, but re-use stack-protector since it's basically the same test
buffer-overflow-on: stack-protector.c
	$(CC) $(CFLAGS) -fno-stack-protector -o $@ $< -D_FORTIFY_SOURCE=2

buffer-overflow-off: stack-protector.c
	$(CC) $(CFLAGS) -fno-stack-protector -o $@ $< -U_FORTIFY_SOURCE

buffer-overflow-default: stack-protector.c
	$(CC) $(CFLAGS) -fno-stack-protector -o $@ $<


format-security-on: format-security.c
	$(CC) $(CFLAGS) -o $@ $< -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security

format-security-off: format-security.c
	$(CC) $(CFLAGS) -o $@ $< -U_FORTIFY_SOURCE -Wno-format

# -Wformat=2 should also enable -Wformat-security
format-security-equal2: format-security.c
	$(CC) $(CFLAGS) -o $@ $< -D_FORTIFY_SOURCE=2 -Wformat=2

format-security-default: format-security.c
	$(CC) $(CFLAGS) -o $@ $<


# test -Wformat/-Wformat-extra-args
format-on: format-extra-args.c
	$(CC) $(CFLAGS) -o $@ $< -Wformat

format-off: format-extra-args.c
	$(CC) $(CFLAGS) -o $@ $< -Wno-format

format-equal0: format-extra-args.c
	$(CC) $(CFLAGS) -o $@ $< -Wformat=0

format-equal1: format-extra-args.c
	$(CC) $(CFLAGS) -o $@ $< -Wformat=1

format-equal2: format-extra-args.c
	$(CC) $(CFLAGS) -o $@ $< -Wformat=2

format-extra-args-on: format-extra-args.c
	$(CC) $(CFLAGS) -o $@ $< -Wformat-extra-args

format-default: format-extra-args.c
	$(CC) $(CFLAGS) -o $@ $<



relro-on: hello.c
	$(CC) $(CFLAGS) -o $@ $< -Wl,-z,relro

relro-off: hello.c
	$(CC) $(CFLAGS) -o $@ $< -Wl,-z,norelro

relro-default: hello.c
	$(CC) $(CFLAGS) -o $@ $<

pie-on: hello.c
	$(CC) $(CFLAGS) -o $@ $< $(PIE_ENABLE_FLAGS)

pie-off: hello.c
	$(CC) $(CFLAGS) -o $@ $< $(PIE_DISABLE_FLAGS)

pie-default: hello.c
	$(CC) $(CFLAGS) -o $@ $<

bind-now-on: hello.c
	$(CC) $(CFLAGS) -o $@ $< -Wl,-z,now

bind-now-off: hello.c
	$(CC) $(CFLAGS) -o $@ $< -Wl,-z,lazy

bind-now-default: hello.c
	$(CC) $(CFLAGS) -o $@ $<

bind-now-pie-default: hello.c
	$(CC) $(CFLAGS) -o $@ $< $(PIE_ENABLE_FLAGS)


clean:
	rm -f $(EXE) bogus-modes

.PHONY: clean

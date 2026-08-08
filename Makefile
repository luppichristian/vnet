CC=clang
CFLAGS=-std=c23 -Wall -Wextra -pedantic -D_CRT_SECURE_NO_WARNINGS -Wno-deprecated-declarations -Iprotocol
TARGETS := $(notdir $(basename $(wildcard targets/*.c)))

all: $(TARGETS)

$(TARGETS): %: targets/%.c
	$(CC) $(CFLAGS) $< -o build/$@.exe
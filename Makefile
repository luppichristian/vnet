CC=clang
CFLAGS=-std=c23 -Wall -Wextra -pedantic -D_CRT_SECURE_NO_WARNINGS -Wno-deprecated-declarations -Iprotocol -Itargets
TARGET_SOURCES := $(wildcard targets/*.c)
TARGETS := $(notdir $(basename $(TARGET_SOURCES)))
PROTOCOL_SOURCES := $(wildcard protocol/*.c)
COMMON_SOURCES := $(PROTOCOL_SOURCES)

all: $(TARGETS)

$(TARGETS): %: targets/%.c $(COMMON_SOURCES)
	$(CC) $(CFLAGS) $^ -o build/$@.exe
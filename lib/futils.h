#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define FORWARD_FILE_BUFFER_SIZE 4096

/* Stores the current file end while preserving the read cursor, or clamps it after truncation. */
bool get_file_end(FILE* file, long* end);

/* Forwards raw bytes through an append-mode destination until source_end. */
bool forward_bytes(FILE* source, FILE* destination, long source_end, size_t* forwarded_bytes);

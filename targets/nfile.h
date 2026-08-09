#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define NETWORK_FILE_BUFFER_SIZE 4096

/* Stores the current file end while preserving the read cursor, or clamps it after truncation. */
static inline bool get_file_end(FILE* file, long* end) {
  const long current = ftell(file);
  if (current < 0 || fseek(file, 0, SEEK_END) != 0) {
    return false;
  }
  *end = ftell(file);
  return *end >= 0 && fseek(file, current < *end ? current : *end, SEEK_SET) == 0;
}

/* Forwards raw bytes through an append-mode destination until source_end. */
static inline bool forward_bytes(FILE* source, FILE* destination, long source_end, size_t* forwarded_bytes) {
  uint8_t buffer[NETWORK_FILE_BUFFER_SIZE];
  long source_position = ftell(source);

  if (source_position < 0) {
    return false;
  }
  *forwarded_bytes = 0;
  if (source_end < source_position) {
    return fseek(source, source_end, SEEK_SET) == 0;
  }

  while (source_position < source_end) {
    const size_t remaining_bytes = (size_t)(source_end - source_position);
    const size_t byte_count = remaining_bytes < sizeof(buffer) ? remaining_bytes : sizeof(buffer);
    if (fread(buffer, 1, byte_count, source) != byte_count || fwrite(buffer, 1, byte_count, destination) != byte_count || fflush(destination) != 0) {
      return false;
    }
    source_position += (long)byte_count;
    *forwarded_bytes += byte_count;
  }
  return true;
}

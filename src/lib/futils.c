/*
 * MIT License
 *
 * Copyright (c) 2026 Christian Luppi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "futils.h"

/* Stores the current file end while preserving the read cursor, or clamps it after truncation. */
bool get_file_end(FILE* file, long* end) {
  const long current = ftell(file);
  if (current < 0 || fseek(file, 0, SEEK_END) != 0) {
    return false;
  }
  *end = ftell(file);
  return *end >= 0 && fseek(file, current < *end ? current : *end, SEEK_SET) == 0;
}

/* Forwards raw bytes through an append-mode destination until source_end. */
bool forward_bytes(FILE* source, FILE* destination, long source_end, size_t* forwarded_bytes) {
  uint8_t buffer[FORWARD_FILE_BUFFER_SIZE];
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

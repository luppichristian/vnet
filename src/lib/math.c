#include "math.h"

uint32_t crc32(const void* data, size_t data_size) {
  const uint8_t* bytes = data;
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < data_size; ++i) {
    crc ^= bytes[i];
    for (int bit = 0; bit < 8; ++bit) {
      const uint32_t mask = -(crc & 1u);
      crc = (crc >> 1) ^ (0xEDB88320u & mask);
    }
  }
  return ~crc;
}

uint16_t checksum16(const void* data, size_t data_size) {
  const uint8_t* bytes = data;
  uint32_t sum = 0;
  for (size_t i = 0; i < data_size; i += 2) {
    const uint16_t word = bytes[i] | (uint16_t)(i + 1 < data_size ? bytes[i + 1] << 8 : 0);
    sum += word;
    sum = (sum & 0xFFFFu) + (sum >> 16);
  }
  return (uint16_t)~sum;
}

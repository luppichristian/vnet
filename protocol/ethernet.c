#include <ethernet.h>
#include <string.h>

uint32_t ethernet_crc32(const void* data, size_t data_size) {
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

bool ethernet_write_frame(FILE* destination, const ethernet_frame_data_t* frame_data) {
  if (frame_data->data_length > ETHERNET_MAX_DATA_LEN) {
    return false;
  }

  const uint16_t data_length = frame_data->data_length;
  const uint16_t padded_data_length = data_length < ETHERNET_MIN_DATA_LEN ? ETHERNET_MIN_DATA_LEN : data_length;
  const uint16_t padding_length = padded_data_length - data_length;
  uint8_t padding[ETHERNET_MIN_DATA_LEN] = {0};
  ethernet_header_t header = {.type_or_length = frame_data->type_or_length};
  ethernet_footer_t footer = {0};
  uint8_t crc_buffer[sizeof(mac_address_t) * 2 + sizeof(header.type_or_length) + ETHERNET_MAX_DATA_LEN];
  size_t offset = 0;

  memset(header.preamble, ETHERNET_PREAMBLE_BYTE, sizeof(header.preamble));
  header.sfd = ETHERNET_SFD;
  memcpy(header.dst_mac, frame_data->dst_addr, sizeof(header.dst_mac));
  memcpy(header.src_mac, frame_data->src_addr, sizeof(header.src_mac));
  memcpy(crc_buffer + offset, header.dst_mac, sizeof(header.dst_mac));
  offset += sizeof(header.dst_mac);
  memcpy(crc_buffer + offset, header.src_mac, sizeof(header.src_mac));
  offset += sizeof(header.src_mac);
  memcpy(crc_buffer + offset, &header.type_or_length, sizeof(header.type_or_length));
  offset += sizeof(header.type_or_length);
  memcpy(crc_buffer + offset, frame_data->data, data_length);
  offset += data_length;
  memcpy(crc_buffer + offset, padding, padding_length);
  offset += padding_length;
  footer.crc = ethernet_crc32(crc_buffer, offset);

  return fwrite(&header, sizeof(header), 1, destination) == 1 && fwrite(frame_data->data, 1, data_length, destination) == data_length && fwrite(padding, 1, padding_length, destination) == padding_length && fwrite(&footer, sizeof(footer), 1, destination) == 1;
}

#include <ethernet.h>
#include <math.h>
#include <string.h>

bool ethernet_mac_parse(const char* text, mac_address_t mac) {
  unsigned int octets[6] = {0};
  char trailing = '\0';
  if (sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x%c", &octets[0], &octets[1], &octets[2], &octets[3], &octets[4], &octets[5], &trailing) != 6) {
    return false;
  }
  for (size_t i = 0; i < sizeof(mac_address_t); ++i) {
    mac[i] = (uint8_t)octets[i];
  }
  return true;
}

bool ethernet_mac_is_group(const mac_address_t mac) {
  return (mac[0] & 1u) != 0;
}

bool ethernet_mac_is_broadcast(const mac_address_t mac) {
  static const mac_address_t broadcast = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  return memcmp(mac, broadcast, sizeof(broadcast)) == 0;
}

void ethernet_mac_print(FILE* destination, const mac_address_t mac) {
  fprintf(destination, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool ethernet_write_frame(FILE* destination, const ethernet_frame_data_t* frame_data) {
  if (frame_data->data_length > ETHERNET_MAX_DATA_LEN || (frame_data->tagged && (frame_data->vlan_id > ETHERNET_VLAN_ID_MAX || frame_data->priority > 7))) {
    return false;
  }

  const uint16_t data_length = frame_data->data_length;
  const uint16_t padded_data_length = data_length < ETHERNET_MIN_DATA_LEN ? ETHERNET_MIN_DATA_LEN : data_length;
  const uint16_t padding_length = padded_data_length - data_length;
  uint8_t padding[ETHERNET_MIN_DATA_LEN] = {0};
  ethernet_header_t header = {.type_or_length = frame_data->tagged ? ETHERNET_ETHERTYPE_VLAN : frame_data->type_or_length};
  ethernet_vlan_tag_t tag = {
      .tag_control_information = (uint16_t)((frame_data->priority << 13) | (frame_data->drop_eligible ? 0x1000 : 0) | frame_data->vlan_id),
      .type_or_length = frame_data->type_or_length,
  };
  ethernet_footer_t footer = {0};
  uint8_t crc_buffer[sizeof(mac_address_t) * 2 + sizeof(header.type_or_length) + sizeof(tag) + ETHERNET_MAX_DATA_LEN];
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
  if (frame_data->tagged) {
    memcpy(crc_buffer + offset, &tag, sizeof(tag));
    offset += sizeof(tag);
  }
  memcpy(crc_buffer + offset, frame_data->data, data_length);
  offset += data_length;
  memcpy(crc_buffer + offset, padding, padding_length);
  offset += padding_length;
  footer.crc = crc32(crc_buffer, offset);

  return fwrite(&header, sizeof(header), 1, destination) == 1 && (!frame_data->tagged || fwrite(&tag, sizeof(tag), 1, destination) == 1) && fwrite(frame_data->data, 1, data_length, destination) == data_length && fwrite(padding, 1, padding_length, destination) == padding_length && fwrite(&footer, sizeof(footer), 1, destination) == 1;
}

bool ethernet_frame_is_start(const uint8_t* bytes, size_t byte_count) {
  if (byte_count < ETHERNET_PREAMBLE_LEN + sizeof(uint8_t)) {
    return false;
  }
  for (size_t i = 0; i < ETHERNET_PREAMBLE_LEN; ++i) {
    if (bytes[i] != ETHERNET_PREAMBLE_BYTE) {
      return false;
    }
  }
  return bytes[ETHERNET_PREAMBLE_LEN] == ETHERNET_SFD;
}

bool ethernet_parse_frame(const uint8_t* bytes, size_t byte_count, ethernet_frame_view_t* frame) {
  if (byte_count < sizeof(frame->header) + sizeof(frame->footer)) {
    return false;
  }
  memcpy(&frame->header, bytes, sizeof(frame->header));
  if (!ethernet_frame_is_start(bytes, byte_count)) {
    return false;
  }
  const uint8_t* cursor = bytes + sizeof(frame->header);
  size_t tag_length = 0;
  frame->tagged = frame->header.type_or_length == ETHERNET_ETHERTYPE_VLAN;
  frame->type_or_length = frame->header.type_or_length;
  if (frame->tagged) {
    ethernet_vlan_tag_t tag = {0};
    if (byte_count < sizeof(frame->header) + sizeof(tag) + sizeof(frame->footer)) return false;
    memcpy(&tag, cursor, sizeof(tag));
    frame->priority = (uint8_t)(tag.tag_control_information >> 13);
    frame->drop_eligible = (tag.tag_control_information & 0x1000) != 0;
    frame->vlan_id = tag.tag_control_information & 0x0FFF;
    frame->type_or_length = tag.type_or_length;
    cursor += sizeof(tag);
    tag_length = sizeof(tag);
  }
  frame->format = ETHERNET_FRAME_FORMAT_IEEE_802_3;
  if (frame->type_or_length <= ETHERNET_MAX_DATA_LEN) {
    frame->client_data_length = frame->type_or_length;
    frame->data_length = frame->client_data_length < ETHERNET_MIN_DATA_LEN ? ETHERNET_MIN_DATA_LEN : frame->client_data_length;
    if (byte_count != sizeof(frame->header) + tag_length + frame->data_length + sizeof(frame->footer)) {
      return false;
    }
  } else {
    if (frame->type_or_length < ETHERNET_ETHERTYPE_MIN || byte_count < sizeof(frame->header) + tag_length + ETHERNET_MIN_DATA_LEN + sizeof(frame->footer)) {
      return false;
    }
    frame->format = ETHERNET_FRAME_FORMAT_II;
    frame->data_length = (uint16_t)(byte_count - sizeof(frame->header) - tag_length - sizeof(frame->footer));
    frame->client_data_length = frame->data_length;
    if (frame->data_length > ETHERNET_MAX_DATA_LEN) {
      return false;
    }
  }
  frame->data = cursor;
  memcpy(&frame->footer, frame->data + frame->data_length, sizeof(frame->footer));
  return crc32(bytes + ETHERNET_PREAMBLE_LEN + sizeof(frame->header.sfd), sizeof(frame->header.dst_mac) + sizeof(frame->header.src_mac) + sizeof(frame->header.type_or_length) + tag_length + frame->data_length) == frame->footer.crc;
}

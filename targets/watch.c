/* This program will allow to inspect an open network traffic file in different modes.
In our case we mimic network traffic through a simple binary file.
We send data by appending to the file and we receive data by reading the file periodically.
*/

#include <ethernet.h>
#include <ipv4.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vnet.h>

/* Max amount of bytes that can be read at each iteration*/
#define MAX_READ 4096

static void print_ipv4_packet(const uint8_t* bytes, uint16_t data_field_length) {
  ipv4_header_t ipv4_header = {0};
  memcpy(&ipv4_header, bytes, sizeof(ipv4_header));
  const uint8_t ipv4_version = ipv4_header.version;
  const uint8_t ipv4_header_length = ipv4_header.ihl * 4;
  if (data_field_length < sizeof(ipv4_header) || ipv4_version != 4 || ipv4_header_length != sizeof(ipv4_header) || ipv4_header.total_length < sizeof(ipv4_header) || ipv4_header.total_length > data_field_length || ipv4_checksum(&ipv4_header, sizeof(ipv4_header)) != 0) {
    fprintf(stdout, "  IPv4:            invalid header\n");
    return;
  }

  fprintf(stdout, "  Valid IPv4 packet (%u bytes):\n", ipv4_header.total_length);
  fprintf(stdout, "    IPv4 source:     %u.%u.%u.%u\n", ipv4_header.src_addr & 0xFF, (ipv4_header.src_addr >> 8) & 0xFF, (ipv4_header.src_addr >> 16) & 0xFF, ipv4_header.src_addr >> 24);
  fprintf(stdout, "    IPv4 destination:%u.%u.%u.%u\n", ipv4_header.dst_addr & 0xFF, (ipv4_header.dst_addr >> 8) & 0xFF, (ipv4_header.dst_addr >> 16) & 0xFF, ipv4_header.dst_addr >> 24);
  fprintf(stdout, "    IPv4 total length: %u bytes, TTL: %u, protocol: %u\n", ipv4_header.total_length, ipv4_header.ttl, ipv4_header.protocol);
}

static bool is_ethernet_frame_start(const uint8_t* bytes, size_t byte_count) {
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

static bool is_vnet_frame_start(const uint8_t* bytes, size_t byte_count) {
  if (byte_count < sizeof(vnet_frame_header_t)) {
    return false;
  }

  vnet_frame_header_t header = {0};
  memcpy(&header, bytes, sizeof(header));
  return vnet_frame_is_valid(&header);
}

static bool is_vnet_frame_prefix(const uint8_t* bytes, size_t byte_count) {
  uint32_t magic = 0;
  return byte_count >= sizeof(magic) && memcpy(&magic, bytes, sizeof(magic)) && magic == VNET_FRAME_MAGIC;
}

static bool print_ethernet_frame(const uint8_t* bytes, size_t byte_count) {
  if (byte_count < sizeof(ethernet_header_t) + sizeof(ethernet_footer_t)) {
    return false;
  }

  ethernet_header_t header = {0};
  memcpy(&header, bytes, sizeof(header));
  for (size_t i = 0; i < ETHERNET_PREAMBLE_LEN; ++i) {
    if (header.preamble[i] != ETHERNET_PREAMBLE_BYTE) {
      return false;
    }
  }
  if (header.sfd != ETHERNET_SFD) {
    return false;
  }

  ethernet_frame_format_t format = ETHERNET_FRAME_FORMAT_IEEE_802_3;
  uint16_t data_field_length = 0;
  uint16_t client_data_length = 0;
  size_t expected_frame_length = 0;
  if (header.type_or_length <= ETHERNET_MAX_DATA_LEN) {
    client_data_length = header.type_or_length;
    data_field_length = client_data_length < ETHERNET_MIN_DATA_LEN ? ETHERNET_MIN_DATA_LEN : client_data_length;
    expected_frame_length = sizeof(header) + data_field_length + sizeof(ethernet_footer_t);
    if (byte_count != expected_frame_length) {
      return false;
    }
  } else {
    if (header.type_or_length < ETHERNET_ETHERTYPE_MIN || byte_count < sizeof(header) + ETHERNET_MIN_DATA_LEN + sizeof(ethernet_footer_t)) {
      return false;
    }

    format = ETHERNET_FRAME_FORMAT_II;
    expected_frame_length = byte_count;
    data_field_length = (uint16_t)(byte_count - sizeof(header) - sizeof(ethernet_footer_t));
    if (data_field_length > ETHERNET_MAX_DATA_LEN) {
      return false;
    }
  }

  ethernet_footer_t footer = {0};
  memcpy(&footer, bytes + expected_frame_length - sizeof(footer), sizeof(footer));
  const uint8_t* crc_data = bytes + ETHERNET_PREAMBLE_LEN + sizeof(header.sfd);
  const size_t crc_data_length = sizeof(header.dst_mac) + sizeof(header.src_mac) + sizeof(header.type_or_length) + data_field_length;
  if (ethernet_crc32(crc_data, crc_data_length) != footer.crc) {
    return false;
  }

  fprintf(stdout, "Received %li bytes (%li bits):\n", (long)byte_count, (long)byte_count * 8);
  fprintf(stdout, "  Valid %s frame (%zu bytes):\n", format == ETHERNET_FRAME_FORMAT_IEEE_802_3 ? "IEEE 802.3 Ethernet" : "Ethernet II", expected_frame_length);
  fprintf(stdout, "    Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", header.dst_mac[0], header.dst_mac[1], header.dst_mac[2], header.dst_mac[3], header.dst_mac[4], header.dst_mac[5]);
  fprintf(stdout, "    Source MAC:      %02X:%02X:%02X:%02X:%02X:%02X\n", header.src_mac[0], header.src_mac[1], header.src_mac[2], header.src_mac[3], header.src_mac[4], header.src_mac[5]);
  if (format == ETHERNET_FRAME_FORMAT_IEEE_802_3) {
    fprintf(stdout, "    Client data:     %u bytes\n", client_data_length);
    fprintf(stdout, "    Padding:         %u bytes\n", data_field_length - client_data_length);
  } else {
    const char* ether_type_name = "unknown";
    if (header.type_or_length == ETHERNET_ETHERTYPE_IPV4) {
      ether_type_name = "IPv4";
    } else if (header.type_or_length == ETHERNET_ETHERTYPE_ARP) {
      ether_type_name = "ARP";
    } else if (header.type_or_length == ETHERNET_ETHERTYPE_IPV6) {
      ether_type_name = "IPv6";
    }
    fprintf(stdout, "    EtherType:       0x%04X (%s)\n", header.type_or_length, ether_type_name);
    fprintf(stdout, "    Data field:      %u bytes (may include padding)\n", data_field_length);
  }
  fprintf(stdout, "    FCS:             %08X (valid)\n", footer.crc);
  if (format == ETHERNET_FRAME_FORMAT_II && header.type_or_length == ETHERNET_ETHERTYPE_IPV4) {
    print_ipv4_packet(bytes + sizeof(header), data_field_length);
  }
  return true;
}

static bool print_vnet_frame(const uint8_t* bytes, size_t byte_count) {
  if (!is_vnet_frame_start(bytes, byte_count)) {
    return false;
  }

  vnet_frame_header_t header = {0};
  memcpy(&header, bytes, sizeof(header));
  if (byte_count != sizeof(header)) {
    return false;
  }

  const char* event = header.type == VNET_FRAME_CONNECTION_START ? "connection start" : "connection end";
  fprintf(stdout, "Received %li bytes (%li bits):\n", (long)byte_count, (long)byte_count * 8);
  fprintf(stdout, "  Valid VNet control frame (%zu bytes):\n", sizeof(header));
  fprintf(stdout, "    Event:           %s\n", event);
  fprintf(stdout, "    Source file:     %s\n", header.source_path);
  fprintf(stdout, "    Destination file:%s\n", header.destination_path);
  return true;
}

static void print_raw_bytes(const uint8_t* bytes, long byte_count) {
  fprintf(stdout, "Received %li bytes (%li bits): ", byte_count, byte_count * 8);
  for (long i = 0; i < byte_count; ++i) {
    for (int bit = 0; bit < 8; ++bit) {
      fputc(((bytes[i] >> bit) & 1u) ? '1' : '0', stdout);
    }
    if (i != (byte_count - 1)) {
      fputchar(' ');
    }
  }
  fputc('\n', stdout);
}

int main(int argc, char** argv) {
  if (argc == 1) {
    fprintf(stderr, "Expected at least 1 argument (the name of the network file).\n");
    return (EXIT_FAILURE);
  }

  const char* fpath = argv[1];
  FILE* f = fopen(fpath, "rb");
  if (!f) {
    fprintf(stderr, "Could not open the file \'%s\' for reading in binary mode.\n", fpath);
    return (EXIT_FAILURE);
  }

  /* Start at the end of the file */
  fseek(f, 0, SEEK_END);
  long offset = ftell(f);

  /* Byte buffer */
  uint8_t buff[MAX_READ + sizeof(vnet_frame_header_t)];
  size_t buffered_bytes = 0;

  /* Loop*/
  while (1) {
    /* Check if we have any bytes to read */
    fseek(f, 0, SEEK_END);
    const long end = ftell(f);
    if (end == offset) {
      _sleep(3);
      continue;
    }

    /* Compute bytes to read */
    const long to_read = min(end - offset, MAX_READ);
    if (to_read < 0) {
      fclose(f);
      fprintf(stderr, "Unexpected file modification while watching the file \'%s\'.", fpath);
      return (EXIT_FAILURE);
    }

    /* Seek back to where we left off before reading */
    fseek(f, offset, SEEK_SET);

    /* Read the actual bytes */
    const long actually_read = fread(buff + buffered_bytes, 1, to_read, f);
    if (actually_read != to_read) {
      fclose(f);
      fprintf(stderr, "Unexpected file op fail while reading the file \'%s\'.", fpath);
      return (EXIT_FAILURE);
    }

    /* Advance offset by what we actually consumed */
    offset += actually_read;

    /* Split consecutive Ethernet and VNet frames at their start sequences. */
    const size_t byte_count = buffered_bytes + (size_t)actually_read;
    size_t frame_start = 0;
    while (frame_start < byte_count) {
      if (is_vnet_frame_start(buff + frame_start, byte_count - frame_start)) {
        print_vnet_frame(buff + frame_start, sizeof(vnet_frame_header_t));
        frame_start += sizeof(vnet_frame_header_t);
        continue;
      }

      size_t frame_end = frame_start + 1;
      for (; frame_end < byte_count; ++frame_end) {
        if (is_ethernet_frame_start(buff + frame_end, byte_count - frame_end) || is_vnet_frame_prefix(buff + frame_end, byte_count - frame_end)) {
          break;
        }
      }
      if (frame_end < byte_count) {
        const size_t frame_length = frame_end - frame_start;
        if (!print_ethernet_frame(buff + frame_start, frame_length)) {
          print_raw_bytes(buff + frame_start, (long)frame_length);
        }
        frame_start = frame_end;
        continue;
      }

      const size_t frame_length = byte_count - frame_start;
      if (is_vnet_frame_prefix(buff + frame_start, frame_length) && frame_length < sizeof(vnet_frame_header_t)) {
        memmove(buff, buff + frame_start, frame_length);
        buffered_bytes = frame_length;
      } else {
        if (!print_ethernet_frame(buff + frame_start, frame_length)) {
          print_raw_bytes(buff + frame_start, (long)frame_length);
        }
        buffered_bytes = 0;
      }
      break;
    }
    if (frame_start == byte_count) {
      buffered_bytes = 0;
    }
  }

  fclose(f);
  return (EXIT_SUCCESS);
}

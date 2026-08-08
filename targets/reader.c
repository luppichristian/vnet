/* This program will allow to inspect an open network traffic file in different modes.
In our case we mimic network traffic through a simple binary file.
We send data by appending to the file and we receive data by reading the file periodically.
*/

#include <ethernet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Max amount of bytes that can be read at each iteration*/
#define MAX_READ 1024

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
  if (crc32(crc_data, crc_data_length) != footer.crc) {
    return false;
  }

  fprintf(stdout, "Valid %s frame (%zu bytes):\n", format == ETHERNET_FRAME_FORMAT_IEEE_802_3 ? "IEEE 802.3 Ethernet" : "Ethernet II", expected_frame_length);
  fprintf(stdout, "  Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", header.dst_mac[0], header.dst_mac[1], header.dst_mac[2], header.dst_mac[3], header.dst_mac[4], header.dst_mac[5]);
  fprintf(stdout, "  Source MAC:      %02X:%02X:%02X:%02X:%02X:%02X\n", header.src_mac[0], header.src_mac[1], header.src_mac[2], header.src_mac[3], header.src_mac[4], header.src_mac[5]);
  if (format == ETHERNET_FRAME_FORMAT_IEEE_802_3) {
    fprintf(stdout, "  Client data:     %u bytes\n", client_data_length);
    fprintf(stdout, "  Padding:         %u bytes\n", data_field_length - client_data_length);
  } else {
    const char* ether_type_name = "unknown";
    if (header.type_or_length == ETHERNET_ETHERTYPE_IPV4) {
      ether_type_name = "IPv4";
    } else if (header.type_or_length == ETHERNET_ETHERTYPE_ARP) {
      ether_type_name = "ARP";
    } else if (header.type_or_length == ETHERNET_ETHERTYPE_IPV6) {
      ether_type_name = "IPv6";
    }
    fprintf(stdout, "  EtherType:       0x%04X (%s)\n", header.type_or_length, ether_type_name);
    fprintf(stdout, "  Data field:      %u bytes (may include padding)\n", data_field_length);
  }
  fprintf(stdout, "  FCS:             %08X (valid)\n", footer.crc);
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
  uint8_t buff[MAX_READ];

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
    const long actually_read = fread(buff, 1, to_read, f);
    if (actually_read != to_read) {
      fclose(f);
      fprintf(stderr, "Unexpected file op fail while reading the file \'%s\'.", fpath);
      return (EXIT_FAILURE);
    }

    /* Advance offset by what we actually consumed */
    offset += actually_read;

    /* Attempt to print an ethernet frame */
    if (print_ethernet_frame(buff, actually_read)) {
      continue;
    }

    /* Print raw bytes otherwise */
    print_raw_bytes(buff, actually_read);
  }

  fclose(f);
  return (EXIT_SUCCESS);
}

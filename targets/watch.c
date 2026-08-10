/*
This program inspects an open network traffic file in different modes.
We send data by appending to the file and receive data by reading it periodically.
*/

#include <ethernet.h>
#include <ipv4.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread.h>
#include <vnet.h>

/* Max amount of bytes that can be read at each iteration*/
#define MAX_READ 4096

static void print_ipv4_packet(const uint8_t* bytes, uint16_t data_field_length) {
  ipv4_packet_view_t packet = {0};
  if (!ipv4_parse_packet(bytes, data_field_length, &packet)) {
    fprintf(stdout, "  IPv4:            invalid header\n");
    return;
  }

  fprintf(stdout, "  Valid IPv4 packet (%u bytes):\n", packet.header.total_length);
  fprintf(stdout, "    IPv4 source:     %u.%u.%u.%u\n", packet.header.src_addr & 0xFF, (packet.header.src_addr >> 8) & 0xFF, (packet.header.src_addr >> 16) & 0xFF, packet.header.src_addr >> 24);
  fprintf(stdout, "    IPv4 destination:%u.%u.%u.%u\n", packet.header.dst_addr & 0xFF, (packet.header.dst_addr >> 8) & 0xFF, (packet.header.dst_addr >> 16) & 0xFF, packet.header.dst_addr >> 24);
  fprintf(stdout, "    IPv4 total length: %u bytes, TTL: %u, protocol: %u\n", packet.header.total_length, packet.header.ttl, packet.header.protocol);
}

static bool print_ethernet_frame(const uint8_t* bytes, size_t byte_count) {
  ethernet_frame_view_t frame = {0};
  if (!ethernet_parse_frame(bytes, byte_count, &frame)) {
    return false;
  }

  const ethernet_header_t* header = &frame.header;
  const ethernet_footer_t* footer = &frame.footer;

  fprintf(stdout, "Received %li bytes (%li bits):\n", (long)byte_count, (long)byte_count * 8);
  fprintf(stdout, "  Valid %s frame (%zu bytes):\n", frame.format == ETHERNET_FRAME_FORMAT_IEEE_802_3 ? "IEEE 802.3 Ethernet" : "Ethernet II", byte_count);
  fprintf(stdout, "    Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", header->dst_mac[0], header->dst_mac[1], header->dst_mac[2], header->dst_mac[3], header->dst_mac[4], header->dst_mac[5]);
  fprintf(stdout, "    Source MAC:      %02X:%02X:%02X:%02X:%02X:%02X\n", header->src_mac[0], header->src_mac[1], header->src_mac[2], header->src_mac[3], header->src_mac[4], header->src_mac[5]);
  if (frame.format == ETHERNET_FRAME_FORMAT_IEEE_802_3) {
    fprintf(stdout, "    Client data:     %u bytes\n", frame.client_data_length);
    fprintf(stdout, "    Padding:         %u bytes\n", frame.data_length - frame.client_data_length);
  } else {
    const char* ether_type_name = "unknown";
    if (header->type_or_length == ETHERNET_ETHERTYPE_IPV4) {
      ether_type_name = "IPv4";
    } else if (header->type_or_length == ETHERNET_ETHERTYPE_ARP) {
      ether_type_name = "ARP";
    } else if (header->type_or_length == ETHERNET_ETHERTYPE_IPV6) {
      ether_type_name = "IPv6";
    }
    fprintf(stdout, "    EtherType:       0x%04X (%s)\n", header->type_or_length, ether_type_name);
    fprintf(stdout, "    Data field:      %u bytes (may include padding)\n", frame.data_length);
  }
  fprintf(stdout, "    FCS:             %08X (valid)\n", footer->crc);
  if (frame.format == ETHERNET_FRAME_FORMAT_II && header->type_or_length == ETHERNET_ETHERTYPE_IPV4) {
    print_ipv4_packet(frame.data, frame.data_length);
  }
  return true;
}

static bool print_vnet_frame(const uint8_t* bytes, size_t byte_count) {
  vnet_frame_header_t header = {0};
  if (!vnet_parse_frame(bytes, byte_count, &header)) {
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
      thread_sleep(3);
      continue;
    }

    /* Compute bytes to read */
    const long to_read = end - offset < MAX_READ ? end - offset : MAX_READ;
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
      if (byte_count - frame_start >= sizeof(vnet_frame_header_t) && vnet_parse_frame(buff + frame_start, sizeof(vnet_frame_header_t), &(vnet_frame_header_t) {0})) {
        print_vnet_frame(buff + frame_start, sizeof(vnet_frame_header_t));
        frame_start += sizeof(vnet_frame_header_t);
        continue;
      }

      size_t frame_end = frame_start + 1;
      for (; frame_end < byte_count; ++frame_end) {
        if (ethernet_frame_is_start(buff + frame_end, byte_count - frame_end) || vnet_frame_has_prefix(buff + frame_end, byte_count - frame_end)) {
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
      if (vnet_frame_has_prefix(buff + frame_start, frame_length) && frame_length < sizeof(vnet_frame_header_t)) {
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

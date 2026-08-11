/*
This program inspects an open network traffic file in different modes.
We send data by appending to the file and receive data by reading it periodically.
*/

#include <arp.h>
#include <cmd_app.h>
#include <ethernet.h>
#include <icmp.h>
#include <ipv4.h>
#include <rarp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tcp.h>
#include <thread.h>
#include <udp.h>
#include <vnet.h>

/* Max amount of bytes that can be read at each iteration*/
#define MAX_READ 4096

typedef struct watch_context {
  const char* path;
} watch_context_t;

static void command_info(void* argument, char* arguments) {
  const watch_context_t* context = argument;
  if (!cmd_app_arguments_empty(arguments)) {
    fputs("Usage: info\n", stderr);
    return;
  }
  fprintf(stdout, "Watching file: %s\n", context->path);
}

static void print_data(const char* label, const uint8_t* data, size_t data_length) {
  fprintf(stdout, "    %s: %zu bytes", label, data_length);
  if (data_length > 0) {
    fputs(" (\"", stdout);
    for (size_t i = 0; i < data_length; ++i) {
      fputc(data[i] >= 32 && data[i] <= 126 ? data[i] : '.', stdout);
    }
    fputc('"', stdout);
  }
  fputs(")\n", stdout);
}

static void print_arp_packet(const uint8_t* bytes, size_t byte_count) {
  arp_packet_t packet = {0};
  if (byte_count < sizeof(packet) || !arp_parse_packet(bytes, sizeof(packet), &packet)) {
    fputs("  ARP:             invalid packet\n", stdout);
    return;
  }
  fprintf(stdout, "  Valid ARP %s:\n", packet.operation == ARP_OPERATION_REQUEST ? "request" : "reply");
  fputs("    Sender MAC:     ", stdout);
  ethernet_mac_print(stdout, packet.sender_hardware_address);
  fputs("\n    Sender IPv4:    ", stdout);
  ipv4_address_print(stdout, packet.sender_protocol_address);
  fputs("\n    Target MAC:     ", stdout);
  ethernet_mac_print(stdout, packet.target_hardware_address);
  fputs("\n    Target IPv4:    ", stdout);
  ipv4_address_print(stdout, packet.target_protocol_address);
  fputc('\n', stdout);
}

static void print_rarp_packet(const uint8_t* bytes, size_t byte_count) {
  rarp_packet_t packet = {0};
  if (byte_count < sizeof(packet) || !rarp_parse_packet(bytes, sizeof(packet), &packet)) {
    fputs("  RARP:            invalid packet\n", stdout);
    return;
  }
  fprintf(stdout, "  Valid RARP %s:\n", packet.operation == RARP_OPERATION_REQUEST ? "request" : "reply");
  fputs("    Sender MAC:     ", stdout);
  ethernet_mac_print(stdout, packet.sender_hardware_address);
  fputs("\n    Sender IPv4:    ", stdout);
  ipv4_address_print(stdout, packet.sender_protocol_address);
  fputs("\n    Target MAC:     ", stdout);
  ethernet_mac_print(stdout, packet.target_hardware_address);
  fputs("\n    Target IPv4:    ", stdout);
  ipv4_address_print(stdout, packet.target_protocol_address);
  fputc('\n', stdout);
}

static void print_icmp_packet(const uint8_t* bytes, size_t byte_count) {
  icmp_echo_header_t header = {0};
  const uint8_t* data = NULL;
  size_t data_length = 0;
  if (!icmp_parse_echo_packet(bytes, byte_count, &header, &data, &data_length)) {
    fputs("  ICMP:            invalid or unsupported packet\n", stdout);
    return;
  }
  fprintf(stdout, "  Valid ICMP Echo %s:\n", header.type == ICMP_TYPE_ECHO_REQUEST ? "request" : "reply");
  fprintf(stdout, "    Identifier:     %u, sequence: %u, checksum: %04X (valid)\n", header.identifier, header.sequence_number, header.checksum);
  print_data("ICMP data", data, data_length);
}

static void print_udp_packet(const ipv4_packet_view_t* ip4) {
  udp_packet_view_t packet = {0};
  if (!udp_parse_packet(ip4->payload, ip4->payload_length, ip4->header.src_addr, ip4->header.dst_addr, &packet)) {
    fputs("  UDP:             invalid packet\n", stdout);
    return;
  }
  fputs("  Valid UDP datagram:\n", stdout);
  fprintf(stdout, "    Source port:    %u\n    Destination port: %u\n    UDP length:      %u bytes, checksum: %04X (%s)\n", packet.header.src_port, packet.header.dst_port, packet.header.length, packet.header.checksum, packet.header.checksum == 0 ? "omitted" : "valid");
  print_data("UDP data", packet.data, packet.data_length);
}

static void print_tcp_flags(const tcp_header_t* header) {
  const struct {
    uint16_t flag;
    const char* name;
  } flags[] = {
      { TCP_FLAG_NS,  "NS"},
      {TCP_FLAG_CWR, "CWR"},
      {TCP_FLAG_ECE, "ECE"},
      {TCP_FLAG_URG, "URG"},
      {TCP_FLAG_ACK, "ACK"},
      {TCP_FLAG_PSH, "PSH"},
      {TCP_FLAG_RST, "RST"},
      {TCP_FLAG_SYN, "SYN"},
      {TCP_FLAG_FIN, "FIN"},
  };
  bool first = true;
  fputs("    Flags:          ", stdout);
  for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i) {
    const bool set = (flags[i].flag == TCP_FLAG_NS && header->ns) || (flags[i].flag == TCP_FLAG_CWR && header->cwr) || (flags[i].flag == TCP_FLAG_ECE && header->ece) || (flags[i].flag == TCP_FLAG_URG && header->urg) || (flags[i].flag == TCP_FLAG_ACK && header->ack) || (flags[i].flag == TCP_FLAG_PSH && header->psh) || (flags[i].flag == TCP_FLAG_RST && header->rst) || (flags[i].flag == TCP_FLAG_SYN && header->syn) || (flags[i].flag == TCP_FLAG_FIN && header->fin);
    if (set) {
      fprintf(stdout, "%s%s", first ? "" : ",", flags[i].name);
      first = false;
    }
  }
  fputs(first ? "none\n" : "\n", stdout);
}

static void print_tcp_packet(const ipv4_packet_view_t* ip4) {
  tcp_packet_view_t packet = {0};
  if (!tcp_parse_packet(ip4->payload, ip4->payload_length, ip4->header.src_addr, ip4->header.dst_addr, &packet)) {
    fputs("  TCP:             invalid packet\n", stdout);
    return;
  }
  fputs("  Valid TCP segment:\n", stdout);
  fprintf(stdout, "    Source port:    %u\n    Destination port: %u\n    Sequence number: %u\n    Acknowledgement:  %u\n    Header length:    %u bytes, window: %u, checksum: %04X (valid)\n", packet.header.src_port, packet.header.dst_port, packet.header.sequence_number, packet.header.acknowledgement_number, packet.header.data_offset * 4, packet.header.window_size, packet.header.checksum);
  print_tcp_flags(&packet.header);
  print_data("TCP data", packet.data, packet.data_length);
}

static void print_ipv4_packet(const uint8_t* bytes, uint16_t data_field_length) {
  ipv4_packet_view_t packet = {0};
  if (!ipv4_parse_packet(bytes, data_field_length, &packet)) {
    fprintf(stdout, "  IPv4:            invalid header\n");
    return;
  }

  fprintf(stdout, "  Valid IPv4 packet (%u bytes):\n", packet.header.total_length);
  fputs("    IPv4 source:     ", stdout);
  ipv4_address_print(stdout, packet.header.src_addr);
  fputc('\n', stdout);
  fputs("    IPv4 destination:", stdout);
  ipv4_address_print(stdout, packet.header.dst_addr);
  fputc('\n', stdout);
  fprintf(stdout, "    IPv4 total length: %u bytes, TTL: %u, protocol: %u\n", packet.header.total_length, packet.header.ttl, packet.header.protocol);
  if (packet.header.protocol == ICMP_IPV4_PROTOCOL) {
    print_icmp_packet(packet.payload, packet.payload_length);
  } else if (packet.header.protocol == UDP_IPV4_PROTOCOL) {
    print_udp_packet(&packet);
  } else if (packet.header.protocol == TCP_IPV4_PROTOCOL) {
    print_tcp_packet(&packet);
  } else {
    fprintf(stdout, "  IPv4 payload:    unsupported protocol %u\n", packet.header.protocol);
  }
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
  fputs("    Destination MAC: ", stdout);
  ethernet_mac_print(stdout, header->dst_mac);
  fputc('\n', stdout);
  fputs("    Source MAC:      ", stdout);
  ethernet_mac_print(stdout, header->src_mac);
  fputc('\n', stdout);
  if (frame.format == ETHERNET_FRAME_FORMAT_IEEE_802_3) {
    fprintf(stdout, "    Client data:     %u bytes\n", frame.client_data_length);
    fprintf(stdout, "    Padding:         %u bytes\n", frame.data_length - frame.client_data_length);
  } else {
    const char* ether_type_name = "unknown";
    if (header->type_or_length == ETHERNET_ETHERTYPE_IPV4) ether_type_name = "IPv4";
    else if (header->type_or_length == ETHERNET_ETHERTYPE_ARP)
      ether_type_name = "ARP";
    else if (header->type_or_length == ETHERNET_ETHERTYPE_RARP)
      ether_type_name = "RARP";
    else if (header->type_or_length == ETHERNET_ETHERTYPE_IPV6)
      ether_type_name = "IPv6";
    fprintf(stdout, "    EtherType:       0x%04X (%s)\n", header->type_or_length, ether_type_name);
    fprintf(stdout, "    Data field:      %u bytes (may include padding)\n", frame.data_length);
  }
  fprintf(stdout, "    FCS:             %08X (valid)\n", footer->crc);
  if (frame.format == ETHERNET_FRAME_FORMAT_II) {
    if (header->type_or_length == ETHERNET_ETHERTYPE_IPV4) print_ipv4_packet(frame.data, frame.data_length);
    else if (header->type_or_length == ETHERNET_ETHERTYPE_ARP)
      print_arp_packet(frame.data, frame.data_length);
    else if (header->type_or_length == ETHERNET_ETHERTYPE_RARP)
      print_rarp_packet(frame.data, frame.data_length);
  }
  return true;
}

static bool print_vnet_frame(const uint8_t* bytes, size_t byte_count) {
  vnet_frame_header_t header = {0};
  if (!vnet_parse_frame(bytes, byte_count, &header)) return false;
  const char* event = header.type == VNET_FRAME_CONNECTION_START ? "connection start" : "connection end";
  fprintf(stdout, "Received %li bytes (%li bits):\n", (long)byte_count, (long)byte_count * 8);
  fprintf(stdout, "  Valid VNet control frame (%zu bytes):\n", sizeof(header));
  fprintf(stdout, "    Event:           %s\n    Source file:     %s\n    Destination file:%s\n", event, header.source_path, header.destination_path);
  return true;
}

static void print_raw_bytes(const uint8_t* bytes, long byte_count) {
  fprintf(stdout, "Received %li bytes (%li bits): ", byte_count, byte_count * 8);
  for (long i = 0; i < byte_count; ++i) {
    for (int bit = 0; bit < 8; ++bit) fputc(((bytes[i] >> bit) & 1u) ? '1' : '0', stdout);
    if (i != byte_count - 1) fputchar(' ');
  }
  fputc('\n', stdout);
}

int main(int argc, char** argv) {
  if (argc == 1) {
    fprintf(stderr, "Expected at least 1 argument (the name of the network file).\n");
    return EXIT_FAILURE;
  }
  const char* fpath = argv[1];
  FILE* f = fopen(fpath, "rb");
  if (!f) {
    fprintf(stderr, "Could not open the file '%s' for reading in binary mode.\n", fpath);
    return EXIT_FAILURE;
  }
  fseek(f, 0, SEEK_END);
  long offset = ftell(f);
  uint8_t buff[MAX_READ + sizeof(vnet_frame_header_t)];
  size_t buffered_bytes = 0;
  cmd_app_t commands;
  cmd_app_init(&commands);
  if (!cmd_app_register(&commands, "info", "Show the watched network file.", command_info, &(watch_context_t) {.path = fpath}) || !cmd_app_start(&commands)) {
    fputs("Could not start the command application.\n", stderr);
    fclose(f);
    return EXIT_FAILURE;
  }
  while (cmd_app_is_running(&commands)) {
    fseek(f, 0, SEEK_END);
    const long end = ftell(f);
    if (end == offset) {
      thread_sleep(3);
      continue;
    }
    const long to_read = end - offset < MAX_READ ? end - offset : MAX_READ;
    if (to_read < 0) {
      cmd_app_stop(&commands);
      cmd_app_join(&commands);
      fclose(f);
      fprintf(stderr, "Unexpected file modification while watching the file '%s'.", fpath);
      return EXIT_FAILURE;
    }
    fseek(f, offset, SEEK_SET);
    const long actually_read = fread(buff + buffered_bytes, 1, to_read, f);
    if (actually_read != to_read) {
      cmd_app_stop(&commands);
      cmd_app_join(&commands);
      fclose(f);
      fprintf(stderr, "Unexpected file op fail while reading the file '%s'.", fpath);
      return EXIT_FAILURE;
    }
    offset += actually_read;
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
        if (ethernet_frame_is_start(buff + frame_end, byte_count - frame_end) || vnet_frame_has_prefix(buff + frame_end, byte_count - frame_end)) break;
      }
      if (frame_end < byte_count) {
        const size_t frame_length = frame_end - frame_start;
        if (!print_ethernet_frame(buff + frame_start, frame_length)) print_raw_bytes(buff + frame_start, (long)frame_length);
        frame_start = frame_end;
        continue;
      }
      const size_t frame_length = byte_count - frame_start;
      if (vnet_frame_has_prefix(buff + frame_start, frame_length) && frame_length < sizeof(vnet_frame_header_t)) {
        memmove(buff, buff + frame_start, frame_length);
        buffered_bytes = frame_length;
      } else {
        if (!print_ethernet_frame(buff + frame_start, frame_length)) print_raw_bytes(buff + frame_start, (long)frame_length);
        buffered_bytes = 0;
      }
      break;
    }
    if (frame_start == byte_count) buffered_bytes = 0;
  }
  cmd_app_stop(&commands);
  cmd_app_join(&commands);
  fclose(f);
  return EXIT_SUCCESS;
}

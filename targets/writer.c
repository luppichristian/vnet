/* This program will write data to the network traffic file.
In our case we mimic network traffic through a simple binary file.
We send data by appending to the file and we receive data by reading the file periodically.
*/

#include <arp.h>
#include <assert.h>
#include <ethernet.h>
#include <icmp.h>
#include <ipv4.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct ethernet_frame_data {
  mac_address_t dst_addr;
  mac_address_t src_addr;
  uint16_t type_or_length;
  uint16_t data_length;
  void* data;
} ethernet_frame_data_t;

static void write_ethernet_frame(FILE* f, const ethernet_frame_data_t* frame_data) {
  const uint16_t data_length = frame_data->data_length;
  assert(data_length <= ETHERNET_MAX_DATA_LEN);

  const uint16_t padded_data_length = data_length < ETHERNET_MIN_DATA_LEN ? ETHERNET_MIN_DATA_LEN : data_length;
  const uint16_t padding_length = padded_data_length - data_length;
  uint8_t padding[ETHERNET_MIN_DATA_LEN] = {0};

  /* Build the header*/
  ethernet_header_t header = {0};
  {
    /* Set the preamble */
    for (int i = 0; i < ETHERNET_PREAMBLE_LEN; ++i) {
      header.preamble[i] = ETHERNET_PREAMBLE_BYTE;
    }

    /* Set the SFD */
    header.sfd = ETHERNET_SFD;

    header.type_or_length = frame_data->type_or_length;

    /* Set the mac addresses */
    memcpy(header.dst_mac, frame_data->dst_addr, sizeof(mac_address_t));
    memcpy(header.src_mac, frame_data->src_addr, sizeof(mac_address_t));
  }

  /* Build the footer */
  ethernet_footer_t footer = {0};
  {
    /* FCS covers destination, source, length, data, and padding; not preamble/SFD. */
    uint8_t crc_buf[sizeof(mac_address_t) * 2 + sizeof(header.type_or_length) + ETHERNET_MAX_DATA_LEN];
    size_t offset = 0;
    memcpy(crc_buf + offset, header.dst_mac, sizeof(header.dst_mac));
    offset += sizeof(mac_address_t);
    memcpy(crc_buf + offset, header.src_mac, sizeof(header.src_mac));
    offset += sizeof(mac_address_t);
    memcpy(crc_buf + offset, &header.type_or_length, sizeof(header.type_or_length));
    offset += sizeof(header.type_or_length);
    memcpy(crc_buf + offset, frame_data->data, data_length);
    offset += data_length;
    memcpy(crc_buf + offset, padding, padding_length);
    offset += padding_length;
    footer.crc = crc32(crc_buf, offset);
  }

  /* Write the entire frame: header + payload + footer*/
  fwrite(&header, sizeof(ethernet_header_t), 1, f);
  fwrite(frame_data->data, data_length, 1, f);
  fwrite(padding, padding_length, 1, f);
  fwrite(&footer, sizeof(ethernet_footer_t), 1, f);
}

typedef struct ipv4_packet_data {
  mac_address_t dst_mac_addr;
  mac_address_t src_mac_addr;
  ipv4_address_t src_addr;
  ipv4_address_t dst_addr;
  uint8_t protocol;
  const void* data;
  uint16_t data_length;
} ipv4_packet_data_t;

static void write_ipv4_packet(FILE* f, const ipv4_packet_data_t* packet_data) {
  assert(packet_data->data_length <= ETHERNET_MAX_DATA_LEN - sizeof(ipv4_header_t));

  /* Prepare data for the actual ipv4 packet */
  uint8_t ipv4_packet[sizeof(ipv4_header_t) + ETHERNET_MAX_DATA_LEN] = {0};
  ipv4_header_t ipv4_header = {
      .version = 4,
      .ihl = 5,
      .total_length = sizeof(ipv4_header) + packet_data->data_length,
      .fragment_id = 1,
      .dont_fragment = 1,
      .ttl = IPV4_DEFAULT_TTL,
      .protocol = packet_data->protocol,
      .src_addr = packet_data->src_addr,
      .dst_addr = packet_data->dst_addr,
  };
  ipv4_header.header_checksum = ipv4_checksum(&ipv4_header, sizeof(ipv4_header));
  memcpy(ipv4_packet, &ipv4_header, sizeof(ipv4_header));
  memcpy(ipv4_packet + sizeof(ipv4_header), packet_data->data, packet_data->data_length);

  /* Write the ethernet frame */
  ethernet_frame_data_t frame_data = {
      .type_or_length = ETHERNET_ETHERTYPE_IPV4,
      .data_length = sizeof(ipv4_header) + packet_data->data_length,
      .data = ipv4_packet,
  };
  memcpy(frame_data.dst_addr, packet_data->dst_mac_addr, sizeof(frame_data.dst_addr));
  memcpy(frame_data.src_addr, packet_data->src_mac_addr, sizeof(frame_data.src_addr));
  write_ethernet_frame(f, &frame_data);
}

typedef struct icmp_echo_request_data {
  mac_address_t dst_mac_addr;
  mac_address_t src_mac_addr;
  ipv4_address_t src_addr;
  ipv4_address_t dst_addr;
  uint16_t identifier;
  uint16_t sequence_number;
  const void* data;
  uint16_t data_length;
} icmp_echo_request_data_t;

static void write_icmp_echo_request(FILE* f, const icmp_echo_request_data_t* request_data) {
  assert(request_data->data_length <= ETHERNET_MAX_DATA_LEN - sizeof(ipv4_header_t) - sizeof(icmp_echo_header_t));

  uint8_t icmp_packet[sizeof(icmp_echo_header_t) + ETHERNET_MAX_DATA_LEN] = {0};
  icmp_echo_header_t icmp_header = {
      .type = ICMP_TYPE_ECHO_REQUEST,
      .code = ICMP_CODE_ECHO,
      .identifier = request_data->identifier,
      .sequence_number = request_data->sequence_number,
  };
  memcpy(icmp_packet, &icmp_header, sizeof(icmp_header));
  if (request_data->data_length > 0) {
    memcpy(icmp_packet + sizeof(icmp_header), request_data->data, request_data->data_length);
  }
  ((icmp_echo_header_t*)icmp_packet)->checksum = icmp_checksum(icmp_packet, sizeof(icmp_header) + request_data->data_length);

  ipv4_packet_data_t ipv4_data = {
      .src_addr = request_data->src_addr,
      .dst_addr = request_data->dst_addr,
      .protocol = ICMP_IPV4_PROTOCOL,
      .data = icmp_packet,
      .data_length = sizeof(icmp_header) + request_data->data_length,
  };
  memcpy(ipv4_data.dst_mac_addr, request_data->dst_mac_addr, sizeof(ipv4_data.dst_mac_addr));
  memcpy(ipv4_data.src_mac_addr, request_data->src_mac_addr, sizeof(ipv4_data.src_mac_addr));
  write_ipv4_packet(f, &ipv4_data);
}

typedef struct arp_packet_data {
  mac_address_t sender_hardware_address;
  ipv4_address_t sender_protocol_address;
  ipv4_address_t target_protocol_address;
} arp_packet_data_t;

static void write_arp_packet(FILE* f, const arp_packet_data_t* packet_data) {
  arp_packet_t arp_packet = {
      .hardware_type = ARP_HARDWARE_TYPE_ETHERNET,
      .protocol_type = ETHERNET_ETHERTYPE_IPV4,
      .hardware_address_length = sizeof(mac_address_t),
      .protocol_address_length = sizeof(ipv4_address_t),
      .operation = ARP_OPERATION_REQUEST,
      .sender_protocol_address = packet_data->sender_protocol_address,
      .target_protocol_address = packet_data->target_protocol_address,
  };
  memcpy(arp_packet.sender_hardware_address, packet_data->sender_hardware_address, sizeof(arp_packet.sender_hardware_address));

  ethernet_frame_data_t frame_data = {
      .dst_addr = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
      .type_or_length = ETHERNET_ETHERTYPE_ARP,
      .data_length = sizeof(arp_packet),
      .data = &arp_packet,
  };
  memcpy(frame_data.src_addr, packet_data->sender_hardware_address, sizeof(frame_data.src_addr));
  write_ethernet_frame(f, &frame_data);
}

int main(int argc, char** argv) {
  if (argc == 1) {
    fprintf(stderr, "Expected at least 1 argument (the name of the network file).\n");
    return (EXIT_FAILURE);
  }

  const char* fpath = argv[1];
  FILE* f = fopen(fpath, "ab");
  if (!f) {
    fprintf(stderr, "Could not open the file \'%s\' for appending in binary mode.\n", fpath);
    return (EXIT_FAILURE);
  }

  {
    /* Construct an IPv4 packet carried by an Ethernet II frame. */
    uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03};
    ipv4_packet_data_t packet_data = {
        .dst_mac_addr = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        .src_mac_addr = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
        .src_addr = IPV4_ADDRESS(192, 168, 1, 1),
        .dst_addr = IPV4_ADDRESS(192, 168, 1, 2),
        .protocol = IPV4_PROTOCOL_TEST,
        .data = data,
        .data_length = sizeof(data),
    };
    write_ipv4_packet(f, &packet_data);

    arp_packet_data_t arp_data = {
        .sender_hardware_address = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
        .sender_protocol_address = IPV4_ADDRESS(192, 168, 1, 1),
        .target_protocol_address = IPV4_ADDRESS(192, 168, 1, 2),
    };
    write_arp_packet(f, &arp_data);

    icmp_echo_request_data_t icmp_data = {
        .dst_mac_addr = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        .src_mac_addr = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
        .src_addr = IPV4_ADDRESS(192, 168, 1, 1),
        .dst_addr = IPV4_ADDRESS(192, 168, 1, 2),
        .identifier = 1,
        .sequence_number = 1,
    };
    write_icmp_echo_request(f, &icmp_data);
  }

  fclose(f);
  return (EXIT_SUCCESS);
}

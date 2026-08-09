/*
This program writes Ethernet traffic to the network file.
*/

#include <arp.h>
#include <icmp.h>
#include <ipv4.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

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
    if (!ipv4_write_ethernet_packet(f, &packet_data)) {
      fclose(f);
      return EXIT_FAILURE;
    }

    arp_packet_data_t arp_data = {
        .sender_hardware_address = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
        .sender_protocol_address = IPV4_ADDRESS(192, 168, 1, 1),
        .target_protocol_address = IPV4_ADDRESS(192, 168, 1, 2),
    };
    if (!arp_write_ethernet_request(f, &arp_data)) {
      fclose(f);
      return EXIT_FAILURE;
    }

    icmp_echo_request_data_t icmp_data = {
        .dst_mac_addr = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        .src_mac_addr = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
        .src_addr = IPV4_ADDRESS(192, 168, 1, 1),
        .dst_addr = IPV4_ADDRESS(192, 168, 1, 2),
        .identifier = 1,
        .sequence_number = 1,
    };
    if (!icmp_write_ethernet_echo_request(f, &icmp_data)) {
      fclose(f);
      return EXIT_FAILURE;
    }
  }

  fclose(f);
  return (EXIT_SUCCESS);
}

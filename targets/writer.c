/* This program will write data to the network traffic file.
In our case we mimic network traffic through a simple binary file.
We send data by appending to the file and we receive data by reading the file periodically.
*/

#include <assert.h>
#include <ethernet.h>
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
    /* Construct data for an ethernet frame */
    uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03};
    ethernet_frame_data_t frame_data = {
        .dst_addr = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        .src_addr = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
        .type_or_length = ETHERNET_ETHERTYPE_IPV4,
        .data_length = sizeof(data),
        .data = data,
    };

    write_ethernet_frame(f, &frame_data);
  }

  fclose(f);
  return (EXIT_SUCCESS);
}

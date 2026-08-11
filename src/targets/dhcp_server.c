#include "dhcp_server.h"

static void command_info(void* argument, char* arguments) {
  dhcp_server_context_t* context = argument;
  if (!cmd_app_arguments_empty(arguments)) {
    fputs("Usage: info\n", stderr);
    return;
  }
  fputs("DHCP server IPv4: ", stdout);
  ipv4_address_print(stdout, context->address);
  fputs("\nLease client: ", stdout);
  ethernet_mac_print(stdout, context->client_mac);
  fputs("\nLease address: ", stdout);
  ipv4_address_print(stdout, context->client_address);
  fputs("\n", stdout);
}

static bool reply(dhcp_server_context_t* context, const ethernet_frame_view_t* frame, const dhcp_message_t* request, uint8_t type) {
  dhcp_message_t message = {0};
  if (!dhcp_write_server_message(type, request->transaction_id, request->client_mac, context->client_address, context->address, context->mask, context->gateway, context->dns_server, &message)) return false;
  FILE* destination = fopen(context->path, "ab");
  if (!destination) return false;
  udp_packet_data_t packet = {
      .src_addr = context->address,
      .dst_addr = IPV4_ADDRESS(255, 255, 255, 255),
      .src_port = DHCP_SERVER_UDP_PORT,
      .dst_port = DHCP_CLIENT_UDP_PORT,
      .data = &message,
      .data_length = sizeof(message),
  };
  memcpy(packet.src_mac_addr, context->mac, sizeof(packet.src_mac_addr));
  memcpy(packet.dst_mac_addr, frame->header.src_mac, sizeof(packet.dst_mac_addr));
  const bool written = udp_write_ethernet_packet(destination, &packet);
  fclose(destination);
  return written;
}

static void handle_frame(dhcp_server_context_t* context, const uint8_t* bytes, size_t count) {
  ethernet_frame_view_t frame = {0};
  ipv4_packet_view_t ipv4 = {0};
  udp_packet_view_t udp = {0};
  dhcp_message_t message = {0};
  if (!ethernet_parse_frame(bytes, count, &frame) || frame.format != ETHERNET_FRAME_FORMAT_II || frame.header.type_or_length != ETHERNET_ETHERTYPE_IPV4 || !ipv4_parse_packet(frame.data, frame.data_length, &ipv4) || ipv4.header.protocol != UDP_IPV4_PROTOCOL || !udp_parse_packet(ipv4.payload, ipv4.payload_length, ipv4.header.src_addr, ipv4.header.dst_addr, &udp) || udp.header.dst_port != DHCP_SERVER_UDP_PORT || !dhcp_parse_message(udp.data, udp.data_length, &message) || memcmp(message.client_mac, context->client_mac, sizeof(context->client_mac)) != 0) return;
  if (message.type == DHCP_MESSAGE_DISCOVER && reply(context, &frame, &message, DHCP_MESSAGE_OFFER)) fputs("DHCP OFFER sent.\n", stdout);
  else if (message.type == DHCP_MESSAGE_REQUEST && message.client_address == context->client_address && message.server_address == context->address && reply(context, &frame, &message, DHCP_MESSAGE_ACK))
    fputs("DHCP ACK sent.\n", stdout);
}

int main(int argc, char** argv) {
  if (argc != 9) {
    fputs("Usage: dhcp_server <file> <mac-address> <server-ip> <client-mac> <client-ip> <mask> <gateway> <dns-server>\n", stderr);
    return EXIT_FAILURE;
  }
  dhcp_server_context_t context = {.path = argv[1]};
  if (!ethernet_mac_parse(argv[2], context.mac) || !ipv4_parse_address(argv[3], &context.address) || !ethernet_mac_parse(argv[4], context.client_mac) || !ipv4_parse_address(argv[5], &context.client_address) || !ipv4_parse_address(argv[6], &context.mask) || !ipv4_mask_is_contiguous(context.mask) || !ipv4_parse_address(argv[7], &context.gateway) || !ipv4_parse_address(argv[8], &context.dns_server)) return EXIT_FAILURE;
  context.source = fopen(context.path, "rb");
  if (!context.source || fseek(context.source, 0, SEEK_END) != 0) return EXIT_FAILURE;
  cmd_app_init(&context.commands);
  if (!cmd_app_register(&context.commands, "info", "Show the configured client lease.", command_info, &context) || !cmd_app_start(&context.commands)) return EXIT_FAILURE;
  uint8_t buffer[DHCP_SERVER_BUFFER_SIZE];
  while (cmd_app_is_running(&context.commands)) {
    long end = 0;
    if (!get_file_end(context.source, &end)) break;
    long position = ftell(context.source);
    if (position < end) {
      size_t count = (size_t)(end - position) < sizeof(buffer) ? (size_t)(end - position) : sizeof(buffer);
      if (fread(buffer, 1, count, context.source) != count) break;
      for (size_t start = 0, next = 0; start < count; start = next) {
        for (next = start + 1; next < count && !ethernet_frame_is_start(buffer + next, count - next); ++next) {}
        handle_frame(&context, buffer + start, next - start);
      }
    }
    thread_sleep(5);
  }
  cmd_app_stop(&context.commands);
  cmd_app_join(&context.commands);
  fclose(context.source);
  return EXIT_SUCCESS;
}

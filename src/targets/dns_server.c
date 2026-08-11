#include "dns_server.h"

static void command_info(void* argument, char* arguments) {
  dns_server_context_t* context = argument;
  if (!cmd_app_arguments_empty(arguments)) {
    fputs("Usage: info\n", stderr);
    return;
  }
  fprintf(stdout, "DNS server file: %s\nDNS server IPv4: ", context->path);
  ipv4_address_print(stdout, context->address);
  fprintf(stdout, "\nA record: %s -> ", context->name);
  ipv4_address_print(stdout, context->record_address);
  fputs("\n", stdout);
}

static bool write_dns_response(dns_server_context_t* context, const ethernet_frame_view_t* frame, const ipv4_packet_view_t* ipv4, const udp_packet_view_t* udp, const dns_message_t* query) {
  dns_message_t response = {0};
  if (!dns_write_response(query->transaction_id, query->name, strcmpi(query->name, context->name) == 0 ? context->record_address : 0, &response)) return false;
  FILE* destination = fopen(context->path, "ab");
  if (!destination) return false;
  udp_packet_data_t packet = {
      .src_addr = context->address,
      .dst_addr = ipv4->header.src_addr,
      .src_port = DNS_UDP_PORT,
      .dst_port = udp->header.src_port,
      .data = &response,
      .data_length = sizeof(response),
  };
  memcpy(packet.src_mac_addr, context->mac, sizeof(packet.src_mac_addr));
  memcpy(packet.dst_mac_addr, frame->header.src_mac, sizeof(packet.dst_mac_addr));
  const bool written = udp_write_ethernet_packet(destination, &packet);
  fclose(destination);
  return written;
}

static bool write_arp_reply(dns_server_context_t* context, const arp_packet_t* request) {
  arp_reply_data_t reply = {.sender_protocol_address = context->address, .target_protocol_address = request->sender_protocol_address};
  memcpy(reply.sender_hardware_address, context->mac, sizeof(reply.sender_hardware_address));
  memcpy(reply.target_hardware_address, request->sender_hardware_address, sizeof(reply.target_hardware_address));
  FILE* destination = fopen(context->path, "ab");
  if (!destination) return false;
  const bool written = arp_write_ethernet_reply(destination, &reply);
  fclose(destination);
  return written;
}

static void handle_frame(dns_server_context_t* context, const uint8_t* bytes, size_t byte_count) {
  ethernet_frame_view_t frame = {0};
  ipv4_packet_view_t ipv4 = {0};
  udp_packet_view_t udp = {0};
  dns_message_t query = {0};
  if (!ethernet_parse_frame(bytes, byte_count, &frame) || frame.format != ETHERNET_FRAME_FORMAT_II) return;
  if (frame.header.type_or_length == ETHERNET_ETHERTYPE_ARP) {
    arp_packet_t request = {0};
    if (arp_parse_packet(frame.data, sizeof(request), &request) && request.operation == ARP_OPERATION_REQUEST && request.target_protocol_address == context->address) write_arp_reply(context, &request);
    return;
  }
  if (frame.header.type_or_length != ETHERNET_ETHERTYPE_IPV4 || memcmp(frame.header.dst_mac, context->mac, sizeof(context->mac)) != 0 || !ipv4_parse_packet(frame.data, frame.data_length, &ipv4) || ipv4.header.dst_addr != context->address || ipv4.header.protocol != UDP_IPV4_PROTOCOL || !udp_parse_packet(ipv4.payload, ipv4.payload_length, ipv4.header.src_addr, ipv4.header.dst_addr, &udp) || udp.header.dst_port != DNS_UDP_PORT || !dns_parse_message(udp.data, udp.data_length, &query) || query.type != DNS_MESSAGE_QUERY) return;
  if (write_dns_response(context, &frame, &ipv4, &udp, &query)) fprintf(stdout, "DNS query: %s (%s).\n", query.name, strcmpi(query.name, context->name) == 0 ? "answered" : "name error");
}

int main(int argc, char** argv) {
  if (argc != 6) {
    fputs("Usage: dns_server <file> <mac-address> <ip-address> <name> <address>\n", stderr);
    return EXIT_FAILURE;
  }
  dns_server_context_t context = {.path = argv[1]};
  if (!ethernet_mac_parse(argv[2], context.mac) || !ipv4_parse_address(argv[3], &context.address) || !dns_write_query(1, argv[4], &(dns_message_t) {0}) || !ipv4_parse_address(argv[5], &context.record_address)) return EXIT_FAILURE;
  memcpy(context.name, argv[4], strlen(argv[4]) + 1);
  context.source = fopen(context.path, "rb");
  if (!context.source || fseek(context.source, 0, SEEK_END) != 0) return EXIT_FAILURE;
  cmd_app_init(&context.commands);
  if (!cmd_app_register(&context.commands, "info", "Show the authoritative A record.", command_info, &context) || !cmd_app_start(&context.commands)) return EXIT_FAILURE;
  uint8_t buffer[DNS_SERVER_BUFFER_SIZE] = {0};
  while (cmd_app_is_running(&context.commands)) {
    long end = 0;
    if (!get_file_end(context.source, &end)) break;
    const long position = ftell(context.source);
    if (position < end) {
      const size_t count = (size_t)(end - position) < sizeof(buffer) ? (size_t)(end - position) : sizeof(buffer);
      if (fread(buffer, 1, count, context.source) != count) break;
      size_t start = 0;
      while (start < count) {
        size_t next = start + 1;
        while (next < count && !ethernet_frame_is_start(buffer + next, count - next)) ++next;
        handle_frame(&context, buffer + start, next - start);
        start = next;
      }
    }
    thread_sleep(5);
  }
  cmd_app_stop(&context.commands);
  cmd_app_join(&context.commands);
  fclose(context.source);
  return EXIT_SUCCESS;
}

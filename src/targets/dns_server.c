#include "dns_server.h"

static bool parse_record(const char* type, const char* name, const char* value, dns_record_t* record);

static const char* record_type_name(uint16_t type) {
  return type == DNS_RECORD_A ? "A" : type == DNS_RECORD_CNAME ? "CNAME" : "unknown";
}

static const dns_record_t* find_record(const dns_server_context_t* context, const char* name) {
  for (size_t i = 0; i < context->record_count; ++i) {
    if (strcmpi(context->records[i].name, name) == 0) return &context->records[i];
  }
  return NULL;
}

static void command_info(void* argument, char* arguments) {
  dns_server_context_t* context = argument;
  if (!cmd_app_arguments_empty(arguments)) {
    fputs("Usage: info\n", stderr);
    return;
  }
  mutex_lock(&context->mutex);
  fprintf(stdout, "DNS server file: %s\nDNS server MAC: ", context->path);
  ethernet_mac_print(stdout, context->mac);
  fputs("\nDNS server IPv4: ", stdout);
  ipv4_address_print(stdout, context->address);
  fprintf(stdout, "\nRecords (%zu):\n", context->record_count);
  for (size_t i = 0; i < context->record_count; ++i) {
    const dns_record_t* record = &context->records[i];
    fprintf(stdout, "  %-5s %-40s ", record_type_name(record->type), record->name);
    if (record->type == DNS_RECORD_A) ipv4_address_print(stdout, record->data.address);
    else fputs(record->data.name, stdout);
    fputc('\n', stdout);
  }
  mutex_unlock(&context->mutex);
}

static void command_record(void* argument, char* arguments) {
  dns_server_context_t* context = argument;
  char* cursor = arguments;
  char* action = cmd_app_next_argument(&cursor);
  char* type = cmd_app_next_argument(&cursor);
  char* name = cmd_app_next_argument(&cursor);
  if (!action || !type || !name) {
    fputs("Usage: record <add|delete> <A|CNAME> <name> [address|target]\n", stderr);
    return;
  }
  if (strcmpi(action, "delete") == 0 && !cmd_app_next_argument(&cursor)) {
    bool removed = false;
    mutex_lock(&context->mutex);
    for (size_t i = 0; i < context->record_count; ++i) {
      if (strcmpi(record_type_name(context->records[i].type), type) == 0 && strcmpi(context->records[i].name, name) == 0) {
        context->records[i] = context->records[--context->record_count];
        removed = true;
        break;
      }
    }
    mutex_unlock(&context->mutex);
    fputs(removed ? "DNS record removed.\n" : "No such DNS record.\n", removed ? stdout : stderr);
    return;
  }
  char* value = cmd_app_next_argument(&cursor);
  dns_record_t record = {0};
  if (strcmpi(action, "add") != 0 || !value || cmd_app_next_argument(&cursor) || !parse_record(type, name, value, &record)) {
    fputs("Usage: record <add|delete> <A|CNAME> <name> [address|target]\n", stderr);
    return;
  }
  mutex_lock(&context->mutex);
  size_t index = context->record_count;
  for (size_t i = 0; i < context->record_count; ++i) {
    if (context->records[i].type == record.type && strcmpi(context->records[i].name, record.name) == 0) {
      index = i;
      break;
    }
  }
  if (index < DNS_SERVER_RECORD_CAPACITY) context->records[index] = record;
  if (index == context->record_count && index < DNS_SERVER_RECORD_CAPACITY) ++context->record_count;
  mutex_unlock(&context->mutex);
  fputs(index < DNS_SERVER_RECORD_CAPACITY ? "DNS record set.\n" : "DNS record table is full.\n", index < DNS_SERVER_RECORD_CAPACITY ? stdout : stderr);
}

static bool write_dns_response(dns_server_context_t* context, const ethernet_frame_view_t* frame, const ipv4_packet_view_t* ipv4, const udp_packet_view_t* udp, const dns_message_t* query) {
  dns_message_t response = {0};
  mutex_lock(&context->mutex);
  const dns_record_t* record = find_record(context, query->record.name);
  const bool valid = dns_write_response(query->transaction_id, query->record.name, record, &response);
  mutex_unlock(&context->mutex);
  if (!valid) return false;
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
  if (write_dns_response(context, &frame, &ipv4, &udp, &query)) fprintf(stdout, "DNS query: %s (%s).\n", query.record.name, find_record(context, query.record.name) ? "answered" : "name error");
}

static bool parse_record(const char* type, const char* name, const char* value, dns_record_t* record) {
  if (strcmpi(type, "A") == 0) {
    ipv4_address_t address = 0;
    return ipv4_parse_address(value, &address) && dns_record_write_a(name, address, record);
  }
  return strcmpi(type, "CNAME") == 0 && dns_record_write_cname(name, value, record);
}

int main(int argc, char** argv) {
  if (argc < 7 || (argc - 4) % 3 != 0) {
    fputs("Usage: dns_server <file> <mac-address> <ip-address> <A|CNAME> <name> <address|target> [...records]\n", stderr);
    return EXIT_FAILURE;
  }
  dns_server_context_t context = {.path = argv[1]};
  if (!ethernet_mac_parse(argv[2], context.mac) || !ipv4_parse_address(argv[3], &context.address) || (size_t)((argc - 4) / 3) > DNS_SERVER_RECORD_CAPACITY) return EXIT_FAILURE;
  for (int index = 4; index < argc; index += 3) {
    if (!parse_record(argv[index], argv[index + 1], argv[index + 2], &context.records[context.record_count++])) return EXIT_FAILURE;
  }
  context.source = fopen(context.path, "rb");
  if (!context.source || fseek(context.source, 0, SEEK_END) != 0) return EXIT_FAILURE;
  if (!mutex_init(&context.mutex)) {
    fclose(context.source);
    return EXIT_FAILURE;
  }
  cmd_app_init(&context.commands);
  if (!cmd_app_register(&context.commands, "info", "Show the configured server and authoritative records.", command_info, &context) || !cmd_app_register(&context.commands, "record", "Add, replace, or delete an authoritative DNS record.", command_record, &context) || !cmd_app_start(&context.commands)) {
    mutex_destroy(&context.mutex);
    fclose(context.source);
    return EXIT_FAILURE;
  }
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
  mutex_destroy(&context.mutex);
  fclose(context.source);
  return EXIT_SUCCESS;
}

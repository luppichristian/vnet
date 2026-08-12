#include "dhcp_server.h"

static void print_service(const dhcp_server_context_t* context) {
  const dhcp_service_t* service = &context->service;
  fputs("DHCP server: ", stdout); ipv4_address_print(stdout, service->server_address);
  fputs("  state=", stdout); fputs(service->enabled ? "enabled\n" : "disabled\n", stdout);
  fputs("Pool: ", stdout); ipv4_address_print(stdout, service->first_address); fputs(" - ", stdout); ipv4_address_print(stdout, service->last_address);
  fputs("\nMask: ", stdout); ipv4_address_print(stdout, service->mask);
  fputs("\nGateway: ", stdout); ipv4_address_print(stdout, service->gateway);
  fputs("\nDNS: ", stdout); ipv4_address_print(stdout, service->dns_server);
  fprintf(stdout, "\nLeases (%zu):\n", service->count);
  for (size_t i = 0; i < service->count; ++i) { fputs("  ", stdout); ethernet_mac_print(stdout, service->leases[i].client_mac); fputs("  ", stdout); ipv4_address_print(stdout, service->leases[i].address); fprintf(stdout, "  %s\n", service->leases[i].reserved ? "reserved" : "dynamic"); }
}

static void command_info(void* argument, char* arguments) { if (!cmd_app_arguments_empty(arguments)) { fputs("Usage: info\n", stderr); return; } dhcp_server_context_t* context = argument; mutex_lock(&context->mutex); print_service(context); mutex_unlock(&context->mutex); }

static void command_config(void* argument, char* arguments) {
  dhcp_server_context_t* context = argument; char* cursor = arguments; char* first = cmd_app_next_argument(&cursor); char* last = cmd_app_next_argument(&cursor); char* mask = cmd_app_next_argument(&cursor); char* gateway = cmd_app_next_argument(&cursor); char* dns = cmd_app_next_argument(&cursor); ipv4_address_t values[5] = {0};
  if (!first || !last || !mask || !gateway || !dns || cmd_app_next_argument(&cursor) || !ipv4_parse_address(first, &values[0]) || !ipv4_parse_address(last, &values[1]) || !ipv4_parse_address(mask, &values[2]) || !ipv4_parse_address(gateway, &values[3]) || !ipv4_parse_address(dns, &values[4])) { fputs("Usage: config <first-ip> <last-ip> <mask> <gateway> <dns>\n", stderr); return; }
  mutex_lock(&context->mutex); const bool ok = dhcp_service_configure(&context->service, context->service.server_address, values[0], values[1], values[2], values[3], values[4]); mutex_unlock(&context->mutex); fputs(ok ? "DHCP service configured.\n" : "Invalid DHCP configuration.\n", ok ? stdout : stderr);
}

static void command_enable(void* argument, char* arguments) { dhcp_server_context_t* context = argument; if (!cmd_app_arguments_empty(arguments)) { fputs("Usage: enable <on|off>\n", stderr); return; } (void)context; }
static void command_lease(void* argument, char* arguments) {
  dhcp_server_context_t* context = argument; char* cursor = arguments; char* action = cmd_app_next_argument(&cursor); char* one = cmd_app_next_argument(&cursor); char* two = cmd_app_next_argument(&cursor); mac_address_t mac = {0}; ipv4_address_t address = 0;
  if (action && strcmpi(action, "list") == 0 && !one) { mutex_lock(&context->mutex); print_service(context); mutex_unlock(&context->mutex); return; }
  if (action && strcmpi(action, "delete") == 0 && one && !two && ipv4_parse_address(one, &address)) { mutex_lock(&context->mutex); bool ok = dhcp_service_remove(&context->service, address); mutex_unlock(&context->mutex); fputs(ok ? "Lease removed.\n" : "No such lease.\n", ok ? stdout : stderr); return; }
  if (action && strcmpi(action, "reserve") == 0 && one && two && !cmd_app_next_argument(&cursor) && ethernet_mac_parse(one, mac) && ipv4_parse_address(two, &address)) { mutex_lock(&context->mutex); bool ok = dhcp_service_reserve(&context->service, mac, address); mutex_unlock(&context->mutex); fputs(ok ? "Reservation set.\n" : "Could not set reservation.\n", ok ? stdout : stderr); return; }
  fputs("Usage: lease list | lease reserve <mac> <ip> | lease delete <ip>\n", stderr);
}

static bool reply(dhcp_server_context_t* context, const ethernet_frame_view_t* frame, const dhcp_message_t* request) {
  dhcp_message_t response = {0}; bool valid = request->type == DHCP_MESSAGE_DISCOVER ? dhcp_service_offer(&context->service, request, &response) : dhcp_service_acknowledge(&context->service, request, &response); if (!valid) return false;
  FILE* destination = fopen(context->path, "ab"); if (!destination) return false;
  udp_packet_data_t packet = {.src_addr = context->service.server_address, .dst_addr = IPV4_ADDRESS(255,255,255,255), .src_port = DHCP_SERVER_UDP_PORT, .dst_port = DHCP_CLIENT_UDP_PORT, .data = &response, .data_length = sizeof(response)}; memcpy(packet.src_mac_addr, context->mac, sizeof(packet.src_mac_addr)); memcpy(packet.dst_mac_addr, frame->header.src_mac, sizeof(packet.dst_mac_addr)); bool written = udp_write_ethernet_packet(destination, &packet); fclose(destination); return written;
}

static void handle_frame(dhcp_server_context_t* context, const uint8_t* bytes, size_t count) {
  ethernet_frame_view_t frame = {0}; ipv4_packet_view_t ip4 = {0}; udp_packet_view_t udp = {0}; dhcp_message_t message = {0};
  if (!ethernet_parse_frame(bytes,count,&frame) || frame.format != ETHERNET_FRAME_FORMAT_II || frame.header.type_or_length != ETHERNET_ETHERTYPE_IPV4 || !ipv4_parse_packet(frame.data,frame.data_length,&ip4) || ip4.header.protocol != UDP_IPV4_PROTOCOL || !udp_parse_packet(ip4.payload,ip4.payload_length,ip4.header.src_addr,ip4.header.dst_addr,&udp) || udp.header.dst_port != DHCP_SERVER_UDP_PORT || !dhcp_parse_message(udp.data,udp.data_length,&message)) return;
  mutex_lock(&context->mutex); bool written = reply(context,&frame,&message); mutex_unlock(&context->mutex); if (written) fprintf(stdout,"DHCP %s sent.\n",message.type == DHCP_MESSAGE_DISCOVER ? "OFFER" : "response");
}

int main(int argc, char** argv) {
  if (argc != 4) { fputs("Usage: dhcp_server <file> <mac-address> <server-ip>\n",stderr); return EXIT_FAILURE; }
  dhcp_server_context_t context = {.path=argv[1]};
  dhcp_service_init(&context.service,context.lease_entries,DHCP_SERVER_LEASE_CAPACITY);
  if (!ethernet_mac_parse(argv[2],context.mac) || !ipv4_parse_address(argv[3],&context.service.server_address)) return EXIT_FAILURE;
  context.source=fopen(context.path,"rb"); if (!context.source || fseek(context.source,0,SEEK_END)!=0 || !mutex_init(&context.mutex)) return EXIT_FAILURE;
  cmd_app_init(&context.commands); if (!cmd_app_register(&context.commands,"info","Show DHCP configuration and leases.",command_info,&context) || !cmd_app_register(&context.commands,"config","Configure DHCP pool and supplied IPv4 options.",command_config,&context) || !cmd_app_register(&context.commands,"lease","List, reserve, or remove leases.",command_lease,&context) || !cmd_app_start(&context.commands)) return EXIT_FAILURE;
  uint8_t buffer[DHCP_SERVER_BUFFER_SIZE]; while (cmd_app_is_running(&context.commands)) { long end=0, position=ftell(context.source); if (!get_file_end(context.source,&end)) break; if (position<end) { size_t count=(size_t)(end-position)<sizeof(buffer)?(size_t)(end-position):sizeof(buffer); if (fread(buffer,1,count,context.source)!=count) break; for(size_t start=0,next=0;start<count;start=next){for(next=start+1;next<count&&!ethernet_frame_is_start(buffer+next,count-next);++next){} handle_frame(&context,buffer+start,next-start);} } thread_sleep(5); }
  cmd_app_stop(&context.commands); cmd_app_join(&context.commands); mutex_destroy(&context.mutex); fclose(context.source); return EXIT_SUCCESS;
}

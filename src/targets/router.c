/*
Interactive IPv4 router connecting multiple append-only VNet media.
OSI/ISO layer: Layer 3; it routes IPv4 packets and resolves each egress next hop through ARP.
*/

#include <arp.h>
#include <arp_table.h>
#include <cmd_app.h>
#include <ethernet.h>
#include <futils.h>
#include <interface_table.h>
#include <ipv4.h>
#include <math.h>
#include <mutex.h>
#include <rarp.h>
#include <rarp_table.h>
#include <rip.h>
#include <route_table.h>
#include <udp.h>

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread.h>
#include <time.h>
#include <vnet.h>

#define ROUTER_INTERFACE_CAPACITY 16
#define ROUTER_ROUTE_CAPACITY     128
#define ROUTER_ARP_CAPACITY       256
#define ROUTER_RARP_CAPACITY      128
#define ROUTER_PENDING_CAPACITY   64
#define ROUTER_BUFFER_SIZE        8192
#define SLEEP_INTERVAL_MS         5
#define RIP_ROUTE_TIMEOUT_SECONDS 180
#define RIP_UPDATE_INTERVAL_SECONDS 30

typedef struct router_port {
  FILE* source;
  FILE* destination;
  uint8_t buffer[ROUTER_BUFFER_SIZE];
  size_t buffer_length;
  size_t injected_bytes;
} router_port_t;

typedef struct router_pending_packet {
  ipv4_header_t header;
  uint8_t payload[ETHERNET_MAX_DATA_LEN - sizeof(ipv4_header_t)];
  ipv4_address_t next_hop;
  size_t egress_interface;
  uint16_t payload_length;
  bool active;
} router_pending_packet_t;

typedef struct router_context {
  interface_entry_t interface_entries[ROUTER_INTERFACE_CAPACITY];
  route_entry_t route_entries[ROUTER_ROUTE_CAPACITY];
  arp_entry_t arp_entries[ROUTER_ARP_CAPACITY];
  rarp_entry_t rarp_entries[ROUTER_RARP_CAPACITY];
  router_pending_packet_t pending_packets[ROUTER_PENDING_CAPACITY];
  interface_table_t interfaces;
  route_table_t routes;
  arp_table_t arp;
  rarp_table_t rarp;
  router_port_t ports[ROUTER_INTERFACE_CAPACITY];
  bool dynamic_routing;
  uint32_t next_rip_update;
  mutex_t mutex;
  cmd_app_t commands;
} router_context_t;

static cmd_app_t* command_app;

static const mac_address_t rip_multicast_mac = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x09};

static uint32_t router_now(void) {
  return (uint32_t)time(NULL);
}

static void handle_signal(int sig) {
  if (sig == SIGINT && command_app) {
    cmd_app_stop(command_app);
  }
}

static void print_usage(void) {
  fputs("Usage: router -i <file> <mac-address> <ip-address> <mask> [... ] [-r <network> <mask> <next-hop|direct> <interface> <metric> [...]] [-rarp <client-mac> <ip-address> [...]] [-dynamic-routing <on|off>]\n", stderr);
}

static bool append_frame(router_context_t* context, size_t interface_index, const ethernet_frame_data_t* frame) {
  router_port_t* port = &context->ports[interface_index];
  const long before = ftell(port->destination);
  if (before < 0 || !ethernet_write_frame(port->destination, frame)) {
    return false;
  }
  const long after = ftell(port->destination);
  if (after < before || fflush(port->destination) != 0) {
    return false;
  }
  port->injected_bytes += (size_t)(after - before);
  return true;
}

static bool write_rip_packet(router_context_t* context, size_t interface_index, uint8_t command, const rip_route_entry_t* entries, size_t entry_count) {
  const interface_entry_t* entry = interface_table_get(&context->interfaces, interface_index);
  if (!entry || !entry->enabled) return false;
  uint8_t rip_bytes[sizeof(rip_header_t) + RIP_MAX_ENTRIES_PER_PACKET * sizeof(rip_route_entry_t)] = {0};
  size_t rip_length = 0;
  if (!rip_write_packet(command, entries, entry_count, rip_bytes, sizeof(rip_bytes), &rip_length)) return false;
  udp_packet_data_t packet = {
      .src_addr = entry->ip4,
      .dst_addr = RIP_MULTICAST_ADDRESS,
      .src_port = RIP_UDP_PORT,
      .dst_port = RIP_UDP_PORT,
      .data = rip_bytes,
      .data_length = (uint16_t)rip_length,
  };
  memcpy(packet.src_mac_addr, entry->mac, sizeof(packet.src_mac_addr));
  memcpy(packet.dst_mac_addr, rip_multicast_mac, sizeof(packet.dst_mac_addr));
  router_port_t* port = &context->ports[interface_index];
  const long before = ftell(port->destination);
  if (before < 0 || !udp_write_ethernet_packet(port->destination, &packet)) return false;
  const long after = ftell(port->destination);
  if (after < before || fflush(port->destination) != 0) return false;
  port->injected_bytes += (size_t)(after - before);
  return true;
}

static bool write_rip_response(router_context_t* context, size_t interface_index) {
  bool wrote = false;
  size_t route_index = 0;
  while (route_index < context->routes.count || !wrote) {
    rip_route_entry_t entries[RIP_MAX_ENTRIES_PER_PACKET] = {0};
    size_t entry_count = 0;
    while (route_index < context->routes.count && entry_count < RIP_MAX_ENTRIES_PER_PACKET) {
      const route_entry_t* route = &context->routes.entries[route_index++];
      if (route->source == ROUTE_SOURCE_RIP && route->interface_index == interface_index) continue;
      entries[entry_count++] = (rip_route_entry_t) {
          .address_family = RIP_ADDRESS_FAMILY_IPV4,
          .destination = route->destination,
          .subnet_mask = route->mask,
          .next_hop = 0,
          .metric = route->metric == 0 ? RIP_METRIC_MIN : route->metric > RIP_METRIC_INFINITY ? RIP_METRIC_INFINITY : route->metric,
      };
    }
    if (!write_rip_packet(context, interface_index, RIP_COMMAND_RESPONSE, entries, entry_count)) return false;
    wrote = true;
  }
  return true;
}

static bool write_rip_updates(router_context_t* context) {
  for (size_t i = 0; i < context->interfaces.count; ++i) {
    if (!write_rip_response(context, i)) return false;
  }
  return true;
}

static bool write_rip_requests(router_context_t* context) {
  for (size_t i = 0; i < context->interfaces.count; ++i) {
    if (!write_rip_packet(context, i, RIP_COMMAND_REQUEST, NULL, 0)) return false;
  }
  return true;
}

static bool write_arp_request(router_context_t* context, size_t interface_index, ipv4_address_t target) {
  const interface_entry_t* entry = interface_table_get(&context->interfaces, interface_index);
  if (!entry) {
    return false;
  }
  uint8_t bytes[sizeof(arp_packet_t)] = {0};
  arp_packet_data_t request = {
      .sender_protocol_address = entry->ip4,
      .target_protocol_address = target,
  };
  memcpy(request.sender_hardware_address, entry->mac, sizeof(request.sender_hardware_address));
  FILE* destination = tmpfile();
  if (!destination || !arp_write_ethernet_request(destination, &request)) {
    if (destination) fclose(destination);
    return false;
  }
  const long length = ftell(destination);
  if (length <= 0 || (size_t)length > sizeof(bytes) + sizeof(ethernet_header_t) + ETHERNET_MIN_DATA_LEN + sizeof(ethernet_footer_t) || fseek(destination, 0, SEEK_SET) != 0) {
    fclose(destination);
    return false;
  }
  uint8_t* frame_bytes = malloc((size_t)length);
  if (!frame_bytes) {
    fclose(destination);
    return false;
  }
  const bool read = fread(frame_bytes, 1, (size_t)length, destination) == (size_t)length;
  fclose(destination);
  if (!read) {
    free(frame_bytes);
    return false;
  }
  const size_t start = 0;
  const bool written = fwrite(frame_bytes + start, 1, (size_t)length, context->ports[interface_index].destination) == (size_t)length && fflush(context->ports[interface_index].destination) == 0;
  if (written) context->ports[interface_index].injected_bytes += (size_t)length;
  free(frame_bytes);
  return written;
}

static bool write_arp_reply(router_context_t* context, size_t interface_index, const arp_packet_t* request) {
  const interface_entry_t* entry = interface_table_get(&context->interfaces, interface_index);
  if (!entry) return false;
  arp_reply_data_t reply = {
      .sender_protocol_address = entry->ip4,
      .target_protocol_address = request->sender_protocol_address,
  };
  memcpy(reply.sender_hardware_address, entry->mac, sizeof(reply.sender_hardware_address));
  memcpy(reply.target_hardware_address, request->sender_hardware_address, sizeof(reply.target_hardware_address));
  return arp_write_ethernet_reply(context->ports[interface_index].destination, &reply) && fflush(context->ports[interface_index].destination) == 0;
}

static bool write_rarp_reply(router_context_t* context, size_t interface_index, const rarp_packet_t* request, ipv4_address_t assigned_ip4) {
  const interface_entry_t* entry = interface_table_get(&context->interfaces, interface_index);
  if (!entry) return false;
  rarp_reply_data_t reply = {
      .server_protocol_address = entry->ip4,
      .client_protocol_address = assigned_ip4,
  };
  memcpy(reply.server_hardware_address, entry->mac, sizeof(reply.server_hardware_address));
  memcpy(reply.client_hardware_address, request->sender_hardware_address, sizeof(reply.client_hardware_address));
  return rarp_write_ethernet_reply(context->ports[interface_index].destination, &reply) && fflush(context->ports[interface_index].destination) == 0;
}

static bool forward_ipv4(router_context_t* context, size_t interface_index, const ipv4_header_t* header, const uint8_t* payload, uint16_t payload_length, const mac_address_t destination_mac) {
  const interface_entry_t* entry = interface_table_get(&context->interfaces, interface_index);
  if (!entry || header->ttl <= 1) return false;
  uint8_t bytes[ETHERNET_MAX_DATA_LEN] = {0};
  ipv4_header_t forwarded = *header;
  --forwarded.ttl;
  forwarded.header_checksum = 0;
  forwarded.header_checksum = checksum16(&forwarded, sizeof(forwarded));
  memcpy(bytes, &forwarded, sizeof(forwarded));
  memcpy(bytes + sizeof(forwarded), payload, payload_length);
  ethernet_frame_data_t frame = {
      .type_or_length = ETHERNET_ETHERTYPE_IPV4,
      .data_length = (uint16_t)(sizeof(forwarded) + payload_length),
      .data = bytes,
  };
  memcpy(frame.dst_addr, destination_mac, sizeof(frame.dst_addr));
  memcpy(frame.src_addr, entry->mac, sizeof(frame.src_addr));
  return append_frame(context, interface_index, &frame);
}

static bool queue_packet(router_context_t* context, size_t egress_interface, ipv4_address_t next_hop, const ipv4_packet_view_t* packet) {
  for (size_t i = 0; i < ROUTER_PENDING_CAPACITY; ++i) {
    router_pending_packet_t* pending = &context->pending_packets[i];
    if (!pending->active) {
      pending->header = packet->header;
      memcpy(pending->payload, packet->payload, packet->payload_length);
      pending->payload_length = packet->payload_length;
      pending->next_hop = next_hop;
      pending->egress_interface = egress_interface;
      pending->active = true;
      return true;
    }
  }
  return false;
}

static bool route_ipv4(router_context_t* context, size_t ingress_interface, const ipv4_packet_view_t* packet) {
  if (packet->header.ttl <= 1) {
    fputs("Dropped IPv4 packet with expired TTL.\n", stderr);
    return true;
  }
  if (interface_table_find_ip4(&context->interfaces, packet->header.dst_addr)) {
    return true;
  }
  const route_entry_t* route = route_table_lookup(&context->routes, packet->header.dst_addr);
  fputs("Router IPv4: src=", stdout);
  ipv4_address_print(stdout, packet->header.src_addr);
  fputs(" dst=", stdout);
  ipv4_address_print(stdout, packet->header.dst_addr);
  fprintf(stdout, " ttl=%u protocol=%u payload=%u bytes\n", packet->header.ttl, packet->header.protocol, packet->payload_length);
  if (!route) {
    fputs("Dropped IPv4 packet without a route.\n", stderr);
    return true;
  }
  const interface_entry_t* egress = interface_table_get(&context->interfaces, route->interface_index);
  if (!egress || !egress->enabled) {
    fputs("Dropped IPv4 packet with an unavailable egress interface.\n", stderr);
    return true;
  }
  const ipv4_address_t next_hop = route->next_hop ? route->next_hop : packet->header.dst_addr;
  arp_entry_t* neighbor = arp_table_find(&context->arp, route->interface_index, next_hop);
  if (neighbor) {
    if (!forward_ipv4(context, route->interface_index, &packet->header, packet->payload, packet->payload_length, neighbor->mac)) return false;
    fputs("Forwarded IPv4 packet from interface ", stdout);
    fprintf(stdout, "%zu to interface %zu.\n", ingress_interface + 1, route->interface_index + 1);
    return true;
  }
  if (!queue_packet(context, route->interface_index, next_hop, packet)) {
    fputs("Dropped IPv4 packet because the pending-neighbor queue is full.\n", stderr);
    return true;
  }
  if (!write_arp_request(context, route->interface_index, next_hop)) return false;
  fputs("Resolving next hop ", stdout);
  ipv4_address_print(stdout, next_hop);
  fprintf(stdout, " on interface %zu.\n", route->interface_index + 1);
  return true;
}

static bool flush_pending(router_context_t* context, size_t interface_index, ipv4_address_t ip4, const mac_address_t mac) {
  for (size_t i = 0; i < ROUTER_PENDING_CAPACITY; ++i) {
    router_pending_packet_t* pending = &context->pending_packets[i];
    if (pending->active && pending->egress_interface == interface_index && pending->next_hop == ip4) {
      if (!forward_ipv4(context, interface_index, &pending->header, pending->payload, pending->payload_length, mac)) return false;
      pending->active = false;
    }
  }
  return true;
}

static bool handle_arp(router_context_t* context, size_t ingress_interface, const ethernet_frame_view_t* frame) {
  arp_packet_t packet = {0};
  if (!arp_parse_packet(frame->data, sizeof(packet), &packet)) return true;
  arp_table_learn(&context->arp, ingress_interface, packet.sender_protocol_address, packet.sender_hardware_address);
  fputs("Learned ARP neighbor on interface ", stdout);
  fprintf(stdout, "%zu: ", ingress_interface + 1);
  ipv4_address_print(stdout, packet.sender_protocol_address);
  fputc('\n', stdout);
  if (!flush_pending(context, ingress_interface, packet.sender_protocol_address, packet.sender_hardware_address)) return false;
  const interface_entry_t* entry = interface_table_get(&context->interfaces, ingress_interface);
  if (packet.operation == ARP_OPERATION_REQUEST && entry && packet.target_protocol_address == entry->ip4) {
    const long before = ftell(context->ports[ingress_interface].destination);
    if (before < 0 || !write_arp_reply(context, ingress_interface, &packet)) return false;
    const long after = ftell(context->ports[ingress_interface].destination);
    if (after < before) return false;
    context->ports[ingress_interface].injected_bytes += (size_t)(after - before);
    fprintf(stdout, "Replied to ARP request on interface %zu.\n", ingress_interface + 1);
  }
  return true;
}

static bool handle_rarp(router_context_t* context, size_t ingress_interface, const ethernet_frame_view_t* frame) {
  rarp_packet_t packet = {0};
  if (!rarp_parse_packet(frame->data, sizeof(packet), &packet) || packet.operation != RARP_OPERATION_REQUEST) return true;
  rarp_entry_t* assignment = rarp_table_find(&context->rarp, packet.sender_hardware_address);
  if (!assignment) return true;
  const long before = ftell(context->ports[ingress_interface].destination);
  if (before < 0 || !write_rarp_reply(context, ingress_interface, &packet, assignment->ip4)) return false;
  const long after = ftell(context->ports[ingress_interface].destination);
  if (after < before) return false;
  context->ports[ingress_interface].injected_bytes += (size_t)(after - before);
  return true;
}

static bool handle_rip(router_context_t* context, size_t ingress_interface, const ipv4_packet_view_t* ipv4_packet) {
  const interface_entry_t* ingress = interface_table_get(&context->interfaces, ingress_interface);
  if (!context->dynamic_routing || !ingress || ipv4_packet->header.src_addr == ingress->ip4 || ipv4_packet->header.protocol != UDP_IPV4_PROTOCOL || !rip_is_multicast_address(ipv4_packet->header.dst_addr)) return true;
  udp_packet_view_t udp_packet = {0};
  rip_packet_view_t rip_packet = {0};
  if (!udp_parse_packet(ipv4_packet->payload, ipv4_packet->payload_length, ipv4_packet->header.src_addr, ipv4_packet->header.dst_addr, &udp_packet) || udp_packet.header.src_port != RIP_UDP_PORT || udp_packet.header.dst_port != RIP_UDP_PORT || !rip_parse_packet(udp_packet.data, udp_packet.data_length, &rip_packet)) return true;
  if (rip_packet.header.command == RIP_COMMAND_REQUEST) {
    return write_rip_response(context, ingress_interface);
  }
  const uint32_t expires_at = router_now() + RIP_ROUTE_TIMEOUT_SECONDS;
  for (size_t i = 0; i < rip_packet.entry_count; ++i) {
    const rip_route_entry_t* advertised = &rip_packet.entries[i];
    const uint32_t metric = advertised->metric == RIP_METRIC_INFINITY ? RIP_METRIC_INFINITY : advertised->metric + 1;
    const ipv4_address_t next_hop = advertised->next_hop ? advertised->next_hop : ipv4_packet->header.src_addr;
    if (!route_table_learn_rip(&context->routes, advertised->destination, advertised->subnet_mask, next_hop, ingress_interface, metric, expires_at)) return false;
  }
  fprintf(stdout, "Learned %zu RIP route%s on interface %zu.\n", rip_packet.entry_count, rip_packet.entry_count == 1 ? "" : "s", ingress_interface + 1);
  return true;
}

static bool handle_ethernet(router_context_t* context, size_t ingress_interface, const uint8_t* bytes, size_t byte_count) {
  ethernet_frame_view_t frame = {0};
  if (!ethernet_parse_frame(bytes, byte_count, &frame) || frame.format != ETHERNET_FRAME_FORMAT_II) return true;
  const interface_entry_t* entry = interface_table_get(&context->interfaces, ingress_interface);
  if (!entry) return false;
  fprintf(stdout, "Router frame: ingress=%zu bytes=%zu dst=", ingress_interface + 1, byte_count);
  ethernet_mac_print(stdout, frame.header.dst_mac);
  fputs(" src=", stdout);
  ethernet_mac_print(stdout, frame.header.src_mac);
  fprintf(stdout, " EtherType=0x%04X\n", frame.header.type_or_length);
  const bool destination_is_interface = memcmp(frame.header.dst_mac, entry->mac, sizeof(entry->mac)) == 0;
  const bool destination_is_rip_multicast = memcmp(frame.header.dst_mac, rip_multicast_mac, sizeof(rip_multicast_mac)) == 0;
  if (frame.header.type_or_length == ETHERNET_ETHERTYPE_ARP && (destination_is_interface || ethernet_mac_is_broadcast(frame.header.dst_mac))) return handle_arp(context, ingress_interface, &frame);
  if (frame.header.type_or_length == ETHERNET_ETHERTYPE_RARP && (destination_is_interface || ethernet_mac_is_broadcast(frame.header.dst_mac))) return handle_rarp(context, ingress_interface, &frame);
  if (frame.header.type_or_length != ETHERNET_ETHERTYPE_IPV4 || (!destination_is_interface && !destination_is_rip_multicast)) return true;
  ipv4_packet_view_t packet = {0};
  if (!ipv4_parse_packet(frame.data, frame.client_data_length, &packet)) return true;
  if (destination_is_rip_multicast) return handle_rip(context, ingress_interface, &packet);
  return route_ipv4(context, ingress_interface, &packet);
}

static bool process_port(router_context_t* context, size_t interface_index) {
  router_port_t* port = &context->ports[interface_index];
  size_t offset = 0;
  while (offset < port->buffer_length) {
    const size_t remaining = port->buffer_length - offset;
    vnet_frame_header_t control = {0};
    if (remaining >= sizeof(control) && vnet_parse_frame(port->buffer + offset, sizeof(control), &control)) {
      offset += sizeof(control);
      continue;
    }
    if (!ethernet_frame_is_start(port->buffer + offset, remaining)) {
      ++offset;
      continue;
    }
    size_t end = offset + 1;
    while (end < port->buffer_length && !ethernet_frame_is_start(port->buffer + end, port->buffer_length - end) && !vnet_frame_has_prefix(port->buffer + end, port->buffer_length - end)) {
      ++end;
    }
    ethernet_frame_view_t frame = {0};
    if (ethernet_parse_frame(port->buffer + offset, end - offset, &frame)) {
      if (!handle_ethernet(context, interface_index, port->buffer + offset, end - offset)) return false;
      offset = end;
      continue;
    }
    if (end == port->buffer_length && remaining < sizeof(ethernet_header_t) + ETHERNET_MIN_DATA_LEN + sizeof(ethernet_footer_t)) break;
    ++offset;
  }
  if (offset > 0) {
    memmove(port->buffer, port->buffer + offset, port->buffer_length - offset);
    port->buffer_length -= offset;
  }
  return true;
}

static void print_info(router_context_t* context) {
  mutex_lock(&context->mutex);
  fprintf(stdout, "Dynamic routing: %s%s\n", context->dynamic_routing ? "on" : "off", context->dynamic_routing ? " (RIP v2)" : "");
  fprintf(stdout, "Interfaces (%zu):\n", context->interfaces.count);
  for (size_t i = 0; i < context->interfaces.count; ++i) {
    const interface_entry_t* entry = &context->interfaces.entries[i];
    fprintf(stdout, "  %zu  %-32s ", i + 1, entry->path);
    ethernet_mac_print(stdout, entry->mac);
    fputs("  ", stdout);
    ipv4_address_print(stdout, entry->ip4);
    fputs("/", stdout);
    ipv4_address_print(stdout, entry->mask);
    fprintf(stdout, "  %s\n", entry->enabled ? "up" : "down");
  }
  fprintf(stdout, "Routes (%zu):\n", context->routes.count);
  for (size_t i = 0; i < context->routes.count; ++i) {
    const route_entry_t* route = &context->routes.entries[i];
    fputs("  ", stdout);
    ipv4_address_print(stdout, route->destination);
    fputs("/", stdout);
    ipv4_address_print(stdout, route->mask);
    fputs(" via ", stdout);
    if (route->next_hop) ipv4_address_print(stdout, route->next_hop);
    else
      fputs("direct", stdout);
    fprintf(stdout, " dev %zu metric %u %s\n", route->interface_index + 1, route->metric, route_source_name(route->source));
  }
  fprintf(stdout, "ARP neighbors (%zu):\n", context->arp.count);
  for (size_t i = 0; i < context->arp.count; ++i) {
    const arp_entry_t* entry = &context->arp.entries[i];
    fprintf(stdout, "  dev %zu  ", entry->interface_index + 1);
    ipv4_address_print(stdout, entry->ip4);
    fputs("  ", stdout);
    ethernet_mac_print(stdout, entry->mac);
    fputc('\n', stdout);
  }
  fprintf(stdout, "RARP assignments (%zu):\n", context->rarp.count);
  for (size_t i = 0; i < context->rarp.count; ++i) {
    fputs("  ", stdout);
    ethernet_mac_print(stdout, context->rarp.entries[i].mac);
    fputs("  ", stdout);
    ipv4_address_print(stdout, context->rarp.entries[i].ip4);
    fputc('\n', stdout);
  }
  mutex_unlock(&context->mutex);
}

static void command_info(void* argument, char* arguments) {
  if (!cmd_app_arguments_empty(arguments)) {
    fputs("Usage: info\n", stderr);
    return;
  }
  print_info(argument);
}

static void command_arp(void* argument, char* arguments) {
  router_context_t* context = argument;
  char* cursor = arguments;
  char* interface_text = cmd_app_next_argument(&cursor);
  char* ip4_text = cmd_app_next_argument(&cursor);
  uint16_t interface_number = 0;
  ipv4_address_t ip4 = 0;
  if (!interface_text || !ip4_text || cmd_app_next_argument(&cursor) || !cmd_app_parse_uint16(interface_text, &interface_number) || interface_number == 0 || interface_number > context->interfaces.count || !ipv4_parse_address(ip4_text, &ip4)) {
    fputs("Usage: arp <interface> <ip-address>\n", stderr);
    return;
  }
  mutex_lock(&context->mutex);
  const bool written = write_arp_request(context, interface_number - 1, ip4);
  mutex_unlock(&context->mutex);
  if (!written) {
    fputs("Could not send ARP request.\n", stderr);
  }
}

static void command_interface(void* argument, char* arguments) {
  router_context_t* context = argument;
  char* cursor = arguments;
  char* state = cmd_app_next_argument(&cursor);
  char* number = cmd_app_next_argument(&cursor);
  uint16_t index = 0;
  if (!state || !number || cmd_app_next_argument(&cursor) || !cmd_app_parse_uint16(number, &index) || index == 0 || index > context->interfaces.count || (strcmpi(state, "up") != 0 && strcmpi(state, "down") != 0)) {
    fputs("Usage: interface <up|down> <number>\n", stderr);
    return;
  }
  mutex_lock(&context->mutex);
  interface_table_set_enabled(&context->interfaces, index - 1, strcmpi(state, "up") == 0);
  mutex_unlock(&context->mutex);
  fprintf(stdout, "Interface %u is administratively %s.\n", index, state);
}

static void command_dynamic_routing(void* argument, char* arguments) {
  router_context_t* context = argument;
  char* state = cmd_app_next_argument(&arguments);
  if (!state || cmd_app_next_argument(&arguments) || (strcmpi(state, "on") != 0 && strcmpi(state, "off") != 0)) {
    fputs("Usage: dynamic-routing <on|off>\n", stderr);
    return;
  }
  mutex_lock(&context->mutex);
  const bool enabled = strcmpi(state, "on") == 0;
  context->dynamic_routing = enabled;
  if (enabled) {
    context->next_rip_update = router_now() + RIP_UPDATE_INTERVAL_SECONDS;
    if (!write_rip_requests(context) || !write_rip_updates(context)) {
      mutex_unlock(&context->mutex);
      fputs("Could not start RIP routing updates.\n", stderr);
      return;
    }
  } else {
    route_table_remove_rip(&context->routes);
  }
  mutex_unlock(&context->mutex);
  fprintf(stdout, "Dynamic routing is %s.\n", enabled ? "on (RIP v2)" : "off");
}

static void command_route(void* argument, char* arguments) {
  router_context_t* context = argument;
  char* cursor = arguments;
  char* action = cmd_app_next_argument(&cursor);
  if (action && strcmpi(action, "delete") == 0) {
    char* index_text = cmd_app_next_argument(&cursor);
    uint16_t index = 0;
    if (!index_text || cmd_app_next_argument(&cursor) || !cmd_app_parse_uint16(index_text, &index) || index == 0) {
      fputs("Usage: route delete <number>\n", stderr);
      return;
    }
    mutex_lock(&context->mutex);
    const bool removed = route_table_remove(&context->routes, index - 1);
    mutex_unlock(&context->mutex);
    fputs(removed ? "Route removed.\n" : "No such route.\n", removed ? stdout : stderr);
    return;
  }
  char* network_text = cmd_app_next_argument(&cursor);
  char* mask_text = cmd_app_next_argument(&cursor);
  char* next_hop_text = cmd_app_next_argument(&cursor);
  char* interface_text = cmd_app_next_argument(&cursor);
  char* metric_text = cmd_app_next_argument(&cursor);
  ipv4_address_t network = 0;
  ipv4_address_t mask = 0;
  ipv4_address_t next_hop = 0;
  uint16_t interface_number = 0;
  uint32_t metric = 0;
  if (!action || strcmpi(action, "add") != 0 || !network_text || !mask_text || !next_hop_text || !interface_text || !metric_text || cmd_app_next_argument(&cursor) || !ipv4_parse_address(network_text, &network) || !ipv4_parse_address(mask_text, &mask) || (strcmpi(next_hop_text, "direct") != 0 && !ipv4_parse_address(next_hop_text, &next_hop)) || !cmd_app_parse_uint16(interface_text, &interface_number) || interface_number == 0 || interface_number > context->interfaces.count || !cmd_app_parse_uint32(metric_text, &metric)) {
    fputs("Usage: route add <network> <mask> <next-hop|direct> <interface> <metric> | route delete <number>\n", stderr);
    return;
  }
  mutex_lock(&context->mutex);
  const bool added = route_table_add(&context->routes, network, mask, next_hop, interface_number - 1, metric);
  mutex_unlock(&context->mutex);
  fputs(added ? "Route added.\n" : "Could not add route (invalid prefix or table full).\n", added ? stdout : stderr);
}

static void command_rarp_table(void* argument, char* arguments) {
  router_context_t* context = argument;
  char* cursor = arguments;
  char* action = cmd_app_next_argument(&cursor);
  char* mac_text = cmd_app_next_argument(&cursor);
  mac_address_t mac = {0};
  if (!action || !mac_text || !ethernet_mac_parse(mac_text, mac)) {
    fputs("Usage: rarp-table <set|delete> <mac-address> [ip-address]\n", stderr);
    return;
  }
  if (strcmpi(action, "delete") == 0 && !cmd_app_next_argument(&cursor)) {
    mutex_lock(&context->mutex);
    const bool removed = rarp_table_remove(&context->rarp, mac);
    mutex_unlock(&context->mutex);
    fputs(removed ? "RARP assignment removed.\n" : "No such RARP assignment.\n", removed ? stdout : stderr);
    return;
  }
  char* ip4_text = cmd_app_next_argument(&cursor);
  ipv4_address_t ip4 = 0;
  if (strcmpi(action, "set") != 0 || !ip4_text || cmd_app_next_argument(&cursor) || !ipv4_parse_address(ip4_text, &ip4)) {
    fputs("Usage: rarp-table <set|delete> <mac-address> [ip-address]\n", stderr);
    return;
  }
  mutex_lock(&context->mutex);
  const bool set = rarp_table_set(&context->rarp, mac, ip4);
  mutex_unlock(&context->mutex);
  fputs(set ? "RARP assignment set.\n" : "RARP table is full.\n", set ? stdout : stderr);
}

static void command_arp_delete(void* argument, char* arguments) {
  router_context_t* context = argument;
  char* cursor = arguments;
  char* interface_text = cmd_app_next_argument(&cursor);
  char* ip4_text = cmd_app_next_argument(&cursor);
  uint16_t interface_number = 0;
  ipv4_address_t ip4 = 0;
  if (!interface_text || !ip4_text || cmd_app_next_argument(&cursor) || !cmd_app_parse_uint16(interface_text, &interface_number) || interface_number == 0 || interface_number > context->interfaces.count || !ipv4_parse_address(ip4_text, &ip4)) {
    fputs("Usage: arp-delete <interface> <ip-address>\n", stderr);
    return;
  }
  mutex_lock(&context->mutex);
  const bool removed = arp_table_remove(&context->arp, interface_number - 1, ip4);
  mutex_unlock(&context->mutex);
  fputs(removed ? "ARP neighbor removed.\n" : "No such ARP neighbor.\n", removed ? stdout : stderr);
}

static bool parse_options(router_context_t* context, int argc, char** argv) {
  for (int i = 1; i < argc;) {
    if (strcmpi(argv[i], "-i") == 0) {
      if (i + 4 >= argc || context->interfaces.count == ROUTER_INTERFACE_CAPACITY) return false;
      mac_address_t mac = {0};
      ipv4_address_t ip4 = 0;
      ipv4_address_t mask = 0;
      if (!ethernet_mac_parse(argv[i + 2], mac) || !ipv4_parse_address(argv[i + 3], &ip4) || !ipv4_parse_address(argv[i + 4], &mask) || !interface_table_add(&context->interfaces, argv[i + 1], mac, ip4, mask)) return false;
      i += 5;
    } else if (strcmpi(argv[i], "-r") == 0) {
      if (i + 5 >= argc) return false;
      ipv4_address_t network = 0;
      ipv4_address_t mask = 0;
      ipv4_address_t next_hop = 0;
      uint16_t interface_number = 0;
      uint32_t metric = 0;
      if (!ipv4_parse_address(argv[i + 1], &network) || !ipv4_parse_address(argv[i + 2], &mask) || (strcmpi(argv[i + 3], "direct") != 0 && !ipv4_parse_address(argv[i + 3], &next_hop)) || !cmd_app_parse_uint16(argv[i + 4], &interface_number) || interface_number == 0 || interface_number > context->interfaces.count || !cmd_app_parse_uint32(argv[i + 5], &metric) || !route_table_add(&context->routes, network, mask, next_hop, interface_number - 1, metric)) return false;
      i += 6;
    } else if (strcmpi(argv[i], "-dynamic-routing") == 0) {
      if (i + 1 >= argc || (strcmpi(argv[i + 1], "on") != 0 && strcmpi(argv[i + 1], "off") != 0)) return false;
      context->dynamic_routing = strcmpi(argv[i + 1], "on") == 0;
      i += 2;
    } else if (strcmpi(argv[i], "-rarp") == 0) {
      if (i + 2 >= argc || context->rarp.count == ROUTER_RARP_CAPACITY) return false;
      mac_address_t mac = {0};
      ipv4_address_t ip4 = 0;
      if (!ethernet_mac_parse(argv[i + 1], mac) || !ipv4_parse_address(argv[i + 2], &ip4) || !rarp_table_set(&context->rarp, mac, ip4)) return false;
      i += 3;
    } else {
      return false;
    }
  }
  if (context->interfaces.count < 2) return false;
  for (size_t i = 0; i < context->interfaces.count; ++i) {
    const interface_entry_t* entry = &context->interfaces.entries[i];
    if (!route_table_add_connected(&context->routes, entry->ip4 & entry->mask, entry->mask, i)) return false;
  }
  return true;
}

int main(int argc, char** argv) {
  router_context_t context = {0};
  interface_table_init(&context.interfaces, context.interface_entries, ROUTER_INTERFACE_CAPACITY);
  route_table_init(&context.routes, context.route_entries, ROUTER_ROUTE_CAPACITY);
  arp_table_init(&context.arp, context.arp_entries, ROUTER_ARP_CAPACITY);
  rarp_table_init(&context.rarp, context.rarp_entries, ROUTER_RARP_CAPACITY);
  if (!parse_options(&context, argc, argv)) {
    print_usage();
    return EXIT_FAILURE;
  }
  if (!mutex_init(&context.mutex)) {
    fputs("Could not initialize router mutex.\n", stderr);
    return EXIT_FAILURE;
  }
  int status = EXIT_SUCCESS;
  signal(SIGINT, handle_signal);
  for (size_t i = 0; i < context.interfaces.count; ++i) {
    router_port_t* port = &context.ports[i];
    port->source = fopen(context.interfaces.entries[i].path, "rb");
    port->destination = fopen(context.interfaces.entries[i].path, "ab");
    if (!port->source || !port->destination || fseek(port->source, 0, SEEK_END) != 0) {
      fprintf(stderr, "Could not open router interface %zu.\n", i + 1);
      status = EXIT_FAILURE;
      goto cleanup;
    }
  }
  cmd_app_init(&context.commands);
  if (!cmd_app_register(&context.commands, "info", "Show router state, including RIP route sources.", command_info, &context) || !cmd_app_register(&context.commands, "arp", "Resolve an IPv4 neighbor on one interface.", command_arp, &context) || !cmd_app_register(&context.commands, "arp-delete", "Remove one learned ARP neighbor.", command_arp_delete, &context) || !cmd_app_register(&context.commands, "interface", "Administratively bring an interface up or down.", command_interface, &context) || !cmd_app_register(&context.commands, "dynamic-routing", "Enable or disable RIP v2 dynamic routing.", command_dynamic_routing, &context) || !cmd_app_register(&context.commands, "route", "Add or delete a route in the forwarding table.", command_route, &context) || !cmd_app_register(&context.commands, "rarp-table", "Set or delete a static RARP assignment.", command_rarp_table, &context) || !cmd_app_start(&context.commands)) {
    fputs("Could not start the command application.\n", stderr);
    status = EXIT_FAILURE;
    goto cleanup;
  }
  command_app = &context.commands;
  if (context.dynamic_routing) {
    context.next_rip_update = router_now() + RIP_UPDATE_INTERVAL_SECONDS;
    mutex_lock(&context.mutex);
    const bool started_rip = write_rip_requests(&context) && write_rip_updates(&context);
    mutex_unlock(&context.mutex);
    if (!started_rip) {
      fputs("Could not start RIP routing updates.\n", stderr);
      status = EXIT_FAILURE;
      goto cleanup;
    }
  }

  while (cmd_app_is_running(&context.commands)) {
    long ends[ROUTER_INTERFACE_CAPACITY] = {0};
    for (size_t i = 0; i < context.interfaces.count; ++i) {
      context.ports[i].injected_bytes = 0;
      if (!get_file_end(context.ports[i].source, &ends[i])) {
        fputs("Could not snapshot router interface traffic.\n", stderr);
        status = EXIT_FAILURE;
        goto cleanup;
      }
    }
    mutex_lock(&context.mutex);
    if (context.dynamic_routing) {
      const uint32_t now = router_now();
      route_table_expire_rip(&context.routes, now);
      if (now >= context.next_rip_update) {
        if (!write_rip_updates(&context)) {
          mutex_unlock(&context.mutex);
          fputs("Could not send RIP routing update.\n", stderr);
          status = EXIT_FAILURE;
          goto cleanup;
        }
        context.next_rip_update = now + RIP_UPDATE_INTERVAL_SECONDS;
      }
    }
    for (size_t i = 0; i < context.interfaces.count; ++i) {
      router_port_t* port = &context.ports[i];
      const long position = ftell(port->source);
      const long remaining = ends[i] - position;
      const size_t capacity = sizeof(port->buffer) - port->buffer_length;
      const size_t requested = remaining <= 0 ? 0 : (unsigned long)remaining < capacity ? (size_t)remaining
                                                                                        : capacity;
      const size_t read_count = fread(port->buffer + port->buffer_length, 1, requested, port->source);
      if (read_count > 0) {
        port->buffer_length += read_count;
        if (!process_port(&context, i)) {
          mutex_unlock(&context.mutex);
          status = EXIT_FAILURE;
          goto cleanup;
        }
      }
      if (position < 0 || ferror(port->source) || port->buffer_length == sizeof(port->buffer)) {
        mutex_unlock(&context.mutex);
        fputs("Could not process router interface traffic.\n", stderr);
        status = EXIT_FAILURE;
        goto cleanup;
      }
      clearerr(port->source);
    }
    for (size_t i = 0; i < context.interfaces.count; ++i) {
      router_port_t* port = &context.ports[i];
      if (port->injected_bytes > 0 && fseek(port->source, (long)port->injected_bytes, SEEK_CUR) != 0) {
        mutex_unlock(&context.mutex);
        fputs("Could not skip router-injected traffic.\n", stderr);
        status = EXIT_FAILURE;
        goto cleanup;
      }
    }
    mutex_unlock(&context.mutex);
    thread_sleep(SLEEP_INTERVAL_MS);
  }

cleanup:
  if (command_app) {
    cmd_app_stop(command_app);
    cmd_app_join(command_app);
    command_app = NULL;
  }
  for (size_t i = 0; i < context.interfaces.count; ++i) {
    if (context.ports[i].source) fclose(context.ports[i].source);
    if (context.ports[i].destination) fclose(context.ports[i].destination);
  }
  mutex_destroy(&context.mutex);
  return status;
}

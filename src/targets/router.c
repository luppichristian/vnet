/*
 * MIT License
 *
 * Copyright (c) 2026 Christian Luppi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "router.h"

static const mac_address_t ethernet_broadcast_mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
#define ROUTER_ACL_PROTOCOL_ANY 0
#define ROUTER_ACL_PORT_ANY     0
#define ROUTER_INTERFACE_NONE   ((size_t)-1)

static bool write_arp_request(router_context_t* context, size_t interface_index, ipv4_address_t target);
static bool forward_ipv4(router_context_t* context, size_t interface_index, const ipv4_header_t* header, const uint8_t* payload, uint16_t payload_length, const mac_address_t destination_mac);
static bool queue_packet(router_context_t* context, size_t egress_interface, ipv4_address_t next_hop, const ipv4_packet_view_t* packet, const ipv4_packet_view_t* report_packet, bool report_next_hop_failure, size_t report_interface, uint32_t now);
static bool write_udp_on_interface(router_context_t* context, size_t interface_index, const udp_packet_data_t* packet);
static bool emit_generated_ipv4(router_context_t* context, const ipv4_packet_view_t* packet);
static void clear_dhcp_relay_entries(router_context_t* context, size_t ingress_interface);
static router_dhcp_relay_entry_t* find_dhcp_relay_entry(router_context_t* context, uint16_t transaction_id, const mac_address_t client_mac, ipv4_address_t server_address);
static router_dhcp_relay_entry_t* remember_dhcp_relay(router_context_t* context, size_t ingress_interface, const dhcp_message_t* message, ipv4_address_t server_address, uint32_t now);
static bool handle_dhcp_relay(router_context_t* context, size_t ingress_interface, const ethernet_frame_view_t* frame, const ipv4_packet_view_t* packet, bool* handled);
static bool append_frame(router_context_t* context, size_t interface_index, const ethernet_frame_data_t* frame);
static bool append_generated_frame_file(router_context_t* context, size_t interface_index, FILE* frame_file);
static size_t find_ingress_interface(const router_context_t* context, size_t port_index, const ethernet_frame_view_t* frame);
static router_acl_action_t evaluate_acl(router_context_t* context, size_t interface_index, router_acl_direction_t direction, const ipv4_packet_view_t* packet);
static const char* acl_action_name(router_acl_action_t action);
static const char* acl_direction_name(router_acl_direction_t direction);
static bool parse_acl_protocol(const char* text, uint8_t* protocol);
static bool parse_acl_port(const char* text, bool* any, uint16_t* port);
static bool acl_protocol_has_ports(uint8_t protocol);
static uint16_t acl_rule_sort_key(const router_acl_rule_t* rule);

static bool append_generated_frame_file(router_context_t* context, size_t interface_index, FILE* frame_file) {
  if (!context || !frame_file) return false;
  const long length = ftell(frame_file);
  if (length <= 0 || fseek(frame_file, 0, SEEK_SET) != 0) return false;
  uint8_t* bytes = malloc((size_t)length);
  if (!bytes) return false;
  const bool read = fread(bytes, 1, (size_t)length, frame_file) == (size_t)length;
  if (!read) {
    free(bytes);
    return false;
  }
  ethernet_frame_view_t parsed = {0};
  const bool ok = ethernet_parse_frame(bytes, (size_t)length, &parsed);
  if (!ok) {
    free(bytes);
    return false;
  }
  ethernet_frame_data_t frame = {
      .type_or_length = parsed.type_or_length,
      .data_length = parsed.client_data_length,
      .data = parsed.data,
      .tagged = parsed.tagged,
      .priority = parsed.priority,
      .drop_eligible = parsed.drop_eligible,
      .vlan_id = parsed.vlan_id,
  };
  memcpy(frame.dst_addr, parsed.header.dst_mac, sizeof(frame.dst_addr));
  memcpy(frame.src_addr, parsed.header.src_mac, sizeof(frame.src_addr));
  const bool appended = append_frame(context, interface_index, &frame);
  free(bytes);
  return appended;
}


static const char* acl_action_name(router_acl_action_t action) {
  return action == ROUTER_ACL_ACTION_PERMIT ? "permit" : "deny";
}

static const char* acl_direction_name(router_acl_direction_t direction) {
  return direction == ROUTER_ACL_DIRECTION_EGRESS ? "out" : "in";
}

static bool acl_protocol_has_ports(uint8_t protocol) {
  return protocol == TCP_IPV4_PROTOCOL || protocol == UDP_IPV4_PROTOCOL;
}

static bool parse_acl_protocol(const char* text, uint8_t* protocol) {
  if (!text || !protocol) return false;
  if (strcmpi(text, "any") == 0) {
    *protocol = ROUTER_ACL_PROTOCOL_ANY;
    return true;
  }
  if (strcmpi(text, "tcp") == 0) {
    *protocol = TCP_IPV4_PROTOCOL;
    return true;
  }
  if (strcmpi(text, "udp") == 0) {
    *protocol = UDP_IPV4_PROTOCOL;
    return true;
  }
  if (strcmpi(text, "icmp") == 0) {
    *protocol = ICMP_IPV4_PROTOCOL;
    return true;
  }
  uint16_t value = 0;
  if (!cmd_app_parse_uint16(text, &value) || value > UINT8_MAX) return false;
  *protocol = (uint8_t)value;
  return true;
}

static bool parse_acl_port(const char* text, bool* any, uint16_t* port) {
  if (!text || !any || !port) return false;
  if (strcmpi(text, "any") == 0) {
    *any = true;
    *port = ROUTER_ACL_PORT_ANY;
    return true;
  }
  *any = false;
  return cmd_app_parse_uint16(text, port);
}

static uint16_t acl_rule_sort_key(const router_acl_rule_t* rule) {
  return rule ? rule->sequence : 0;
}

static bool acl_packet_ports(const ipv4_packet_view_t* packet, uint16_t* src_port, uint16_t* dst_port) {
  if (!packet || !src_port || !dst_port) return false;
  *src_port = 0;
  *dst_port = 0;
  if (packet->header.protocol == UDP_IPV4_PROTOCOL) {
    udp_packet_view_t udp = {0};
    if (!udp_parse_packet(packet->payload, packet->payload_length, packet->header.src_addr, packet->header.dst_addr, &udp)) return false;
    *src_port = udp.header.src_port;
    *dst_port = udp.header.dst_port;
    return true;
  }
  if (packet->header.protocol == TCP_IPV4_PROTOCOL) {
    tcp_packet_view_t tcp = {0};
    if (!tcp_parse_packet(packet->payload, packet->payload_length, packet->header.src_addr, packet->header.dst_addr, &tcp)) return false;
    *src_port = tcp.header.src_port;
    *dst_port = tcp.header.dst_port;
    return true;
  }
  return true;
}

static router_acl_action_t evaluate_acl(router_context_t* context, size_t interface_index, router_acl_direction_t direction, const ipv4_packet_view_t* packet) {
  uint16_t source_port = 0;
  uint16_t destination_port = 0;
  if (!context || !packet) return ROUTER_ACL_ACTION_DENY;
  if (acl_protocol_has_ports(packet->header.protocol) && !acl_packet_ports(packet, &source_port, &destination_port)) {
    return ROUTER_ACL_ACTION_DENY;
  }
  router_acl_rule_t* best = NULL;
  for (size_t i = 0; i < ROUTER_ACL_RULE_CAPACITY; ++i) {
    router_acl_rule_t* rule = &context->acl_rules[i];
    if (!rule->active || rule->interface_index != interface_index || rule->direction != direction) continue;
    if (rule->protocol != ROUTER_ACL_PROTOCOL_ANY && rule->protocol != packet->header.protocol) continue;
    if ((packet->header.src_addr & rule->src_mask) != rule->src_network) continue;
    if ((packet->header.dst_addr & rule->dst_mask) != rule->dst_network) continue;
    if (acl_protocol_has_ports(rule->protocol ? rule->protocol : packet->header.protocol)) {
      if (!rule->src_port_any && rule->src_port != source_port) continue;
      if (!rule->dst_port_any && rule->dst_port != destination_port) continue;
    } else if (!rule->src_port_any || !rule->dst_port_any) {
      continue;
    }
    if (!best || acl_rule_sort_key(rule) < acl_rule_sort_key(best)) best = rule;
  }
  if (best) {
    ++best->packets;
    best->bytes += sizeof(packet->header) + packet->payload_length;
    return best->action;
  }
  ++context->acl_default_packets[interface_index][direction];
  context->acl_default_bytes[interface_index][direction] += sizeof(packet->header) + packet->payload_length;
  return context->acl_defaults[interface_index][direction];
}

static size_t find_ingress_interface(const router_context_t* context, size_t port_index, const ethernet_frame_view_t* frame) {
  if (!context || !frame) return ROUTER_INTERFACE_NONE;
  for (size_t i = 0; i < context->interfaces.count; ++i) {
    const interface_entry_t* entry = &context->interfaces.entries[i];
    if (entry->port_index != port_index) continue;
    if (entry->tagged != frame->tagged) continue;
    if (entry->tagged && entry->vlan_id != frame->vlan_id) continue;
    return i;
  }
  return ROUTER_INTERFACE_NONE;
}

static bool write_udp_on_interface(router_context_t* context, size_t interface_index, const udp_packet_data_t* packet) {
  FILE* destination = tmpfile();
  if (!destination || !udp_write_ethernet_packet(destination, packet)) {
    if (destination) fclose(destination);
    return false;
  }
  const bool appended = append_generated_frame_file(context, interface_index, destination);
  fclose(destination);
  return appended;
}

static bool append_frame(router_context_t* context, size_t interface_index, const ethernet_frame_data_t* frame) {
  const interface_entry_t* entry = interface_table_get(&context->interfaces, interface_index);
  if (!entry || entry->port_index == ROUTER_INTERFACE_NONE) return false;
  router_port_t* port = &context->ports[entry->port_index];
  ethernet_frame_data_t emitted = *frame;
  if (entry->tagged) {
    emitted.tagged = true;
    emitted.vlan_id = entry->vlan_id;
    emitted.priority = 0;
    emitted.drop_eligible = false;
  }
  const long before = ftell(port->destination);
  if (before < 0 || !ethernet_write_frame(port->destination, &emitted)) {
    return false;
  }
  const long after = ftell(port->destination);
  if (after < before || fflush(port->destination) != 0) {
    return false;
  }
  port->injected_bytes += (size_t)(after - before);
  return true;
}

static bool ipv4_source_is_valid_unicast(ipv4_address_t address, ipv4_address_t ingress_mask) {
  return !ipv4_address_is_unspecified(address) && !ipv4_address_is_loopback(address) && !ipv4_address_is_limited_broadcast(address) && !ipv4_address_is_subnet_broadcast(address, ingress_mask) && !ipv4_address_is_multicast(address);
}

static bool frame_targets_eligible_unicast(const ethernet_frame_view_t* frame, const interface_entry_t* ingress_entry, const ipv4_packet_view_t* packet) {
  if (!frame || !ingress_entry || !packet || ethernet_mac_is_group(frame->header.dst_mac) || ipv4_address_is_multicast(packet->header.dst_addr) || ipv4_address_is_limited_broadcast(packet->header.dst_addr) || ipv4_address_is_subnet_broadcast(packet->header.dst_addr, ingress_entry->mask)) {
    return false;
  }
  return true;
}

static bool packet_allows_icmp_error(const ethernet_frame_view_t* frame, const interface_entry_t* ingress_entry, const ipv4_packet_view_t* packet) {
  if (!frame_targets_eligible_unicast(frame, ingress_entry, packet) || !ipv4_source_is_valid_unicast(packet->header.src_addr, ingress_entry->mask)) {
    return false;
  }
  return packet->header.protocol != ICMP_IPV4_PROTOCOL || !icmp_packet_is_error(packet->payload, packet->payload_length);
}

static bool emit_routed_ipv4(router_context_t* context, ipv4_address_t destination, uint8_t protocol, const uint8_t* payload, uint16_t payload_length) {
  const route_entry_t* route = route_table_lookup(&context->routes, destination);
  if (!route) return true;
  const interface_entry_t* entry = interface_table_get(&context->interfaces, route->interface_index);
  if (!entry || !entry->enabled) return true;
  ipv4_packet_view_t view = {
      .header =
          {
              .version = 4,
              .ihl = 5,
              .total_length = (uint16_t)(sizeof(ipv4_header_t) + payload_length),
              .ttl = IPV4_DEFAULT_TTL,
              .protocol = protocol,
              .src_addr = entry->ip4,
              .dst_addr = destination,
          },
      .payload = payload,
      .payload_length = payload_length,
  };
  if (evaluate_acl(context, route->interface_index, ROUTER_ACL_DIRECTION_EGRESS, &view) != ROUTER_ACL_ACTION_PERMIT) {
    fputs("Dropped generated IPv4 packet by egress ACL.\n", stderr);
    return true;
  }
  const ipv4_address_t next_hop = route->next_hop ? route->next_hop : destination;
  const arp_entry_t* neighbor = arp_table_find_const(&context->arp, route->interface_index, next_hop);
  if (!neighbor) {
    return write_arp_request(context, route->interface_index, next_hop);
  }
  ipv4_packet_data_t packet = {
      .src_addr = entry->ip4,
      .dst_addr = destination,
      .protocol = protocol,
      .data = payload,
      .data_length = payload_length,
  };
  memcpy(packet.src_mac_addr, entry->mac, sizeof(packet.src_mac_addr));
  memcpy(packet.dst_mac_addr, neighbor->mac, sizeof(packet.dst_mac_addr));
  FILE* frame_file = tmpfile();
  if (!frame_file || !ipv4_write_ethernet_packet(frame_file, &packet)) {
    if (frame_file) fclose(frame_file);
    return false;
  }
  const bool appended = append_generated_frame_file(context, route->interface_index, frame_file);
  fclose(frame_file);
  return appended;
}

static bool emit_generated_ipv4(router_context_t* context, const ipv4_packet_view_t* packet) {
  if (!context || !packet) return false;
  const route_entry_t* route = route_table_lookup(&context->routes, packet->header.dst_addr);
  if (!route) {
    fputs("Dropped generated IPv4 packet without a route.\n", stderr);
    return true;
  }
  const interface_entry_t* egress = interface_table_get(&context->interfaces, route->interface_index);
  if (!egress || !egress->enabled) {
    fputs("Dropped generated IPv4 packet with an unavailable egress interface.\n", stderr);
    return true;
  }
  const ipv4_address_t next_hop = route->next_hop ? route->next_hop : packet->header.dst_addr;
  const arp_entry_t* neighbor = arp_table_find_const(&context->arp, route->interface_index, next_hop);
  if (neighbor) return forward_ipv4(context, route->interface_index, &packet->header, packet->payload, packet->payload_length, neighbor->mac);
  if (!queue_packet(context, route->interface_index, next_hop, packet, packet, false, route->interface_index, (uint32_t)time(NULL))) {
    fputs("Dropped generated IPv4 packet because the pending-neighbor queue is full.\n", stderr);
    return true;
  }
  if (!write_arp_request(context, route->interface_index, next_hop)) return false;
  fputs("Resolving next hop ", stdout);
  ipv4_address_print(stdout, next_hop);
  fprintf(stdout, " for generated traffic on interface %zu.\n", route->interface_index + 1);
  return true;
}

static bool emit_icmp_error(router_context_t* context, const ethernet_frame_view_t* frame, size_t ingress_interface, const ipv4_packet_view_t* offending, uint8_t type, uint8_t code) {
  const interface_entry_t* ingress_entry = interface_table_get(&context->interfaces, ingress_interface);
  if (!ingress_entry || !packet_allows_icmp_error(frame, ingress_entry, offending)) {
    return true;
  }
  uint8_t payload[sizeof(icmp_error_header_t) + sizeof(ipv4_header_t) + ICMP_ERROR_QUOTE_DATA_LEN] = {0};
  uint16_t payload_length = 0;
  if (!icmp_write_error_payload(payload, sizeof(payload), &offending->header, offending->payload, offending->payload_length, type, code, &payload_length)) {
    return false;
  }
  return emit_routed_ipv4(context, offending->header.src_addr, ICMP_IPV4_PROTOCOL, payload, payload_length);
}


static bool write_arp_request(router_context_t* context, size_t interface_index, ipv4_address_t target) {
  const interface_entry_t* entry = interface_table_get(&context->interfaces, interface_index);
  if (!entry) {
    return false;
  }
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
  const bool appended = append_generated_frame_file(context, interface_index, destination);
  fclose(destination);
  return appended;
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
  FILE* destination = tmpfile();
  if (!destination || !arp_write_ethernet_reply(destination, &reply)) {
    if (destination) fclose(destination);
    return false;
  }
  const bool appended = append_generated_frame_file(context, interface_index, destination);
  fclose(destination);
  return appended;
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
  FILE* destination = tmpfile();
  if (!destination || !rarp_write_ethernet_reply(destination, &reply)) {
    if (destination) fclose(destination);
    return false;
  }
  const bool appended = append_generated_frame_file(context, interface_index, destination);
  fclose(destination);
  return appended;
}

static void clear_dhcp_relay_entries(router_context_t* context, size_t ingress_interface) {
  for (size_t i = 0; i < ROUTER_DHCP_RELAY_CAPACITY; ++i) {
    if (context->dhcp_relays[i].active && context->dhcp_relays[i].ingress_interface == ingress_interface) context->dhcp_relays[i].active = false;
  }
}

static router_dhcp_relay_entry_t* find_dhcp_relay_entry(router_context_t* context, uint16_t transaction_id, const mac_address_t client_mac, ipv4_address_t server_address) {
  for (size_t i = 0; i < ROUTER_DHCP_RELAY_CAPACITY; ++i) {
    router_dhcp_relay_entry_t* entry = &context->dhcp_relays[i];
    if (entry->active && entry->transaction_id == transaction_id && entry->server_address == server_address && memcmp(entry->client_mac, client_mac, sizeof(entry->client_mac)) == 0) return entry;
  }
  return NULL;
}

static router_dhcp_relay_entry_t* remember_dhcp_relay(router_context_t* context, size_t ingress_interface, const dhcp_message_t* message, ipv4_address_t server_address, uint32_t now) {
  router_dhcp_relay_entry_t* entry = find_dhcp_relay_entry(context, message->transaction_id, message->client_mac, server_address);
  if (!entry) {
    for (size_t i = 0; i < ROUTER_DHCP_RELAY_CAPACITY; ++i) {
      if (!context->dhcp_relays[i].active) {
        entry = &context->dhcp_relays[i];
        break;
      }
    }
  }
  if (!entry) {
    entry = &context->dhcp_relays[0];
    for (size_t i = 1; i < ROUTER_DHCP_RELAY_CAPACITY; ++i) {
      if (context->dhcp_relays[i].updated_at < entry->updated_at) entry = &context->dhcp_relays[i];
    }
  }
  *entry = (router_dhcp_relay_entry_t) {
      .transaction_id = message->transaction_id,
      .server_address = server_address,
      .ingress_interface = ingress_interface,
      .updated_at = now,
      .active = true,
  };
  memcpy(entry->client_mac, message->client_mac, sizeof(entry->client_mac));
  return entry;
}

static bool handle_dhcp_relay(router_context_t* context, size_t ingress_interface, const ethernet_frame_view_t* frame, const ipv4_packet_view_t* packet, bool* handled) {
  *handled = false;
  const interface_entry_t* ingress = interface_table_get(&context->interfaces, ingress_interface);
  if (!ingress || packet->header.protocol != UDP_IPV4_PROTOCOL) return true;
  udp_packet_view_t udp = {0};
  dhcp_message_t message = {0};
  if (!udp_parse_packet(packet->payload, packet->payload_length, packet->header.src_addr, packet->header.dst_addr, &udp) || !dhcp_parse_message(udp.data, udp.data_length, &message)) return true;

  const bool client_broadcast = ethernet_mac_is_broadcast(frame->header.dst_mac) && udp.header.src_port == DHCP_CLIENT_UDP_PORT && udp.header.dst_port == DHCP_SERVER_UDP_PORT && ipv4_address_is_limited_broadcast(packet->header.dst_addr) && packet->header.src_addr == 0;
  if (client_broadcast) {
    const ipv4_address_t server_address = context->dhcp_relay_servers[ingress_interface];
    if (!server_address) return true;
    uint8_t udp_bytes[sizeof(udp_header_t) + ETHERNET_MAX_DATA_LEN] = {0};
    uint16_t udp_length = 0;
    udp_packet_data_t relay_udp = {
        .src_addr = ingress->ip4,
        .dst_addr = server_address,
        .src_port = DHCP_SERVER_UDP_PORT,
        .dst_port = DHCP_SERVER_UDP_PORT,
        .data = &message,
        .data_length = sizeof(message),
    };
    if (!udp_serialize_packet(&relay_udp, udp_bytes, sizeof(udp_bytes), &udp_length)) return false;
    ipv4_header_t header = {
        .version = 4,
        .ihl = 5,
        .total_length = (uint16_t)(sizeof(ipv4_header_t) + udp_length),
        .fragment_id = 1,
        .dont_fragment = 1,
        .ttl = IPV4_DEFAULT_TTL,
        .protocol = UDP_IPV4_PROTOCOL,
        .src_addr = ingress->ip4,
        .dst_addr = server_address,
    };
    header.header_checksum = checksum16(&header, sizeof(header));
    ipv4_packet_view_t relay_packet = {.header = header, .payload = udp_bytes, .payload_length = udp_length};
    remember_dhcp_relay(context, ingress_interface, &message, server_address, (uint32_t)time(NULL));
    *handled = true;
    if (!emit_generated_ipv4(context, &relay_packet)) return false;
    fprintf(stdout, "Relayed DHCP %s from interface %zu to ", message.type == DHCP_MESSAGE_DISCOVER ? "DISCOVER" : "REQUEST", ingress_interface + 1);
    ipv4_address_print(stdout, server_address);
    fputs(".\n", stdout);
    return true;
  }

  if (udp.header.src_port != DHCP_SERVER_UDP_PORT || udp.header.dst_port != DHCP_CLIENT_UDP_PORT || !ipv4_address_is_limited_broadcast(packet->header.dst_addr)) return true;
  router_dhcp_relay_entry_t* relay = find_dhcp_relay_entry(context, message.transaction_id, message.client_mac, message.server_address);
  if (!relay) return true;
  udp_packet_data_t response = {
      .src_addr = message.server_address,
      .dst_addr = IPV4_ADDRESS(255, 255, 255, 255),
      .src_port = DHCP_SERVER_UDP_PORT,
      .dst_port = DHCP_CLIENT_UDP_PORT,
      .data = &message,
      .data_length = sizeof(message),
  };
  memcpy(response.src_mac_addr, context->interfaces.entries[relay->ingress_interface].mac, sizeof(response.src_mac_addr));
  memcpy(response.dst_mac_addr, ethernet_broadcast_mac, sizeof(response.dst_mac_addr));
  *handled = true;
  if (!write_udp_on_interface(context, relay->ingress_interface, &response)) return false;
  fprintf(stdout, "Relayed DHCP %s from ", message.type == DHCP_MESSAGE_OFFER ? "OFFER" : message.type == DHCP_MESSAGE_ACK ? "ACK" : "NAK", message.server_address);
  ipv4_address_print(stdout, message.server_address);
  fprintf(stdout, " back to interface %zu.\n", relay->ingress_interface + 1);
  if (message.type != DHCP_MESSAGE_OFFER) relay->active = false;
  return true;
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


static bool queue_packet(router_context_t* context, size_t egress_interface, ipv4_address_t next_hop, const ipv4_packet_view_t* packet, const ipv4_packet_view_t* report_packet, bool report_next_hop_failure, size_t report_interface, uint32_t now) {
  for (size_t i = 0; i < ROUTER_PENDING_CAPACITY; ++i) {
    router_pending_packet_t* pending = &context->pending_packets[i];
    if (!pending->active) {
      pending->header = packet->header;
      memcpy(pending->payload, packet->payload, packet->payload_length);
      pending->payload_length = packet->payload_length;
      pending->report_header = report_packet->header;
      memcpy(pending->report_payload, report_packet->payload, report_packet->payload_length);
      pending->report_payload_length = report_packet->payload_length;
      pending->next_hop = next_hop;
      pending->egress_interface = egress_interface;
      pending->report_interface = report_interface;
      pending->next_retry_at = now + ROUTER_ARP_RETRY_INTERVAL_SECONDS;
      pending->arp_attempts = 1;
      pending->report_next_hop_failure = report_next_hop_failure;
      pending->active = true;
      return true;
    }
  }
  return false;
}

static bool route_ipv4(router_context_t* context, size_t ingress_interface, const ethernet_frame_view_t* frame, const ipv4_packet_view_t* packet) {
  const ipv4_packet_view_t* received_packet = packet;
  ipv4_packet_view_t translated_packet = {0};
  ipv4_header_t translated_header = {0};
  uint8_t translated_payload[ETHERNET_MAX_DATA_LEN - sizeof(ipv4_header_t)] = {0};
  const bool transport = packet->header.protocol == UDP_IPV4_PROTOCOL || packet->header.protocol == TCP_IPV4_PROTOCOL;
  if (evaluate_acl(context, ingress_interface, ROUTER_ACL_DIRECTION_INGRESS, packet) != ROUTER_ACL_ACTION_PERMIT) {
    fputs("Dropped IPv4 packet by ingress ACL.\n", stderr);
    return true;
  }
  if (context->nat_enabled && ingress_interface == context->nat_outside_interface) {
    uint16_t source_port = 0;
    uint16_t destination_port = 0;
    if (transport) {
      if (packet->header.protocol == UDP_IPV4_PROTOCOL) {
        udp_packet_view_t udp = {0};
        if (!udp_parse_packet(packet->payload, packet->payload_length, packet->header.src_addr, packet->header.dst_addr, &udp)) return false;
        source_port = udp.header.src_port;
        destination_port = udp.header.dst_port;
      } else {
        tcp_packet_view_t tcp = {0};
        if (!tcp_parse_packet(packet->payload, packet->payload_length, packet->header.src_addr, packet->header.dst_addr, &tcp)) return false;
        source_port = tcp.header.src_port;
        destination_port = tcp.header.dst_port;
      }
    }
    nat_entry_t* nat = transport ? nat_table_find_inbound_pat(&context->nat, packet->header.protocol, packet->header.dst_addr, destination_port, packet->header.src_addr, source_port) : NULL;
    if (!nat) nat = nat_table_find_inbound_nat(&context->nat, packet->header.dst_addr, packet->header.src_addr);
    if (!nat) {
      fputs("Dropped unsolicited NAT packet.\n", stderr);
      return true;
    }
    uint16_t translated_length = packet->payload_length;
    if (nat->kind == NAT_TRANSLATION_PAT && !nat_rewrite_transport(packet, packet->header.src_addr, nat->inside_address, source_port, nat->inside_port, translated_payload, sizeof(translated_payload), &translated_length)) return false;
    translated_header = packet->header;
    translated_header.dst_addr = nat->inside_address;
    translated_packet = (ipv4_packet_view_t) {.header = translated_header, .payload = nat->kind == NAT_TRANSLATION_PAT ? translated_payload : packet->payload, .payload_length = translated_length};
    packet = &translated_packet;
    fputs("NAT destination: ", stdout);
    ipv4_address_print(stdout, nat->outside_address);
    if (nat->kind == NAT_TRANSLATION_PAT) fprintf(stdout, ":%u", destination_port);
    fputs(" -> ", stdout);
    ipv4_address_print(stdout, nat->inside_address);
    if (nat->kind == NAT_TRANSLATION_PAT) fprintf(stdout, ":%u", nat->inside_port);
    fputs(".\n", stdout);
  }
  if (packet->header.ttl <= 1) {
    if (!emit_icmp_error(context, frame, ingress_interface, received_packet, ICMP_TYPE_TIME_EXCEEDED, ICMP_CODE_TTL_EXPIRED)) return false;
    fputs("Dropped IPv4 packet with expired TTL.\n", stderr);
    return true;
  }
  const interface_entry_t* local = interface_table_find_ip4(&context->interfaces, packet->header.dst_addr);
  if (local) return true;
  const route_entry_t* route = route_table_lookup(&context->routes, packet->header.dst_addr);
  fputs("Router IPv4: src=", stdout);
  ipv4_address_print(stdout, packet->header.src_addr);
  fputs(" dst=", stdout);
  ipv4_address_print(stdout, packet->header.dst_addr);
  fprintf(stdout, " ttl=%u protocol=%u payload=%u bytes\n", packet->header.ttl, packet->header.protocol, packet->payload_length);
  if (!route) {
    if (!emit_icmp_error(context, frame, ingress_interface, received_packet, ICMP_TYPE_DESTINATION_UNREACHABLE, ICMP_CODE_NETWORK_UNREACHABLE)) return false;
    fputs("Dropped IPv4 packet without a route.\n", stderr);
    return true;
  }
  const interface_entry_t* egress = interface_table_get(&context->interfaces, route->interface_index);
  if (!egress || !egress->enabled) {
    if (!emit_icmp_error(context, frame, ingress_interface, received_packet, ICMP_TYPE_DESTINATION_UNREACHABLE, ICMP_CODE_HOST_UNREACHABLE)) return false;
    fputs("Dropped IPv4 packet with an unavailable egress interface.\n", stderr);
    return true;
  }
  if (context->nat_enabled && ingress_interface == context->nat_inside_interface && route->interface_index == context->nat_outside_interface) {
    nat_entry_t* nat = NULL;
    if (transport) {
      uint16_t source_port = 0;
      uint16_t destination_port = 0;
      if (packet->header.protocol == UDP_IPV4_PROTOCOL) {
        udp_packet_view_t udp = {0};
        if (!udp_parse_packet(packet->payload, packet->payload_length, packet->header.src_addr, packet->header.dst_addr, &udp)) return false;
        source_port = udp.header.src_port;
        destination_port = udp.header.dst_port;
      } else {
        tcp_packet_view_t tcp = {0};
        if (!tcp_parse_packet(packet->payload, packet->payload_length, packet->header.src_addr, packet->header.dst_addr, &tcp)) return false;
        source_port = tcp.header.src_port;
        destination_port = tcp.header.dst_port;
      }
      nat = nat_table_find_outbound_pat(&context->nat, packet->header.protocol, packet->header.src_addr, source_port, egress->ip4);
      if (!nat && context->dynamic_pat_enabled) nat = nat_table_open_dynamic_pat(&context->nat, packet->header.protocol, packet->header.src_addr, source_port, packet->header.dst_addr, destination_port, egress->ip4);
      if (nat) {
        if (!nat_rewrite_transport(packet, egress->ip4, packet->header.dst_addr, nat->outside_port, destination_port, translated_payload, sizeof(translated_payload), &translated_packet.payload_length)) return false;
        translated_header = packet->header;
        translated_header.src_addr = egress->ip4;
        translated_packet.header = translated_header;
        translated_packet.payload = translated_payload;
        packet = &translated_packet;
      }
    } else if (context->dynamic_nat_enabled || nat_table_find_outbound_nat(&context->nat, packet->header.src_addr, packet->header.dst_addr)) {
      nat = nat_table_find_outbound_nat(&context->nat, packet->header.src_addr, packet->header.dst_addr);
      if (!nat && context->dynamic_nat_enabled) nat = nat_table_open_dynamic_nat(&context->nat, packet->header.src_addr);
      if (!nat) {
        fputs("Dropped IPv4 packet because no dynamic NAT address is available.\n", stderr);
        return true;
      }
      translated_header = packet->header;
      translated_header.src_addr = nat->outside_address;
      translated_packet = (ipv4_packet_view_t) {.header = translated_header, .payload = packet->payload, .payload_length = packet->payload_length};
      packet = &translated_packet;
    }
  }
  if (evaluate_acl(context, route->interface_index, ROUTER_ACL_DIRECTION_EGRESS, packet) != ROUTER_ACL_ACTION_PERMIT) {
    fputs("Dropped IPv4 packet by egress ACL.\n", stderr);
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
  if (!queue_packet(context, route->interface_index, next_hop, packet, received_packet, packet_allows_icmp_error(frame, interface_table_get(&context->interfaces, ingress_interface), received_packet), ingress_interface, (uint32_t)time(NULL))) {
    fputs("Dropped IPv4 packet because the pending-neighbor queue is full.\n", stderr);
    return true;
  }
  if (!write_arp_request(context, route->interface_index, next_hop)) return false;
  fputs("Resolving next hop ", stdout);
  ipv4_address_print(stdout, next_hop);
  fprintf(stdout, " on interface %zu.\n", route->interface_index + 1);
  return true;
}

static bool service_pending(router_context_t* context, uint32_t now) {
  for (size_t i = 0; i < ROUTER_PENDING_CAPACITY; ++i) {
    router_pending_packet_t* pending = &context->pending_packets[i];
    if (!pending->active) continue;
    if (arp_table_find_const(&context->arp, pending->egress_interface, pending->next_hop)) continue;
    if (now < pending->next_retry_at) continue;
    if (pending->arp_attempts < ROUTER_ARP_RETRY_LIMIT) {
      if (!write_arp_request(context, pending->egress_interface, pending->next_hop)) return false;
      ++pending->arp_attempts;
      pending->next_retry_at = now + ROUTER_ARP_RETRY_INTERVAL_SECONDS;
      continue;
    }
    if (pending->report_next_hop_failure) {
      ethernet_frame_view_t synthetic_frame = {0};
      const interface_entry_t* entry = interface_table_get(&context->interfaces, pending->report_interface);
      if (entry) {
        memcpy(synthetic_frame.header.dst_mac, entry->mac, sizeof(entry->mac));
      }
      ipv4_packet_view_t report_packet = {
          .header = pending->report_header,
          .payload = pending->report_payload,
          .payload_length = pending->report_payload_length,
      };
      if (!emit_icmp_error(context, &synthetic_frame, pending->report_interface, &report_packet, ICMP_TYPE_DESTINATION_UNREACHABLE, ICMP_CODE_HOST_UNREACHABLE)) return false;
    }
    pending->active = false;
    fputs("Dropped IPv4 packet after ARP retries exhausted for next hop ", stderr);
    ipv4_address_print(stderr, pending->next_hop);
    fputs(".\n", stderr);
  }
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
    if (!write_arp_reply(context, ingress_interface, &packet)) return false;
    fprintf(stdout, "Replied to ARP request on interface %zu.\n", ingress_interface + 1);
  }
  return true;
}

static bool handle_rarp(router_context_t* context, size_t ingress_interface, const ethernet_frame_view_t* frame) {
  rarp_packet_t packet = {0};
  if (!rarp_parse_packet(frame->data, sizeof(packet), &packet) || packet.operation != RARP_OPERATION_REQUEST) return true;
  rarp_entry_t* assignment = rarp_table_find(&context->rarp, packet.sender_hardware_address);
  if (!assignment) return true;
  return write_rarp_reply(context, ingress_interface, &packet, assignment->ip4);
}



static bool handle_ethernet(router_context_t* context, size_t port_index, const uint8_t* bytes, size_t byte_count) {
  ethernet_frame_view_t frame = {0};
  if (!ethernet_parse_frame(bytes, byte_count, &frame) || frame.format != ETHERNET_FRAME_FORMAT_II) return true;
  const size_t ingress_interface = find_ingress_interface(context, port_index, &frame);
  if (ingress_interface == ROUTER_INTERFACE_NONE) return true;
  const interface_entry_t* entry = interface_table_get(&context->interfaces, ingress_interface);
  if (!entry) return false;
  fprintf(stdout, "Router frame: ingress=%zu bytes=%zu dst=", ingress_interface + 1, byte_count);
  ethernet_mac_print(stdout, frame.header.dst_mac);
  fputs(" src=", stdout);
  ethernet_mac_print(stdout, frame.header.src_mac);
  fprintf(stdout, " EtherType=0x%04X", frame.header.type_or_length);
  if (frame.tagged) fprintf(stdout, " VLAN=%u", frame.vlan_id);
  fputc('\n', stdout);
  const bool destination_is_interface = memcmp(frame.header.dst_mac, entry->mac, sizeof(entry->mac)) == 0;
  const bool destination_is_broadcast = ethernet_mac_is_broadcast(frame.header.dst_mac);
  if (frame.header.type_or_length == ETHERNET_ETHERTYPE_ARP && (destination_is_interface || destination_is_broadcast)) return handle_arp(context, ingress_interface, &frame);
  if (frame.header.type_or_length == ETHERNET_ETHERTYPE_RARP && (destination_is_interface || destination_is_broadcast)) return handle_rarp(context, ingress_interface, &frame);
  if (frame.header.type_or_length != ETHERNET_ETHERTYPE_IPV4 || (!destination_is_interface && !destination_is_broadcast)) return true;
  ipv4_packet_view_t packet = {0};
  if (!ipv4_parse_packet(frame.data, frame.client_data_length, &packet)) return true;
  bool handled = false;
  if (!handle_dhcp_relay(context, ingress_interface, &frame, &packet, &handled)) return false;
  if (handled) return true;
  if (destination_is_broadcast) return true;
  return route_ipv4(context, ingress_interface, &frame, &packet);
}

static bool process_port(router_context_t* context, size_t port_index) {
  router_port_t* port = &context->ports[port_index];
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
      if (!handle_ethernet(context, port_index, port->buffer + offset, end - offset)) return false;
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

static router_acl_rule_t* find_acl_rule(router_context_t* context, size_t interface_index, router_acl_direction_t direction, uint16_t sequence) {
  for (size_t i = 0; i < ROUTER_ACL_RULE_CAPACITY; ++i) {
    router_acl_rule_t* rule = &context->acl_rules[i];
    if (rule->active && rule->interface_index == interface_index && rule->direction == direction && rule->sequence == sequence) return rule;
  }
  return NULL;
}

static bool assign_interface_ports(router_context_t* context) {
  if (!context) return false;
  context->port_count = 0;
  for (size_t i = 0; i < context->interfaces.count; ++i) {
    interface_entry_t* entry = &context->interfaces.entries[i];
    if (!entry->tagged) {
      entry->port_index = context->port_count++;
    } else {
      if (!interface_table_index_valid(&context->interfaces, entry->parent_index)) return false;
      entry->port_index = context->interfaces.entries[entry->parent_index].port_index;
    }
  }
  return context->port_count > 0;
}

static void print_info(router_context_t* context) {
  mutex_lock(&context->mutex);
  fprintf(stdout, "Interfaces (%zu):\n", context->interfaces.count);
  for (size_t i = 0; i < context->interfaces.count; ++i) {
    const interface_entry_t* entry = &context->interfaces.entries[i];
    fprintf(stdout, "  %zu  %-32s ", i + 1, entry->path);
    ethernet_mac_print(stdout, entry->mac);
    fputs("  ", stdout);
    ipv4_address_print(stdout, entry->ip4);
    fputs("/", stdout);
    ipv4_address_print(stdout, entry->mask);
    fprintf(stdout, "  %s", entry->enabled ? "up" : "down");
    if (entry->tagged) fprintf(stdout, "  parent=%zu vlan=%u", entry->parent_index + 1, entry->vlan_id);
    else
      fprintf(stdout, "  untagged port=%zu", entry->port_index + 1);
    fputc('\n', stdout);
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
  fprintf(stdout, "ACLs:\n");
  for (size_t interface_index = 0; interface_index < context->interfaces.count; ++interface_index) {
    for (size_t direction = 0; direction < 2; ++direction) {
      fprintf(stdout, "  dev %zu %s default=%s packets=%llu bytes=%llu\n", interface_index + 1, acl_direction_name((router_acl_direction_t)direction), acl_action_name(context->acl_defaults[interface_index][direction]), (unsigned long long)context->acl_default_packets[interface_index][direction], (unsigned long long)context->acl_default_bytes[interface_index][direction]);
      for (size_t i = 0; i < ROUTER_ACL_RULE_CAPACITY; ++i) {
        const router_acl_rule_t* rule = &context->acl_rules[i];
        if (!rule->active || rule->interface_index != interface_index || rule->direction != direction) continue;
        fprintf(stdout, "    seq %u %s ", rule->sequence, acl_action_name(rule->action));
        ipv4_address_print(stdout, rule->src_network);
        fputs("/", stdout);
        ipv4_address_print(stdout, rule->src_mask);
        fputs(" -> ", stdout);
        ipv4_address_print(stdout, rule->dst_network);
        fputs("/", stdout);
        ipv4_address_print(stdout, rule->dst_mask);
        fprintf(stdout, " proto=%u", rule->protocol);
        if (rule->src_port_any) fputs(" sport=any", stdout);
        else
          fprintf(stdout, " sport=%u", rule->src_port);
        if (rule->dst_port_any) fputs(" dport=any", stdout);
        else
          fprintf(stdout, " dport=%u", rule->dst_port);
        fprintf(stdout, " packets=%llu bytes=%llu\n", (unsigned long long)rule->packets, (unsigned long long)rule->bytes);
      }
    }
  }
  if (context->nat_enabled) {
    fprintf(stdout, "NAT: inside dev %zu, outside dev %zu  dynamic-nat=%s dynamic-pat=%s\n", context->nat_inside_interface + 1, context->nat_outside_interface + 1, context->dynamic_nat_enabled ? "on" : "off", context->dynamic_pat_enabled ? "on" : "off");
    fputs("NAT pool:", stdout);
    for (size_t i = 0; i < context->nat.pool_count; ++i) {
      fputc(' ', stdout);
      ipv4_address_print(stdout, context->nat.pool[i]);
    }
    fputc('\n', stdout);
    for (size_t i = 0; i < ROUTER_NAT_CAPACITY; ++i) {
      const nat_entry_t* entry = &context->nat_entries[i];
      if (!entry->active) continue;
      fputs("  ", stdout);
      ipv4_address_print(stdout, entry->inside_address);
      if (entry->kind == NAT_TRANSLATION_PAT) fprintf(stdout, ":%u", entry->inside_port);
      fputs(" -> ", stdout);
      ipv4_address_print(stdout, entry->outside_address);
      if (entry->kind == NAT_TRANSLATION_PAT) fprintf(stdout, ":%u", entry->outside_port);
      fprintf(stdout, "  %s %s", entry->is_static ? "static" : "dynamic", entry->kind == NAT_TRANSLATION_PAT ? "pat" : "nat");
      if (!entry->is_static) {
        fputs(" remote=", stdout);
        ipv4_address_print(stdout, entry->remote_address);
        if (entry->kind == NAT_TRANSLATION_PAT) fprintf(stdout, ":%u", entry->remote_port);
      }
      if (entry->kind == NAT_TRANSLATION_PAT) fprintf(stdout, " %s", entry->protocol == TCP_IPV4_PROTOCOL ? "tcp" : "udp");
      fputc('\n', stdout);
    }
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

static void command_acl(void* argument, char* arguments) {
  router_context_t* context = argument;
  char* cursor = arguments;
  char* action = cmd_app_next_argument(&cursor);
  if (!action) {
    print_info(context);
    return;
  }
  char* interface_text = cmd_app_next_argument(&cursor);
  char* direction_text = cmd_app_next_argument(&cursor);
  uint16_t interface_number = 0;
  router_acl_direction_t direction = ROUTER_ACL_DIRECTION_INGRESS;
  if (!interface_text || !direction_text || !cmd_app_parse_uint16(interface_text, &interface_number) || interface_number == 0 || interface_number > context->interfaces.count || (strcmpi(direction_text, "in") != 0 && strcmpi(direction_text, "out") != 0)) {
    fputs("Usage: acl <default|add|delete> <interface> <in|out> ...\n", stderr);
    return;
  }
  direction = strcmpi(direction_text, "out") == 0 ? ROUTER_ACL_DIRECTION_EGRESS : ROUTER_ACL_DIRECTION_INGRESS;
  if (strcmpi(action, "default") == 0) {
    char* decision = cmd_app_next_argument(&cursor);
    if (!decision || cmd_app_next_argument(&cursor) || (strcmpi(decision, "permit") != 0 && strcmpi(decision, "deny") != 0)) {
      fputs("Usage: acl default <interface> <in|out> <permit|deny>\n", stderr);
      return;
    }
    mutex_lock(&context->mutex);
    context->acl_defaults[interface_number - 1][direction] = strcmpi(decision, "permit") == 0 ? ROUTER_ACL_ACTION_PERMIT : ROUTER_ACL_ACTION_DENY;
    mutex_unlock(&context->mutex);
    fputs("ACL default updated.\n", stdout);
    return;
  }
  if (strcmpi(action, "delete") == 0) {
    char* sequence_text = cmd_app_next_argument(&cursor);
    uint16_t sequence = 0;
    if (!sequence_text || cmd_app_next_argument(&cursor) || !cmd_app_parse_uint16(sequence_text, &sequence)) {
      fputs("Usage: acl delete <interface> <in|out> <sequence>\n", stderr);
      return;
    }
    mutex_lock(&context->mutex);
    router_acl_rule_t* rule = find_acl_rule(context, interface_number - 1, direction, sequence);
    if (rule) memset(rule, 0, sizeof(*rule));
    mutex_unlock(&context->mutex);
    fputs(rule ? "ACL rule removed.\n" : "No such ACL rule.\n", rule ? stdout : stderr);
    return;
  }
  char* sequence_text = cmd_app_next_argument(&cursor);
  char* decision = cmd_app_next_argument(&cursor);
  char* src_network_text = cmd_app_next_argument(&cursor);
  char* src_mask_text = cmd_app_next_argument(&cursor);
  char* dst_network_text = cmd_app_next_argument(&cursor);
  char* dst_mask_text = cmd_app_next_argument(&cursor);
  char* protocol_text = cmd_app_next_argument(&cursor);
  char* src_port_text = cmd_app_next_argument(&cursor);
  char* dst_port_text = cmd_app_next_argument(&cursor);
  uint16_t sequence = 0;
  ipv4_address_t src_network = 0;
  ipv4_address_t src_mask = 0;
  ipv4_address_t dst_network = 0;
  ipv4_address_t dst_mask = 0;
  uint8_t protocol = 0;
  bool src_port_any = true;
  bool dst_port_any = true;
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  if (strcmpi(action, "add") != 0 || !sequence_text || !decision || !src_network_text || !src_mask_text || !dst_network_text || !dst_mask_text || !protocol_text || !src_port_text || !dst_port_text || cmd_app_next_argument(&cursor) || !cmd_app_parse_uint16(sequence_text, &sequence) || (strcmpi(decision, "permit") != 0 && strcmpi(decision, "deny") != 0) || !ipv4_parse_address(src_network_text, &src_network) || !ipv4_parse_address(src_mask_text, &src_mask) || !ipv4_parse_address(dst_network_text, &dst_network) || !ipv4_parse_address(dst_mask_text, &dst_mask) || !parse_acl_protocol(protocol_text, &protocol) || !parse_acl_port(src_port_text, &src_port_any, &src_port) || !parse_acl_port(dst_port_text, &dst_port_any, &dst_port)) {
    fputs("Usage: acl add <interface> <in|out> <sequence> <permit|deny> <src-network> <src-mask> <dst-network> <dst-mask> <protocol|any> <src-port|any> <dst-port|any>\n", stderr);
    return;
  }
  mutex_lock(&context->mutex);
  router_acl_rule_t* rule = find_acl_rule(context, interface_number - 1, direction, sequence);
  if (!rule) {
    for (size_t i = 0; i < ROUTER_ACL_RULE_CAPACITY; ++i) {
      if (!context->acl_rules[i].active) {
        rule = &context->acl_rules[i];
        break;
      }
    }
  }
  if (rule) {
    *rule = (router_acl_rule_t) {
        .sequence = sequence,
        .src_port = src_port,
        .dst_port = dst_port,
        .src_network = src_network & src_mask,
        .src_mask = src_mask,
        .dst_network = dst_network & dst_mask,
        .dst_mask = dst_mask,
        .interface_index = interface_number - 1,
        .protocol = protocol,
        .src_port_any = src_port_any,
        .dst_port_any = dst_port_any,
        .active = true,
        .direction = direction,
        .action = strcmpi(decision, "permit") == 0 ? ROUTER_ACL_ACTION_PERMIT : ROUTER_ACL_ACTION_DENY,
    };
  }
  mutex_unlock(&context->mutex);
  fputs(rule ? "ACL rule added.\n" : "ACL table is full.\n", rule ? stdout : stderr);
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

static void command_dhcp_relay(void* argument, char* arguments) {
  router_context_t* context = argument;
  char* cursor = arguments;
  char* interface_text = cmd_app_next_argument(&cursor);
  char* server_text = cmd_app_next_argument(&cursor);
  uint16_t interface_number = 0;
  ipv4_address_t server_address = 0;
  if (!interface_text || !server_text || cmd_app_next_argument(&cursor) || !cmd_app_parse_uint16(interface_text, &interface_number) || interface_number == 0 || interface_number > context->interfaces.count || (strcmpi(server_text, "none") != 0 && !ipv4_parse_address(server_text, &server_address))) {
    fputs("Usage: dhcp-relay <interface> <server-ip|none>\n", stderr);
    return;
  }
  mutex_lock(&context->mutex);
  context->dhcp_relay_servers[interface_number - 1] = strcmpi(server_text, "none") == 0 ? 0 : server_address;
  clear_dhcp_relay_entries(context, interface_number - 1);
  mutex_unlock(&context->mutex);
  fputs("DHCP relay updated.\n", stdout);
}

static bool parse_options(router_context_t* context, int argc, char** argv) {
  for (int i = 1; i < argc;) {
    if (strcmpi(argv[i], "-i") == 0) {
      if (i + 4 >= argc || context->interfaces.count == ROUTER_INTERFACE_CAPACITY) return false;
      mac_address_t mac = {0};
      ipv4_address_t ip4 = 0;
      ipv4_address_t mask = 0;
      if (!ethernet_mac_parse(argv[i + 2], mac) || !ipv4_parse_address(argv[i + 3], &ip4) || !ipv4_parse_address(argv[i + 4], &mask) || !interface_table_add_base(&context->interfaces, argv[i + 1], mac, ip4, mask)) return false;
      i += 5;
    } else if (strcmpi(argv[i], "-subif") == 0) {
      uint16_t parent = 0;
      uint16_t vlan_id = 0;
      ipv4_address_t ip4 = 0;
      ipv4_address_t mask = 0;
      if (i + 4 >= argc || !cmd_app_parse_uint16(argv[i + 1], &parent) || !cmd_app_parse_uint16(argv[i + 2], &vlan_id) || parent == 0 || parent > context->interfaces.count || !ipv4_parse_address(argv[i + 3], &ip4) || !ipv4_parse_address(argv[i + 4], &mask) || !interface_table_add_subinterface(&context->interfaces, parent - 1, vlan_id, ip4, mask)) return false;
      i += 5;
    } else if (strcmpi(argv[i], "-acl-default") == 0) {
      uint16_t interface_number = 0;
      router_acl_direction_t direction = ROUTER_ACL_DIRECTION_INGRESS;
      if (i + 3 >= argc || !cmd_app_parse_uint16(argv[i + 1], &interface_number) || interface_number == 0 || interface_number > context->interfaces.count || (strcmpi(argv[i + 2], "in") != 0 && strcmpi(argv[i + 2], "out") != 0) || (strcmpi(argv[i + 3], "permit") != 0 && strcmpi(argv[i + 3], "deny") != 0)) return false;
      direction = strcmpi(argv[i + 2], "out") == 0 ? ROUTER_ACL_DIRECTION_EGRESS : ROUTER_ACL_DIRECTION_INGRESS;
      context->acl_defaults[interface_number - 1][direction] = strcmpi(argv[i + 3], "permit") == 0 ? ROUTER_ACL_ACTION_PERMIT : ROUTER_ACL_ACTION_DENY;
      i += 4;
    } else if (strcmpi(argv[i], "-acl") == 0) {
      uint16_t interface_number = 0;
      uint16_t sequence = 0;
      ipv4_address_t src_network = 0;
      ipv4_address_t src_mask = 0;
      ipv4_address_t dst_network = 0;
      ipv4_address_t dst_mask = 0;
      uint8_t protocol = 0;
      bool src_port_any = true;
      bool dst_port_any = true;
      uint16_t src_port = 0;
      uint16_t dst_port = 0;
      if (i + 10 >= argc || !cmd_app_parse_uint16(argv[i + 1], &interface_number) || interface_number == 0 || interface_number > context->interfaces.count || (strcmpi(argv[i + 2], "in") != 0 && strcmpi(argv[i + 2], "out") != 0) || !cmd_app_parse_uint16(argv[i + 3], &sequence) || (strcmpi(argv[i + 4], "permit") != 0 && strcmpi(argv[i + 4], "deny") != 0) || !ipv4_parse_address(argv[i + 5], &src_network) || !ipv4_parse_address(argv[i + 6], &src_mask) || !ipv4_parse_address(argv[i + 7], &dst_network) || !ipv4_parse_address(argv[i + 8], &dst_mask) || !parse_acl_protocol(argv[i + 9], &protocol) || !parse_acl_port(argv[i + 10], &src_port_any, &src_port) || !parse_acl_port(argv[i + 11], &dst_port_any, &dst_port)) return false;
      router_acl_rule_t* slot = NULL;
      for (size_t j = 0; j < ROUTER_ACL_RULE_CAPACITY; ++j) {
        if (!context->acl_rules[j].active) {
          slot = &context->acl_rules[j];
          break;
        }
      }
      if (!slot) return false;
      *slot = (router_acl_rule_t) {
          .sequence = sequence,
          .src_port = src_port,
          .dst_port = dst_port,
          .src_network = src_network & src_mask,
          .src_mask = src_mask,
          .dst_network = dst_network & dst_mask,
          .dst_mask = dst_mask,
          .interface_index = interface_number - 1,
          .protocol = protocol,
          .src_port_any = src_port_any,
          .dst_port_any = dst_port_any,
          .active = true,
          .direction = strcmpi(argv[i + 2], "out") == 0 ? ROUTER_ACL_DIRECTION_EGRESS : ROUTER_ACL_DIRECTION_INGRESS,
          .action = strcmpi(argv[i + 4], "permit") == 0 ? ROUTER_ACL_ACTION_PERMIT : ROUTER_ACL_ACTION_DENY,
      };
      i += 12;
    } else if (strcmpi(argv[i], "-r") == 0) {
      if (i + 5 >= argc) return false;
      ipv4_address_t network = 0;
      ipv4_address_t mask = 0;
      ipv4_address_t next_hop = 0;
      uint16_t interface_number = 0;
      uint32_t metric = 0;
      if (!ipv4_parse_address(argv[i + 1], &network) || !ipv4_parse_address(argv[i + 2], &mask) || (strcmpi(argv[i + 3], "direct") != 0 && !ipv4_parse_address(argv[i + 3], &next_hop)) || !cmd_app_parse_uint16(argv[i + 4], &interface_number) || interface_number == 0 || interface_number > context->interfaces.count || !cmd_app_parse_uint32(argv[i + 5], &metric) || !route_table_add(&context->routes, network, mask, next_hop, interface_number - 1, metric)) return false;
      i += 6;
    } else if (strcmpi(argv[i], "-dhcp-relay") == 0) {
      uint16_t interface_number = 0;
      ipv4_address_t server_address = 0;
      if (i + 2 >= argc || !cmd_app_parse_uint16(argv[i + 1], &interface_number) || interface_number == 0 || interface_number > context->interfaces.count || !ipv4_parse_address(argv[i + 2], &server_address)) return false;
      context->dhcp_relay_servers[interface_number - 1] = server_address;
      i += 3;
    } else if (strcmpi(argv[i], "-nat") == 0) {
      uint16_t inside = 0;
      uint16_t outside = 0;
      if (i + 2 >= argc || context->nat_enabled || !cmd_app_parse_uint16(argv[i + 1], &inside) || !cmd_app_parse_uint16(argv[i + 2], &outside) || inside == 0 || outside == 0 || inside > context->interfaces.count || outside > context->interfaces.count || inside == outside) return false;
      context->nat_inside_interface = inside - 1;
      context->nat_outside_interface = outside - 1;
      context->nat_enabled = true;
      i += 3;
    } else if (strcmpi(argv[i], "-dynamic-nat") == 0) {
      ipv4_address_t outside_address = 0;
      if (i + 1 >= argc || !context->nat_enabled || !ipv4_parse_address(argv[i + 1], &outside_address) || !nat_table_add_pool(&context->nat, outside_address)) return false;
      context->dynamic_nat_enabled = true;
      i += 2;
    } else if (strcmpi(argv[i], "-dynamic-pat") == 0) {
      if (!context->nat_enabled || context->dynamic_pat_enabled) return false;
      context->dynamic_pat_enabled = true;
      i += 1;
    } else if (strcmpi(argv[i], "-static-nat") == 0) {
      ipv4_address_t inside_address = 0;
      ipv4_address_t outside_address = 0;
      if (i + 2 >= argc || !context->nat_enabled || !ipv4_parse_address(argv[i + 1], &inside_address) || !ipv4_parse_address(argv[i + 2], &outside_address) || !nat_table_add_static_nat(&context->nat, inside_address, outside_address)) return false;
      i += 3;
    } else if (strcmpi(argv[i], "-static-pat") == 0) {
      ipv4_address_t inside_address = 0;
      ipv4_address_t outside_address = 0;
      uint16_t inside_port = 0;
      uint16_t outside_port = 0;
      const uint8_t protocol = i + 1 < argc && strcmpi(argv[i + 1], "udp") == 0 ? UDP_IPV4_PROTOCOL : i + 1 < argc && strcmpi(argv[i + 1], "tcp") == 0 ? TCP_IPV4_PROTOCOL : 0;
      if (i + 5 >= argc || !context->nat_enabled || !protocol || !ipv4_parse_address(argv[i + 2], &inside_address) || !cmd_app_parse_uint16(argv[i + 3], &inside_port) || !ipv4_parse_address(argv[i + 4], &outside_address) || !cmd_app_parse_uint16(argv[i + 5], &outside_port) || !nat_table_add_static_pat(&context->nat, protocol, inside_address, inside_port, outside_address, outside_port)) return false;
      i += 6;
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
  if (!assign_interface_ports(context)) return false;
  for (size_t i = 0; i < context->interfaces.count; ++i) {
    const interface_entry_t* entry = &context->interfaces.entries[i];
    if (!route_table_add_connected(&context->routes, entry->ip4 & entry->mask, entry->mask, i)) return false;
  }
  return true;
}

int main(int argc, char** argv) {
  static router_context_t context = {0};
  interface_table_init(&context.interfaces, context.interface_entries, ROUTER_INTERFACE_CAPACITY);
  route_table_init(&context.routes, context.route_entries, ROUTER_ROUTE_CAPACITY);
  arp_table_init(&context.arp, context.arp_entries, ROUTER_ARP_CAPACITY);
  rarp_table_init(&context.rarp, context.rarp_entries, ROUTER_RARP_CAPACITY);
  nat_table_init(&context.nat, context.nat_entries, ROUTER_NAT_CAPACITY, context.nat_pool, ROUTER_NAT_POOL_CAPACITY, NAT_EPHEMERAL_PORT_MIN);
  for (size_t i = 0; i < ROUTER_INTERFACE_CAPACITY; ++i) {
    context.acl_defaults[i][ROUTER_ACL_DIRECTION_INGRESS] = ROUTER_ACL_ACTION_PERMIT;
    context.acl_defaults[i][ROUTER_ACL_DIRECTION_EGRESS] = ROUTER_ACL_ACTION_PERMIT;
  }
  if (!parse_options(&context, argc, argv)) {
    fputs("Usage: router -i <file> <mac-address> <ip-address> <mask> [... ] [-subif <parent-interface> <vlan-id> <ip-address> <mask> ...] [-acl-default <interface> <in|out> <permit|deny> ...] [-acl <interface> <in|out> <sequence> <permit|deny> <src-network> <src-mask> <dst-network> <dst-mask> <protocol|any> <src-port|any> <dst-port|any> ...] [-r <network> <mask> <next-hop|direct> <interface> <metric> [...]] [-rarp <client-mac> <ip-address> [...]] [-dhcp-relay <interface> <server-ip> ...] [-nat <inside-interface> <outside-interface>] [-dynamic-nat <outside-address> ...] [-dynamic-pat] [-static-nat <inside-address> <outside-address> ...] [-static-pat <tcp|udp> <inside-address> <inside-port> <outside-address> <outside-port> ...]\n", stderr);
    return EXIT_FAILURE;
  }
  if (!mutex_init(&context.mutex)) {
    fputs("Could not initialize router mutex.\n", stderr);
    return EXIT_FAILURE;
  }
  int status = EXIT_SUCCESS;
  bool commands_started = false;
  for (size_t i = 0; i < context.port_count; ++i) {
    router_port_t* port = &context.ports[i];
    const interface_entry_t* base = NULL;
    for (size_t j = 0; j < context.interfaces.count; ++j) {
      if (!context.interfaces.entries[j].tagged && context.interfaces.entries[j].port_index == i) {
        base = &context.interfaces.entries[j];
        break;
      }
    }
    if (!base) {
      status = EXIT_FAILURE;
      goto cleanup;
    }
    port->source = fopen(base->path, "rb");
    port->destination = fopen(base->path, "ab");
    if (!port->source || !port->destination || fseek(port->source, 0, SEEK_END) != 0) {
      fprintf(stderr, "Could not open router port %zu.\n", i + 1);
      status = EXIT_FAILURE;
      goto cleanup;
    }
  }
  cmd_app_init(&context.commands);
  if (!cmd_app_register(&context.commands, "info", "Show router state, interfaces, static routes, policies, and tables.", command_info, &context) || !cmd_app_register(&context.commands, "arp", "Resolve an IPv4 neighbor on one interface.", command_arp, &context) || !cmd_app_register(&context.commands, "arp-delete", "Remove one learned ARP neighbor.", command_arp_delete, &context) || !cmd_app_register(&context.commands, "interface", "Administratively bring an interface up or down.", command_interface, &context) || !cmd_app_register(&context.commands, "acl", "Show or update per-interface ACL rules and defaults.", command_acl, &context) || !cmd_app_register(&context.commands, "dhcp-relay", "Assign or clear a DHCP relay server per ingress interface.", command_dhcp_relay, &context) || !cmd_app_register(&context.commands, "route", "Add or delete a static route in the forwarding table.", command_route, &context) || !cmd_app_register(&context.commands, "rarp-table", "Set or delete a static RARP assignment.", command_rarp_table, &context) || !cmd_app_start(&context.commands)) {
    fputs("Could not start the command application.\n", stderr);
    status = EXIT_FAILURE;
    goto cleanup;
  }
  commands_started = true;

  while (cmd_app_is_running(&context.commands)) {
    long ends[ROUTER_INTERFACE_CAPACITY] = {0};
    for (size_t i = 0; i < context.port_count; ++i) {
      context.ports[i].injected_bytes = 0;
      if (!get_file_end(context.ports[i].source, &ends[i])) {
        fputs("Could not snapshot router interface traffic.\n", stderr);
        status = EXIT_FAILURE;
        goto cleanup;
      }
    }
    mutex_lock(&context.mutex);
    if (!service_pending(&context, (uint32_t)time(NULL))) {
      mutex_unlock(&context.mutex);
      fputs("Could not advance pending next-hop resolution.\n", stderr);
      status = EXIT_FAILURE;
      goto cleanup;
    }
    for (size_t i = 0; i < context.port_count; ++i) {
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
    for (size_t i = 0; i < context.port_count; ++i) {
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
  if (commands_started) {
    cmd_app_stop(&context.commands);
    cmd_app_join(&context.commands);
  }
  for (size_t i = 0; i < context.port_count; ++i) {
    if (context.ports[i].source) fclose(context.ports[i].source);
    if (context.ports[i].destination) fclose(context.ports[i].destination);
  }
  mutex_destroy(&context.mutex);
  return status;
}

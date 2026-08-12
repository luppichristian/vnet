#include "router.h"

static const mac_address_t rip_multicast_mac = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x09};
static const mac_address_t ospf_multicast_mac = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x05};

static const char* dynamic_routing_name(router_dynamic_routing_mode_t mode) {
  switch (mode) {
    case ROUTER_DYNAMIC_ROUTING_OFF:  return "off";
    case ROUTER_DYNAMIC_ROUTING_RIP:  return "rip";
    case ROUTER_DYNAMIC_ROUTING_OSPF: return "ospf";
  }
  return "off";
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
      if (context->rip_outbound_prefix_lists[interface_index][0] && !prefix_list_permits(&context->prefix_lists, context->rip_outbound_prefix_lists[interface_index], route->destination, route->mask)) continue;
      entries[entry_count++] = (rip_route_entry_t) {
          .address_family = RIP_ADDRESS_FAMILY_IPV4,
          .destination = route->destination,
          .subnet_mask = route->mask,
          .next_hop = 0,
          .metric = route->metric == 0 ? RIP_METRIC_MIN : route->metric > RIP_METRIC_INFINITY ? RIP_METRIC_INFINITY
                                                                                              : route->metric,
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

static bool write_ospf_updates(router_context_t* context) {
  ospf_router_link_t links[ROUTER_INTERFACE_CAPACITY] = {0};
  for (size_t i = 0; i < context->interfaces.count; ++i) {
    const interface_entry_t* entry = &context->interfaces.entries[i];
    links[i] = (ospf_router_link_t) {
        .network = entry->ip4 & entry->mask,
        .mask = entry->mask,
        .metric = 10,
    };
  }
  uint8_t ospf_bytes[sizeof(ospf_header_t) + ROUTER_INTERFACE_CAPACITY * sizeof(ospf_router_link_t)] = {0};
  size_t ospf_length = 0;
  if (!ospf_write_router_update(context->interfaces.entries[0].ip4, links, context->interfaces.count, ospf_bytes, sizeof(ospf_bytes), &ospf_length)) return false;
  for (size_t i = 0; i < context->interfaces.count; ++i) {
    const interface_entry_t* entry = &context->interfaces.entries[i];
    if (!entry->enabled) continue;
    ipv4_packet_data_t packet = {
        .src_addr = entry->ip4,
        .dst_addr = OSPF_ALL_SPF_ROUTERS,
        .protocol = OSPF_IPV4_PROTOCOL,
        .data = ospf_bytes,
        .data_length = (uint16_t)ospf_length,
    };
    memcpy(packet.src_mac_addr, entry->mac, sizeof(packet.src_mac_addr));
    memcpy(packet.dst_mac_addr, ospf_multicast_mac, sizeof(packet.dst_mac_addr));
    router_port_t* port = &context->ports[i];
    const long before = ftell(port->destination);
    if (before < 0 || !ipv4_write_ethernet_packet(port->destination, &packet)) return false;
    const long after = ftell(port->destination);
    if (after < before || fflush(port->destination) != 0) return false;
    port->injected_bytes += (size_t)(after - before);
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

static bool router_socket_emit(void* argument, ipv4_address_t destination, uint8_t protocol, const uint8_t* payload, uint16_t payload_length) {
  router_socket_emit_argument_t* emit = argument;
  if (!emit || !emit->context || !payload || !payload_length) return false;
  router_context_t* context = emit->context;
  const route_entry_t* route = route_table_lookup(&context->routes, destination);
  if (!route || route->interface_index != emit->interface_index) return false;
  const interface_entry_t* entry = interface_table_get(&context->interfaces, route->interface_index);
  if (!entry || !entry->enabled) return false;
  const ipv4_address_t next_hop = route->next_hop ? route->next_hop : destination;
  const arp_entry_t* neighbor = arp_table_find(&context->arp, route->interface_index, next_hop);
  if (!neighbor) {
    write_arp_request(context, route->interface_index, next_hop);
    return false;
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
  router_port_t* port = &context->ports[route->interface_index];
  const long before = ftell(port->destination);
  if (before < 0 || !ipv4_write_ethernet_packet(port->destination, &packet)) return false;
  const long after = ftell(port->destination);
  if (after < before || fflush(port->destination) != 0) return false;
  port->injected_bytes += (size_t)(after - before);
  return true;
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
  ipv4_packet_view_t translated_packet = {0};
  ipv4_header_t translated_header = {0};
  uint8_t translated_payload[ETHERNET_MAX_DATA_LEN - sizeof(ipv4_header_t)] = {0};
  const bool transport = packet->header.protocol == UDP_IPV4_PROTOCOL || packet->header.protocol == TCP_IPV4_PROTOCOL;
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
    fputs("Dropped IPv4 packet with expired TTL.\n", stderr);
    return true;
  }
  const interface_entry_t* local = interface_table_find_ip4(&context->interfaces, packet->header.dst_addr);
  if (local) return packet->header.protocol != SOCKET_PROTOCOL_TCP || socket_receive_ipv4(&context->sockets[ingress_interface], packet);
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
  if (context->dynamic_routing != ROUTER_DYNAMIC_ROUTING_RIP || !ingress || ipv4_packet->header.src_addr == ingress->ip4 || ipv4_packet->header.protocol != UDP_IPV4_PROTOCOL || !rip_is_multicast_address(ipv4_packet->header.dst_addr)) return true;
  udp_packet_view_t udp_packet = {0};
  rip_packet_view_t rip_packet = {0};
  if (!udp_parse_packet(ipv4_packet->payload, ipv4_packet->payload_length, ipv4_packet->header.src_addr, ipv4_packet->header.dst_addr, &udp_packet) || udp_packet.header.src_port != RIP_UDP_PORT || udp_packet.header.dst_port != RIP_UDP_PORT || !rip_parse_packet(udp_packet.data, udp_packet.data_length, &rip_packet)) return true;
  if (rip_packet.header.command == RIP_COMMAND_REQUEST) {
    return write_rip_response(context, ingress_interface);
  }
  const uint32_t expires_at = (uint32_t)time(NULL) + RIP_ROUTE_TIMEOUT_SECONDS;
  for (size_t i = 0; i < rip_packet.entry_count; ++i) {
    const rip_route_entry_t* advertised = &rip_packet.entries[i];
    if (context->rip_inbound_prefix_lists[ingress_interface][0] && !prefix_list_permits(&context->prefix_lists, context->rip_inbound_prefix_lists[ingress_interface], advertised->destination, advertised->subnet_mask)) continue;
    const uint32_t metric = advertised->metric == RIP_METRIC_INFINITY ? RIP_METRIC_INFINITY : advertised->metric + 1;
    const ipv4_address_t next_hop = advertised->next_hop ? advertised->next_hop : ipv4_packet->header.src_addr;
    if (!route_table_learn_rip(&context->routes, advertised->destination, advertised->subnet_mask, next_hop, ingress_interface, metric, expires_at)) return false;
  }
  fprintf(stdout, "Learned %zu RIP route%s on interface %zu.\n", rip_packet.entry_count, rip_packet.entry_count == 1 ? "" : "s", ingress_interface + 1);
  return true;
}

static bool handle_ospf(router_context_t* context, size_t ingress_interface, const ipv4_packet_view_t* ipv4_packet) {
  const interface_entry_t* ingress = interface_table_get(&context->interfaces, ingress_interface);
  if (context->dynamic_routing != ROUTER_DYNAMIC_ROUTING_OSPF || !ingress || ipv4_packet->header.src_addr == ingress->ip4 || ipv4_packet->header.protocol != OSPF_IPV4_PROTOCOL || !ospf_is_all_spf_routers(ipv4_packet->header.dst_addr)) return true;
  ospf_packet_view_t packet = {0};
  if (!ospf_parse_router_update(ipv4_packet->payload, ipv4_packet->payload_length, &packet)) return true;
  const uint32_t expires_at = (uint32_t)time(NULL) + OSPF_ROUTE_TIMEOUT_SECONDS;
  for (size_t i = 0; i < packet.link_count; ++i) {
    const ospf_router_link_t* link = &packet.links[i];
    if (!route_table_learn_ospf(&context->routes, link->network, link->mask, ipv4_packet->header.src_addr, ingress_interface, link->metric, expires_at)) return false;
  }
  fprintf(stdout, "Learned %zu OSPF route%s from router ", packet.link_count, packet.link_count == 1 ? "" : "s");
  ipv4_address_print(stdout, packet.header.router_id);
  fputs(".\n", stdout);
  return true;
}

static router_bgp_peer_t* find_bgp_peer(router_context_t* context, size_t interface_index, ipv4_address_t address) {
  for (size_t i = 0; i < context->bgp_peer_count; ++i) {
    router_bgp_peer_t* peer = &context->bgp_peers[i];
    if (peer->interface_index == interface_index && peer->address == address) return peer;
  }
  return NULL;
}

static bool bgp_send_open(router_context_t* context, router_bgp_peer_t* peer) {
  uint8_t bytes[sizeof(bgp_open_t)] = {0};
  uint16_t length = 0;
  const interface_entry_t* entry = interface_table_get(&context->interfaces, peer->interface_index);
  if (!entry || !bgp_write_open(peer->local_as, entry->ip4, bytes, sizeof(bytes), &length) || !socket_send(&context->sockets[peer->interface_index], peer->socket, bytes, length)) return false;
  peer->open_sent = true;
  return true;
}

static bool bgp_send_keepalive(router_context_t* context, router_bgp_peer_t* peer, uint32_t now) {
  uint8_t bytes[BGP_HEADER_LENGTH] = {0};
  uint16_t length = 0;
  if (!bgp_write_keepalive(bytes, sizeof(bytes), &length) || !socket_send(&context->sockets[peer->interface_index], peer->socket, bytes, length)) return false;
  peer->last_keepalive = now;
  return true;
}

static bool bgp_advertise_routes(router_context_t* context, router_bgp_peer_t* peer) {
  const interface_entry_t* entry = interface_table_get(&context->interfaces, peer->interface_index);
  if (!entry) return false;
  for (size_t i = 0; i < context->routes.count; ++i) {
    const route_entry_t* route = &context->routes.entries[i];
    if (route->source != ROUTE_SOURCE_CONNECTED && route->source != ROUTE_SOURCE_STATIC) continue;
    if (peer->outbound_prefix_list[0] && !prefix_list_permits(&context->prefix_lists, peer->outbound_prefix_list, route->destination, route->mask)) continue;
    uint8_t bytes[BGP_MAX_MESSAGE_LENGTH] = {0};
    uint16_t length = 0;
    if (!bgp_write_update(route->destination, route->mask, entry->ip4, peer->local_as, bytes, sizeof(bytes), &length) || !socket_send(&context->sockets[peer->interface_index], peer->socket, bytes, length)) return false;
  }
  return true;
}

static bool bgp_receive_messages(router_context_t* context, router_bgp_peer_t* peer, uint32_t now) {
  uint8_t bytes[SOCKET_RECEIVE_CAPACITY] = {0};
  const size_t byte_count = socket_receive(&context->sockets[peer->interface_index], peer->socket, bytes, sizeof(bytes), NULL, NULL);
  for (size_t offset = 0; offset < byte_count;) {
    bgp_message_view_t message = {0};
    if (!bgp_parse_message(bytes + offset, byte_count - offset, &message)) return false;
    peer->last_received = now;
    if (message.header.type == BGP_MESSAGE_OPEN) {
      const bgp_open_t* open = (const bgp_open_t*)(bytes + offset);
      if (open->autonomous_system != peer->remote_as || !open->hold_time) return false;
      peer->open_received = true;
      if (!peer->open_sent && !bgp_send_open(context, peer)) return false;
      if (!bgp_send_keepalive(context, peer, now)) return false;
    } else if (message.header.type == BGP_MESSAGE_KEEPALIVE) {
      if (!peer->open_sent || !peer->open_received) return false;
      if (!peer->established) {
        peer->established = true;
        fputs("BGP established with ", stdout);
        ipv4_address_print(stdout, peer->address);
        fputs(".\n", stdout);
        if (!bgp_advertise_routes(context, peer)) return false;
      }
    } else if (message.header.type == BGP_MESSAGE_UPDATE) {
      bgp_update_t update = {0};
      if (!peer->established || !bgp_parse_update(&message, &update) || update.autonomous_system != peer->remote_as || update.next_hop != peer->address) return false;
      if (peer->inbound_prefix_list[0] && !prefix_list_permits(&context->prefix_lists, peer->inbound_prefix_list, update.network, update.mask)) {
        fputs("Rejected BGP route by prefix list.\n", stdout);
      } else if (!route_table_learn_bgp(&context->routes, update.network, update.mask, peer->address, peer->interface_index, 0)) {
        return false;
      } else {
        fputs("Learned BGP route ", stdout);
        ipv4_address_print(stdout, update.network);
        fputs("/", stdout);
        ipv4_address_print(stdout, update.mask);
        fputs(" from ", stdout);
        ipv4_address_print(stdout, peer->address);
        fputs(".\n", stdout);
      }
    } else {
      return false;
    }
    offset += message.header.length;
  }
  return true;
}

static bool bgp_tick(router_context_t* context, uint32_t now) {
  for (size_t interface_index = 0; interface_index < context->interfaces.count; ++interface_index) {
    socket_context_t* sockets = &context->sockets[interface_index];
    socket_handle_t listener = context->bgp_listeners[interface_index];
    if (listener) {
      socket_handle_t connection = SOCKET_INVALID_HANDLE;
      while (socket_accept(sockets, listener, &connection)) {
        const socket_entry_t* socket = socket_get(sockets, connection);
        router_bgp_peer_t* peer = socket ? find_bgp_peer(context, interface_index, socket->remote_address) : NULL;
        if (!peer || peer->active || peer->socket) {
          socket_close(sockets, connection);
        } else {
          peer->socket = connection;
          peer->last_received = now;
        }
      }
    }
  }
  for (size_t i = 0; i < context->bgp_peer_count; ++i) {
    router_bgp_peer_t* peer = &context->bgp_peers[i];
    socket_context_t* sockets = &context->sockets[peer->interface_index];
    const socket_entry_t* socket = peer->socket ? socket_get(sockets, peer->socket) : NULL;
    if (socket && socket->state == SOCKET_STATE_CLOSE_WAIT) {
      route_table_remove_bgp_peer(&context->routes, peer->address, peer->interface_index);
      socket_close(sockets, peer->socket);
      peer->socket = SOCKET_INVALID_HANDLE;
      peer->open_sent = peer->open_received = peer->established = false;
      socket = NULL;
    }
    if (peer->active && !socket && peer->last_attempt != now) {
      peer->last_attempt = now;
      if (socket_open(sockets, SOCKET_PROTOCOL_TCP, &peer->socket) && socket_connect(sockets, peer->socket, peer->address, BGP_TCP_PORT)) peer->last_received = now;
      else {
        if (peer->socket) socket_close(sockets, peer->socket);
        peer->socket = SOCKET_INVALID_HANDLE;
      }
      socket = peer->socket ? socket_get(sockets, peer->socket) : NULL;
    }
    if (!socket) continue;
    if (socket->state == SOCKET_STATE_ESTABLISHED) {
      if (!peer->open_sent && !bgp_send_open(context, peer)) return false;
      if (!bgp_receive_messages(context, peer, now)) return false;
      if (peer->established && now - peer->last_keepalive >= BGP_KEEPALIVE_SECONDS && !bgp_send_keepalive(context, peer, now)) return false;
      if (peer->last_received && now - peer->last_received >= BGP_HOLD_TIME_SECONDS) {
        route_table_remove_bgp_peer(&context->routes, peer->address, peer->interface_index);
        socket_close(sockets, peer->socket);
        peer->socket = SOCKET_INVALID_HANDLE;
        peer->open_sent = peer->open_received = peer->established = false;
      }
    }
  }
  for (size_t i = 0; i < context->interfaces.count; ++i) {
    if (!socket_tick(&context->sockets[i], now)) return false;
  }
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
  const bool destination_is_ospf_multicast = memcmp(frame.header.dst_mac, ospf_multicast_mac, sizeof(ospf_multicast_mac)) == 0;
  if (frame.header.type_or_length == ETHERNET_ETHERTYPE_ARP && (destination_is_interface || ethernet_mac_is_broadcast(frame.header.dst_mac))) return handle_arp(context, ingress_interface, &frame);
  if (frame.header.type_or_length == ETHERNET_ETHERTYPE_RARP && (destination_is_interface || ethernet_mac_is_broadcast(frame.header.dst_mac))) return handle_rarp(context, ingress_interface, &frame);
  if (frame.header.type_or_length != ETHERNET_ETHERTYPE_IPV4 || (!destination_is_interface && !destination_is_rip_multicast && !destination_is_ospf_multicast)) return true;
  ipv4_packet_view_t packet = {0};
  if (!ipv4_parse_packet(frame.data, frame.client_data_length, &packet)) return true;
  if (destination_is_rip_multicast) return handle_rip(context, ingress_interface, &packet);
  if (destination_is_ospf_multicast) return handle_ospf(context, ingress_interface, &packet);
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
  fprintf(stdout, "Dynamic routing: %s\n", dynamic_routing_name(context->dynamic_routing));
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
  fprintf(stdout, "BGP peers (%zu):\n", context->bgp_peer_count);
  for (size_t i = 0; i < context->bgp_peer_count; ++i) {
    const router_bgp_peer_t* peer = &context->bgp_peers[i];
    fputs("  ", stdout);
    ipv4_address_print(stdout, peer->address);
    fprintf(stdout, "  dev %zu  AS %u -> %u  %s  %s  in=%s out=%s\n", peer->interface_index + 1, peer->local_as, peer->remote_as, peer->active ? "active" : "passive", peer->established ? "established" : "idle", peer->inbound_prefix_list[0] ? peer->inbound_prefix_list : "none", peer->outbound_prefix_list[0] ? peer->outbound_prefix_list : "none");
  }
  fprintf(stdout, "RIP prefix lists:\n");
  for (size_t i = 0; i < context->interfaces.count; ++i) {
    fprintf(stdout, "  dev %zu  in=%s out=%s\n", i + 1, context->rip_inbound_prefix_lists[i][0] ? context->rip_inbound_prefix_lists[i] : "none", context->rip_outbound_prefix_lists[i][0] ? context->rip_outbound_prefix_lists[i] : "none");
  }
  fprintf(stdout, "Prefix-list rules (%zu):\n", context->prefix_lists.count);
  for (size_t i = 0; i < context->prefix_lists.count; ++i) {
    const prefix_list_rule_t* rule = &context->prefix_lists.entries[i];
    fprintf(stdout, "  %-31s %u %s ", rule->name, rule->sequence, prefix_list_action_name(rule->action));
    ipv4_address_print(stdout, rule->network);
    fputs("/", stdout);
    ipv4_address_print(stdout, rule->mask);
    fprintf(stdout, " ge %u le %u\n", rule->minimum_length, rule->maximum_length);
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

static void command_dynamic_routing(void* argument, char* arguments) {
  router_context_t* context = argument;
  char* mode_text = cmd_app_next_argument(&arguments);
  if (!mode_text || cmd_app_next_argument(&arguments) || (strcmpi(mode_text, "off") != 0 && strcmpi(mode_text, "rip") != 0 && strcmpi(mode_text, "ospf") != 0)) {
    fputs("Usage: dynamic-routing <off|rip|ospf>\n", stderr);
    return;
  }
  const router_dynamic_routing_mode_t mode = strcmpi(mode_text, "rip") == 0 ? ROUTER_DYNAMIC_ROUTING_RIP : strcmpi(mode_text, "ospf") == 0 ? ROUTER_DYNAMIC_ROUTING_OSPF
                                                                                                                                           : ROUTER_DYNAMIC_ROUTING_OFF;
  mutex_lock(&context->mutex);
  route_table_remove_rip(&context->routes);
  route_table_remove_ospf(&context->routes);
  context->dynamic_routing = mode;
  const uint32_t now = (uint32_t)time(NULL);
  bool started = true;
  if (mode == ROUTER_DYNAMIC_ROUTING_RIP) {
    context->next_rip_update = now + RIP_UPDATE_INTERVAL_SECONDS;
    started = write_rip_requests(context) && write_rip_updates(context);
  } else if (mode == ROUTER_DYNAMIC_ROUTING_OSPF) {
    context->next_ospf_update = now + OSPF_UPDATE_INTERVAL_SECONDS;
    started = write_ospf_updates(context);
  }
  mutex_unlock(&context->mutex);
  if (!started) {
    fputs("Could not start selected dynamic routing protocol.\n", stderr);
    return;
  }
  fprintf(stdout, "Dynamic routing: %s.\n", dynamic_routing_name(mode));
}

static void command_prefix_list(void* argument, char* arguments) {
  router_context_t* context = argument;
  char* cursor = arguments;
  char* action = cmd_app_next_argument(&cursor);
  char* name = cmd_app_next_argument(&cursor);
  char* sequence_text = cmd_app_next_argument(&cursor);
  uint16_t sequence = 0;
  if (!action || !name || !sequence_text || !cmd_app_parse_uint16(sequence_text, &sequence)) {
    fputs("Usage: prefix-list <add|delete> <name> <sequence> [permit|deny <network> <mask> <ge> <le>]\n", stderr);
    return;
  }
  if (strcmpi(action, "delete") == 0 && !cmd_app_next_argument(&cursor)) {
    mutex_lock(&context->mutex);
    const bool removed = prefix_list_remove(&context->prefix_lists, name, sequence);
    mutex_unlock(&context->mutex);
    fputs(removed ? "Prefix-list rule removed.\n" : "No such prefix-list rule.\n", removed ? stdout : stderr);
    return;
  }
  char* decision = cmd_app_next_argument(&cursor);
  char* network_text = cmd_app_next_argument(&cursor);
  char* mask_text = cmd_app_next_argument(&cursor);
  char* minimum_text = cmd_app_next_argument(&cursor);
  char* maximum_text = cmd_app_next_argument(&cursor);
  ipv4_address_t network = 0;
  ipv4_address_t mask = 0;
  uint16_t minimum = 0;
  uint16_t maximum = 0;
  if (strcmpi(action, "add") != 0 || !decision || !network_text || !mask_text || !minimum_text || !maximum_text || cmd_app_next_argument(&cursor) || (strcmpi(decision, "permit") != 0 && strcmpi(decision, "deny") != 0) || !ipv4_parse_address(network_text, &network) || !ipv4_parse_address(mask_text, &mask) || !cmd_app_parse_uint16(minimum_text, &minimum) || !cmd_app_parse_uint16(maximum_text, &maximum) || minimum > 32 || maximum > 32) {
    fputs("Usage: prefix-list <add|delete> <name> <sequence> [permit|deny <network> <mask> <ge> <le>]\n", stderr);
    return;
  }
  mutex_lock(&context->mutex);
  const bool added = prefix_list_add(&context->prefix_lists, name, sequence, strcmpi(decision, "permit") == 0 ? PREFIX_LIST_PERMIT : PREFIX_LIST_DENY, network, mask, (uint8_t)minimum, (uint8_t)maximum);
  mutex_unlock(&context->mutex);
  fputs(added ? "Prefix-list rule added.\n" : "Could not add prefix-list rule.\n", added ? stdout : stderr);
}

static void command_bgp_prefix_list(void* argument, char* arguments) {
  router_context_t* context = argument;
  char* cursor = arguments;
  char* peer_text = cmd_app_next_argument(&cursor);
  char* direction = cmd_app_next_argument(&cursor);
  char* name = cmd_app_next_argument(&cursor);
  uint16_t peer_number = 0;
  if (!peer_text || !direction || !name || cmd_app_next_argument(&cursor) || !cmd_app_parse_uint16(peer_text, &peer_number) || peer_number == 0 || peer_number > context->bgp_peer_count || (strcmpi(direction, "in") != 0 && strcmpi(direction, "out") != 0) || (strcmpi(name, "none") != 0 && strlen(name) >= PREFIX_LIST_NAME_LEN)) {
    fputs("Usage: bgp-prefix-list <peer> <in|out> <name|none>\n", stderr);
    return;
  }
  mutex_lock(&context->mutex);
  char* assigned = strcmpi(direction, "in") == 0 ? context->bgp_peers[peer_number - 1].inbound_prefix_list : context->bgp_peers[peer_number - 1].outbound_prefix_list;
  if (strcmpi(name, "none") != 0) {
    bool exists = false;
    for (size_t i = 0; i < context->prefix_lists.count; ++i) {
      if (strcmpi(context->prefix_lists.entries[i].name, name) == 0) {
        exists = true;
        break;
      }
    }
    if (!exists) {
      mutex_unlock(&context->mutex);
      fputs("No such prefix list.\n", stderr);
      return;
    }
  }
  assigned[0] = '\0';
  if (strcmpi(name, "none") != 0) strncpy(assigned, name, PREFIX_LIST_NAME_LEN - 1);
  mutex_unlock(&context->mutex);
  fputs("BGP prefix list assigned.\n", stdout);
}

static void command_rip_prefix_list(void* argument, char* arguments) {
  router_context_t* context = argument;
  char* cursor = arguments;
  char* interface_text = cmd_app_next_argument(&cursor);
  char* direction = cmd_app_next_argument(&cursor);
  char* name = cmd_app_next_argument(&cursor);
  uint16_t interface_number = 0;
  if (!interface_text || !direction || !name || cmd_app_next_argument(&cursor) || !cmd_app_parse_uint16(interface_text, &interface_number) || interface_number == 0 || interface_number > context->interfaces.count || (strcmpi(direction, "in") != 0 && strcmpi(direction, "out") != 0) || (strcmpi(name, "none") != 0 && strlen(name) >= PREFIX_LIST_NAME_LEN)) {
    fputs("Usage: rip-prefix-list <interface> <in|out> <name|none>\n", stderr);
    return;
  }
  mutex_lock(&context->mutex);
  if (strcmpi(name, "none") != 0) {
    bool exists = false;
    for (size_t i = 0; i < context->prefix_lists.count; ++i) {
      if (strcmpi(context->prefix_lists.entries[i].name, name) == 0) {
        exists = true;
        break;
      }
    }
    if (!exists) {
      mutex_unlock(&context->mutex);
      fputs("No such prefix list.\n", stderr);
      return;
    }
  }
  char* assigned = strcmpi(direction, "in") == 0 ? context->rip_inbound_prefix_lists[interface_number - 1] : context->rip_outbound_prefix_lists[interface_number - 1];
  assigned[0] = '\0';
  if (strcmpi(name, "none") != 0) strncpy(assigned, name, PREFIX_LIST_NAME_LEN - 1);
  mutex_unlock(&context->mutex);
  fputs("RIP prefix list assigned.\n", stdout);
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
      if (i + 1 >= argc || (strcmpi(argv[i + 1], "off") != 0 && strcmpi(argv[i + 1], "rip") != 0 && strcmpi(argv[i + 1], "ospf") != 0)) return false;
      context->dynamic_routing = strcmpi(argv[i + 1], "rip") == 0 ? ROUTER_DYNAMIC_ROUTING_RIP : strcmpi(argv[i + 1], "ospf") == 0 ? ROUTER_DYNAMIC_ROUTING_OSPF
                                                                                                                                   : ROUTER_DYNAMIC_ROUTING_OFF;
      i += 2;
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
    } else if (strcmpi(argv[i], "-bgp") == 0) {
      if (i + 5 >= argc || context->bgp_peer_count == ROUTER_BGP_PEER_CAPACITY) return false;
      uint16_t interface_number = 0;
      uint16_t local_as = 0;
      uint16_t remote_as = 0;
      ipv4_address_t address = 0;
      if ((strcmpi(argv[i + 1], "active") != 0 && strcmpi(argv[i + 1], "passive") != 0) || !cmd_app_parse_uint16(argv[i + 2], &interface_number) || interface_number == 0 || interface_number > context->interfaces.count || !ipv4_parse_address(argv[i + 3], &address) || !cmd_app_parse_uint16(argv[i + 4], &local_as) || !cmd_app_parse_uint16(argv[i + 5], &remote_as) || !local_as || !remote_as || local_as == remote_as || find_bgp_peer(context, interface_number - 1, address)) return false;
      context->bgp_peers[context->bgp_peer_count++] = (router_bgp_peer_t) {
          .address = address,
          .local_as = local_as,
          .remote_as = remote_as,
          .interface_index = interface_number - 1,
          .active = strcmpi(argv[i + 1], "active") == 0,
      };
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
  prefix_list_init(&context.prefix_lists, context.prefix_list_entries, ROUTER_PREFIX_LIST_CAPACITY);
  nat_table_init(&context.nat, context.nat_entries, ROUTER_NAT_CAPACITY, context.nat_pool, ROUTER_NAT_POOL_CAPACITY, NAT_EPHEMERAL_PORT_MIN);
  if (!parse_options(&context, argc, argv)) {
    fputs("Usage: router -i <file> <mac-address> <ip-address> <mask> [... ] [-r <network> <mask> <next-hop|direct> <interface> <metric> [...]] [-bgp <active|passive> <interface> <peer-ip> <local-as> <peer-as> [...]] [-rarp <client-mac> <ip-address> [...]] [-dynamic-routing <off|rip|ospf>] [-nat <inside-interface> <outside-interface>] [-dynamic-nat <outside-address> ...] [-dynamic-pat] [-static-nat <inside-address> <outside-address> ...] [-static-pat <tcp|udp> <inside-address> <inside-port> <outside-address> <outside-port> ...]\n", stderr);
    return EXIT_FAILURE;
  }
  if (!mutex_init(&context.mutex)) {
    fputs("Could not initialize router mutex.\n", stderr);
    return EXIT_FAILURE;
  }
  int status = EXIT_SUCCESS;
  bool commands_started = false;
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
  for (size_t i = 0; i < context.interfaces.count; ++i) {
    context.socket_arguments[i] = (router_socket_emit_argument_t) {.context = &context, .interface_index = i};
    if (!socket_context_init(&context.sockets[i], context.interfaces.entries[i].ip4, router_socket_emit, &context.socket_arguments[i])) {
      fputs("Could not initialize router socket context.\n", stderr);
      status = EXIT_FAILURE;
      goto cleanup;
    }
  }
  for (size_t i = 0; i < context.bgp_peer_count; ++i) {
    const router_bgp_peer_t* peer = &context.bgp_peers[i];
    socket_handle_t* listener = &context.bgp_listeners[peer->interface_index];
    if (!peer->active && !*listener && (!socket_open(&context.sockets[peer->interface_index], SOCKET_PROTOCOL_TCP, listener) || !socket_bind(&context.sockets[peer->interface_index], *listener, BGP_TCP_PORT) || !socket_listen(&context.sockets[peer->interface_index], *listener))) {
      fputs("Could not listen for BGP peers.\n", stderr);
      status = EXIT_FAILURE;
      goto cleanup;
    }
  }
  cmd_app_init(&context.commands);
  if (!cmd_app_register(&context.commands, "info", "Show router state, including dynamic route sources.", command_info, &context) || !cmd_app_register(&context.commands, "arp", "Resolve an IPv4 neighbor on one interface.", command_arp, &context) || !cmd_app_register(&context.commands, "arp-delete", "Remove one learned ARP neighbor.", command_arp_delete, &context) || !cmd_app_register(&context.commands, "interface", "Administratively bring an interface up or down.", command_interface, &context) || !cmd_app_register(&context.commands, "dynamic-routing", "Select off, RIP v2, or OSPF dynamic routing.", command_dynamic_routing, &context) || !cmd_app_register(&context.commands, "prefix-list", "Add or delete a named IPv4 prefix-list rule.", command_prefix_list, &context) || !cmd_app_register(&context.commands, "bgp-prefix-list", "Assign or clear a BGP peer prefix list.", command_bgp_prefix_list, &context) || !cmd_app_register(&context.commands, "rip-prefix-list", "Assign or clear a RIP interface prefix list.", command_rip_prefix_list, &context) || !cmd_app_register(&context.commands, "route", "Add or delete a route in the forwarding table.", command_route, &context) || !cmd_app_register(&context.commands, "rarp-table", "Set or delete a static RARP assignment.", command_rarp_table, &context) || !cmd_app_start(&context.commands)) {
    fputs("Could not start the command application.\n", stderr);
    status = EXIT_FAILURE;
    goto cleanup;
  }
  commands_started = true;
  if (context.dynamic_routing != ROUTER_DYNAMIC_ROUTING_OFF) {
    const uint32_t now = (uint32_t)time(NULL);
    mutex_lock(&context.mutex);
    const bool started = context.dynamic_routing == ROUTER_DYNAMIC_ROUTING_RIP ? (context.next_rip_update = now + RIP_UPDATE_INTERVAL_SECONDS, write_rip_requests(&context) && write_rip_updates(&context)) : (context.next_ospf_update = now + OSPF_UPDATE_INTERVAL_SECONDS, write_ospf_updates(&context));
    mutex_unlock(&context.mutex);
    if (!started) {
      fputs("Could not start selected dynamic routing protocol.\n", stderr);
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
    if (context.dynamic_routing == ROUTER_DYNAMIC_ROUTING_RIP) {
      const uint32_t now = (uint32_t)time(NULL);
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
    } else if (context.dynamic_routing == ROUTER_DYNAMIC_ROUTING_OSPF) {
      const uint32_t now = (uint32_t)time(NULL);
      route_table_expire_ospf(&context.routes, now);
      if (now >= context.next_ospf_update) {
        if (!write_ospf_updates(&context)) {
          mutex_unlock(&context.mutex);
          fputs("Could not send OSPF routing update.\n", stderr);
          status = EXIT_FAILURE;
          goto cleanup;
        }
        context.next_ospf_update = now + OSPF_UPDATE_INTERVAL_SECONDS;
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
    if (!bgp_tick(&context, (uint32_t)time(NULL))) {
      mutex_unlock(&context.mutex);
      fputs("Could not advance BGP sessions.\n", stderr);
      status = EXIT_FAILURE;
      goto cleanup;
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
  if (commands_started) {
    cmd_app_stop(&context.commands);
    cmd_app_join(&context.commands);
  }
  for (size_t i = 0; i < context.interfaces.count; ++i) {
    if (context.ports[i].source) fclose(context.ports[i].source);
    if (context.ports[i].destination) fclose(context.ports[i].destination);
  }
  mutex_destroy(&context.mutex);
  return status;
}

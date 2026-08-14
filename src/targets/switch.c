#include "switch.h"

#include <math.h>
#include <time.h>

#define SWITCH_STP_LLC_DSAP    0x42u
#define SWITCH_STP_LLC_SSAP    0x42u
#define SWITCH_STP_LLC_CONTROL 0x03u
#define SWITCH_STP_PROTOCOL_ID 0u
#define SWITCH_STP_VERSION     0u
#define SWITCH_STP_TYPE_CONFIG 0u
#define SWITCH_STP_FLAG_TC     0x01u

static const mac_address_t switch_stp_destination_mac = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00};

static uint32_t switch_now_ms(void) {
#ifdef _WIN32
  return (uint32_t)GetTickCount64();
#else
  struct timespec now = {0};
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    return (uint32_t)time(NULL) * 1000u;
  }
  return (uint32_t)(now.tv_sec * 1000u + (uint32_t)(now.tv_nsec / 1000000L));
#endif
}

static switch_bridge_id_t switch_bridge_id_make(uint16_t priority, const mac_address_t mac) {
  switch_bridge_id_t bridge_id = (switch_bridge_id_t)priority << 48;
  for (size_t i = 0; i < sizeof(mac_address_t); ++i) {
    bridge_id |= (switch_bridge_id_t)mac[i] << (40 - i * 8);
  }
  return bridge_id;
}

static void switch_bridge_id_to_mac(switch_bridge_id_t bridge_id, mac_address_t mac) {
  for (size_t i = 0; i < sizeof(mac_address_t); ++i) {
    mac[i] = (uint8_t)(bridge_id >> (40 - i * 8));
  }
}

static uint16_t switch_bridge_id_priority(switch_bridge_id_t bridge_id) {
  return (uint16_t)(bridge_id >> 48);
}

static void switch_bridge_id_print(FILE* destination, switch_bridge_id_t bridge_id) {
  mac_address_t mac = {0};
  switch_bridge_id_to_mac(bridge_id, mac);
  fprintf(destination, "%u / ", switch_bridge_id_priority(bridge_id));
  ethernet_mac_print(destination, mac);
}

static void switch_default_bridge_mac(const char* path, mac_address_t mac) {
  const uint32_t hash = crc32(path, strlen(path));
  mac[0] = 0x02;
  mac[1] = (uint8_t)(hash >> 24);
  mac[2] = (uint8_t)(hash >> 16);
  mac[3] = (uint8_t)(hash >> 8);
  mac[4] = (uint8_t)hash;
  mac[5] = (uint8_t)strlen(path);
}

static const char* switch_stp_role_name(switch_stp_port_role_t role) {
  switch (role) {
    case SWITCH_STP_PORT_ROLE_ROOT:
      return "root";
    case SWITCH_STP_PORT_ROLE_DESIGNATED:
      return "designated";
    case SWITCH_STP_PORT_ROLE_ALTERNATE:
      return "alternate";
    default:
      return "disabled";
  }
}

static const char* switch_stp_state_name(switch_stp_port_state_t state) {
  switch (state) {
    case SWITCH_STP_PORT_STATE_FORWARDING:
      return "forwarding";
    case SWITCH_STP_PORT_STATE_BLOCKING:
      return "blocking";
    default:
      return "disabled";
  }
}

static int switch_compare_priority_vector(switch_bridge_id_t left_root_id, uint32_t left_cost, switch_bridge_id_t left_bridge_id, uint16_t left_port_id, switch_bridge_id_t right_root_id, uint32_t right_cost, switch_bridge_id_t right_bridge_id, uint16_t right_port_id) {
  if (left_root_id != right_root_id) return left_root_id < right_root_id ? -1 : 1;
  if (left_cost != right_cost) return left_cost < right_cost ? -1 : 1;
  if (left_bridge_id != right_bridge_id) return left_bridge_id < right_bridge_id ? -1 : 1;
  if (left_port_id != right_port_id) return left_port_id < right_port_id ? -1 : 1;
  return 0;
}

static bool switch_parse_bridge_priority(const char* text, uint16_t* priority) {
  uint16_t parsed = 0;
  return cmd_app_parse_uint16(text, &parsed) && parsed <= 61440u && parsed % 4096u == 0 && (*priority = parsed, true);
}

static void print_port(const switch_port_t* port, size_t index) {
  fprintf(stdout, "  %zu: %s  ", index + 1, port->path);
  if (port->mode == SWITCH_PORT_ACCESS) {
    fprintf(stdout, "access VLAN %u", port->access_vlan_id);
  } else {
    fputs("trunk VLANs ", stdout);
    bool first = true;
    for (uint16_t vlan_id = 1; vlan_id <= ETHERNET_VLAN_ID_MAX; ++vlan_id) {
      if (port->allowed_vlans[vlan_id]) {
        fprintf(stdout, "%s%u", first ? "" : ",", vlan_id);
        first = false;
      }
    }
    if (first) fputs("none", stdout);
  }
  fprintf(stdout, "  STP cost %u role %s state %s\n", port->stp_path_cost, switch_stp_role_name(port->stp_role), switch_stp_state_name(port->stp_state));
}

static void switch_print_stp_summary(const switch_context_t* context) {
  fputs("STP bridge ID: ", stdout);
  switch_bridge_id_print(stdout, context->bridge_id);
  fputc('\n', stdout);
  fputs("STP root ID:   ", stdout);
  switch_bridge_id_print(stdout, context->root_id);
  fprintf(stdout, "\nSTP root path cost: %u\n", context->root_path_cost);
  if (context->root_port < context->port_count) {
    fprintf(stdout, "STP root port: %zu (%s)\n", context->root_port + 1, context->ports[context->root_port].path);
  } else {
    fputs("STP root port: self\n", stdout);
  }
  fprintf(stdout, "Topology changes: %u\n", context->topology_change_count);
}

static void switch_print_fdb(const switch_context_t* context) {
  fprintf(stdout, "Forwarding database (%zu):\n", context->devices->count);
  for (size_t i = 0; i < context->devices->count; ++i) {
    fputs("  ", stdout);
    ethernet_mac_print(stdout, context->devices->entries[i].mac);
    fprintf(stdout, "  VLAN %u  port %zu (%s)\n", context->devices->entries[i].vlan_id, context->devices->entries[i].port + 1, context->ports[context->devices->entries[i].port].path);
  }
}

static void command_info(void* argument, char* arguments) {
  const switch_context_t* context = argument;
  if (!cmd_app_arguments_empty(arguments)) {
    fputs("Usage: info\n", stderr);
    return;
  }
  fprintf(stdout, "Switch file: %s\nPorts (%zu):\n", context->path, context->port_count);
  for (size_t i = 0; i < context->port_count; ++i) {
    print_port(&context->ports[i], i);
  }
  switch_print_stp_summary(context);
  switch_print_fdb(context);
}

static void command_fdb(void* argument, char* arguments) {
  switch_context_t* context = argument;
  char* cursor = arguments;
  char* action = cmd_app_next_argument(&cursor);
  if (!action || strcmpi(action, "show") == 0) {
    if (action && cmd_app_next_argument(&cursor)) {
      fputs("Usage: fdb [show|delete <mac-address> <vlan>|flush]\n", stderr);
      return;
    }
    switch_print_fdb(context);
    return;
  }
  if (strcmpi(action, "flush") == 0 && !cmd_app_next_argument(&cursor)) {
    fdb_table_clear(context->devices);
    fputs("FDB cleared.\n", stdout);
    return;
  }
  char* mac_text = cmd_app_next_argument(&cursor);
  char* vlan_text = cmd_app_next_argument(&cursor);
  mac_address_t mac = {0};
  uint16_t vlan_id = 0;
  if (strcmpi(action, "delete") != 0 || !mac_text || !vlan_text || cmd_app_next_argument(&cursor) || !ethernet_mac_parse(mac_text, mac) || !cmd_app_parse_uint16(vlan_text, &vlan_id) || vlan_id > ETHERNET_VLAN_ID_MAX) {
    fputs("Usage: fdb [show|delete <mac-address> <vlan>|flush]\n", stderr);
    return;
  }
  const bool removed = fdb_table_remove(context->devices, mac, vlan_id);
  fputs(removed ? "FDB entry removed.\n" : "No such FDB entry.\n", removed ? stdout : stderr);
}

static void command_stp(void* argument, char* arguments) {
  switch_context_t* context = argument;
  char* cursor = arguments;
  char* action = cmd_app_next_argument(&cursor);
  if (!action || strcmpi(action, "show") == 0) {
    if (action && cmd_app_next_argument(&cursor)) {
      fputs("Usage: stp [show|bridge <priority> <mac-address>|cost <port> <cost>]\n", stderr);
      return;
    }
    switch_print_stp_summary(context);
    for (size_t i = 0; i < context->port_count; ++i) {
      const switch_port_t* port = &context->ports[i];
      fprintf(stdout, "  Port %zu: role=%s state=%s cost=%u bpdu-rx=%u bpdu-tx=%u", i + 1, switch_stp_role_name(port->stp_role), switch_stp_state_name(port->stp_state), port->stp_path_cost, port->stp_rx_bpdus, port->stp_tx_bpdus);
      if (port->stp_neighbor.valid) {
        fputs(" neighbor=", stdout);
        switch_bridge_id_print(stdout, port->stp_neighbor.bridge_id);
      }
      fputc('\n', stdout);
    }
    return;
  }
  if (strcmpi(action, "bridge") == 0) {
    char* priority_text = cmd_app_next_argument(&cursor);
    char* mac_text = cmd_app_next_argument(&cursor);
    mac_address_t mac = {0};
    uint16_t priority = 0;
    if (!priority_text || !mac_text || cmd_app_next_argument(&cursor) || !switch_parse_bridge_priority(priority_text, &priority) || !ethernet_mac_parse(mac_text, mac) || ethernet_mac_is_group(mac)) {
      fputs("Usage: stp bridge <priority-multiple-of-4096> <mac-address>\n", stderr);
      return;
    }
    context->bridge_id = switch_bridge_id_make(priority, mac);
    context->topology_change_until_ms = switch_now_ms() + SWITCH_STP_TC_WINDOW_MS;
    fputs("STP bridge ID updated.\n", stdout);
    return;
  }
  if (strcmpi(action, "cost") == 0) {
    char* port_text = cmd_app_next_argument(&cursor);
    char* cost_text = cmd_app_next_argument(&cursor);
    uint16_t port_number = 0;
    uint16_t cost = 0;
    if (!port_text || !cost_text || cmd_app_next_argument(&cursor) || !cmd_app_parse_uint16(port_text, &port_number) || !cmd_app_parse_uint16(cost_text, &cost) || port_number == 0 || port_number > context->port_count || cost == 0) {
      fputs("Usage: stp cost <port> <cost>\n", stderr);
      return;
    }
    context->ports[port_number - 1].stp_path_cost = cost;
    context->topology_change_until_ms = switch_now_ms() + SWITCH_STP_TC_WINDOW_MS;
    fputs("STP path cost updated.\n", stdout);
    return;
  }
  fputs("Usage: stp [show|bridge <priority> <mac-address>|cost <port> <cost>]\n", stderr);
}

static bool switch_is_stp_destination(const mac_address_t mac) {
  return memcmp(mac, switch_stp_destination_mac, sizeof(mac_address_t)) == 0;
}

static bool switch_port_can_forward_vlan(const switch_port_t* port, uint16_t vlan_id) {
  return port->mode == SWITCH_PORT_ACCESS ? port->access_vlan_id == vlan_id : port->allowed_vlans[vlan_id];
}

static bool port_accepts_vlan(const switch_port_t* port, const ethernet_frame_view_t* frame, uint16_t* vlan_id) {
  if (port->mode == SWITCH_PORT_ACCESS) {
    if (frame->tagged) return false;
    *vlan_id = port->access_vlan_id;
    return true;
  }
  if (!frame->tagged || !port->allowed_vlans[frame->vlan_id]) return false;
  *vlan_id = frame->vlan_id;
  return true;
}

static bool switch_parse_bpdu(const ethernet_frame_view_t* frame, switch_stp_bpdu_t* bpdu) {
  if (frame->tagged || frame->format != ETHERNET_FRAME_FORMAT_IEEE_802_3 || !switch_is_stp_destination(frame->header.dst_mac) || frame->client_data_length != sizeof(*bpdu) || frame->data_length < sizeof(*bpdu)) {
    return false;
  }
  memcpy(bpdu, frame->data, sizeof(*bpdu));
  return bpdu->llc_dsap == SWITCH_STP_LLC_DSAP && bpdu->llc_ssap == SWITCH_STP_LLC_SSAP && bpdu->llc_control == SWITCH_STP_LLC_CONTROL && bpdu->protocol_id == SWITCH_STP_PROTOCOL_ID && bpdu->version == SWITCH_STP_VERSION && bpdu->type == SWITCH_STP_TYPE_CONFIG && (bpdu->flags & (uint8_t)~SWITCH_STP_FLAG_TC) == 0 && (bpdu->bridge_id & 0x0001000000000000ull) == 0 && (bpdu->root_id & 0x0001000000000000ull) == 0 && bpdu->port_id != 0;
}

static void switch_flag_topology_change(switch_context_t* context, const char* reason) {
  ++context->topology_change_count;
  context->topology_change_until_ms = switch_now_ms() + SWITCH_STP_TC_WINDOW_MS;
  if (context->devices->count > 0) {
    fdb_table_clear(context->devices);
    fprintf(stdout, "STP topology change: %s. Cleared FDB.\n", reason);
  } else {
    fprintf(stdout, "STP topology change: %s.\n", reason);
  }
}

static void switch_expire_neighbors(switch_context_t* context, uint32_t now_ms) {
  for (size_t i = 0; i < context->port_count; ++i) {
    switch_stp_neighbor_t* neighbor = &context->ports[i].stp_neighbor;
    if (neighbor->valid && now_ms - neighbor->last_seen_ms > SWITCH_STP_MAX_AGE_MS) {
      neighbor->valid = false;
    }
  }
}

static void switch_recompute_stp(switch_context_t* context, uint32_t now_ms) {
  switch_bridge_id_t previous_root_id = context->root_id;
  uint32_t previous_root_cost = context->root_path_cost;
  size_t previous_root_port = context->root_port;
  switch_stp_port_role_t previous_roles[SWITCH_DEVICE_CAPACITY] = {0};
  switch_stp_port_state_t previous_states[SWITCH_DEVICE_CAPACITY] = {0};
  for (size_t i = 0; i < context->port_count; ++i) {
    previous_roles[i] = context->ports[i].stp_role;
    previous_states[i] = context->ports[i].stp_state;
  }

  switch_expire_neighbors(context, now_ms);
  context->root_id = context->bridge_id;
  context->root_path_cost = 0;
  context->root_port = context->port_count;
  for (size_t i = 0; i < context->port_count; ++i) {
    const switch_port_t* port = &context->ports[i];
    if (!port->started || !port->stp_neighbor.valid) continue;
    const uint32_t candidate_cost = port->stp_neighbor.root_path_cost + port->stp_path_cost;
    if (switch_compare_priority_vector(port->stp_neighbor.root_id, candidate_cost, port->stp_neighbor.bridge_id, port->stp_neighbor.port_id, context->root_id, context->root_path_cost, context->bridge_id, (uint16_t)(context->root_port + 1)) < 0) {
      context->root_id = port->stp_neighbor.root_id;
      context->root_path_cost = candidate_cost;
      context->root_port = i;
    }
  }

  for (size_t i = 0; i < context->port_count; ++i) {
    switch_port_t* port = &context->ports[i];
    if (!port->started) {
      port->stp_role = SWITCH_STP_PORT_ROLE_DISABLED;
      port->stp_state = SWITCH_STP_PORT_STATE_DISABLED;
      continue;
    }
    if (context->root_port == i && context->root_id != context->bridge_id) {
      port->stp_role = SWITCH_STP_PORT_ROLE_ROOT;
      port->stp_state = SWITCH_STP_PORT_STATE_FORWARDING;
      continue;
    }
    if (!port->stp_neighbor.valid || switch_compare_priority_vector(context->root_id, context->root_path_cost, context->bridge_id, port->stp_port_id, port->stp_neighbor.root_id, port->stp_neighbor.root_path_cost, port->stp_neighbor.bridge_id, port->stp_neighbor.port_id) <= 0) {
      port->stp_role = SWITCH_STP_PORT_ROLE_DESIGNATED;
      port->stp_state = SWITCH_STP_PORT_STATE_FORWARDING;
    } else {
      port->stp_role = SWITCH_STP_PORT_ROLE_ALTERNATE;
      port->stp_state = SWITCH_STP_PORT_STATE_BLOCKING;
    }
  }

  bool changed = previous_root_id != context->root_id || previous_root_cost != context->root_path_cost || previous_root_port != context->root_port;
  for (size_t i = 0; i < context->port_count && !changed; ++i) {
    changed = previous_roles[i] != context->ports[i].stp_role || previous_states[i] != context->ports[i].stp_state;
  }
  if (changed) {
    switch_flag_topology_change(context, "spanning-tree convergence updated");
  }
}

static bool switch_write_bpdu(switch_context_t* context, size_t port_index, size_t* forwarded_bytes) {
  switch_port_t* port = &context->ports[port_index];
  if (!port->started || port->stp_role == SWITCH_STP_PORT_ROLE_ALTERNATE || port->stp_role == SWITCH_STP_PORT_ROLE_DISABLED) {
    return true;
  }
  const long before = ftell(port->destination);
  if (before < 0) {
    return false;
  }
  mac_address_t src_mac = {0};
  switch_bridge_id_to_mac(context->bridge_id, src_mac);
  switch_stp_bpdu_t bpdu = {
      .llc_dsap = SWITCH_STP_LLC_DSAP,
      .llc_ssap = SWITCH_STP_LLC_SSAP,
      .llc_control = SWITCH_STP_LLC_CONTROL,
      .protocol_id = SWITCH_STP_PROTOCOL_ID,
      .version = SWITCH_STP_VERSION,
      .type = SWITCH_STP_TYPE_CONFIG,
      .flags = switch_now_ms() < context->topology_change_until_ms ? SWITCH_STP_FLAG_TC : 0,
      .root_id = context->root_id,
      .root_path_cost = context->root_path_cost,
      .bridge_id = context->bridge_id,
      .port_id = port->stp_port_id,
  };
  ethernet_frame_data_t frame = {
      .tagged = false,
      .type_or_length = sizeof(bpdu),
      .data_length = sizeof(bpdu),
      .data = &bpdu,
  };
  memcpy(frame.dst_addr, switch_stp_destination_mac, sizeof(frame.dst_addr));
  memcpy(frame.src_addr, src_mac, sizeof(frame.src_addr));
  const bool written = ethernet_write_frame(port->destination, &frame);
  const long after = ftell(port->destination);
  if (!written || after < before || fflush(port->destination) != 0) {
    return false;
  }
  *forwarded_bytes += (size_t)(after - before);
  ++port->stp_tx_bpdus;
  return true;
}

static bool switch_send_bpdus(switch_context_t* context, uint32_t now_ms, uint32_t* last_bpdu_ms, size_t* forwarded_bytes) {
  if (now_ms - *last_bpdu_ms < SWITCH_STP_HELLO_TIME_MS) {
    return true;
  }
  *last_bpdu_ms = now_ms;
  for (size_t i = 0; i < context->port_count; ++i) {
    if (!switch_write_bpdu(context, i, &forwarded_bytes[i])) {
      return false;
    }
  }
  return true;
}

static bool forward_frame(switch_port_t* port, const ethernet_frame_view_t* frame, uint16_t vlan_id, size_t* forwarded_bytes) {
  const long before = ftell(port->destination);
  if (before < 0) return false;
  ethernet_frame_data_t output = {
      .tagged = port->mode == SWITCH_PORT_TRUNK,
      .priority = frame->priority,
      .drop_eligible = frame->drop_eligible,
      .vlan_id = vlan_id,
      .type_or_length = frame->type_or_length,
      .data_length = frame->client_data_length,
      .data = frame->data,
  };
  memcpy(output.dst_addr, frame->header.dst_mac, sizeof(output.dst_addr));
  memcpy(output.src_addr, frame->header.src_mac, sizeof(output.src_addr));
  const bool written = ethernet_write_frame(port->destination, &output);
  const long after = ftell(port->destination);
  if (!written || after < before || fflush(port->destination) != 0) return false;
  *forwarded_bytes += (size_t)(after - before);
  return true;
}

static bool forward_ethernet(switch_context_t* context, size_t* forwarded_bytes, size_t ingress_port, const uint8_t* bytes, size_t byte_count) {
  ethernet_frame_view_t frame = {0};
  uint16_t vlan_id = 0;
  switch_port_t* source_port = &context->ports[ingress_port];
  if (!ethernet_parse_frame(bytes, byte_count, &frame) || !port_accepts_vlan(source_port, &frame, &vlan_id)) {
    return true;
  }
  if (source_port->stp_state != SWITCH_STP_PORT_STATE_FORWARDING) {
    fprintf(stdout, "STP drop: blocked ingress on port %zu in VLAN %u.\n", ingress_port + 1, vlan_id);
    return true;
  }
  const bool known_source = fdb_table_find(context->devices, frame.header.src_mac, vlan_id) != NULL;
  if (!fdb_table_learn(context->devices, frame.header.src_mac, vlan_id, ingress_port) && !ethernet_mac_is_group(frame.header.src_mac)) {
    fputs("Switch device table is full; cannot learn another MAC address.\n", stderr);
  } else if (!known_source && !ethernet_mac_is_group(frame.header.src_mac)) {
    fputs("Learned ", stdout);
    ethernet_mac_print(stdout, frame.header.src_mac);
    fprintf(stdout, " in VLAN %u on port %zu.\n", vlan_id, ingress_port + 1);
  }

  bool targets[SWITCH_DEVICE_CAPACITY] = {false};
  if (ethernet_mac_is_group(frame.header.dst_mac)) {
    for (size_t i = 0; i < context->port_count; ++i) {
      targets[i] = i != ingress_port && context->ports[i].stp_state == SWITCH_STP_PORT_STATE_FORWARDING && switch_port_can_forward_vlan(&context->ports[i], vlan_id);
    }
  } else {
    fdb_entry_t* destination = fdb_table_find(context->devices, frame.header.dst_mac, vlan_id);
    if (destination && destination->port != ingress_port && context->ports[destination->port].stp_state == SWITCH_STP_PORT_STATE_FORWARDING) {
      targets[destination->port] = true;
    } else if (!destination) {
      for (size_t i = 0; i < context->port_count; ++i) {
        targets[i] = i != ingress_port && context->ports[i].stp_state == SWITCH_STP_PORT_STATE_FORWARDING && switch_port_can_forward_vlan(&context->ports[i], vlan_id);
      }
    }
  }

  fputs("Switch frame: ingress=", stdout);
  fprintf(stdout, "%zu bytes=%zu dst=", ingress_port + 1, byte_count);
  ethernet_mac_print(stdout, frame.header.dst_mac);
  fputs(" src=", stdout);
  ethernet_mac_print(stdout, frame.header.src_mac);
  fprintf(stdout, " VLAN=%u", vlan_id);
  if (frame.format == ETHERNET_FRAME_FORMAT_II) fprintf(stdout, " EtherType=0x%04X", frame.type_or_length);
  else
    fprintf(stdout, " IEEE802.3-length=%u", frame.type_or_length);
  fputs(" egress=", stdout);
  bool first_target = true;
  for (size_t i = 0; i < context->port_count; ++i) {
    if (targets[i]) {
      fprintf(stdout, "%s%zu", first_target ? "" : ",", i + 1);
      first_target = false;
    }
  }
  fputs(first_target ? "drop\n" : "\n", stdout);

  for (size_t i = 0; i < context->port_count; ++i) {
    if (targets[i] && !forward_frame(&context->ports[i], &frame, vlan_id, &forwarded_bytes[i])) {
      return false;
    }
  }
  return true;
}

static bool switch_handle_bpdu(switch_context_t* context, size_t port_index, const switch_stp_bpdu_t* bpdu, uint32_t now_ms) {
  switch_port_t* port = &context->ports[port_index];
  const bool topology_change = (bpdu->flags & SWITCH_STP_FLAG_TC) != 0;
  if (topology_change && (!port->stp_neighbor.valid || !port->stp_neighbor.topology_change)) {
    switch_flag_topology_change(context, "received topology-change BPDU");
  }
  port->stp_neighbor = (switch_stp_neighbor_t) {
      .valid = true,
      .root_id = bpdu->root_id,
      .root_path_cost = bpdu->root_path_cost,
      .bridge_id = bpdu->bridge_id,
      .port_id = bpdu->port_id,
      .topology_change = topology_change,
      .last_seen_ms = now_ms,
  };
  ++port->stp_rx_bpdus;
  fprintf(stdout, "STP BPDU: port=%zu root=", port_index + 1);
  switch_bridge_id_print(stdout, bpdu->root_id);
  fputs(" bridge=", stdout);
  switch_bridge_id_print(stdout, bpdu->bridge_id);
  fprintf(stdout, " cost=%u%s.\n", bpdu->root_path_cost, topology_change ? " TC" : "");
  return true;
}

static bool process_port(switch_context_t* context, size_t* forwarded_bytes, size_t port_index, uint32_t now_ms) {
  switch_port_t* source_port = &context->ports[port_index];
  size_t offset = 0;
  while (offset < source_port->buffer_length) {
    const size_t remaining = source_port->buffer_length - offset;
    vnet_frame_header_t control = {0};
    if (remaining >= sizeof(control) && vnet_parse_frame(source_port->buffer + offset, sizeof(control), &control)) {
      if (strcmpi(control.destination_path, source_port->path) == 0 && control.type == VNET_FRAME_CONNECTION_END) {
        fdb_table_remove_port(context->devices, port_index);
        source_port->stp_neighbor.valid = false;
        fprintf(stdout, "Port %zu disconnected; removed its learned devices.\n", port_index + 1);
      }
      offset += sizeof(control);
      continue;
    }
    if (!ethernet_frame_is_start(source_port->buffer + offset, remaining)) {
      ++offset;
      continue;
    }
    size_t end = offset + 1;
    while (end < source_port->buffer_length && !ethernet_frame_is_start(source_port->buffer + end, source_port->buffer_length - end) && !vnet_frame_has_prefix(source_port->buffer + end, source_port->buffer_length - end)) {
      ++end;
    }
    ethernet_frame_view_t frame = {0};
    if (ethernet_parse_frame(source_port->buffer + offset, end - offset, &frame)) {
      switch_stp_bpdu_t bpdu = {0};
      if (switch_parse_bpdu(&frame, &bpdu)) {
        if (!switch_handle_bpdu(context, port_index, &bpdu, now_ms)) return false;
      } else if (!forward_ethernet(context, forwarded_bytes, port_index, source_port->buffer + offset, end - offset)) {
        return false;
      }
      offset = end;
      continue;
    }
    if (end == source_port->buffer_length && remaining < sizeof(ethernet_header_t) + sizeof(ethernet_vlan_tag_t) + ETHERNET_MIN_DATA_LEN + sizeof(ethernet_footer_t)) break;
    ++offset;
  }
  if (offset > 0) {
    memmove(source_port->buffer, source_port->buffer + offset, source_port->buffer_length - offset);
    source_port->buffer_length -= offset;
  }
  return true;
}

static bool parse_trunk_vlans(switch_port_t* port, const char* text) {
  const char* cursor = text;
  bool any = false;
  while (*cursor) {
    uint16_t vlan_id = 0;
    if (*cursor < '0' || *cursor > '9') return false;
    while (*cursor >= '0' && *cursor <= '9') {
      vlan_id = (uint16_t)(vlan_id * 10 + (uint16_t)(*cursor++ - '0'));
      if (vlan_id > ETHERNET_VLAN_ID_MAX) return false;
    }
    if (vlan_id == 0 || port->allowed_vlans[vlan_id]) return false;
    port->allowed_vlans[vlan_id] = true;
    any = true;
    if (*cursor == '\0') break;
    if (*cursor++ != ',') return false;
  }
  return any;
}

int main(int argc, char** argv) {
  if (argc < 6) {
    fprintf(stderr, "Usage: switch <file> [-bridge <priority> <mac-address>] -f [access <vlan> | trunk <vlan,...>] <other file>...\n");
    return EXIT_FAILURE;
  }
  const char* switch_path = argv[1];
  mac_address_t bridge_mac = {0};
  switch_default_bridge_mac(switch_path, bridge_mac);
  switch_bridge_id_t bridge_id = switch_bridge_id_make(SWITCH_STP_DEFAULT_PRIORITY, bridge_mac);
  int argument = 2;
  while (argument < argc && strcmpi(argv[argument], "-f") != 0) {
    if (strcmpi(argv[argument], "-bridge") == 0) {
      uint16_t priority = 0;
      if (argument + 2 >= argc || !switch_parse_bridge_priority(argv[argument + 1], &priority) || !ethernet_mac_parse(argv[argument + 2], bridge_mac) || ethernet_mac_is_group(bridge_mac)) {
        fputs("Bridge priority must be 0 through 61440 in steps of 4096, and the bridge MAC must be unicast.\n", stderr);
        return EXIT_FAILURE;
      }
      bridge_id = switch_bridge_id_make(priority, bridge_mac);
      argument += 3;
      continue;
    }
    fprintf(stderr, "Usage: switch <file> [-bridge <priority> <mac-address>] -f [access <vlan> | trunk <vlan,...>] <other file>...\n");
    return EXIT_FAILURE;
  }
  if (argument >= argc || strcmpi(argv[argument], "-f") != 0) {
    fprintf(stderr, "Usage: switch <file> [-bridge <priority> <mac-address>] -f [access <vlan> | trunk <vlan,...>] <other file>...\n");
    return EXIT_FAILURE;
  }
  ++argument;

  const size_t maximum_port_count = (size_t)(argc - argument) / 3;
  switch_port_t* ports = calloc(maximum_port_count, sizeof(*ports));
  fdb_entry_t* device_entries = calloc(SWITCH_DEVICE_CAPACITY, sizeof(*device_entries));
  long* source_ends = calloc(maximum_port_count, sizeof(*source_ends));
  size_t* forwarded_bytes = calloc(maximum_port_count, sizeof(*forwarded_bytes));
  FILE* switch_destination = NULL;
  fdb_table_t devices;
  int status = EXIT_SUCCESS;
  cmd_app_t commands = {0};
  bool commands_started = false;
  size_t port_count = 0;
  if (!ports || !device_entries || !source_ends || !forwarded_bytes) {
    fputs("Could not allocate switch state.\n", stderr);
    status = EXIT_FAILURE;
    goto cleanup;
  }
  fdb_table_init(&devices, device_entries, SWITCH_DEVICE_CAPACITY);

  for (; argument < argc;) {
    if (port_count == SWITCH_DEVICE_CAPACITY || argument + 2 >= argc) {
      fputs("Usage: switch <file> [-bridge <priority> <mac-address>] -f [access <vlan> | trunk <vlan,...>] <other file>...\n", stderr);
      status = EXIT_FAILURE;
      goto cleanup;
    }
    switch_port_t* port = &ports[port_count];
    const char* mode = argv[argument++];
    const char* vlan_text = argv[argument++];
    port->path = argv[argument++];
    port->stp_path_cost = SWITCH_STP_DEFAULT_PATH_COST;
    port->stp_port_id = (uint16_t)(port_count + 1);
    port->stp_role = SWITCH_STP_PORT_ROLE_DESIGNATED;
    port->stp_state = SWITCH_STP_PORT_STATE_FORWARDING;
    if (strcmpi(mode, "access") == 0) {
      port->mode = SWITCH_PORT_ACCESS;
      if (!cmd_app_parse_uint16(vlan_text, &port->access_vlan_id) || port->access_vlan_id == 0 || port->access_vlan_id > ETHERNET_VLAN_ID_MAX) {
        fputs("Access port VLAN must be 1 through 4094.\n", stderr);
        status = EXIT_FAILURE;
        goto cleanup;
      }
    } else if (strcmpi(mode, "trunk") == 0) {
      port->mode = SWITCH_PORT_TRUNK;
      if (!parse_trunk_vlans(port, vlan_text)) {
        fputs("Trunk VLANs must be a unique comma-separated list in the range 1 through 4094.\n", stderr);
        status = EXIT_FAILURE;
        goto cleanup;
      }
    } else {
      fputs("Port mode must be access or trunk.\n", stderr);
      status = EXIT_FAILURE;
      goto cleanup;
    }
    if (port->path[0] == '-' || strcmpi(port->path, switch_path) == 0) {
      fputs("Each port must be a file distinct from the switch file.\n", stderr);
      status = EXIT_FAILURE;
      goto cleanup;
    }
    for (size_t i = 0; i < port_count; ++i) {
      if (strcmpi(port->path, ports[i].path) == 0) {
        fputs("Each port file must be specified only once.\n", stderr);
        status = EXIT_FAILURE;
        goto cleanup;
      }
    }
    ++port_count;
  }

  switch_destination = fopen(switch_path, "ab");
  if (!switch_destination) {
    fprintf(stderr, "Could not open the switch file '%s'.\n", switch_path);
    status = EXIT_FAILURE;
    goto cleanup;
  }
  for (size_t i = 0; i < port_count; ++i) {
    ports[i].source = fopen(ports[i].path, "rb");
    ports[i].destination = fopen(ports[i].path, "ab");
    if (!ports[i].source || !ports[i].destination || fseek(ports[i].source, 0, SEEK_END) != 0) {
      fprintf(stderr, "Could not open files for switch port %zu.\n", i + 1);
      status = EXIT_FAILURE;
      goto cleanup;
    }
    if (!vnet_frame_write(switch_destination, VNET_FRAME_CONNECTION_START, ports[i].path, switch_path) || !vnet_frame_write(ports[i].destination, VNET_FRAME_CONNECTION_START, switch_path, ports[i].path) || fseek(ports[i].source, (long)sizeof(vnet_frame_header_t), SEEK_CUR) != 0) {
      status = EXIT_FAILURE;
      goto cleanup;
    }
    ports[i].started = true;
    fprintf(stdout, "Opened bilateral connection between switch '%s' and '%s' on port %zu.\n", switch_path, ports[i].path, i + 1);
  }

  switch_context_t context = {
      .path = switch_path,
      .ports = ports,
      .port_count = port_count,
      .devices = &devices,
      .bridge_id = bridge_id,
      .root_id = bridge_id,
      .root_port = port_count,
  };
  cmd_app_init(&commands);
  if (!cmd_app_register(&commands, "info", "Show switch ports, STP state, VLAN policies, and the forwarding database.", command_info, &context) || !cmd_app_register(&commands, "fdb", "Show, delete, or flush learned MAC mappings.", command_fdb, &context) || !cmd_app_register(&commands, "stp", "Show or tune STP bridge identity and path costs.", command_stp, &context) || !cmd_app_start(&commands)) {
    fputs("Could not start the command application.\n", stderr);
    status = EXIT_FAILURE;
    goto cleanup;
  }
  commands_started = true;

  uint32_t last_bpdu_ms = 0;
  while (cmd_app_is_running(&commands)) {
    const uint32_t now_ms = switch_now_ms();
    switch_recompute_stp(&context, now_ms);
    for (size_t i = 0; i < port_count; ++i) {
      if (!get_file_end(ports[i].source, &source_ends[i])) {
        fprintf(stderr, "Could not snapshot switch port %zu.\n", i + 1);
        status = EXIT_FAILURE;
        goto cleanup;
      }
    }
    memset(forwarded_bytes, 0, port_count * sizeof(*forwarded_bytes));
    for (size_t i = 0; i < port_count; ++i) {
      const long position = ftell(ports[i].source);
      const size_t capacity = sizeof(ports[i].buffer) - ports[i].buffer_length;
      const long remaining = source_ends[i] - position;
      const size_t requested = remaining <= 0 ? 0 : (unsigned long)remaining < capacity ? (size_t)remaining : capacity;
      const size_t read_count = fread(ports[i].buffer + ports[i].buffer_length, 1, requested, ports[i].source);
      if (read_count > 0) {
        ports[i].buffer_length += read_count;
        if (!process_port(&context, forwarded_bytes, i, now_ms)) {
          status = EXIT_FAILURE;
          goto cleanup;
        }
      }
      if (position < 0 || ferror(ports[i].source) || ports[i].buffer_length == sizeof(ports[i].buffer)) {
        fprintf(stderr, "Could not process traffic for switch port %zu.\n", i + 1);
        status = EXIT_FAILURE;
        goto cleanup;
      }
      clearerr(ports[i].source);
    }
    switch_recompute_stp(&context, now_ms);
    if (!switch_send_bpdus(&context, now_ms, &last_bpdu_ms, forwarded_bytes)) {
      status = EXIT_FAILURE;
      goto cleanup;
    }
    for (size_t i = 0; i < port_count; ++i) {
      if (forwarded_bytes[i] > 0 && fseek(ports[i].source, (long)forwarded_bytes[i], SEEK_CUR) != 0) {
        fprintf(stderr, "Could not skip switch output on port %zu.\n", i + 1);
        status = EXIT_FAILURE;
        goto cleanup;
      }
    }
    if (fflush(stdout) != 0) {
      status = EXIT_FAILURE;
      goto cleanup;
    }
    thread_sleep(SLEEP_INTERVAL_MS);
  }

cleanup:
  if (commands_started) {
    cmd_app_stop(&commands);
    cmd_app_join(&commands);
  }
  if (switch_destination) {
    for (size_t i = 0; i < port_count; ++i) {
      if (ports && ports[i].started && (!vnet_frame_write(switch_destination, VNET_FRAME_CONNECTION_END, ports[i].path, switch_path) || !vnet_frame_write(ports[i].destination, VNET_FRAME_CONNECTION_END, switch_path, ports[i].path))) {
        status = EXIT_FAILURE;
      }
    }
  }
  for (size_t i = 0; ports && i < port_count; ++i) {
    if (ports[i].source) fclose(ports[i].source);
    if (ports[i].destination) fclose(ports[i].destination);
  }
  if (switch_destination) fclose(switch_destination);
  free(forwarded_bytes);
  free(source_ends);
  free(device_entries);
  free(ports);
  return status;
}

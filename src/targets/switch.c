#include "switch.h"

static void print_port(const switch_port_t* port, size_t index) {
  fprintf(stdout, "  %zu: %s  ", index + 1, port->path);
  if (port->mode == SWITCH_PORT_ACCESS) {
    fprintf(stdout, "access VLAN %u\n", port->access_vlan_id);
    return;
  }
  fputs("trunk VLANs ", stdout);
  bool first = true;
  for (uint16_t vlan_id = 1; vlan_id <= ETHERNET_VLAN_ID_MAX; ++vlan_id) {
    if (port->allowed_vlans[vlan_id]) {
      fprintf(stdout, "%s%u", first ? "" : ",", vlan_id);
      first = false;
    }
  }
  fputs(first ? "none\n" : "\n", stdout);
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
  fprintf(stdout, "Forwarding database (%zu):\n", context->devices->count);
  for (size_t i = 0; i < context->devices->count; ++i) {
    fputs("  ", stdout);
    ethernet_mac_print(stdout, context->devices->entries[i].mac);
    fprintf(stdout, "  VLAN %u  port %zu (%s)\n", context->devices->entries[i].vlan_id, context->devices->entries[i].port + 1, context->ports[context->devices->entries[i].port].path);
  }
}

static void command_fdb(void* argument, char* arguments) {
  switch_context_t* context = argument;
  char* cursor = arguments;
  char* action = cmd_app_next_argument(&cursor);
  if (!action || strcmpi(action, "show") == 0) {
    if (action && cmd_app_next_argument(&cursor)) {
      fputs("Usage: fdb [show|delete <mac-address> <vlan>]\n", stderr);
      return;
    }
    fprintf(stdout, "Forwarding database (%zu):\n", context->devices->count);
    for (size_t i = 0; i < context->devices->count; ++i) {
      fputs("  ", stdout);
      ethernet_mac_print(stdout, context->devices->entries[i].mac);
      fprintf(stdout, "  VLAN %u  port %zu (%s)\n", context->devices->entries[i].vlan_id, context->devices->entries[i].port + 1, context->ports[context->devices->entries[i].port].path);
    }
    return;
  }
  char* mac_text = cmd_app_next_argument(&cursor);
  char* vlan_text = cmd_app_next_argument(&cursor);
  mac_address_t mac = {0};
  uint16_t vlan_id = 0;
  if (strcmpi(action, "delete") != 0 || !mac_text || !vlan_text || cmd_app_next_argument(&cursor) || !ethernet_mac_parse(mac_text, mac) || !cmd_app_parse_uint16(vlan_text, &vlan_id) || vlan_id > ETHERNET_VLAN_ID_MAX) {
    fputs("Usage: fdb [show|delete <mac-address> <vlan>]\n", stderr);
    return;
  }
  const bool removed = fdb_table_remove(context->devices, mac, vlan_id);
  fputs(removed ? "FDB entry removed.\n" : "No such FDB entry.\n", removed ? stdout : stderr);
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

static bool forward_frame(switch_port_t* port, const ethernet_frame_view_t* frame, uint16_t vlan_id, const uint8_t* bytes, size_t byte_count, size_t* forwarded_bytes) {
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
  (void)vlan_id;
  return true;
}

/* Broadcast, multicast, and unknown unicast are flooded only through ports participating in the ingress VLAN. */
static bool forward_ethernet(switch_port_t* ports, size_t port_count, fdb_table_t* devices, size_t* forwarded_bytes, size_t ingress_port, const uint8_t* bytes, size_t byte_count) {
  ethernet_frame_view_t frame = {0};
  uint16_t vlan_id = 0;
  if (!ethernet_parse_frame(bytes, byte_count, &frame) || !port_accepts_vlan(&ports[ingress_port], &frame, &vlan_id)) {
    return true;
  }
  const bool known_source = fdb_table_find(devices, frame.header.src_mac, vlan_id) != NULL;
  if (!fdb_table_learn(devices, frame.header.src_mac, vlan_id, ingress_port) && !ethernet_mac_is_group(frame.header.src_mac)) {
    fputs("Switch device table is full; cannot learn another MAC address.\n", stderr);
  } else if (!known_source && !ethernet_mac_is_group(frame.header.src_mac)) {
    fputs("Learned ", stdout);
    ethernet_mac_print(stdout, frame.header.src_mac);
    fprintf(stdout, " in VLAN %u on port %zu.\n", vlan_id, ingress_port + 1);
  }

  bool targets[SWITCH_DEVICE_CAPACITY] = {false};
  if (ethernet_mac_is_group(frame.header.dst_mac)) {
    for (size_t i = 0; i < port_count; ++i) {
      targets[i] = i != ingress_port && (ports[i].mode == SWITCH_PORT_ACCESS ? ports[i].access_vlan_id == vlan_id : ports[i].allowed_vlans[vlan_id]);
    }
  } else {
    fdb_entry_t* destination = fdb_table_find(devices, frame.header.dst_mac, vlan_id);
    if (destination && destination->port != ingress_port) {
      targets[destination->port] = true;
    } else if (!destination) {
      for (size_t i = 0; i < port_count; ++i) {
        targets[i] = i != ingress_port && (ports[i].mode == SWITCH_PORT_ACCESS ? ports[i].access_vlan_id == vlan_id : ports[i].allowed_vlans[vlan_id]);
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
  for (size_t i = 0; i < port_count; ++i) {
    if (targets[i]) {
      fprintf(stdout, "%s%zu", first_target ? "" : ",", i + 1);
      first_target = false;
    }
  }
  fputs(first_target ? "drop\n" : "\n", stdout);

  for (size_t i = 0; i < port_count; ++i) {
    if (targets[i] && !forward_frame(&ports[i], &frame, vlan_id, bytes, byte_count, &forwarded_bytes[i])) {
      return false;
    }
  }
  return true;
}

static bool process_port(switch_port_t* ports, size_t port_count, fdb_table_t* devices, size_t* forwarded_bytes, size_t port) {
  switch_port_t* source_port = &ports[port];
  size_t offset = 0;
  while (offset < source_port->buffer_length) {
    const size_t remaining = source_port->buffer_length - offset;
    vnet_frame_header_t control = {0};
    if (remaining >= sizeof(control) && vnet_parse_frame(source_port->buffer + offset, sizeof(control), &control)) {
      if (strcmpi(control.destination_path, source_port->path) == 0 && control.type == VNET_FRAME_CONNECTION_END) {
        fdb_table_remove_port(devices, port);
        fprintf(stdout, "Port %zu disconnected; removed its learned devices.\n", port + 1);
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
      if (!forward_ethernet(ports, port_count, devices, forwarded_bytes, port, source_port->buffer + offset, end - offset)) return false;
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
  if (argc < 6 || strcmpi(argv[2], "-f") != 0) {
    fprintf(stderr, "Usage: switch <file> -f [access <vlan> | trunk <vlan,...>] <other file>...\n");
    return EXIT_FAILURE;
  }
  const char* switch_path = argv[1];
  const size_t maximum_port_count = (size_t)(argc - 3) / 3;
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

  for (int argument = 3; argument < argc;) {
    if (port_count == SWITCH_DEVICE_CAPACITY || argument + 2 >= argc) {
      fputs("Usage: switch <file> -f [access <vlan> | trunk <vlan,...>] <other file>...\n", stderr);
      status = EXIT_FAILURE;
      goto cleanup;
    }
    switch_port_t* port = &ports[port_count];
    const char* mode = argv[argument++];
    const char* vlan_text = argv[argument++];
    port->path = argv[argument++];
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

  switch_context_t context = {.path = switch_path, .ports = ports, .port_count = port_count, .devices = &devices};
  cmd_app_init(&commands);
  if (!cmd_app_register(&commands, "info", "Show switch ports, VLAN policies, and the forwarding database.", command_info, &context) || !cmd_app_register(&commands, "fdb", "Show or delete a learned MAC mapping in a VLAN.", command_fdb, &context) || !cmd_app_start(&commands)) {
    fputs("Could not start the command application.\n", stderr);
    status = EXIT_FAILURE;
    goto cleanup;
  }
  commands_started = true;

  while (cmd_app_is_running(&commands)) {
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
        if (!process_port(ports, port_count, &devices, forwarded_bytes, i)) {
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

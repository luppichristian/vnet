/*
Learning Ethernet switch for append-only VNet traffic files.
OSI/ISO layer: Layer 2 (data link); it learns and forwards by Ethernet MAC address.
*/

#include <cmd_app.h>
#include <ethernet.h>
#include <futils.h>
#include <fdb_table.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread.h>
#include <vnet.h>

#define SWITCH_DEVICE_CAPACITY 256
#define SWITCH_BUFFER_SIZE     8192
#define SLEEP_INTERVAL_MS      5

typedef struct switch_port {
  const char* path;
  FILE* source;
  FILE* destination;
  bool started;
  uint8_t buffer[SWITCH_BUFFER_SIZE];
  size_t buffer_length;
} switch_port_t;

typedef struct switch_context {
  const char* path;
  const switch_port_t* ports;
  size_t port_count;
} switch_context_t;

static cmd_app_t* command_app;

static void handle_signal(int sig) {
  if (sig == SIGINT && command_app) {
    cmd_app_stop(command_app);
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
    fprintf(stdout, "  %zu: %s\n", i + 1, context->ports[i].path);
  }
}

static bool forward_frame(switch_port_t* ports, size_t port, const uint8_t* bytes, size_t byte_count, size_t* forwarded_bytes) {
  if (fwrite(bytes, 1, byte_count, ports[port].destination) != byte_count || fflush(ports[port].destination) != 0) {
    return false;
  }
  *forwarded_bytes += byte_count;
  return true;
}

/* Broadcast, multicast, and unknown unicast are flooded; known unicast uses one learned port. */
static bool forward_ethernet(switch_port_t* ports, size_t port_count, fdb_table_t* devices, size_t* forwarded_bytes, size_t ingress_port, const uint8_t* bytes, size_t byte_count) {
  ethernet_frame_view_t frame = {0};
  if (!ethernet_parse_frame(bytes, byte_count, &frame)) {
    return true;
  }
  const bool known_source = fdb_table_find(devices, frame.header.src_mac) != NULL;
  if (!fdb_table_learn(devices, frame.header.src_mac, ingress_port) && !ethernet_mac_is_group(frame.header.src_mac)) {
    fputs("Switch device table is full; cannot learn another MAC address.\n", stderr);
  } else if (!known_source && !ethernet_mac_is_group(frame.header.src_mac)) {
    fputs("Learned ", stdout);
    ethernet_mac_print(stdout, frame.header.src_mac);
    fprintf(stdout, " on port %zu.\n", ingress_port + 1);
  }

  bool targets[SWITCH_DEVICE_CAPACITY] = {false};
  if (ethernet_mac_is_group(frame.header.dst_mac)) {
    for (size_t i = 0; i < port_count; ++i) {
      targets[i] = i != ingress_port;
    }
  } else {
    fdb_entry_t* destination = fdb_table_find(devices, frame.header.dst_mac);
    if (destination && destination->port != ingress_port) {
      targets[destination->port] = true;
    } else if (!destination) {
      for (size_t i = 0; i < port_count; ++i) {
        targets[i] = i != ingress_port;
      }
    }
  }

  for (size_t i = 0; i < port_count; ++i) {
    if (targets[i] && !forward_frame(ports, i, bytes, byte_count, &forwarded_bytes[i])) {
      return false;
    }
  }
  return true;
}

static void handle_vnet(fdb_table_t* devices, size_t port, const vnet_frame_header_t* control) {
  if (control->type == VNET_FRAME_CONNECTION_END) {
    fdb_table_remove_port(devices, port);
    fprintf(stdout, "Port %zu disconnected; removed its learned devices.\n", port + 1);
  }
}

static bool process_port(switch_port_t* ports, size_t port_count, fdb_table_t* devices, size_t* forwarded_bytes, size_t port) {
  switch_port_t* source_port = &ports[port];
  size_t offset = 0;
  while (offset < source_port->buffer_length) {
    const size_t remaining = source_port->buffer_length - offset;
    vnet_frame_header_t control = {0};
    if (remaining >= sizeof(control) && vnet_parse_frame(source_port->buffer + offset, sizeof(control), &control)) {
      if (strcmpi(control.destination_path, source_port->path) == 0) {
        handle_vnet(devices, port, &control);
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
      if (!forward_ethernet(ports, port_count, devices, forwarded_bytes, port, source_port->buffer + offset, end - offset)) {
        return false;
      }
      offset = end;
      continue;
    }
    if (end == source_port->buffer_length && remaining < sizeof(ethernet_header_t) + ETHERNET_MIN_DATA_LEN + sizeof(ethernet_footer_t)) {
      break;
    }
    ++offset;
  }
  if (offset > 0) {
    memmove(source_port->buffer, source_port->buffer + offset, source_port->buffer_length - offset);
    source_port->buffer_length -= offset;
  }
  return true;
}

int main(int argc, char** argv) {
  if (argc < 4 || strcmpi(argv[2], "-f") != 0) {
    fprintf(stderr, "Usage: switch <file> -f <other files>\n");
    return EXIT_FAILURE;
  }
  const char* switch_path = argv[1];
  const size_t port_count = (size_t)argc - 3;
  if (port_count > SWITCH_DEVICE_CAPACITY) {
    fprintf(stderr, "Too many switch ports.\n");
    return EXIT_FAILURE;
  }
  switch_port_t* ports = calloc(port_count, sizeof(*ports));
  fdb_entry_t* device_entries = calloc(SWITCH_DEVICE_CAPACITY, sizeof(*device_entries));
  long* source_ends = calloc(port_count, sizeof(*source_ends));
  size_t* forwarded_bytes = calloc(port_count, sizeof(*forwarded_bytes));
  FILE* switch_destination = NULL;
  fdb_table_t devices;
  int status = EXIT_SUCCESS;
  if (!ports || !device_entries || !source_ends || !forwarded_bytes) {
    fputs("Could not allocate switch state.\n", stderr);
    status = EXIT_FAILURE;
    goto cleanup;
  }
  fdb_table_init(&devices, device_entries, SWITCH_DEVICE_CAPACITY);

  signal(SIGINT, handle_signal);
  for (size_t i = 0; i < port_count; ++i) {
    ports[i].path = argv[i + 3];
    if (ports[i].path[0] == '-' || strcmpi(ports[i].path, switch_path) == 0) {
      fputs("Each port must be a file distinct from the switch file.\n", stderr);
      status = EXIT_FAILURE;
      goto cleanup;
    }
    for (size_t j = 0; j < i; ++j) {
      if (strcmpi(ports[i].path, ports[j].path) == 0) {
        fputs("Each port file must be specified only once.\n", stderr);
        status = EXIT_FAILURE;
        goto cleanup;
      }
    }
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

  cmd_app_t commands;
  cmd_app_init(&commands);
  if (!cmd_app_register(&commands, "info", "Show the switch file and connected port files.", command_info, &(switch_context_t) {.path = switch_path, .ports = ports, .port_count = port_count}) || !cmd_app_start(&commands)) {
    fputs("Could not start the command application.\n", stderr);
    status = EXIT_FAILURE;
    goto cleanup;
  }
  command_app = &commands;

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
      const size_t requested = remaining <= 0 ? 0 : (unsigned long)remaining < capacity ? (size_t)remaining
                                                                                        : capacity;
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
  if (command_app) {
    cmd_app_stop(command_app);
    cmd_app_join(command_app);
    command_app = NULL;
  }
  if (switch_destination) {
    for (size_t i = 0; i < port_count; ++i) {
      if (ports && ports[i].started) {
        if (!vnet_frame_write(switch_destination, VNET_FRAME_CONNECTION_END, ports[i].path, switch_path) || !vnet_frame_write(ports[i].destination, VNET_FRAME_CONNECTION_END, switch_path, ports[i].path)) {
          status = EXIT_FAILURE;
        }
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

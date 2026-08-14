#include "link.h"

#include <inttypes.h>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <time.h>
#endif

static uint64_t link_now_ms(void) {
#ifdef _WIN32
  return GetTickCount64();
#else
  struct timespec ts = {0};
  timespec_get(&ts, TIME_UTC);
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
#endif
}

static uint32_t link_rng_next(uint32_t* state) {
  *state = *state * 1664525u + 1013904223u;
  return *state;
}

static bool event_hits(uint32_t* state, uint16_t permyriad) {
  return permyriad > 0 && (link_rng_next(state) % 10000u) < permyriad;
}

static uint32_t randomized_latency_ms(link_port_t* port, const link_impairment_config_t* config) {
  if (config->jitter_ms == 0) return config->latency_ms;
  const uint32_t span = config->jitter_ms * 2u + 1u;
  const int64_t delta = (int64_t)(link_rng_next(&port->rng_state) % span) - (int64_t)config->jitter_ms;
  const int64_t delayed = (int64_t)config->latency_ms + delta;
  return delayed > 0 ? (uint32_t)delayed : 0;
}

static uint64_t serialization_delay_ms(size_t bytes, const link_impairment_config_t* config) {
  if (config->bandwidth_bps == 0) return 0;
  const uint64_t bits = (uint64_t)bytes * 8u;
  return (bits * 1000u + config->bandwidth_bps - 1u) / config->bandwidth_bps;
}

static void repair_fcs(uint8_t* bytes, size_t length) {
  if (length < sizeof(ethernet_header_t) + sizeof(ethernet_footer_t)) return;
  ethernet_frame_view_t frame = {0};
  if (!ethernet_parse_frame(bytes, length, &frame)) return;
  const size_t tag_length = frame.tagged ? sizeof(ethernet_vlan_tag_t) : 0;
  ethernet_footer_t* footer = (ethernet_footer_t*)(bytes + length - sizeof(ethernet_footer_t));
  footer->crc = crc32(bytes + ETHERNET_PREAMBLE_LEN + sizeof(frame.header.sfd), sizeof(frame.header.dst_mac) + sizeof(frame.header.src_mac) + sizeof(frame.header.type_or_length) + tag_length + frame.data_length);
}

static void corrupt_ethernet_frame(link_port_t* port, link_unit_t* unit) {
  if (unit->is_vnet || unit->length <= sizeof(ethernet_header_t) + sizeof(ethernet_footer_t)) return;
  const size_t first_mutable = sizeof(ethernet_header_t);
  const size_t last_mutable = unit->length - sizeof(ethernet_footer_t);
  if (last_mutable <= first_mutable) return;
  const size_t offset = first_mutable + (link_rng_next(&port->rng_state) % (uint32_t)(last_mutable - first_mutable));
  unit->bytes[offset] ^= (uint8_t)(1u << (link_rng_next(&port->rng_state) % 8u));
  repair_fcs(unit->bytes, unit->length);
  ++port->stats.corrupted_units;
}

static void fail_ethernet_fcs(link_port_t* port, link_unit_t* unit) {
  if (unit->is_vnet || unit->length < sizeof(ethernet_footer_t)) return;
  ethernet_footer_t* footer = (ethernet_footer_t*)(unit->bytes + unit->length - sizeof(ethernet_footer_t));
  footer->crc ^= 1u << (link_rng_next(&port->rng_state) % 31u);
  ++port->stats.fcs_failed_units;
}

static bool queue_push(link_port_t* port, const link_impairment_config_t* config, const link_unit_t* unit) {
  if (port->queue_length >= config->queue_capacity || port->queue_length >= LINK_QUEUE_CAPACITY) {
    ++port->stats.dropped_queue_full;
    return false;
  }
  port->queue[port->queue_length++] = *unit;
  return true;
}

static bool queue_unit(link_port_t* port, const link_impairment_config_t* config, link_unit_t* unit) {
  const uint64_t now = link_now_ms();
  const uint64_t base_ready = now + randomized_latency_ms(port, config);
  unit->ready_at_ms = base_ready > port->next_transmit_at_ms ? base_ready : port->next_transmit_at_ms;
  port->next_transmit_at_ms = unit->ready_at_ms + serialization_delay_ms(unit->length, config);
  if (event_hits(&port->rng_state, config->corruption_permyriad)) corrupt_ethernet_frame(port, unit);
  if (event_hits(&port->rng_state, config->fcs_failure_permyriad)) fail_ethernet_fcs(port, unit);
  if (config->reorder_permyriad > 0 && !unit->is_vnet && event_hits(&port->rng_state, config->reorder_permyriad)) {
    if (port->has_reorder_hold) {
      if (!queue_push(port, config, unit) || !queue_push(port, config, &port->reorder_hold)) {
        port->has_reorder_hold = false;
        return false;
      }
      port->has_reorder_hold = false;
      ++port->stats.reordered_units;
      return true;
    }
    port->reorder_hold = *unit;
    port->has_reorder_hold = true;
    return true;
  }
  if (port->has_reorder_hold) {
    if (!queue_push(port, config, unit) || !queue_push(port, config, &port->reorder_hold)) {
      port->has_reorder_hold = false;
      return false;
    }
    port->has_reorder_hold = false;
    ++port->stats.reordered_units;
    return true;
  }
  return queue_push(port, config, unit);
}

static void flush_reorder_hold(link_port_t* port, const link_impairment_config_t* config) {
  if (!port->has_reorder_hold) return;
  if (queue_push(port, config, &port->reorder_hold)) {
    port->has_reorder_hold = false;
  }
}

static bool try_extract_vnet(const uint8_t* bytes, size_t available, link_unit_t* unit, size_t* consumed) {
  if (available < sizeof(vnet_frame_header_t)) return false;
  if (!vnet_parse_frame(bytes, sizeof(vnet_frame_header_t), &(vnet_frame_header_t) {0})) return false;
  memcpy(unit->bytes, bytes, sizeof(vnet_frame_header_t));
  unit->length = sizeof(vnet_frame_header_t);
  unit->is_vnet = true;
  *consumed = sizeof(vnet_frame_header_t);
  return true;
}

static bool try_extract_ethernet(const uint8_t* bytes, size_t available, link_unit_t* unit, size_t* consumed) {
  if (!ethernet_frame_is_start(bytes, available)) return false;
  const size_t minimum = sizeof(ethernet_header_t) + ETHERNET_MIN_DATA_LEN + sizeof(ethernet_footer_t);
  if (available < minimum) return false;
  size_t end = 0;
  for (size_t i = minimum; i <= available; ++i) {
    if (i > minimum && (ethernet_frame_is_start(bytes + i, available - i) || vnet_frame_has_prefix(bytes + i, available - i))) {
      end = i;
      break;
    }
  }
  if (end == 0) end = available;
  ethernet_frame_view_t frame = {0};
  if (!ethernet_parse_frame(bytes, end, &frame) || end > LINK_MAX_UNIT_SIZE) return false;
  memcpy(unit->bytes, bytes, end);
  unit->length = end;
  unit->is_vnet = false;
  *consumed = end;
  return true;
}

static bool enqueue_available_units(connect_context_t* context, link_port_t* port) {
  size_t offset = 0;
  while (offset < port->buffer_length) {
    link_unit_t unit = {0};
    size_t consumed = 0;
    const size_t available = port->buffer_length - offset;
    if (try_extract_vnet(port->buffer + offset, available, &unit, &consumed) || try_extract_ethernet(port->buffer + offset, available, &unit, &consumed)) {
      ++port->stats.units_seen;
      if (unit.is_vnet) ++port->stats.vnet_frames_seen;
      else
        ++port->stats.ethernet_frames_seen;
      if (!context->link_up) {
        ++port->stats.dropped_link_down;
      } else if (!unit.is_vnet && event_hits(&port->rng_state, context->config.loss_permyriad)) {
        ++port->stats.dropped_loss;
      } else if (!queue_unit(port, &context->config, &unit)) {
        return false;
      }
      offset += consumed;
      continue;
    }
    break;
  }
  if (offset > 0) {
    memmove(port->buffer, port->buffer + offset, port->buffer_length - offset);
    port->buffer_length -= offset;
  }
  return true;
}

static bool forward_ready_units(link_port_t* port) {
  const uint64_t now = link_now_ms();
  while (port->queue_length > 0) {
    const link_unit_t* unit = &port->queue[0];
    if (unit->ready_at_ms > now) break;
    if (fwrite(unit->bytes, 1, unit->length, port->destination) != unit->length || fflush(port->destination) != 0) {
      return false;
    }
    port->injected_bytes += unit->length;
    ++port->stats.forwarded_units;
    port->stats.forwarded_bytes += unit->length;
    memmove(port->queue, port->queue + 1, sizeof(port->queue[0]) * (port->queue_length - 1));
    --port->queue_length;
  }
  return true;
}

static void print_config(const connect_context_t* context) {
  fprintf(stdout,
          "Latency: %u ms\nJitter: %u ms\nBandwidth: %u bps\nQueue: %u frames\nLoss: %.2f%%\nCorruption: %.2f%%\nFCS failure: %.2f%%\nReordering: %.2f%%\nSeed: %u\nLink state: %s\n",
          context->config.latency_ms,
          context->config.jitter_ms,
          context->config.bandwidth_bps,
          context->config.queue_capacity,
          context->config.loss_permyriad / 100.0,
          context->config.corruption_permyriad / 100.0,
          context->config.fcs_failure_permyriad / 100.0,
          context->config.reorder_permyriad / 100.0,
          context->config.seed,
          context->link_up ? "up" : "down");
}

static void print_port_stats(const link_port_t* port, size_t index) {
  fprintf(stdout,
          "Direction %zu: %s -> %s\n  seen=%" PRIu64 " ethernet=%" PRIu64 " vnet=%" PRIu64 " forwarded=%" PRIu64 " bytes=%" PRIu64 "\n  drop_down=%" PRIu64 " drop_queue=%" PRIu64 " drop_loss=%" PRIu64 " corrupt=%" PRIu64 " fcs_fail=%" PRIu64 " reorder=%" PRIu64 "\n  queued=%zu buffered=%zu injected=%zu\n",
          index + 1,
          port->source_path,
          port->destination_path,
          port->stats.units_seen,
          port->stats.ethernet_frames_seen,
          port->stats.vnet_frames_seen,
          port->stats.forwarded_units,
          port->stats.forwarded_bytes,
          port->stats.dropped_link_down,
          port->stats.dropped_queue_full,
          port->stats.dropped_loss,
          port->stats.corrupted_units,
          port->stats.fcs_failed_units,
          port->stats.reordered_units,
          port->queue_length + (port->has_reorder_hold ? 1u : 0u),
          port->buffer_length,
          port->injected_bytes);
}

static void command_info(void* argument, char* arguments) {
  const connect_context_t* context = argument;
  if (!cmd_app_arguments_empty(arguments)) {
    fputs("Usage: info\n", stderr);
    return;
  }
  fprintf(stdout, "Mode: %s\n", context->bidirectional ? "bidirectional" : "unidirectional");
  print_config(context);
  for (size_t i = 0; i < context->port_count; ++i) {
    print_port_stats(&context->ports[i], i);
  }
}

static void command_link(void* argument, char* arguments) {
  connect_context_t* context = argument;
  if (strcmpi(arguments, "up") == 0) {
    context->link_up = true;
    fputs("Link state set to up.\n", stdout);
  } else if (strcmpi(arguments, "down") == 0) {
    context->link_up = false;
    fputs("Link state set to down.\n", stdout);
  } else {
    fputs("Usage: link <up|down>\n", stderr);
  }
}

static bool parse_u16_permyriad(const char* text, uint16_t* value) {
  uint32_t parsed = 0;
  if (!cmd_app_parse_uint32(text, &parsed) || parsed > 10000u) return false;
  *value = (uint16_t)parsed;
  return true;
}

static bool parse_options(connect_context_t* context, int argc, char** argv, const char** src_f, const char** dst_f) {
  context->config.queue_capacity = 16;
  context->config.seed = 1;
  context->config.starts_up = true;
  context->link_up = true;
  for (int i = 1; i < argc; ++i) {
    const char* arg = argv[i];
    if (arg[0] != '-') {
      if (!*src_f) *src_f = arg;
      else if (!*dst_f)
        *dst_f = arg;
      else
        return false;
      continue;
    }
    if (strcmpi(arg + 1, "b") == 0) {
      context->bidirectional = true;
    } else if (strcmpi(arg + 1, "latency") == 0) {
      if (++i >= argc || !cmd_app_parse_uint32(argv[i], &context->config.latency_ms)) return false;
    } else if (strcmpi(arg + 1, "jitter") == 0) {
      if (++i >= argc || !cmd_app_parse_uint32(argv[i], &context->config.jitter_ms)) return false;
    } else if (strcmpi(arg + 1, "bandwidth") == 0) {
      if (++i >= argc || !cmd_app_parse_uint32(argv[i], &context->config.bandwidth_bps)) return false;
    } else if (strcmpi(arg + 1, "queue") == 0) {
      uint16_t queue_capacity = 0;
      if (++i >= argc || !cmd_app_parse_uint16(argv[i], &queue_capacity) || queue_capacity == 0 || queue_capacity > LINK_QUEUE_CAPACITY) return false;
      context->config.queue_capacity = queue_capacity;
    } else if (strcmpi(arg + 1, "loss") == 0) {
      if (++i >= argc || !parse_u16_permyriad(argv[i], &context->config.loss_permyriad)) return false;
    } else if (strcmpi(arg + 1, "corrupt") == 0) {
      if (++i >= argc || !parse_u16_permyriad(argv[i], &context->config.corruption_permyriad)) return false;
    } else if (strcmpi(arg + 1, "fcs-fail") == 0) {
      if (++i >= argc || !parse_u16_permyriad(argv[i], &context->config.fcs_failure_permyriad)) return false;
    } else if (strcmpi(arg + 1, "reorder") == 0) {
      if (++i >= argc || !parse_u16_permyriad(argv[i], &context->config.reorder_permyriad)) return false;
    } else if (strcmpi(arg + 1, "seed") == 0) {
      if (++i >= argc || !cmd_app_parse_uint32(argv[i], &context->config.seed)) return false;
    } else if (strcmpi(arg + 1, "down") == 0) {
      context->config.starts_up = false;
      context->link_up = false;
    } else {
      return false;
    }
  }
  return *src_f && *dst_f && strcmpi(*src_f, *dst_f) != 0;
}

static bool open_port(link_port_t* port, uint32_t seed) {
  port->source = fopen(port->source_path, "rb");
  port->destination = fopen(port->destination_path, "ab");
  port->rng_state = seed;
  return port->source && port->destination && fseek(port->source, 0, SEEK_END) == 0;
}

static bool write_start_frames(connect_context_t* context) {
  for (size_t i = 0; i < context->port_count; ++i) {
    link_port_t* port = &context->ports[i];
    if (!vnet_frame_write(port->destination, VNET_FRAME_CONNECTION_START, port->source_path, port->destination_path)) return false;
    fprintf(stdout, "Opened connection from '%s' to '%s'.\n", port->source_path, port->destination_path);
  }
  return fflush(stdout) == 0;
}

static void close_frames(connect_context_t* context, int* status) {
  for (size_t i = 0; i < context->port_count; ++i) {
    link_port_t* port = &context->ports[i];
    if (port->destination && !vnet_frame_write(port->destination, VNET_FRAME_CONNECTION_END, port->source_path, port->destination_path)) *status = EXIT_FAILURE;
    else if (port->destination)
      fprintf(stdout, "Closed connection from '%s' to '%s'.\n", port->source_path, port->destination_path);
  }
  fflush(stdout);
}

int main(int argc, char** argv) {
  connect_context_t context = {0};
  const char* src_f = NULL;
  const char* dst_f = NULL;
  if (!parse_options(&context, argc, argv, &src_f, &dst_f)) {
    fputs("Usage: connect <source> <dest> [-b] [-latency <ms>] [-jitter <ms>] [-bandwidth <bps>] [-queue <frames>] [-loss <permyriad>] [-corrupt <permyriad>] [-fcs-fail <permyriad>] [-reorder <permyriad>] [-seed <number>] [-down]\n", stderr);
    return EXIT_FAILURE;
  }

  context.port_count = context.bidirectional ? 2u : 1u;
  context.ports[0].source_path = src_f;
  context.ports[0].destination_path = dst_f;
  if (context.bidirectional) {
    context.ports[1].source_path = dst_f;
    context.ports[1].destination_path = src_f;
  }

  int status = EXIT_SUCCESS;
  cmd_app_t commands = {0};
  bool commands_started = false;
  for (size_t i = 0; i < context.port_count; ++i) {
    if (!open_port(&context.ports[i], context.config.seed + (uint32_t)i * 977u)) {
      fputs(i == 0 ? "Could not open the connection files.\n" : "Could not open the reverse connection files.\n", stderr);
      status = EXIT_FAILURE;
      goto cleanup;
    }
  }
  if (!write_start_frames(&context)) {
    status = EXIT_FAILURE;
    goto cleanup;
  }
  if (context.bidirectional && (fseek(context.ports[0].source, (long)sizeof(vnet_frame_header_t), SEEK_CUR) != 0 || fseek(context.ports[1].source, (long)sizeof(vnet_frame_header_t), SEEK_CUR) != 0)) {
    status = EXIT_FAILURE;
    goto cleanup;
  }

  cmd_app_init(&commands);
  if (!cmd_app_register(&commands, "info", "Show link state, impairments, and counters.", command_info, &context) || !cmd_app_register(&commands, "link", "Administratively bring the link up or down.", command_link, &context) || !cmd_app_start(&commands)) {
    fputs("Could not start the command application.\n", stderr);
    status = EXIT_FAILURE;
    goto cleanup;
  }
  commands_started = true;

  while (cmd_app_is_running(&commands)) {
    for (size_t i = 0; i < context.port_count; ++i) {
      link_port_t* port = &context.ports[i];
      long end = 0;
      port->injected_bytes = 0;
      if (!get_file_end(port->source, &end)) {
        status = EXIT_FAILURE;
        goto cleanup;
      }
      const long position = ftell(port->source);
      const long remaining = end - position;
      const size_t capacity = sizeof(port->buffer) - port->buffer_length;
      const size_t requested = remaining > 0 && (size_t)remaining < capacity ? (size_t)remaining : remaining > 0 ? capacity : 0u;
      const size_t read_count = requested ? fread(port->buffer + port->buffer_length, 1, requested, port->source) : 0u;
      if (read_count > 0) {
        port->buffer_length += read_count;
        if (!enqueue_available_units(&context, port)) {
          status = EXIT_FAILURE;
          goto cleanup;
        }
      }
      if (position < 0 || ferror(port->source) || port->buffer_length == sizeof(port->buffer)) {
        fputs("Could not process link traffic.\n", stderr);
        status = EXIT_FAILURE;
        goto cleanup;
      }
      clearerr(port->source);
    }
    for (size_t i = 0; i < context.port_count; ++i) {
      flush_reorder_hold(&context.ports[i], &context.config);
      if (!forward_ready_units(&context.ports[i])) {
        status = EXIT_FAILURE;
        goto cleanup;
      }
    }
    if (context.bidirectional) {
      if ((context.ports[0].injected_bytes > 0 && fseek(context.ports[1].source, (long)context.ports[0].injected_bytes, SEEK_CUR) != 0) || (context.ports[1].injected_bytes > 0 && fseek(context.ports[0].source, (long)context.ports[1].injected_bytes, SEEK_CUR) != 0)) {
        status = EXIT_FAILURE;
        goto cleanup;
      }
    }
    thread_sleep(SLEEP_INTERVAL_MS);
  }

cleanup:
  if (commands_started) {
    cmd_app_stop(&commands);
    cmd_app_join(&commands);
  }
  close_frames(&context, &status);
  for (size_t i = 0; i < context.port_count; ++i) {
    if (context.ports[i].source) fclose(context.ports[i].source);
    if (context.ports[i].destination) fclose(context.ports[i].destination);
  }
  return status;
}

#pragma once

/*
Utility program to establish a "connection" between 2 network files.
Only data written after the connection opens is forwarded to the other file.
This supports both uni-directional and bi-directional connections.
*/

#include <cmd_app.h>
#include <futils.h>
#include <math.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread.h>
#include <ethernet.h>
#include <vnet.h>

#define SLEEP_INTERVAL_MS 5
#define LINK_BUFFER_SIZE 8192
#define LINK_QUEUE_CAPACITY 64
#define LINK_MAX_UNIT_SIZE 2048

typedef struct link_impairment_config {
  uint32_t latency_ms;
  uint32_t jitter_ms;
  uint32_t bandwidth_bps;
  uint16_t queue_capacity;
  uint16_t loss_permyriad;
  uint16_t corruption_permyriad;
  uint16_t fcs_failure_permyriad;
  uint16_t reorder_permyriad;
  uint32_t seed;
  bool starts_up;
} link_impairment_config_t;

typedef struct link_stats {
  uint64_t units_seen;
  uint64_t ethernet_frames_seen;
  uint64_t vnet_frames_seen;
  uint64_t forwarded_units;
  uint64_t forwarded_bytes;
  uint64_t dropped_link_down;
  uint64_t dropped_queue_full;
  uint64_t dropped_loss;
  uint64_t corrupted_units;
  uint64_t fcs_failed_units;
  uint64_t reordered_units;
} link_stats_t;

typedef struct link_unit {
  uint8_t bytes[LINK_MAX_UNIT_SIZE];
  size_t length;
  uint64_t ready_at_ms;
  bool is_vnet;
} link_unit_t;

typedef struct link_port {
  const char* source_path;
  const char* destination_path;
  FILE* source;
  FILE* destination;
  uint8_t buffer[LINK_BUFFER_SIZE];
  size_t buffer_length;
  size_t injected_bytes;
  uint64_t next_transmit_at_ms;
  uint32_t rng_state;
  link_unit_t queue[LINK_QUEUE_CAPACITY];
  size_t queue_length;
  link_unit_t reorder_hold;
  bool has_reorder_hold;
  link_stats_t stats;
} link_port_t;

typedef struct connect_context {
  link_port_t ports[2];
  size_t port_count;
  link_impairment_config_t config;
  bool bidirectional;
  bool link_up;
} connect_context_t;

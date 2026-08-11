#pragma once

/*
Learning Ethernet switch for append-only VNet traffic files.
OSI/ISO layer: Layer 2 (data link); it learns and forwards by Ethernet MAC address.
*/

#include <cmd_app.h>
#include <ethernet.h>
#include <fdb_table.h>
#include <futils.h>

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
  fdb_table_t* devices;
} switch_context_t;

#pragma once

/*
Utility program to simulate a shared hub medium for multiple network files.
OSI/ISO layer: Layer 1 (physical); it repeats opaque bytes without inspecting MAC addresses.
Only data written after the hub opens is repeated to every other port.
*/

#include <cmd_app.h>
#include <futils.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread.h>
#include <vnet.h>

#define SLEEP_INTERVAL_MS 5

typedef struct hub_port {
  const char* path;
  FILE* source;
  FILE* destination;
  FILE* hub_source;
  bool started;
} hub_port_t;

typedef struct hub_context {
  const char* path;
  const hub_port_t* ports;
  size_t port_count;
} hub_context_t;

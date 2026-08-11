#pragma once

/*
Utility program to establish a "connection" between 2 network files.
Only data written after the connection opens is forwarded to the other file.
This supports both uni-directional and bi-directional connections.
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

typedef struct connect_context {
  const char* source_path;
  const char* destination_path;
  bool bidirectional;
} connect_context_t;
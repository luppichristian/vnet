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

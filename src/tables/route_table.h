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

#include <ipv4.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
==================
IPv4 Routing Table
==================
An IPv4 routing table maps destination prefixes to an egress interface and,
for remote networks, a next-hop router. Forwarding selects the matching route
with the longest prefix; when prefix lengths tie, the lower metric wins. A zero
next_hop denotes a directly connected network, where the destination itself is
resolved through ARP.

Real systems distinguish a control-plane routing information base (RIB) from
an optimized forwarding information base (FIB). This small table retains enough
RIB metadata to model connected and static routes while directly serving forwarding lookup. It does not model recursion or ECMP.
*/
typedef enum route_source {
  ROUTE_SOURCE_CONNECTED,
  ROUTE_SOURCE_STATIC,
} route_source_t;

typedef struct route_entry {
  ipv4_address_t destination;
  ipv4_address_t mask;
  ipv4_address_t next_hop;
  size_t interface_index;
  uint32_t metric;
  route_source_t source;
} route_entry_t;

typedef struct route_table {
  route_entry_t* entries;
  size_t capacity;
  size_t count;
} route_table_t;

/* Binds a caller-owned entry array to an initially empty routing table. */
void route_table_init(route_table_t* table, route_entry_t* entries, size_t capacity);

/* Adds a static route. next_hop is zero for a directly connected destination. */
bool route_table_add(route_table_t* table, ipv4_address_t destination, ipv4_address_t mask, ipv4_address_t next_hop, size_t interface_index, uint32_t metric);

/* Adds a connected interface route with the highest forwarding preference. */
bool route_table_add_connected(route_table_t* table, ipv4_address_t destination, ipv4_address_t mask, size_t interface_index);

/* Returns the longest-prefix matching route, then the lower metric. */
const route_entry_t* route_table_lookup(const route_table_t* table, ipv4_address_t destination);

/* Removes the route at index, retaining the remaining entries. */
bool route_table_remove(route_table_t* table, size_t index);

/* Returns a stable human-readable source name for route-table presentation. */
const char* route_source_name(route_source_t source);

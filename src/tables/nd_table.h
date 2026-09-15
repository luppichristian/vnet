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

#include <ethernet.h>
#include <ipv6.h>

/*
===================
IPv6 Neighbor Cache
===================

IPv6 does not use ARP. Neighbor Discovery resolves an on-link IPv6 next hop to
the Ethernet MAC address needed for transmission. This table stores only the
resolved core mapping for one interface and does not yet model reachability or
timer state.
*/

typedef struct nd_entry {
  size_t interface_index;
  ipv6_address_t ip6;
  mac_address_t mac;
} nd_entry_t;

typedef struct nd_table {
  nd_entry_t* entries;
  size_t capacity;
  size_t count;
} nd_table_t;

void nd_table_init(nd_table_t* table, nd_entry_t* entries, size_t capacity);
nd_entry_t* nd_table_find(nd_table_t* table, size_t interface_index, const ipv6_address_t* ip6);
const nd_entry_t* nd_table_find_const(const nd_table_t* table, size_t interface_index, const ipv6_address_t* ip6);
void nd_table_learn(nd_table_t* table, size_t interface_index, const ipv6_address_t* ip6, const mac_address_t mac);
bool nd_table_remove(nd_table_t* table, size_t interface_index, const ipv6_address_t* ip6);

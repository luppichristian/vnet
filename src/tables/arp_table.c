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
#include "arp_table.h"

#include <string.h>

void arp_table_init(arp_table_t* table, arp_entry_t* entries, size_t capacity) {
  *table = (arp_table_t) {.entries = entries, .capacity = capacity};
}

arp_entry_t* arp_table_find(arp_table_t* table, size_t interface_index, ipv4_address_t ip4) {
  for (size_t i = 0; i < table->count; ++i) {
    if (table->entries[i].interface_index == interface_index && table->entries[i].ip4 == ip4) {
      return &table->entries[i];
    }
  }
  return NULL;
}

const arp_entry_t* arp_table_find_const(const arp_table_t* table, size_t interface_index, ipv4_address_t ip4) {
  for (size_t i = 0; i < table->count; ++i) {
    if (table->entries[i].interface_index == interface_index && table->entries[i].ip4 == ip4) {
      return &table->entries[i];
    }
  }
  return NULL;
}

void arp_table_learn(arp_table_t* table, size_t interface_index, ipv4_address_t ip4, const mac_address_t mac) {
  if (table->capacity == 0) {
    return;
  }
  arp_entry_t* entry = arp_table_find(table, interface_index, ip4);
  if (!entry) {
    if (table->count == table->capacity) {
      table->entries[0] = table->entries[--table->count];
    }
    entry = &table->entries[table->count++];
    entry->interface_index = interface_index;
    entry->ip4 = ip4;
  }
  memcpy(entry->mac, mac, sizeof(entry->mac));
}

bool arp_table_remove(arp_table_t* table, size_t interface_index, ipv4_address_t ip4) {
  arp_entry_t* entry = arp_table_find(table, interface_index, ip4);
  if (!entry) return false;
  *entry = table->entries[--table->count];
  return true;
}

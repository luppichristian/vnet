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
#include "nd_table.h"

#include <string.h>

void nd_table_init(nd_table_t* table, nd_entry_t* entries, size_t capacity) {
  *table = (nd_table_t) {.entries = entries, .capacity = capacity};
}

nd_entry_t* nd_table_find(nd_table_t* table, size_t interface_index, const ipv6_address_t* ip6) {
  for (size_t i = 0; i < table->count; ++i) {
    if (table->entries[i].interface_index == interface_index && ipv6_address_equal(&table->entries[i].ip6, ip6)) return &table->entries[i];
  }
  return NULL;
}

const nd_entry_t* nd_table_find_const(const nd_table_t* table, size_t interface_index, const ipv6_address_t* ip6) {
  for (size_t i = 0; i < table->count; ++i) {
    if (table->entries[i].interface_index == interface_index && ipv6_address_equal(&table->entries[i].ip6, ip6)) return &table->entries[i];
  }
  return NULL;
}

void nd_table_learn(nd_table_t* table, size_t interface_index, const ipv6_address_t* ip6, const mac_address_t mac) {
  if (!table->capacity) return;
  nd_entry_t* entry = nd_table_find(table, interface_index, ip6);
  if (!entry) {
    if (table->count == table->capacity) table->entries[0] = table->entries[--table->count];
    entry = &table->entries[table->count++];
    entry->interface_index = interface_index;
    entry->ip6 = *ip6;
  }
  memcpy(entry->mac, mac, sizeof(entry->mac));
}

bool nd_table_remove(nd_table_t* table, size_t interface_index, const ipv6_address_t* ip6) {
  nd_entry_t* entry = nd_table_find(table, interface_index, ip6);
  if (!entry) return false;
  *entry = table->entries[--table->count];
  return true;
}

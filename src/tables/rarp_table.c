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
#include "rarp_table.h"

#include <string.h>

void rarp_table_init(rarp_table_t* table, rarp_entry_t* entries, size_t capacity) {
  *table = (rarp_table_t) {.entries = entries, .capacity = capacity};
}

rarp_entry_t* rarp_table_find(rarp_table_t* table, const mac_address_t mac) {
  for (size_t i = 0; i < table->count; ++i) {
    if (memcmp(table->entries[i].mac, mac, sizeof(table->entries[i].mac)) == 0) {
      return &table->entries[i];
    }
  }
  return NULL;
}

const rarp_entry_t* rarp_table_find_const(const rarp_table_t* table, const mac_address_t mac) {
  for (size_t i = 0; i < table->count; ++i) {
    if (memcmp(table->entries[i].mac, mac, sizeof(table->entries[i].mac)) == 0) {
      return &table->entries[i];
    }
  }
  return NULL;
}

bool rarp_table_set(rarp_table_t* table, const mac_address_t mac, ipv4_address_t ip4) {
  rarp_entry_t* entry = rarp_table_find(table, mac);
  if (!entry) {
    if (table->count == table->capacity) {
      return false;
    }
    entry = &table->entries[table->count++];
    memcpy(entry->mac, mac, sizeof(entry->mac));
  }
  entry->ip4 = ip4;
  return true;
}

bool rarp_table_remove(rarp_table_t* table, const mac_address_t mac) {
  rarp_entry_t* entry = rarp_table_find(table, mac);
  if (!entry) return false;
  *entry = table->entries[--table->count];
  return true;
}

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

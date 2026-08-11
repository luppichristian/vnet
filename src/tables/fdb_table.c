#include "fdb_table.h"

#include <string.h>

void fdb_table_init(fdb_table_t* table, fdb_entry_t* entries, size_t capacity) {
  *table = (fdb_table_t) {.entries = entries, .capacity = capacity};
}

fdb_entry_t* fdb_table_find(fdb_table_t* table, const mac_address_t mac) {
  for (size_t i = 0; i < table->count; ++i) {
    if (memcmp(table->entries[i].mac, mac, sizeof(table->entries[i].mac)) == 0) {
      return &table->entries[i];
    }
  }
  return NULL;
}

const fdb_entry_t* fdb_table_find_const(const fdb_table_t* table, const mac_address_t mac) {
  for (size_t i = 0; i < table->count; ++i) {
    if (memcmp(table->entries[i].mac, mac, sizeof(table->entries[i].mac)) == 0) {
      return &table->entries[i];
    }
  }
  return NULL;
}

bool fdb_table_learn(fdb_table_t* table, const mac_address_t mac, size_t port) {
  if (ethernet_mac_is_group(mac)) {
    return false;
  }
  fdb_entry_t* entry = fdb_table_find(table, mac);
  if (entry) {
    entry->port = port;
    return true;
  }
  if (table->count == table->capacity) {
    return false;
  }
  entry = &table->entries[table->count++];
  memcpy(entry->mac, mac, sizeof(entry->mac));
  entry->port = port;
  return true;
}

void fdb_table_remove_port(fdb_table_t* table, size_t port) {
  for (size_t i = 0; i < table->count;) {
    if (table->entries[i].port == port) {
      table->entries[i] = table->entries[--table->count];
    } else {
      ++i;
    }
  }
}

bool fdb_table_remove(fdb_table_t* table, const mac_address_t mac) {
  fdb_entry_t* entry = fdb_table_find(table, mac);
  if (!entry) return false;
  *entry = table->entries[--table->count];
  return true;
}

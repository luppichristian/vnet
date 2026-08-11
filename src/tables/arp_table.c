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

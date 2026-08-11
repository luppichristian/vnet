#pragma once

#include <ipv4.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
===================================
Domain Name System Message Format
===================================
DNS is an application-layer naming protocol carried by UDP, IPv4, and Ethernet.
This VNet model supports authoritative A and CNAME records in one uncompressed
question or response. It preserves transaction identifiers and response codes,
but omits recursive resolution, TTLs, classes, multiple-answer messages, EDNS,
DNSSEC, TCP fallback, and DNS wire-name compression. Names use presentation
strings and native values because the simulator has one shared writer and reader.
*/

#define DNS_UDP_PORT 53
#define DNS_NAME_MAX 253

#define DNS_MESSAGE_QUERY    0
#define DNS_MESSAGE_RESPONSE 1

#define DNS_RESPONSE_OK         0
#define DNS_RESPONSE_NAME_ERROR 3

#define DNS_RECORD_NONE  0
#define DNS_RECORD_A     1
#define DNS_RECORD_CNAME 5

#pragma pack(push, 1)

typedef union dns_record_data {
  /* IPv4 address for an A record. */
  ipv4_address_t address;

  /* Canonical presentation-format name for a CNAME record. */
  char name[DNS_NAME_MAX + 1];
} dns_record_data_t;

typedef struct dns_record {
  /* IANA record type: A or CNAME in this model. */
  uint16_t type;

  /* Owner name: the queried alias or canonical name. */
  char name[DNS_NAME_MAX + 1];

  /* Type-specific resource-record data. */
  dns_record_data_t data;
} dns_record_t;

typedef struct dns_message {
  /* Client-selected value copied by the matching server response. */
  uint16_t transaction_id;

  /* Query requests a record; response supplies a record or error. */
  uint8_t type;

  /* Zero on success; NAME_ERROR means no authoritative record exists. */
  uint8_t response_code;

  /* Query type/name or the one response record. */
  dns_record_t record;
} dns_message_t;

#pragma pack(pop)

_Static_assert(sizeof(dns_record_t) == 510, "DNS VNet record size must remain fixed");
_Static_assert(sizeof(dns_message_t) == 514, "DNS VNet message size must remain fixed");

/* Builds an A or CNAME query for a non-empty presentation-format name. */
bool dns_write_query(uint16_t transaction_id, uint16_t record_type, const char* name, dns_message_t* message);

/* Builds one successful response containing record, or a name-error response when record is NULL. */
bool dns_write_response(uint16_t transaction_id, const char* name, const dns_record_t* record, dns_message_t* message);

/* Initializes a valid authoritative A record. address must not be zero. */
bool dns_record_write_a(const char* name, ipv4_address_t address, dns_record_t* record);

/* Initializes a valid authoritative CNAME record. */
bool dns_record_write_cname(const char* name, const char* target, dns_record_t* record);

/* Validates and decodes one complete VNet DNS query or response. */
bool dns_parse_message(const uint8_t* bytes, size_t byte_count, dns_message_t* message);

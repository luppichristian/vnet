#pragma once

#include <ipv4.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
===================================
Domain Name System Message Format
===================================
DNS is an application-layer naming protocol. A client sends a question to a
name server, usually over UDP port 53, and receives resource records that map
names to addresses. DNS data is carried inside UDP, then IPv4 and Ethernet:

  Ethernet II data: IPv4 header | UDP header | DNS header | question/answer

This VNet model supports one uncompressed A-record question or response per
message. It retains DNS transaction identifiers and response codes while
omitting recursive resolution, referrals, caching policy, multiple records,
EDNS, DNSSEC, TCP fallback, and wire-name compression. Names are stored as
NUL-terminated presentation strings rather than DNS label octets because this
compiler-local simulator has one shared writer and reader.
*/

#define DNS_UDP_PORT 53
#define DNS_NAME_MAX 63

#define DNS_MESSAGE_QUERY    0
#define DNS_MESSAGE_RESPONSE 1

#define DNS_RESPONSE_OK        0
#define DNS_RESPONSE_NAME_ERROR 3

#pragma pack(push, 1)

typedef struct dns_message {
  /* Client-chosen value copied by the matching server response. */
  uint16_t transaction_id;

  /* Query requests a name; response supplies an address or error. */
  uint8_t type;

  /* Zero is success. Name error means the authoritative VNet server has no A record. */
  uint8_t response_code;

  /* Presentation-format host name. The terminating NUL is part of this fixed simulation record. */
  char name[DNS_NAME_MAX + 1];

  /* IPv4 A-record value in a successful response; zero otherwise. */
  ipv4_address_t address;
} dns_message_t;

#pragma pack(pop)

_Static_assert(sizeof(dns_message_t) == 72, "DNS VNet message size must remain fixed");

/* Builds one DNS A-record query. name must be a non-empty presentation-format name. */
bool dns_write_query(uint16_t transaction_id, const char* name, dns_message_t* message);

/* Builds one successful DNS A-record response or a name-error response when address is zero. */
bool dns_write_response(uint16_t transaction_id, const char* name, ipv4_address_t address, dns_message_t* message);

/* Validates and decodes one complete VNet DNS query or response. */
bool dns_parse_message(const uint8_t* bytes, size_t byte_count, dns_message_t* message);

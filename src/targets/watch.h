#pragma once

/*
This program inspects an open network traffic file in different modes.
We send data by appending to the file and receive data by reading it periodically.
*/

#include <arp.h>
#include <cmd_app.h>
#include <ethernet.h>
#include <icmp.h>
#include <ipv4.h>
#include <rarp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tcp.h>
#include <thread.h>
#include <udp.h>
#include <vnet.h>

/* Max amount of bytes that can be read at each iteration*/
#define MAX_READ 4096

typedef struct watch_context {
  const char* path;
} watch_context_t;

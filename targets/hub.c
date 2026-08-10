/*
Utility program to simulate a shared hub medium for multiple network files.
OSI/ISO layer: Layer 1 (physical); it repeats opaque bytes without inspecting MAC addresses.
Only data written after the hub opens is repeated to every other port.
*/

#include <futils.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread.h>
#include <vnet.h>

#define SLEEP_INTERVAL_MS 5

static volatile sig_atomic_t running = true;

typedef struct hub_port {
  const char* path;
  FILE* source;
  FILE* destination;
  FILE* hub_source;
  bool started;
} hub_port_t;

static void handle_signal(int sig) {
  if (sig == SIGINT) {
    running = false;
  }
}

int main(int argc, char** argv) {
  if (argc < 4) {
    fprintf(stderr, "Expected one hub file and at least one port file.\n");
    fprintf(stderr, "Usage: hub <file> -f <other files>\n");
    return EXIT_FAILURE;
  }
  if (strcmpi(argv[2], "-f") != 0) {
    fprintf(stderr, "Expected '-f' before the port files.\n");
    return EXIT_FAILURE;
  }

  const char* hub_path = argv[1];
  const size_t port_count = (size_t)argc - 3;
  hub_port_t* ports = calloc(port_count, sizeof(*ports));
  long* port_ends = calloc(port_count, sizeof(*port_ends));
  long* hub_ends = calloc(port_count, sizeof(*hub_ends));
  size_t* received_bytes = calloc(port_count, sizeof(*received_bytes));
  size_t* forwarded_bytes = calloc(port_count, sizeof(*forwarded_bytes));
  FILE* hub_destination = NULL;
  int status = EXIT_SUCCESS;
  if (!ports || !port_ends || !hub_ends || !received_bytes || !forwarded_bytes) {
    fprintf(stderr, "Could not allocate hub ports.\n");
    status = EXIT_FAILURE;
    goto cleanup;
  }

  signal(SIGINT, handle_signal);
  for (size_t i = 0; i < port_count; ++i) {
    ports[i].path = argv[i + 3];
    if (ports[i].path[0] == '-' || strcmpi(ports[i].path, hub_path) == 0) {
      fprintf(stderr, "Each port must be a file distinct from the hub file.\n");
      status = EXIT_FAILURE;
      goto cleanup;
    }
    for (size_t j = 0; j < i; ++j) {
      if (strcmpi(ports[i].path, ports[j].path) == 0) {
        fprintf(stderr, "Each port file must be specified only once.\n");
        status = EXIT_FAILURE;
        goto cleanup;
      }
    }
  }

  hub_destination = fopen(hub_path, "ab");
  if (!hub_destination) {
    fprintf(stderr, "Could not open the hub file '%s'.\n", hub_path);
    status = EXIT_FAILURE;
    goto cleanup;
  }
  for (size_t i = 0; i < port_count; ++i) {
    ports[i].source = fopen(ports[i].path, "rb");
    ports[i].destination = fopen(ports[i].path, "ab");
    ports[i].hub_source = fopen(hub_path, "rb");
    if (!ports[i].source || !ports[i].destination || !ports[i].hub_source || fseek(ports[i].source, 0, SEEK_END) != 0 || fseek(ports[i].hub_source, 0, SEEK_END) != 0) {
      fprintf(stderr, "Could not open the files for hub port %zu.\n", i + 1);
      status = EXIT_FAILURE;
      goto cleanup;
    }
  }

  for (size_t i = 0; i < port_count; ++i) {
    if (!vnet_frame_write(hub_destination, VNET_FRAME_CONNECTION_START, ports[i].path, hub_path) || fseek(ports[i].hub_source, (long)sizeof(vnet_frame_header_t), SEEK_CUR) != 0 || !vnet_frame_write(ports[i].destination, VNET_FRAME_CONNECTION_START, hub_path, ports[i].path) || fseek(ports[i].source, (long)sizeof(vnet_frame_header_t), SEEK_CUR) != 0) {
      status = EXIT_FAILURE;
      goto cleanup;
    }
    ports[i].started = true;
    fprintf(stdout, "Opened bilateral connection between hub '%s' and '%s' on port %zu.\n", hub_path, ports[i].path, i + 1);
  }
  if (fflush(stdout) != 0) {
    status = EXIT_FAILURE;
    goto cleanup;
  }

  while (running) {
    memset(received_bytes, 0, port_count * sizeof(*received_bytes));
    memset(forwarded_bytes, 0, port_count * sizeof(*forwarded_bytes));
    for (size_t i = 0; i < port_count; ++i) {
      if (!get_file_end(ports[i].source, &port_ends[i]) || !get_file_end(ports[i].hub_source, &hub_ends[i])) {
        status = EXIT_FAILURE;
        goto cleanup;
      }
    }

    for (size_t i = 0; i < port_count; ++i) {
      if (!vnet_forward_bytes(ports[i].source, hub_destination, ports[i].path, port_ends[i], &received_bytes[i])) {
        status = EXIT_FAILURE;
        goto cleanup;
      }
    }

    for (size_t i = 0; i < port_count; ++i) {
      if (!vnet_forward_bytes(ports[i].hub_source, ports[i].destination, hub_path, hub_ends[i], &forwarded_bytes[i])) {
        status = EXIT_FAILURE;
        goto cleanup;
      }
    }

    for (size_t i = 0; i < port_count; ++i) {
      if ((received_bytes[i] > 0 && fseek(ports[i].hub_source, (long)received_bytes[i], SEEK_CUR) != 0) || (forwarded_bytes[i] > 0 && fseek(ports[i].source, (long)forwarded_bytes[i], SEEK_CUR) != 0)) {
        status = EXIT_FAILURE;
        goto cleanup;
      }
      if (received_bytes[i] > 0) {
        fprintf(stdout, "Received %zu bytes from '%s' on port %zu.\n", received_bytes[i], ports[i].path, i + 1);
      }
      if (forwarded_bytes[i] > 0) {
        fprintf(stdout, "Forwarded %zu bytes from hub '%s' to '%s' on port %zu.\n", forwarded_bytes[i], hub_path, ports[i].path, i + 1);
      }
    }
    if (fflush(stdout) != 0) {
      status = EXIT_FAILURE;
      goto cleanup;
    }
    thread_sleep(SLEEP_INTERVAL_MS);
  }

cleanup:
  if (hub_destination) {
    for (size_t i = 0; i < port_count; ++i) {
      if (!ports[i].started) {
        continue;
      }
      if (!vnet_frame_write(hub_destination, VNET_FRAME_CONNECTION_END, ports[i].path, hub_path) || !vnet_frame_write(ports[i].destination, VNET_FRAME_CONNECTION_END, hub_path, ports[i].path)) {
        status = EXIT_FAILURE;
      } else {
        fprintf(stdout, "Closed bilateral connection between hub '%s' and '%s' on port %zu.\n", hub_path, ports[i].path, i + 1);
      }
    }
    fflush(stdout);
  }
  for (size_t i = 0; i < port_count; ++i) {
    if (ports && ports[i].source) {
      fclose(ports[i].source);
    }
    if (ports && ports[i].destination) {
      fclose(ports[i].destination);
    }
    if (ports && ports[i].hub_source) {
      fclose(ports[i].hub_source);
    }
  }
  if (hub_destination) {
    fclose(hub_destination);
  }
  free(hub_ends);
  free(port_ends);
  free(forwarded_bytes);
  free(received_bytes);
  free(ports);
  return status;
}

/* Utility program to simulate a shared hub medium for multiple network files.
Only data written after the hub opens is repeated to every other port. */

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vnet.h>

#define SLEEP_INTERVAL_MS 5
#define HUB_BUFFER_SIZE   4096

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

static bool open_file(FILE** file, const char* path, const char* mode) {
  *file = fopen(path, mode);
  if (!*file) {
    fprintf(stderr, "Could not open the file '%s' with mode '%s'.\n", path, mode);
    return false;
  }
  return true;
}

static bool get_file_end(FILE* file, long* end) {
  const long current = ftell(file);
  if (current < 0 || fseek(file, 0, SEEK_END) != 0) {
    return false;
  }
  *end = ftell(file);
  return *end >= 0 && fseek(file, current < *end ? current : *end, SEEK_SET) == 0;
}

static bool is_vnet_frame(FILE* source, long source_end, vnet_frame_header_t* header) {
  const long source_position = ftell(source);
  if (source_position < 0 || source_end - source_position < (long)sizeof(*header)) {
    return false;
  }
  if (fread(header, sizeof(*header), 1, source) != 1 || fseek(source, source_position, SEEK_SET) != 0) {
    return false;
  }
  return header->magic == VNET_FRAME_MAGIC && header->version == VNET_PROTOCOL_VERSION && (header->type == VNET_FRAME_CONNECTION_START || header->type == VNET_FRAME_CONNECTION_END) && memchr(header->source_path, '\0', sizeof(header->source_path)) && memchr(header->destination_path, '\0', sizeof(header->destination_path));
}

static bool write_available(FILE* destination, const uint8_t* bytes, size_t byte_count) {
  return fseek(destination, 0, SEEK_END) == 0 && fwrite(bytes, 1, byte_count, destination) == byte_count && fflush(destination) == 0;
}

static bool forward_available(FILE* source, FILE* destination, const char* source_path, long source_end, size_t* forwarded_bytes) {
  uint8_t buffer[HUB_BUFFER_SIZE];
  long source_position = ftell(source);
  size_t buffer_length = 0;

  if (source_position < 0) {
    return false;
  }
  if (source_end < source_position) {
    return fseek(source, source_end, SEEK_SET) == 0;
  }

  *forwarded_bytes = 0;
  while (source_position < source_end) {
    vnet_frame_header_t header = {0};
    if (is_vnet_frame(source, source_end, &header) && strcmpi(header.destination_path, source_path) == 0) {
      if (buffer_length > 0 && !write_available(destination, buffer, buffer_length)) {
        return false;
      }
      *forwarded_bytes += buffer_length;
      buffer_length = 0;
      if (fseek(source, (long)sizeof(header), SEEK_CUR) != 0) {
        return false;
      }
      source_position += sizeof(header);
      continue;
    }

    if (fread(buffer + buffer_length, 1, 1, source) != 1) {
      return false;
    }
    ++buffer_length;
    ++source_position;
    if (buffer_length == sizeof(buffer)) {
      if (!write_available(destination, buffer, buffer_length)) {
        return false;
      }
      *forwarded_bytes += buffer_length;
      buffer_length = 0;
    }
  }
  if (buffer_length > 0 && !write_available(destination, buffer, buffer_length)) {
    return false;
  }
  *forwarded_bytes += buffer_length;
  return true;
}

static bool write_vnet_frame(FILE* destination, vnet_frame_type_t type, const char* source_path, const char* destination_path, size_t* written_bytes) {
  const size_t source_path_length = strlen(source_path);
  const size_t destination_path_length = strlen(destination_path);
  if (source_path_length >= VNET_PATH_LEN || destination_path_length >= VNET_PATH_LEN) {
    fprintf(stderr, "Source or destination path is too long for a VNet frame.\n");
    return false;
  }

  vnet_frame_header_t header = {
      .magic = VNET_FRAME_MAGIC,
      .version = VNET_PROTOCOL_VERSION,
      .type = type,
  };
  memcpy(header.source_path, source_path, source_path_length);
  memcpy(header.destination_path, destination_path, destination_path_length);
  if (fseek(destination, 0, SEEK_END) != 0 || fwrite(&header, sizeof(header), 1, destination) != 1 || fflush(destination) != 0) {
    return false;
  }

  *written_bytes = sizeof(header);
  return true;
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

  if (!open_file(&hub_destination, hub_path, "ab")) {
    status = EXIT_FAILURE;
    goto cleanup;
  }
  for (size_t i = 0; i < port_count; ++i) {
    if (!open_file(&ports[i].source, ports[i].path, "rb") || !open_file(&ports[i].destination, ports[i].path, "ab") || !open_file(&ports[i].hub_source, hub_path, "rb") || fseek(ports[i].source, 0, SEEK_END) != 0 || fseek(ports[i].hub_source, 0, SEEK_END) != 0) {
      status = EXIT_FAILURE;
      goto cleanup;
    }
  }

  for (size_t i = 0; i < port_count; ++i) {
    size_t frame_bytes = 0;
    if (!write_vnet_frame(hub_destination, VNET_FRAME_CONNECTION_START, ports[i].path, hub_path, &frame_bytes) || fseek(ports[i].hub_source, (long)frame_bytes, SEEK_CUR) != 0 || !write_vnet_frame(ports[i].destination, VNET_FRAME_CONNECTION_START, hub_path, ports[i].path, &frame_bytes) || fseek(ports[i].source, (long)frame_bytes, SEEK_CUR) != 0) {
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
      if (!forward_available(ports[i].source, hub_destination, ports[i].path, port_ends[i], &received_bytes[i])) {
        status = EXIT_FAILURE;
        goto cleanup;
      }
    }

    for (size_t i = 0; i < port_count; ++i) {
      if (!forward_available(ports[i].hub_source, ports[i].destination, hub_path, hub_ends[i], &forwarded_bytes[i])) {
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
    _sleep(SLEEP_INTERVAL_MS);
  }

cleanup:
  if (hub_destination) {
    for (size_t i = 0; i < port_count; ++i) {
      size_t frame_bytes = 0;
      if (!ports[i].started) {
        continue;
      }
      if (!write_vnet_frame(hub_destination, VNET_FRAME_CONNECTION_END, ports[i].path, hub_path, &frame_bytes) || !write_vnet_frame(ports[i].destination, VNET_FRAME_CONNECTION_END, hub_path, ports[i].path, &frame_bytes)) {
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

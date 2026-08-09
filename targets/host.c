/*
Interactive Ethernet host attached to one append-only VNet traffic file.
OSI/ISO layer: Layer 2 endpoint; optional IPv4 configuration supplies Layer 3 identity.
*/

#include <ethernet.h>
#include <ipv4.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vnet.h>

#ifdef _WIN32
#  include <windows.h>
typedef HANDLE host_thread_t;
typedef CRITICAL_SECTION host_mutex_t;
#else
#  include <pthread.h>
#  include <time.h>
typedef pthread_t host_thread_t;
typedef pthread_mutex_t host_mutex_t;
#endif

#define HOST_DEVICE_CAPACITY 64
#define HOST_BUFFER_SIZE     8192
#define SLEEP_INTERVAL_MS    5

typedef struct host_device {
  mac_address_t mac;
  char path[VNET_PATH_LEN];
  bool has_mac;
} host_device_t;

typedef struct host_context {
  const char* path;
  mac_address_t mac;
  ipv4_address_t ip4;
  bool has_ip4;
  volatile sig_atomic_t running;
  FILE* source;
  host_mutex_t mutex;
  host_device_t devices[HOST_DEVICE_CAPACITY];
  size_t device_count;
} host_context_t;

static void lock(host_mutex_t* mutex) {
#ifdef _WIN32
  EnterCriticalSection(mutex);
#else
  pthread_mutex_lock(mutex);
#endif
}

static void unlock(host_mutex_t* mutex) {
#ifdef _WIN32
  LeaveCriticalSection(mutex);
#else
  pthread_mutex_unlock(mutex);
#endif
}

static bool mac_parse(const char* text, mac_address_t mac) {
  unsigned int octets[6] = {0};
  char trailing = '\0';
  if (sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x%c", &octets[0], &octets[1], &octets[2], &octets[3], &octets[4], &octets[5], &trailing) != 6) {
    return false;
  }
  for (size_t i = 0; i < sizeof(mac_address_t); ++i) {
    mac[i] = (uint8_t)octets[i];
  }
  return true;
}

static bool ip4_parse(const char* text, ipv4_address_t* address) {
  unsigned int octets[4] = {0};
  char trailing = '\0';
  if (sscanf(text, "%u.%u.%u.%u%c", &octets[0], &octets[1], &octets[2], &octets[3], &trailing) != 4) {
    return false;
  }
  for (size_t i = 0; i < 4; ++i) {
    if (octets[i] > UINT8_MAX) {
      return false;
    }
  }
  *address = IPV4_ADDRESS(octets[0], octets[1], octets[2], octets[3]);
  return true;
}

static bool mac_is_group(const mac_address_t mac) {
  return (mac[0] & 1u) != 0;
}

static void print_mac(const mac_address_t mac) {
  fprintf(stdout, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static host_device_t* device_find_path(host_context_t* context, const char* path) {
  for (size_t i = 0; i < context->device_count; ++i) {
    if (strcmpi(context->devices[i].path, path) == 0) {
      return &context->devices[i];
    }
  }
  return NULL;
}

static host_device_t* device_find_mac(host_context_t* context, const mac_address_t mac) {
  for (size_t i = 0; i < context->device_count; ++i) {
    if (context->devices[i].has_mac && memcmp(context->devices[i].mac, mac, sizeof(mac_address_t)) == 0) {
      return &context->devices[i];
    }
  }
  return NULL;
}

/* VNet lifecycle frames establish which remote file owns subsequently learned MACs. */
static void device_start(host_context_t* context, const char* path) {
  if (device_find_path(context, path)) {
    return;
  }
  if (context->device_count == HOST_DEVICE_CAPACITY) {
    fprintf(stderr, "Device table is full; ignoring '%s'.\n", path);
    return;
  }
  host_device_t* device = &context->devices[context->device_count++];
  memset(device, 0, sizeof(*device));
  strncpy(device->path, path, sizeof(device->path) - 1);
}

static void device_end(host_context_t* context, const char* path) {
  for (size_t i = 0; i < context->device_count; ++i) {
    if (strcmpi(context->devices[i].path, path) == 0) {
      context->devices[i] = context->devices[--context->device_count];
      return;
    }
  }
}

static void device_learn(host_context_t* context, const mac_address_t mac) {
  host_device_t* device = device_find_mac(context, mac);
  if (!device && context->device_count > 0) {
    device = &context->devices[context->device_count - 1];
  }
  if (device) {
    memcpy(device->mac, mac, sizeof(device->mac));
    device->has_mac = true;
  }
}

static void print_info(host_context_t* context) {
  lock(&context->mutex);
  fprintf(stdout, "Host file: %s\nHost MAC:  ", context->path);
  print_mac(context->mac);
  fputc('\n', stdout);
  if (context->has_ip4) {
    fprintf(stdout, "Host IPv4: %u.%u.%u.%u\n", context->ip4 & 0xFF, (context->ip4 >> 8) & 0xFF, (context->ip4 >> 16) & 0xFF, context->ip4 >> 24);
  }
  fprintf(stdout, "Devices (%zu):\n", context->device_count);
  for (size_t i = 0; i < context->device_count; ++i) {
    fprintf(stdout, "  %-48s ", context->devices[i].path);
    if (context->devices[i].has_mac) {
      print_mac(context->devices[i].mac);
    } else {
      fputs("(MAC not learned)", stdout);
    }
    fputc('\n', stdout);
  }
  fflush(stdout);
  unlock(&context->mutex);
}

static void handle_vnet(host_context_t* context, const vnet_frame_header_t* frame) {
  if (strcmpi(frame->destination_path, context->path) != 0) {
    return;
  }
  lock(&context->mutex);
  if (frame->type == VNET_FRAME_CONNECTION_START) {
    device_start(context, frame->source_path);
    fprintf(stdout, "Connected to '%s'.\n", frame->source_path);
  } else {
    device_end(context, frame->source_path);
    fprintf(stdout, "Disconnected from '%s'.\n", frame->source_path);
  }
  fflush(stdout);
  unlock(&context->mutex);
}

static void handle_ethernet(host_context_t* context, const uint8_t* bytes, size_t byte_count) {
  ethernet_frame_view_t frame = {0};
  if (!ethernet_parse_frame(bytes, byte_count, &frame)) {
    return;
  }
  const bool group = mac_is_group(frame.header.dst_mac);
  if (!group && memcmp(frame.header.dst_mac, context->mac, sizeof(context->mac)) != 0) {
    return;
  }

  lock(&context->mutex);
  device_learn(context, frame.header.src_mac);
  fputs("Received ", stdout);
  group ? fputs(memcmp(frame.header.dst_mac, "\xFF\xFF\xFF\xFF\xFF\xFF", sizeof(frame.header.dst_mac)) == 0 ? "broadcast" : "multicast", stdout) : fputs("unicast", stdout);
  fputs(" frame from ", stdout);
  print_mac(frame.header.src_mac);
  fprintf(stdout, " (%zu bytes).\n", byte_count);
  fflush(stdout);
  unlock(&context->mutex);
}

static void process_bytes(host_context_t* context, uint8_t* buffer, size_t* buffer_length) {
  size_t offset = 0;
  while (offset < *buffer_length) {
    const size_t remaining = *buffer_length - offset;
    vnet_frame_header_t control = {0};
    if (remaining >= sizeof(control) && vnet_parse_frame(buffer + offset, sizeof(control), &control)) {
      handle_vnet(context, &control);
      offset += sizeof(control);
      continue;
    }
    if (!ethernet_frame_is_start(buffer + offset, remaining)) {
      ++offset;
      continue;
    }
    size_t end = offset + 1;
    while (end < *buffer_length && !ethernet_frame_is_start(buffer + end, *buffer_length - end) && !vnet_frame_has_prefix(buffer + end, *buffer_length - end)) {
      ++end;
    }
    ethernet_frame_view_t frame = {0};
    if (ethernet_parse_frame(buffer + offset, end - offset, &frame)) {
      handle_ethernet(context, buffer + offset, end - offset);
      offset = end;
      continue;
    }
    if (end == *buffer_length && remaining < sizeof(ethernet_header_t) + ETHERNET_MIN_DATA_LEN + sizeof(ethernet_footer_t)) {
      break;
    }
    ++offset;
  }
  if (offset > 0) {
    memmove(buffer, buffer + offset, *buffer_length - offset);
    *buffer_length -= offset;
  }
}

#ifdef _WIN32
static DWORD WINAPI receiver_thread(void* argument) {
#else
static void* receiver_thread(void* argument) {
#endif
  host_context_t* context = argument;
  uint8_t buffer[HOST_BUFFER_SIZE] = {0};
  size_t buffer_length = 0;
  while (context->running) {
    const size_t read_count = fread(buffer + buffer_length, 1, sizeof(buffer) - buffer_length, context->source);
    if (read_count > 0) {
      buffer_length += read_count;
      process_bytes(context, buffer, &buffer_length);
    }
    if (ferror(context->source)) {
      lock(&context->mutex);
      fputs("Could not read the network file.\n", stderr);
      unlock(&context->mutex);
      context->running = false;
      break;
    }
    clearerr(context->source);
    if (buffer_length == sizeof(buffer)) {
      lock(&context->mutex);
      fputs("Discarding an oversized or incomplete network frame.\n", stderr);
      unlock(&context->mutex);
      buffer_length = 0;
    }
    _sleep(SLEEP_INTERVAL_MS);
  }
#ifdef _WIN32
  return 0;
#else
  return NULL;
#endif
}

static void print_help(void) {
  fputs("Commands:\n  help  Show this command list.\n  info  Show host and learned devices.\n  quit  Stop the receiver and exit.\n", stdout);
}

int main(int argc, char** argv) {
  if (argc != 3 && argc != 5) {
    fprintf(stderr, "Usage: host <file> <mac-address> (optional -ip4 <address>)\n");
    return EXIT_FAILURE;
  }
  host_context_t context = {.path = argv[1], .running = true};
  if (!mac_parse(argv[2], context.mac) || (argc == 5 && (strcmpi(argv[3], "-ip4") != 0 || !ip4_parse(argv[4], &context.ip4)))) {
    fprintf(stderr, "Usage: host <file> <mac-address> (optional -ip4 <address>)\n");
    return EXIT_FAILURE;
  }
  context.has_ip4 = argc == 5;
  context.source = fopen(context.path, "rb");
  if (!context.source || fseek(context.source, 0, SEEK_END) != 0) {
    fprintf(stderr, "Could not open '%s' for reading.\n", context.path);
    if (context.source) fclose(context.source);
    return EXIT_FAILURE;
  }
#ifdef _WIN32
  InitializeCriticalSection(&context.mutex);
#else
  pthread_mutex_init(&context.mutex, NULL);
#endif
  host_thread_t thread;
#ifdef _WIN32
  thread = CreateThread(NULL, 0, receiver_thread, &context, 0, NULL);
  if (!thread) {
#else
  if (pthread_create(&thread, NULL, receiver_thread, &context) != 0) {
#endif
    fprintf(stderr, "Could not start the packet receiver thread.\n");
    fclose(context.source);
    return EXIT_FAILURE;
  }

  print_help();
  char command[64] = {0};
  while (context.running && fputs("> ", stdout) >= 0 && fflush(stdout) == 0 && fgets(command, sizeof(command), stdin)) {
    command[strcspn(command, "\r\n")] = '\0';
    if (strcmpi(command, "help") == 0) {
      print_help();
    } else if (strcmpi(command, "info") == 0) {
      print_info(&context);
    } else if (strcmpi(command, "quit") == 0) {
      context.running = false;
    } else if (command[0] != '\0') {
      fputs("Unknown command. Type 'help'.\n", stderr);
    }
  }
  context.running = false;
#ifdef _WIN32
  WaitForSingleObject(thread, INFINITE);
  CloseHandle(thread);
  DeleteCriticalSection(&context.mutex);
#else
  pthread_join(thread, NULL);
  pthread_mutex_destroy(&context.mutex);
#endif
  fclose(context.source);
  return EXIT_SUCCESS;
}

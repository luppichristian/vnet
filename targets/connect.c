/* Utility program to establish a "connection" between 2 network files.
Only data written after the connection opens is forwarded to the other file.
This supports both uni-directional and bi-directional connections. */

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vnet.h>

#define SLEEP_INTERVAL_MS      5
#define CONNECTION_BUFFER_SIZE 4096

static volatile sig_atomic_t running = true;

static void handle_signal(int sig) {
  if (sig == SIGINT) {
    running = false;
  }
}

/* Open a file */
static bool open_file(FILE** file, const char* path, const char* mode) {
  *file = fopen(path, mode);
  if (!*file) {
    fprintf(stderr, "Could not open the file '%s' with mode '%s'.\n", path, mode);
    return false;
  }
  return true;
}

/* Get the current file end without moving the read position */
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

/* Forward unread data up to the current file end */
static bool forward_available(FILE* source, FILE* destination, const char* source_path, long source_end, size_t* forwarded_bytes) {
  uint8_t buffer[CONNECTION_BUFFER_SIZE];
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

/* Write a VNet control frame for one forwarding direction */
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
  if (argc < 3) {
    fprintf(stderr, "Expected at least 2 arguments: source and destination file.\n");
    fprintf(stderr, "Usage: <source> <dest> (optional -b)\n");
    return (EXIT_FAILURE);
  }

  /* Setup signal handler for interrupt */
  signal(SIGINT, handle_signal);

  /* Parse command line arguments */
  const char* src_f = NULL;
  const char* dst_f = NULL;
  bool bidirectional = false;
  for (int i = 1; i < argc; ++i) {
    const char* arg = argv[i];
    if (arg[0] == '-') {
      /* Parse option */
      if (strcmpi(arg + 1, "b") == 0) {
        bidirectional = true;
      } else {
        fprintf(stderr, "Unrecognized option: %s.\n", arg);
        return (EXIT_FAILURE);
      }
    } else {
      /* Parse filename */
      if (!src_f) {
        src_f = arg;
        continue;
      }
      if (!dst_f) {
        dst_f = arg;
        continue;
      }

      fprintf(stderr, "Specified too many file names.\n");
      return (EXIT_FAILURE);
    }
  }

  /* Make sure we have a pair of files */
  if (!src_f) {
    fprintf(stderr, "Source file or file A was not specified.\n");
    return (EXIT_FAILURE);
  }
  if (!dst_f) {
    fprintf(stderr, "Destination file or file B was not specified.\n");
    return (EXIT_FAILURE);
  }
  if (strcmpi(src_f, dst_f) == 0) {
    fprintf(stderr, "Source and destination must be different files.\n");
    return (EXIT_FAILURE);
  }

  /* Open file handles */
  FILE* source_a = NULL;
  FILE* destination_a = NULL;
  FILE* source_b = NULL;
  FILE* destination_b = NULL;
  int status = EXIT_SUCCESS;
  bool started_a = false;
  bool started_b = false;
  if (!open_file(&source_a, src_f, "rb") || !open_file(&destination_a, dst_f, "ab") || fseek(source_a, 0, SEEK_END) != 0) {
    status = EXIT_FAILURE;
    goto cleanup;
  }
  if (bidirectional && (!open_file(&source_b, dst_f, "rb") || !open_file(&destination_b, src_f, "ab") || fseek(source_b, 0, SEEK_END) != 0)) {
    status = EXIT_FAILURE;
    goto cleanup;
  }

  /* Notify each destination that forwarding from its source has started */
  size_t start_a_bytes = 0;
  size_t start_b_bytes = 0;
  if (!write_vnet_frame(destination_a, VNET_FRAME_CONNECTION_START, src_f, dst_f, &start_a_bytes)) {
    status = EXIT_FAILURE;
    goto cleanup;
  }
  started_a = true;
  fprintf(stdout, "Opened connection from '%s' to '%s'.\n", src_f, dst_f);
  if (bidirectional && (fseek(source_b, (long)start_a_bytes, SEEK_CUR) != 0 || !write_vnet_frame(destination_b, VNET_FRAME_CONNECTION_START, dst_f, src_f, &start_b_bytes) || fseek(source_a, (long)start_b_bytes, SEEK_CUR) != 0)) {
    status = EXIT_FAILURE;
    goto cleanup;
  }
  started_b = bidirectional;
  if (started_b) {
    fprintf(stdout, "Opened connection from '%s' to '%s'.\n", dst_f, src_f);
  }
  if (fflush(stdout) != 0) {
    status = EXIT_FAILURE;
    goto cleanup;
  }

  /* Loop */
  while (running) {
    long source_a_end = 0;
    long source_b_end = 0;
    size_t forwarded_a = 0;
    size_t forwarded_b = 0;

    if (!get_file_end(source_a, &source_a_end) || (bidirectional && !get_file_end(source_b, &source_b_end)) || !forward_available(source_a, destination_a, src_f, source_a_end, &forwarded_a) || (bidirectional && !forward_available(source_b, destination_b, dst_f, source_b_end, &forwarded_b))) {
      status = EXIT_FAILURE;
      break;
    }
    if (forwarded_a > 0) {
      fprintf(stdout, "Forwarded %zu bytes from '%s' to '%s'.\n", forwarded_a, src_f, dst_f);
    }
    if (forwarded_b > 0) {
      fprintf(stdout, "Forwarded %zu bytes from '%s' to '%s'.\n", forwarded_b, dst_f, src_f);
    }
    if ((forwarded_a > 0 || forwarded_b > 0) && fflush(stdout) != 0) {
      status = EXIT_FAILURE;
      break;
    }
    if (bidirectional && ((forwarded_a > 0 && fseek(source_b, (long)forwarded_a, SEEK_CUR) != 0) || (forwarded_b > 0 && fseek(source_a, (long)forwarded_b, SEEK_CUR) != 0))) {
      status = EXIT_FAILURE;
      break;
    }
    _sleep(SLEEP_INTERVAL_MS);
  }

  /* Cleanup */
cleanup:
  /* Notify each destination that forwarding from its source has stopped */
  size_t end_bytes = 0;
  if (started_a && !write_vnet_frame(destination_a, VNET_FRAME_CONNECTION_END, src_f, dst_f, &end_bytes)) {
    status = EXIT_FAILURE;
  } else if (started_a) {
    fprintf(stdout, "Closed connection from '%s' to '%s'.\n", src_f, dst_f);
  }
  if (started_b && !write_vnet_frame(destination_b, VNET_FRAME_CONNECTION_END, dst_f, src_f, &end_bytes)) {
    status = EXIT_FAILURE;
  } else if (started_b) {
    fprintf(stdout, "Closed connection from '%s' to '%s'.\n", dst_f, src_f);
  }
  if ((started_a || started_b) && fflush(stdout) != 0) {
    status = EXIT_FAILURE;
  }
  if (source_a) {
    fclose(source_a);
  }
  if (destination_a) {
    fclose(destination_a);
  }
  if (source_b) {
    fclose(source_b);
  }
  if (destination_b) {
    fclose(destination_b);
  }
  return status;
}

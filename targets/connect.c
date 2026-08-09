/*
Utility program to establish a "connection" between 2 network files.
Only data written after the connection opens is forwarded to the other file.
This supports both uni-directional and bi-directional connections.
*/

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vnet.h>
#include "nfile.h"

#define SLEEP_INTERVAL_MS 5

static volatile sig_atomic_t running = true;

static void handle_signal(int sig) {
  if (sig == SIGINT) {
    running = false;
  }
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
  source_a = fopen(src_f, "rb");
  destination_a = fopen(dst_f, "ab");
  if (!source_a || !destination_a || fseek(source_a, 0, SEEK_END) != 0) {
    fprintf(stderr, "Could not open the connection files.\n");
    status = EXIT_FAILURE;
    goto cleanup;
  }
  source_b = bidirectional ? fopen(dst_f, "rb") : NULL;
  destination_b = bidirectional ? fopen(src_f, "ab") : NULL;
  if (bidirectional && (!source_b || !destination_b || fseek(source_b, 0, SEEK_END) != 0)) {
    fprintf(stderr, "Could not open the reverse connection files.\n");
    status = EXIT_FAILURE;
    goto cleanup;
  }

  /* Notify each destination that forwarding from its source has started */
  if (!vnet_frame_write(destination_a, VNET_FRAME_CONNECTION_START, src_f, dst_f)) {
    status = EXIT_FAILURE;
    goto cleanup;
  }
  started_a = true;
  fprintf(stdout, "Opened connection from '%s' to '%s'.\n", src_f, dst_f);
  if (bidirectional && (fseek(source_b, (long)sizeof(vnet_frame_header_t), SEEK_CUR) != 0 || !vnet_frame_write(destination_b, VNET_FRAME_CONNECTION_START, dst_f, src_f) || fseek(source_a, (long)sizeof(vnet_frame_header_t), SEEK_CUR) != 0)) {
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

    if (!get_file_end(source_a, &source_a_end) || (bidirectional && !get_file_end(source_b, &source_b_end)) || !vnet_forward_bytes(source_a, destination_a, src_f, source_a_end, &forwarded_a) || (bidirectional && !vnet_forward_bytes(source_b, destination_b, dst_f, source_b_end, &forwarded_b))) {
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
  if (started_a && !vnet_frame_write(destination_a, VNET_FRAME_CONNECTION_END, src_f, dst_f)) {
    status = EXIT_FAILURE;
  } else if (started_a) {
    fprintf(stdout, "Closed connection from '%s' to '%s'.\n", src_f, dst_f);
  }
  if (started_b && !vnet_frame_write(destination_b, VNET_FRAME_CONNECTION_END, dst_f, src_f)) {
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

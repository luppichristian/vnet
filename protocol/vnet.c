#include <vnet.h>
#include <string.h>

#define VNET_FORWARD_BUFFER_SIZE 4096

bool vnet_frame_is_valid(const vnet_frame_header_t* frame) {
  return frame->magic == VNET_FRAME_MAGIC && frame->version == VNET_PROTOCOL_VERSION && (frame->type == VNET_FRAME_CONNECTION_START || frame->type == VNET_FRAME_CONNECTION_END) && memchr(frame->source_path, '\0', sizeof(frame->source_path)) && memchr(frame->destination_path, '\0', sizeof(frame->destination_path));
}

bool vnet_frame_has_prefix(const uint8_t* bytes, size_t byte_count) {
  uint32_t magic = 0;
  return byte_count >= sizeof(magic) && memcpy(&magic, bytes, sizeof(magic)) && magic == VNET_FRAME_MAGIC;
}

bool vnet_parse_frame(const uint8_t* bytes, size_t byte_count, vnet_frame_header_t* frame) {
  if (byte_count != sizeof(*frame)) {
    return false;
  }
  memcpy(frame, bytes, sizeof(*frame));
  return vnet_frame_is_valid(frame);
}

bool vnet_frame_write(FILE* destination, vnet_frame_type_t type, const char* source_path, const char* destination_path) {
  const size_t source_path_length = strlen(source_path);
  const size_t destination_path_length = strlen(destination_path);
  if (source_path_length >= VNET_PATH_LEN || destination_path_length >= VNET_PATH_LEN) {
    fprintf(stderr, "Source or destination path is too long for a VNet frame.\n");
    return false;
  }

  vnet_frame_header_t frame = {
      .magic = VNET_FRAME_MAGIC,
      .version = VNET_PROTOCOL_VERSION,
      .type = type,
  };
  memcpy(frame.source_path, source_path, source_path_length);
  memcpy(frame.destination_path, destination_path, destination_path_length);
  return fwrite(&frame, sizeof(frame), 1, destination) == 1 && fflush(destination) == 0;
}

static bool vnet_frame_peek(FILE* source, long source_end, vnet_frame_header_t* frame) {
  const long source_position = ftell(source);
  if (source_position < 0 || source_end - source_position < (long)sizeof(*frame)) {
    return false;
  }
  return fread(frame, sizeof(*frame), 1, source) == 1 && fseek(source, source_position, SEEK_SET) == 0 && vnet_frame_is_valid(frame);
}

bool vnet_forward_bytes(FILE* source, FILE* destination, const char* source_path, long source_end, size_t* forwarded_bytes) {
  uint8_t buffer[VNET_FORWARD_BUFFER_SIZE];
  long source_position = ftell(source);
  size_t buffer_length = 0;

  if (source_position < 0) {
    return false;
  }
  *forwarded_bytes = 0;
  if (source_end < source_position) {
    return fseek(source, source_end, SEEK_SET) == 0;
  }

  while (source_position < source_end) {
    vnet_frame_header_t frame = {0};
    if (vnet_frame_peek(source, source_end, &frame) && strcmpi(frame.destination_path, source_path) == 0) {
      if (buffer_length > 0 && (fwrite(buffer, 1, buffer_length, destination) != buffer_length || fflush(destination) != 0)) {
        return false;
      }
      *forwarded_bytes += buffer_length;
      buffer_length = 0;
      if (fseek(source, (long)sizeof(frame), SEEK_CUR) != 0) {
        return false;
      }
      source_position += sizeof(frame);
      continue;
    }

    if (fread(buffer + buffer_length, 1, 1, source) != 1) {
      return false;
    }
    ++buffer_length;
    ++source_position;
    if (buffer_length == sizeof(buffer)) {
      if (fwrite(buffer, 1, buffer_length, destination) != buffer_length || fflush(destination) != 0) {
        return false;
      }
      *forwarded_bytes += buffer_length;
      buffer_length = 0;
    }
  }
  if (buffer_length > 0 && (fwrite(buffer, 1, buffer_length, destination) != buffer_length || fflush(destination) != 0)) {
    return false;
  }
  *forwarded_bytes += buffer_length;
  return true;
}

# VNet control frames

VNet is not an Internet protocol. It is simulator-local metadata that marks when a topology utility begins or ends forwarding one append-only traffic file into another.

| Field | Size/meaning |
|---|---|
| Magic | `0x564E4554` identifies a VNet frame |
| Version | currently `1` |
| Type | connection start or connection end |
| Source path | fixed 512-byte, NUL-terminated media-file path |
| Destination path | fixed 512-byte, NUL-terminated media-file path |

The packed record is exactly 1030 bytes. `link`, `hub`, and `switch` write start/end records; forwarding code consumes a valid control frame addressed to its own source path rather than relaying it indefinitely. `watch` decodes it beside Ethernet traffic.

## Why it exists

An append-only file is a shared medium, so a capture otherwise cannot explain *why* a stream of bytes started arriving. Lifecycle frames make topology changes inspectable while keeping ordinary traffic opaque to Layer-1 utilities.

## Real world and model

Ethernet cables and switches do not insert file paths into packets. This is instrumentation, analogous in spirit to an event trace, not a network packet. Its native packed values require reader and writer to use the same platform/compiler configuration.
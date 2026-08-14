# `link` target implementation

`src/targets/link.c` implements the `link` target. It models a point-to-point network link with configurable behavior while forwarding bytes between two media files.

The implementation owns a link context, two directional `link_port_t` records for bidirectional mode, impairment configuration, bounded queues, and per-direction counters. It recognizes VNet lifecycle frames and complete Ethernet frames so impairment is applied to units rather than arbitrary slices whenever possible.

For startup syntax, impairments, runtime commands, forwarding safeguards, and educational scope, see the canonical target reference: [`link`](link.md).
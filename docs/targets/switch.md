# `switch` target

`switch` is a learning Ethernet bridge with VLAN admission/tagging and an explicit IEEE 802.1D-style spanning-tree subset. It is the Layer-2 alternative to `hub`: known unicast traffic does not have to be repeated to every port.

## Startup

```text
switch <file> [-bridge <priority> <mac-address>] -f
       [access <vlan> | trunk <vlan,...>] <other-file> ...
```

| Startup term | Meaning |
|---|---|
| `<file>` | switch's VNet medium/control path |
| `access <vlan>` | accepts untagged ingress in one PVID; emits untagged frames |
| `trunk <vlan,...>` | accepts only listed *tagged* VLANs and preserves 802.1Q tags |
| `-bridge` | explicit bridge priority (0–61440 in 4096 steps) and unicast bridge MAC |

Native VLANs and hybrid ports are deliberately not modeled.

## Implementation and tables

The switch parses/validates Ethernet frames, learns each individual source MAC into `fdb_table` with a port/VLAN context, then selects an egress: known unicast uses the FDB; unknown unicast, broadcast, and multicast flood except ingress. Access ingress is classified with its PVID; trunk policy admits tagged listed VLANs.

It also emits/receives untagged configuration BPDUs, elects a root bridge, assigns root/designated/alternate roles, blocks alternate ports from data forwarding/MAC learning, and flushes dynamic FDB entries on topology change.

## Commands

| Command | Purpose |
|---|---|
| `info` | ports, VLAN policies, STP state, and forwarding database |
| `fdb` | show, delete, or flush learned MAC mappings |
| `stp` | inspect or tune bridge identity and per-port STP path cost |

Real switches implement ASIC pipelines, aging/overflow policy, many VLAN features, RSTP/MSTP, link aggregation, and security controls. VNet preserves the decisions students need to inspect: classification, learning, forwarding/flooding, and loop blocking.
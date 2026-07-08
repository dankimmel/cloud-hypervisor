# vhost-user bounce buffer pool

## What it does

By default, a vhost-user device shares **all of guest RAM** with its
backend (the vhost-user daemon): Cloud Hypervisor sends the guest memory
table over the socket, points the daemon directly at the guest's
virtqueues, and wires the guest's kick eventfds and the KVM irqfds
straight to the daemon. Cloud Hypervisor is not in the data path.

With `bounce=on` for a device, Cloud Hypervisor instead:

1. Allocates a per-device, memfd-backed **bounce pool** and shares *only
   that* with the daemon. From the daemon's perspective the pool is the
   entire "guest": a single memory region at guest physical address 0.
2. Places **shadow virtqueues** inside the pool and gives the daemon
   those ring addresses instead of the guest's.
3. Runs a per-device **data-plane worker thread** that copies request
   data between guest memory and the pool in both directions: on a guest
   kick it copies device-readable buffers into the pool, rewrites the
   descriptor chain to point at the pool, and kicks the daemon; on a
   daemon completion it copies device-written data back into the guest's
   buffers and injects the guest interrupt.

There are **no vhost-user protocol changes** — the daemon sees an
ordinary small guest — and the feature is strictly opt-in per device.

## Why you might want it

- **`MAP_PRIVATE` / anonymous guest RAM.** The default memory-table path
  requires every guest memory region to have a backing file descriptor.
  Bounce mode lifts that requirement, which enables `fork()`-based
  copy-on-write snapshots of a quiesced VM (while paused, no Cloud
  Hypervisor thread touches guest RAM on behalf of a bounce device).
- **Reduced attack surface.** A multi-tenant or untrusted vhost-user
  daemon never gains access to guest RAM — only to the bounce pool, whose
  freed extents are scrubbed so one request cannot observe another's
  data.
- **Overcommit.** The pool is a separate allocation, so guest RAM can be
  overcommitted independently of the I/O buffers.
- **Uniform dirty tracking.** All device writes to guest RAM are
  performed by Cloud Hypervisor through its own mapping, so guest-memory
  dirty tracking is uniform across device types.

The cost is a data copy in each direction plus an extra thread wakeup per
notification, so bounce mode trades throughput for isolation. Enable it
only where the isolation properties above are worth that trade.

## Usage

`bounce=on` is available on every vhost-user device type. It requires a
vhost-user device (`vhost_user=on` where the option exists) and is
mutually exclusive with a vIOMMU (`iommu=on`).

```bash
# vhost-user-blk
--disk vhost_user=on,socket=/tmp/blk.sock,bounce=on

# vhost-user-fs
--fs tag=myfs,socket=/tmp/fs.sock,bounce=on

# vhost-user-net
--net vhost_user=on,socket=/tmp/net.sock,mac=...,bounce=on

# generic vhost-user
--user-devices socket=/tmp/dev.sock,virtio_id=block,queue_sizes=[256],bounce=on
```

### Sizing the pool

The pool contains the shadow rings plus a **buffer arena** that request
data is copied through. The arena has a default size, or you can set it
explicitly with `bounce_pool_size=<bytes>` (accepts suffixes, e.g.
`bounce_pool_size=64M`).

The default arena size is deliberately over-provisioned:

```
arena = 4 × num_queues × queue_size × 4096 bytes
```

This covers a page-scatter driver that keeps every queue slot busy with
one-page descriptors, with 4× headroom for multi-page descriptors. A
4-queue, 256-deep device therefore defaults to ~16 MiB of arena.

If a device uses larger contiguous buffers than the default covers, a
descriptor chain may not fit in the arena. When that happens the queue
**stalls** (it stops consuming new requests until completions free
space) rather than corrupting data, and — if a single chain can never
fit even in an empty arena — Cloud Hypervisor logs a rate-limited error
naming the device and the required versus available bytes. That log is
your cue to raise `bounce_pool_size`.

## Feature interactions

| Interaction | Behavior |
|---|---|
| Live migration | Not supported: dirty logging is refused, because the daemon's dirty log only covers the pool, not guest RAM. |
| Snapshot / restore | Supported. Pause drains in-flight requests first; a snapshot is refused if a wedged daemon left requests in flight. |
| Memory hotplug | Guest RAM changes are invisible to the daemon (a no-op toward it); the pool is unaffected. |
| vIOMMU (`iommu=on`) | Rejected by configuration validation. |
| virtio-fs DAX / generic cache window | Allowed. The cache window is daemon memory mapped toward the guest, outside the memory table bounce replaces, so it keeps working. |
| Daemon reconnect | Supported: the pool and in-flight state are re-established after the daemon restarts. |
| `bounce=off` (default) | Identical to Cloud Hypervisor without the feature. |

### Virtio ring features

Indirect descriptors (`VIRTIO_F_RING_INDIRECT_DESC`) are supported: an
indirect chain is re-published to the daemon as a single pool-side
indirect table, preserving queue depth. Bounce mode currently masks
`VIRTIO_F_RING_EVENT_IDX` and `VIRTIO_F_IN_ORDER` from the negotiated
feature set; neither the guest nor the daemon sees those bits while
bounce is enabled. Event-idx support is planned.

## How it works

See [`vhost-user-bounce-plan.md`](vhost-user-bounce-plan.md) for the full
design: the pool layout, the shadow-queue translation rules and memory
ordering, the pause/drain protocol, and the snapshot/reconnect handling.
The translation core lives in
`virtio-devices/src/vhost_user/bounce/`.

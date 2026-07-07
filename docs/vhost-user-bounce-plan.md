# Implementation plan: vhost-user bounce buffer pool

This document is the authoritative, commit-by-commit implementation plan for
adding an optional per-device bounce buffer pool to Cloud Hypervisor's
vhost-user devices (`blk`, `fs`, `net`, `generic_vhost_user`). It is written
so that an engineer (or coding agent) without prior context can execute it
end to end. Read all of sections 1–4 before writing any code.

---

## 1. Feature overview

### 1.1 What we are building

Today, Cloud Hypervisor (CH) shares **all of guest RAM** with every
vhost-user daemon via `VHOST_USER_SET_MEM_TABLE`, points the daemon directly
at the guest's virtqueue rings, and wires the guest's kick eventfds
(ioeventfds) and the KVM irqfds directly to the daemon. CH is completely out
of the data path.

With `bounce=on` for a device, CH instead:

1. Allocates a per-device, memfd-backed **bounce pool** and shares *only
   that* with the daemon. From the daemon's perspective the pool is the
   entire "guest": a single memory region at guest physical address 0.
2. Creates **shadow rings** (one split virtqueue per guest queue) *inside
   the pool*, and gives the daemon those ring addresses instead of the
   guest's ring addresses.
3. Runs a per-device **data-plane worker thread** that:
   - on guest kick: reads the guest's avail ring, copies device-readable
     buffer contents into freshly allocated pool extents, writes a
     translated descriptor chain + avail entry into the shadow ring, and
     kicks the daemon via a CH-owned eventfd;
   - on daemon call: reads the shadow used ring, copies device-written data
     from the pool back into the guest's buffers, publishes the used entry
     in the guest's used ring, frees + scrubs the pool extents, and injects
     the guest interrupt via the existing `VirtioInterrupt`.

There are **zero vhost-user protocol changes**. The daemon sees a small,
ordinary guest. The feature is strictly opt-in per device.

### 1.2 Motivations (from the feature owner)

- Guest RAM can be mapped `MAP_PRIVATE`/anonymous, enabling `fork()`-based
  COW snapshots of a quiesced VM. (Note: today `update_mem_table` *hard
  fails* on regions without a backing fd — see `vu_common_ctrl.rs`,
  `Error::VhostUserMemoryRegion` on the `None` file-offset arm — so bounce
  mode is what makes vhost-user possible at all with private memory.)
- Reduce the attack surface of a multitenant vhost-user daemon: the daemon
  must never be able to read or write actual guest RAM.
- Allow overcommit of guest RAM without overcommitting I/O rings/buffers.
- Uniform guest-RAM delta tracking: with bounce, *all* device writes to
  guest RAM are performed by CH through `GuestMemoryMmap` (which carries an
  `AtomicBitmap`), so dirty tracking is uniform across device types.

### 1.3 Decisions already made (do not relitigate)

| Topic | Decision |
|---|---|
| Pool scope | One pool per device (never shared across devices). |
| CLI | `bounce=on` (+ optional `bounce_pool_size=<bytes>`) on `--disk`, `--net`, `--fs`, generic vhost-user config. |
| Default pool size | Buffer arena = `4 × num_queues × queue_size × 4096` bytes (deliberately over-provisioned ×4), plus the ring area. Override sets the buffer arena size. |
| Chain doesn't fit *right now* | Backpressure: stop consuming that queue's avail ring until completions free space. |
| Chain can *never* fit (total > arena capacity) | Same stall path, plus a rate-limited (once per stall episode) `error!` log naming the device and required vs. available bytes. Never fabricate a completion; never kill the device. Guest driver timeout/reset is the recovery path. |
| `VIRTIO_F_RING_INDIRECT_DESC` | Masked while bounce is on, then supported in commits 26–27. |
| `VIRTIO_F_RING_EVENT_IDX` | Masked while bounce is on, then supported in commits 28–29. |
| `VIRTIO_F_IN_ORDER` | Masked while bounce is on, indefinitely (batch used-entry semantics are incompatible with per-chain id translation; nobody negotiates it in practice). |
| Live migration | Not supported with bounce: `start_dirty_log` returns an error. |
| Snapshot/restore | Supported. Pause fully drains in-flight requests (bounded wait); restore re-establishes shadow state. No pool contents are serialized. |
| virtio-fs DAX / shared-memory cache | Orthogonal, keeps working. The cache window is daemon memory mapped toward the guest, not guest RAM; it does not pass through the mem table we replace. No exclusivity check. |
| vIOMMU (`iommu=on`) | Rejected by config validation until commits 30–31 add IOVA translation; then allowed. |
| Daemon reconnect | Supported (commits 24–25): re-publish pool + rings, re-submit in-flight chains. Same double-execution caveats as existing reconnect. |
| Scrub-on-free | Always on: freed pool extents are zeroed so a daemon can never read stale data from a previous request. |
| `unsafe` | Forbidden in new code. The only `unsafe` involved is the *pre-existing* `memfd_create` FFI wrapper in `vu_common_ctrl.rs`, which commit 3 relocates verbatim (approved). `MmapRegion::build` and all copies use safe vm-memory APIs. |

---

## 2. Architecture

### 2.1 Components (all new code in `virtio-devices/src/vhost_user/bounce/`)

```
bounce/
  mod.rs          BounceError, BounceState, mask_bounce_features(), re-exports
  allocator.rs    BounceAllocator      – offset allocator for the buffer arena
  pool.rs         BouncePool, PoolLayout – memfd + GuestMemoryMmap + rings + arena
  shadow_queue.rs ShadowQueue          – pure translation logic (the heart)
  worker.rs       BounceEpollHandler   – data-plane thread
```

Modified existing files:

- `virtio-devices/src/vhost_user/vu_common_ctrl.rs` — bounce-aware
  `setup_vhost_user` (mem table, vring addrs, kick/call fds), helpers.
- `virtio-devices/src/vhost_user/mod.rs` — `VhostUserCommon` owns
  `Option<BounceState>`; activation spawns the worker; lifecycle plumbing.
- `virtio-devices/src/epoll_helper.rs` — new default-no-op `on_pause` hook.
- `virtio-devices/src/vhost_user/{blk,fs,net,generic_vhost_user}.rs` —
  plumb the config, mask features.
- `vmm/src/vm_config.rs`, `vmm/src/config.rs`, `vmm/src/device_manager.rs`,
  `vmm/src/api/openapi/cloud-hypervisor.yaml` — CLI/config surface.

### 2.2 Pool layout

One memfd (`memfd_create` + `F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL`),
mmapped once via `MmapRegion::build(Some(FileOffset::new(file, 0)), ...)`,
wrapped as a **single-region `GuestMemoryMmap` at guest physical address
0**. GPA collisions with real guest RAM are irrelevant: the daemon's mem
table contains only this region.

```
offset 0
  ┌ queue 0: desc table (16 × qs bytes, 16-aligned)
  │          avail ring (6 + 2 × qs bytes, 2-aligned)
  │          used ring  (6 + 8 × qs bytes, 4-aligned)
  ├ queue 1: ... (each queue's ring block starts 4096-aligned)
  ├ ...
  ├ buffer arena (4096-aligned start; BounceAllocator manages it)
  └ end (file size = arena start + arena capacity, page-aligned)
```

`qs` is the device's **maximum** queue size (`VhostUserConfig::queue_size`);
the guest may negotiate a smaller actual size, which still fits. Runtime
ring-walk arithmetic must use the **actual** negotiated size (from the
activated `Queue`), matching what the daemon computes from
`SET_VRING_NUM`.

Arena capacity default: `4 * num_queues * queue_size * 4096`, overridable
by `bounce_pool_size` (which sets arena capacity in bytes; ring area is
always added on top).

### 2.3 Shadow queue design

**Counters mirror; descriptor slots do not.** For each queue:

- The shadow avail `idx` and shadow ring *positions* advance in lockstep
  with the guest avail ring: every guest avail entry produces exactly one
  shadow avail entry, published in the same order. Hence
  `SET_VRING_BASE` values keep their existing meaning unchanged.
- Shadow **descriptor slots are allocated by CH** from a per-queue free
  stack (`0..actual_qs`), not copied from the guest's slot numbers. The
  shadow avail entry carries the shadow head. When the daemon publishes a
  used entry `{id, len}`, `id` is a shadow head; CH looks up the in-flight
  record, copies data back, and publishes `{guest_head, len}` in the guest
  used ring. This avoids any dependency on the guest's descriptor
  numbering and simplifies indirect/reconnect/restore work later.
- Ring **flags and event-idx fields are never mirrored**:
  - shadow avail `flags` is always 0 (daemon must always send call
    notifications — CH needs every completion to do copy-back, even when
    the *guest* has interrupts suppressed);
  - guest used `flags`/`avail_event` are managed by CH so the guest always
    kicks (CH needs every kick; there is no polling);
  - the guest's `avail.flags` `NO_INTERRUPT` (and later `used_event`) is
    honored by CH when deciding whether to inject the guest interrupt —
    use `virtio_queue::QueueT::needs_notification` which already
    implements both variants.

**Per-chain flow (`mirror_avail`)** — guest side driven through
`virtio_queue::Queue` (`pop_descriptor_chain`, `go_to_previous_position`,
`add_used`, `needs_notification`, `enable_notification`); shadow side via
raw loads/stores on the pool `GuestMemoryMmap`:

1. `pop_descriptor_chain`. For each descriptor in the chain, record
   `(guest_addr, len, writable)`. Enforce: chain length ≤ actual queue
   size; `INDIRECT` flag ⇒ broken queue (until commit 27); descriptor
   addresses/lengths validated implicitly by vm-memory accessors (any
   `GuestMemoryError` ⇒ broken queue).
2. Compute total pool bytes and shadow slots needed. Allocate **all** pool
   extents and **all** shadow slots up front; if either fails, roll back
   every allocation from this chain, `go_to_previous_position()`, and
   return `Stalled` (and if `total > arena capacity`, mark the permanent
   stall and log once). Zero-length descriptors are legal: mirror them
   with `len = 0` and pool offset 0, no allocation.
3. Copy device-readable (non-writable) segment contents guest → pool.
   Device-writable segments are *not* copied in (pool memory is zeroed).
4. Write the shadow descriptors (addr = pool GPA, same len, `F_NEXT` /
   `F_WRITE` flags preserved, `next` = next allocated shadow slot), write
   the shadow avail ring entry at position `shadow_avail_idx % actual_qs`,
   then store the incremented shadow avail `idx` (Release).
5. Record `InflightChain { guest_head, shadow_head, segments }` in a
   `Vec<Option<InflightChain>>` indexed by shadow head. A collision
   (slot already occupied) is impossible by construction (slots come from
   the free stack); `debug_assert!` it.
6. Report whether the daemon needs a kick (any chain mirrored).

**Per-completion flow (`complete_used`)**:

1. Load shadow used `idx` (Acquire). For each new used elem:
   `id` must map to a live `InflightChain`, else broken queue.
2. Copy back: walk the chain's **writable segments in chain order**,
   copying `min(remaining, seg.len)` bytes pool → guest where `remaining`
   starts at the daemon-reported `len` (cap `len` at the total writable
   bytes; a daemon over-report is capped, not trusted). Copies go through
   `GuestMemoryMmap` volatile APIs so the dirty bitmap sees them and
   region-crossing segments work. Destinations are the *captured*
   addresses from mirror time (immune to guest desc-table rewrites).
3. Free + scrub (zero) all the chain's pool extents; push shadow slots
   back on the free stack; clear the in-flight record.
4. `add_used(guest_mem, guest_head, len)` (virtio-queue publishes the
   entry and bumps guest used idx with correct ordering).
5. Report `needs_interrupt = queue.needs_notification(...)`.

**Broken queue**: any spec violation (chain too long, indirect while
masked, unknown/duplicate used id, guest-memory access error) marks the
queue broken: log `error!` once, stop consuming avail entries and used
entries for that queue permanently (until device reset). Never panic.

### 2.4 Memory ordering rules

| Access | Ordering |
|---|---|
| Guest avail idx read | handled inside virtio-queue (`Acquire`) |
| Shadow avail idx store (after desc+entry writes) | `Release` via `Bytes::store` |
| Shadow used idx load | `Acquire` via `Bytes::load` |
| Guest used idx store | handled inside virtio-queue (`Release`) |
| Everything else in rings | plain volatile via vm-memory |

Never take a `&[u8]`/`&mut [u8]` view of guest or pool memory; use
`Bytes::{load,store,read,write}` / `get_slice` + `VolatileSlice` copies.

### 2.5 Eventfd and thread topology

Per bounce device, at activation:

- `BounceQueueFds { shadow_kick: EventFd, shadow_call: EventFd }` per
  queue. `shadow_kick` is given to the daemon as `SET_VRING_KICK`
  (CH writes it); `shadow_call` as `SET_VRING_CALL` (CH epolls it).
- The guest's real per-queue eventfds (the ioeventfds from the transport,
  delivered in `activate()`'s `queues` vector) are epolled by the bounce
  worker instead of being handed to the daemon.
- The existing `VhostUserEpollHandler` thread is unchanged (reconnect +
  backend-req). The bounce worker is a **second** thread, spawned like
  `net.rs` spawns its ctrl-queue thread: own `dup_eventfds()` kill/pause
  pair, thread name `{id}_bounce`, and `paused_sync` barrier resized to
  `Barrier::new(3)` (main + vhost-user thread + bounce thread); net with a
  ctrl queue and bounce would use 4. Reuse the device's existing seccomp
  `Thread` type; if the filter kills the thread in testing, add the
  missing syscalls to that filter in the same commit.

Worker epoll events (`EPOLL_HELPER_EVENT_LAST + 1 + 2*i` = guest kick of
queue `i`; `+ 2*i + 2` = shadow call of queue `i`):

- guest kick(i): drain eventfd; `mirror_avail` loop until `Idle`/`Stalled`;
  if progressed, `shadow_kick.write(1)`.
- shadow call(i): drain eventfd; `complete_used` until `Idle`; inject
  interrupt if requested; then retry `mirror_avail` on **every** stalled
  queue of the device (a completion on one queue frees arena space usable
  by all), kicking the daemon for any that progress.
- `on_pause` hook (added in commit 11): before parking at the pause
  barrier, run `complete_used` to `Idle` on all queues (with interrupts
  delivered). See §2.6.

### 2.6 Pause, snapshot/restore

`Pausable::pause` for these devices already runs `vu_common.pause()`
(SET_VRING_ENABLE(false) to the daemon, synchronous under REPLY_ACK)
*before* `virtio_common.pause()` (which fires `pause_evt`). The bounce
worker's `on_pause` then:

1. Drains all shadow used rings (final copy-backs → guest RAM).
2. Waits for `inflight_count == 0` on every queue by re-polling the shadow
   used rings with a bounded wait (const `BOUNCE_DRAIN_TIMEOUT: Duration =
   5s`, sleep in small increments). On timeout, log `error!`; the pause
   still completes (the guest is stopped so nothing races), but a
   subsequent snapshot with nonzero in-flight must **fail** with
   `MigratableError::Snapshot` (checked in `VhostUserCommon::snapshot`
   via the shared inflight counter) because pool contents are not
   serialized and the daemon's `DEVICE_STATE` blob may reference them.

After a full drain, an invariant holds: daemon vring base == shadow avail
idx == guest avail idx, and guest used idx == guest avail idx for every
queue. Therefore snapshot needs **no new persistent state**: on restore,
`setup_vhost_user` zeroes the shadow rings, stores shadow avail idx =
restored base, and the worker performs one unconditional `mirror_avail`
sweep at startup (also required to catch kicks lost across save/restore).
This drained-pause property is also exactly what makes external
`fork()`-based COW snapshots consistent: while paused, no CH thread
touches guest RAM on behalf of these devices.

### 2.7 Reconnect (after daemon crash)

`VhostUserEpollHandler::reconnect` re-runs `reinitialize_vhost_user` →
`setup_vhost_user`. With bounce, in-flight chains' pool extents are still
intact (never freed), so the bounce path additionally:

1. Quiesces the bounce worker (shared `Mutex` handoff — see commit 24).
2. Rebuilds the shadow rings: re-publishes every in-flight chain, in
   ascending original mirror order, as avail entries starting at a new
   base `b`; sends `SET_VRING_BASE(b)`; sets shadow avail idx =
   `b + inflight_count`. Completed-and-copied chains are gone; the daemon
   re-executes anything that was in flight (same semantics as today's
   reconnect when a backend loses inflight state).

### 2.8 Control-plane deltas (`vu_common_ctrl.rs`)

When `setup_vhost_user` receives `Some(&BounceSetup)`:

- `update_mem_table` → single `VhostUserMemoryRegionInfo` for the pool:
  `guest_phys_addr: 0`, `memory_size: pool.len()`, `userspace_addr:
  pool host mapping base`, `mmap_offset: 0`, `mmap_handle: memfd`.
- `set_vring_addr` → desc/avail/used host addresses computed as
  `pool host base + ring offset` (not `get_host_address_range`).
- `set_vring_base` → unchanged semantics (guest avail idx, or restored
  bases).
- `set_vring_kick`/`set_vring_call` → the shadow fds; skip the
  `virtio_interrupt.notifier(...)` branch.
- Memory hotplug (`add_memory_region` / `update_mem_table` calls from
  `VhostUserCommon`) becomes a no-op toward the daemon when bounce is on
  (guest RAM is invisible to it). Dirty-log setup (`start_dirty_log`) is
  rejected with `Error::MigrationNotSupported`.

### 2.9 Feature masking

`mask_bounce_features(avail_features) -> u64` clears
`VIRTIO_F_RING_INDIRECT_DESC`, `VIRTIO_F_RING_EVENT_IDX`, and
`VIRTIO_F_IN_ORDER` (constants already exist in `virtio-devices/src/lib.rs`).
Devices apply it to `avail_features` **before** `negotiate_features_vhost_user`
so neither the guest nor the daemon ever sees the masked bits. Commits 27
and 29 remove the first two bits from the mask respectively.

---

## 3. Ground rules for every commit

These apply to **every** commit in the chain. Deviations require the
feature owner's sign-off.

1. **≤ 200 lines of production-code modifications per commit** (added +
   changed, excluding `#[cfg(test)]`/`tests/` code, which is unlimited).
   If a commit is trending over, split it and renumber locally.
2. **TDD, interface-first.** Logic-bearing code lands as a pair:
   - Commit A: public interface (types, signatures, `todo!()` bodies or
     stub returns) **plus the full unit-test battery**, every test
     annotated `#[ignore = "implemented in commit <N>"]`.
   - Commit B (or C…): the implementation, removing the `#[ignore]`
     attributes of exactly the tests it satisfies. All unignored tests
     pass at every commit boundary.
   Declarative plumbing (struct fields, parser table entries, help text,
   OpenAPI schema) may land with its passing tests in a single commit.
3. **Gates before `git commit`** (all must pass, in this order):
   ```sh
   cargo +nightly fmt --all
   cargo clippy --locked --all-targets --tests -p virtio-devices -p vmm -- -D warnings
   cargo test -p virtio-devices
   cargo test -p vmm --features kvm     # when vmm was touched
   ```
   Before the final commit of the series, additionally run the
   whole-workspace clippy/test forms from `CONTRIBUTING.md`. If a build
   failure looks feature-related, retry with `--features kvm` (see
   `AGENTS.md`).
4. **No `unsafe`** in new code (§1.3). `#[expect(...)]`/`#[allow(...)]`
   only if removed later in the same series with a note in both commits.
5. **Commit message format** (see `CONTRIBUTING.md` and
   `scripts/gitlint/rules/`): `<component>: Summary` title (components
   here: `virtio-devices`, `vmm`, `docs`, `tests`, `option_parser`),
   72-column body explaining why + how, then trailers. Reference this
   plan: `Implements: docs/vhost-user-bounce-plan.md commit <N>`.
   Template (no agent/model attribution trailers — this series is not
   destined for upstream):
   ```
   virtio-devices: Add bounce buffer allocator interface

   <why + what, wrapped at 72 columns>

   Implements: docs/vhost-user-bounce-plan.md commit 1
   Signed-off-by: Dan Kimmel <dan.p.kimmel@gmail.com>
   ```
6. **Test coverage target: 100 % of new production lines** exercised by
   unit tests (the listed cases are the minimum; add cases for any branch
   you write that the list misses).
7. Follow `AGENTS.md` and `CONTRIBUTING.md` style rules (thiserror
   message conventions, minimal logging, rustdoc on public API).

### Shared test utilities (written once, in commit 5)

`bounce/test_utils.rs` (compiled `#[cfg(test)]`, `pub(crate)`):

- `fn guest_mem(regions: &[(u64, usize)]) -> GuestMemoryMmap` — anonymous
  test memory.
- `struct GuestRingBuilder` — lays out a split virtqueue at fixed
  addresses in test memory; methods: `desc(slot, addr, len, flags, next)`,
  `chain(&[(addr, len, writable)]) -> head`, `publish_avail(head)`,
  `set_avail_flags(f)`, `used_idx()`, `used_elem(pos) -> (id, len)`,
  `queue() -> virtio_queue::Queue` (configured with the ring addresses).
- `struct FakeDaemon<'a>` — operates on a `BouncePool`'s shadow rings the
  way a backend would: `avail_idx(q)`, `pop_avail(q) -> shadow_head`,
  `read_chain(q, head) -> Vec<(GuestAddress, u32, bool)>`,
  `write_at(pool_gpa, bytes)`, `complete(q, head, len)` (writes used elem
  + bumps idx with Release).
- `struct TestInterrupt` — `VirtioInterrupt` impl recording triggered
  queue indexes (and exposing an `EventFd` per queue for worker tests).

---

## 4. Commit chain

LOC budgets below are production-code estimates; test code is unlimited.

---

### Commit 1 — `virtio-devices: Add bounce buffer allocator interface`

**Goal:** Introduce the `bounce` module skeleton and the arena allocator's
public interface with its full (ignored) test battery. Major files:
`virtio-devices/src/vhost_user/bounce/mod.rs` (new),
`virtio-devices/src/vhost_user/bounce/allocator.rs` (new),
`virtio-devices/src/vhost_user/mod.rs` (add `pub mod bounce;`).

**Interface** (~70 LOC):

```rust
pub const BOUNCE_ALLOC_ALIGN: u64 = 64;

#[derive(Error, Debug)]
pub enum BounceError {
    #[error("Invalid free of pool extent at offset {offset} len {len}")]
    InvalidFree { offset: u64, len: u64 },
    // extended by later commits
}

pub struct BounceAllocator { /* capacity, sorted free list, free_bytes */ }
impl BounceAllocator {
    pub fn new(capacity: u64) -> Self;
    /// First-fit; returned offset is BOUNCE_ALLOC_ALIGN-aligned; len is
    /// rounded up to the alignment internally. len == 0 is rejected
    /// (callers special-case zero-length descriptors).
    pub fn alloc(&mut self, len: u64) -> Option<u64>;
    /// Frees a previously allocated extent; coalesces neighbors.
    pub fn free(&mut self, offset: u64, len: u64) -> Result<(), BounceError>;
    pub fn free_bytes(&self) -> u64;
    pub fn capacity(&self) -> u64;
}
```

**Tests (all `#[ignore]`, unignored in commit 2):**

- `alloc_returns_aligned_offset_within_capacity`
- `alloc_zero_len_rejected`
- `alloc_rounds_len_up_to_alignment` (alloc 1 byte, then verify free_bytes
  dropped by exactly `BOUNCE_ALLOC_ALIGN`)
- `alloc_exhaustion_returns_none_without_side_effects`
- `free_then_alloc_reuses_space`
- `free_coalesces_with_previous_and_next` (alloc A,B,C; free B, free A,
  free C; a full-capacity alloc succeeds)
- `alloc_first_fit_is_deterministic` (free two gaps of different sizes;
  a small alloc lands in the lower-offset gap)
- `free_bytes_accounting_over_interleaved_ops` (scripted sequence of 50
  allocs/frees; free_bytes matches a model)
- `invalid_free_unallocated_range_rejected`
- `invalid_free_overlapping_free_range_rejected`
- `full_drain_restores_initial_state` (after freeing everything,
  `free_bytes == capacity` and one alloc of `capacity` succeeds)

**Done when:** module compiles, `cargo test -p virtio-devices` passes
(ignored tests count as passed), clippy/fmt clean.

---

### Commit 2 — `virtio-devices: Implement bounce buffer allocator`

**Goal:** Make every commit-1 test pass. Major file: `allocator.rs`.
(~110 LOC.) Implementation: sorted `Vec<(offset, len)>` free list,
first-fit with alignment rounding, binary-search insert + neighbor
coalescing on free, strict validation that a freed extent is fully inside
exactly the gap between free entries (reject overlaps). Remove all
commit-1 `#[ignore]`s.

---

### Commit 3 — `virtio-devices: Add bounce pool interface`

**Goal:** Pool = memfd + mapping + ring layout + arena, and the layout
math, as interface + ignored tests. Also relocate the existing
`memfd_create` helper. Major files: `bounce/pool.rs` (new),
`vu_common_ctrl.rs` (make `memfd_create` `pub(crate)` in a shared spot —
move it to `bounce/pool.rs` and re-import it from `vu_common_ctrl.rs`, or
vice versa; move verbatim, keeping its `// SAFETY:` comment; this is the
only `unsafe` in the series and is pre-approved).

**Interface** (~110 LOC incl. layout struct + error variants
`MemfdCreate`, `SetFileSize`, `SetSeals`, `NewMmapRegion`,
`PoolMemory(#[source] vm_memory::Error)`):

```rust
pub struct PoolLayout {
    pub num_queues: usize,
    pub queue_size: u16,      // maximum queue size
    pub buffer_capacity: u64, // arena bytes (already defaulted/overridden)
}
pub fn default_buffer_capacity(num_queues: usize, queue_size: u16) -> u64; // 4*nq*qs*4096

#[derive(Clone, Copy)]
pub struct RingOffsets { pub desc: u64, pub avail: u64, pub used: u64 }

pub struct BouncePool { /* mem: GuestMemoryMmap, offsets, arena base, allocator */ }
impl BouncePool {
    pub fn new(layout: &PoolLayout) -> Result<Self, BounceError>;
    pub fn mem(&self) -> &GuestMemoryMmap;         // single region @ GPA 0
    pub fn len(&self) -> u64;                      // total file/mapping size
    pub fn ring_offsets(&self, queue: usize) -> RingOffsets;
    pub fn host_base(&self) -> u64;                // mapping base as u64
    pub fn memfd(&self) -> RawFd;
    pub fn buffer_capacity(&self) -> u64;
    pub fn alloc(&mut self, len: u64) -> Option<GuestAddress>;      // arena-relative → pool GPA
    pub fn free(&mut self, addr: GuestAddress, len: u64) -> Result<(), BounceError>; // scrubs
    pub fn free_bytes(&self) -> u64;
    pub fn zero_rings(&mut self) -> Result<(), BounceError>;
}
```

**Tests (ignored until commit 4):**

- `default_buffer_capacity_formula` (4 × nq × qs × 4096 for several
  nq/qs combos)
- `layout_ring_blocks_are_page_aligned_and_disjoint` (for nq=3, qs=256:
  every desc/avail/used range disjoint, desc 16-aligned, avail 2-aligned,
  used 4-aligned, arena starts page-aligned after last ring)
- `layout_ring_sizes_match_virtio_spec` (desc = 16·qs, avail = 6+2·qs+2,
  used = 6+8·qs+2 — the trailing event-idx fields are reserved
  unconditionally so the layout stays feature-independent and commit 29
  needs no layout change)
- `new_pool_memory_is_zeroed`
- `pool_mem_is_single_region_at_gpa_zero_with_fd`
- `alloc_returns_gpa_inside_arena`
- `alloc_free_roundtrip_scrubs_extent` (write pattern via `mem()`, free,
  read back zeros)
- `free_bytes_tracks_allocator`
- `zero_rings_clears_only_ring_area` (dirty arena + rings; `zero_rings`;
  arena byte intact, rings zero)
- `host_base_offset_math` (`host_base() + ring_offsets(q).desc` equals
  `mem().get_host_address(GuestAddress(offsets.desc))`)
- `memfd_is_sealed` (fcntl `F_GET_SEALS` via `libc` **in test code only**
  is acceptable, or assert `set_len` fails after sealing using safe
  `File::set_len` on a cloned fd)

---

### Commit 4 — `virtio-devices: Implement bounce pool`

Make commit-3 tests pass (~140 LOC): memfd creation + sealing (mirroring
the `update_log_base` pattern in `vu_common_ctrl.rs`), `MmapRegion::build`,
`GuestRegionMmap::new(region, GuestAddress(0))` →
`GuestMemoryMmap::from_regions`, layout computation, alloc/free/scrub via
`mem().write` of a zero buffer or `get_slice` fill. Unignore tests.

---

### Commit 5 — `virtio-devices: Add shadow queue interface`

**Goal:** The complete translation-core interface plus the *entire* unit
test battery for mirroring, completion, and robustness (ignored), plus the
shared test utilities (§3). Major files: `bounce/shadow_queue.rs` (new),
`bounce/test_utils.rs` (new, test-only).

**Interface** (~120 LOC of types/signatures/stubs):

```rust
pub struct ShadowQueueConfig { pub queue_index: usize, pub queue_size: u16 } // actual size

#[derive(Debug, PartialEq)]
pub enum MirrorOutcome { Progress { chains: usize }, Stalled { needed: u64 }, Idle }
#[derive(Debug, PartialEq)]
pub enum CompleteOutcome { Progress { chains: usize, needs_interrupt: bool }, Idle }

pub struct ShadowQueue { /* cfg, free slot stack, inflight: Vec<Option<InflightChain>>,
                            shadow_avail_idx: Wrapping<u16>, next_used: Wrapping<u16>,
                            broken: bool, stalled: Option<StallInfo> */ }
impl ShadowQueue {
    pub fn new(cfg: ShadowQueueConfig) -> Self;
    /// Consume new guest avail entries into the shadow ring.
    pub fn mirror_avail(&mut self, guest_mem: &GuestMemoryMmap,
        guest_q: &mut Queue, pool: &mut BouncePool) -> MirrorOutcome;
    /// Consume new shadow used entries back to the guest.
    pub fn complete_used(&mut self, guest_mem: &GuestMemoryMmap,
        guest_q: &mut Queue, pool: &mut BouncePool) -> CompleteOutcome;
    pub fn inflight_count(&self) -> usize;
    pub fn is_broken(&self) -> bool;
    pub fn is_stalled(&self) -> bool;
    /// Initialize counters for a fresh daemon session starting at `base`
    /// (activation, restore); assumes zeroed shadow rings.
    pub fn reset_session(&mut self, base: u16);
}
```

Internal (private) helpers to spec now: `read_shadow_used_idx` (Acquire),
`publish_shadow_avail` (entry write then Release idx store),
`write_shadow_desc`, and `struct InflightChain { guest_head: u16,
segments: Vec<Segment>, pool_extents: Vec<(GuestAddress, u64)>,
slots: Vec<u16> }`, `struct Segment { guest_addr: GuestAddress, pool_addr:
GuestAddress, len: u32, writable: bool }`.

Errors are internal: `mirror_avail`/`complete_used` return outcomes, not
`Result` — violations flip `broken` and log (`error!`, once).

**Tests (all ignored; the unignore split is stated per commit below):**

*Mirroring (→ commit 6):*
- `mirror_single_readable_descriptor_copies_data_and_publishes`
  (shadow desc addr within arena, len/flags preserved, data bytes equal,
  shadow avail idx == guest avail idx, `Progress{1}`)
- `mirror_writable_descriptor_allocates_but_does_not_copy`
- `mirror_chain_preserves_order_flags_and_linkage` (3-desc R/W/R chain;
  `FakeDaemon::read_chain` sees same lens/writability in order)
- `mirror_multiple_chains_in_one_call`
- `mirror_idle_when_no_new_entries` (second call → `Idle`)
- `mirror_zero_length_descriptor`
- `mirror_avail_ring_and_idx_wrap` (drive > 65536/qs·qs chains through a
  tiny queue with immediate fake completions; indices wrap correctly)
- `mirror_does_not_forward_guest_no_interrupt_flag` (guest sets
  `VRING_AVAIL_F_NO_INTERRUPT`; shadow avail flags == 0)
- `mirror_uses_shadow_allocated_slots` (guest head 7 may map to shadow
  head 0; in-flight table translates)
- `mirror_indirect_flag_marks_queue_broken`
- `mirror_chain_longer_than_queue_marks_queue_broken` (self-referencing
  `next` loop)
- `mirror_desc_addr_outside_guest_memory_marks_queue_broken`
- `broken_queue_mirror_is_idle_and_logs_once`

*Backpressure (→ commit 6, same code path):*
- `mirror_stalls_when_arena_exhausted_and_rolls_back` (pool free_bytes
  and slot stack unchanged after `Stalled`; guest queue cursor unmoved —
  a later call after frees consumes the same chain)
- `mirror_stall_is_all_or_nothing_across_chains` (first chain fits and is
  published; second stalls; `Progress{1}` then `Stalled`)
- `mirror_oversized_chain_reports_needed_bytes` (`Stalled{needed}` >
  `buffer_capacity`; `is_stalled()`)
- `mirror_slot_exhaustion_stalls` (many 1-desc chains in flight)

*Completion (→ commit 7):*
- `complete_copies_back_writable_data_and_publishes_guest_used`
  (fake daemon writes pattern + completes; guest buffer matches, guest
  used elem is `{guest_head, len}`, `needs_interrupt == true`)
- `complete_respects_daemon_len_cap` (len smaller than writable total →
  only len bytes copied)
- `complete_caps_len_at_writable_total` (daemon over-reports; no write
  past the writable segments; published len is the capped value)
- `complete_readonly_chain_copies_nothing`
- `complete_frees_and_scrubs_extents_and_recycles_slots`
- `complete_out_of_order_completions`
- `complete_multiple_in_one_call`
- `complete_idle_when_no_new_used`
- `complete_used_ring_and_idx_wrap`
- `complete_unknown_id_marks_queue_broken`
- `complete_stale_duplicate_id_marks_queue_broken`
- `complete_honors_guest_no_interrupt_flag` (`needs_interrupt == false`)
- `complete_uses_captured_segments_not_live_desc_table` (guest rewrites
  its desc table after mirror; copy-back still lands at original addr)
- `broken_queue_complete_is_idle`

*Lifecycle & accounting (→ commit 8):*
- `reset_session_zeroes_counters_and_inflight`
- `stall_recovery_after_completion_frees_space` (stall → complete other
  chain → mirror retry succeeds; `is_stalled()` false again)
- `permanent_stall_logs_error_once_per_episode` (needed > capacity; use a
  test logger or assert the stall-episode flag toggles)
- `soak_10k_requests_accounting_converges` (loop mirror/fake-complete
  with random-ish sizes; at the end: inflight 0, free_bytes ==
  capacity, slot stack full, no broken flag)
- `interleaved_two_queue_pool_sharing` (two ShadowQueues, one pool;
  completions on one unblock the other)

---

### Commit 6 — `virtio-devices: Implement shadow queue avail mirroring`

Implement `mirror_avail` + `reset_session` (+ private shadow-ring write
helpers) per §2.3 steps 1–6 (~190 LOC). Unignore the mirroring and
backpressure test groups. Watch the budget: if the rollback plumbing
pushes past 200 LOC, land `reset_session` + helpers + happy-path in this
commit and split validation/rollback into a follow-on commit 6b with its
subset of tests.

---

### Commit 7 — `virtio-devices: Implement shadow queue completion path`

Implement `complete_used` per §2.3 (~150 LOC). Unignore the completion
test group.

---

### Commit 8 — `virtio-devices: Harden shadow queue lifecycle`

Implement stall-episode logging, broken-queue log-once, any residual
edge cases (~60 LOC), unignore the lifecycle/accounting group. All
shadow-queue tests now run.

---

### Commit 9 — `virtio-devices: Add bounce control-plane helper interface`

**Goal:** Pure helpers that `setup_vhost_user` will call, testable without
a daemon, as interface + ignored tests. Major files: `bounce/mod.rs`,
`vu_common_ctrl.rs`.

**Interface** (~70 LOC):

```rust
// bounce/mod.rs
pub struct BounceQueueFds { pub shadow_kick: EventFd, pub shadow_call: EventFd }
impl BounceQueueFds { pub fn new() -> Result<Self, BounceError>; /* + try_clone */ }

// vu_common_ctrl.rs (pub(crate))
fn bounce_mem_region(pool: &BouncePool) -> VhostUserMemoryRegionInfo;
fn bounce_vring_config(pool: &BouncePool, queue_index: usize,
    actual_size: u16, max_size: u16) -> VringConfigData;

pub struct BounceSetup<'a> { pub pool: &'a BouncePool, pub fds: &'a [BounceQueueFds] }
```

**Tests (ignored until commit 10):**
- `bounce_mem_region_is_pool_at_gpa_zero` (fd, size, userspace_addr,
  offset 0)
- `bounce_vring_config_points_into_pool_rings` (desc/avail/used ==
  host_base + offsets; queue_max_size/queue_size set from args; flags 0;
  log_addr None)
- `bounce_vring_config_uses_actual_size_smaller_than_max`
- `bounce_queue_fds_are_distinct_nonblocking_eventfds`

---

### Commit 10 — `virtio-devices: Wire bounce path into vhost-user setup`

**Goal:** `setup_vhost_user`/`reinitialize_vhost_user` take
`bounce: Option<&BounceSetup>` and branch per §2.8; implement commit-9
helpers; all existing callers pass `None`. Major files:
`vu_common_ctrl.rs`, `vhost_user/mod.rs` (reconnect call site),
`{blk,fs,net,generic_vhost_user}.rs` (mechanical `None`). (~130 LOC.)
Also: `update_mem_table` gains a `bounce` short-circuit; hotplug
`add_memory_region_internal` returns `Ok(())` when bounce is on
(decision helper `VhostUserCommon::forwards_memory_to_backend() -> bool`
so it is unit-testable). Unignore commit-9 tests; add
`forwards_memory_to_backend_false_with_bounce` (not ignored — helper is
trivial and implemented here).

---

### Commit 11 — `virtio-devices: Add pause hook to EpollHelperHandler`

**Goal:** Let handlers run code after the pause event is observed but
*before* parking at `paused_sync`. Major file: `epoll_helper.rs`
(~12 LOC): add to the trait
`fn on_pause(&mut self, _helper: &mut EpollHelper) {}` (default no-op) and
call it in `run_with_timeout`'s `EPOLL_HELPER_EVENT_PAUSE` arm right
before `paused_sync.wait()`.

**Tests (same commit, not ignored — the hook is complete here):**
- `on_pause_runs_before_barrier_release` (handler impl sets an
  `Arc<AtomicBool>`; main thread fires pause_evt, waits on the barrier,
  asserts the flag is set the moment the barrier releases)
- `default_on_pause_is_noop_for_existing_handlers` (existing dummy
  handler still runs — effectively a compile/behavior regression test)

---

### Commit 12 — `virtio-devices: Add bounce data-plane worker interface`

**Goal:** Worker struct + event map + ignored behavioral tests driven with
real eventfds and `FakeDaemon`. Major file: `bounce/worker.rs` (new).

**Interface** (~100 LOC): `BounceEpollHandler` fields per §2.5
(`guest_mem: GuestMemoryAtomic<GuestMemoryMmap>`, `pool:
Arc<Mutex<BouncePool>>`, `queues: Vec<(usize, Queue, EventFd)>`,
`shadow: Vec<ShadowQueue>`, `fds: Vec<BounceQueueFds>`, `interrupt:
Arc<dyn VirtioInterrupt>`, `kill_evt`, `pause_evt`), `pub fn run(&mut
self, paused, paused_sync) -> Result<(), EpollHelperError>`, plus
`EpollHelperHandler` impl skeleton (event constants, `handle_event`
dispatch calling `todo!()` private methods, `on_pause` stub).

**Tests (ignored until commit 13)** — each spawns the worker on a thread,
uses `GuestRingBuilder` + `FakeDaemon` + `TestInterrupt`, then kills via
`kill_evt`:
- `guest_kick_mirrors_and_kicks_daemon` (write chain, publish, signal
  guest evt; wait `shadow_kick` readable; `FakeDaemon` sees the chain)
- `daemon_call_copies_back_and_interrupts` (fake-complete + signal
  `shadow_call`; wait `TestInterrupt` fired; guest used ring updated)
- `end_to_end_echo_roundtrip` (readable request + writable response;
  fake daemon "echoes"; guest sees response bytes)
- `completion_retries_stalled_queues_across_queue_boundary` (queue 0
  stalled on arena space; completion arrives on queue 1; queue 0's chain
  gets mirrored and daemon kicked without a new guest kick)
- `pause_drains_pending_completions_before_barrier` (fake-complete
  without signaling call evt; fire pause; after barrier, guest used ring
  contains the completion)
- `kill_event_terminates_worker_promptly`
- `worker_initial_sweep_mirrors_preexisting_avail_entries` (entries
  published before the worker starts are mirrored without any kick —
  restore semantics, §2.6)
- `two_queues_route_events_independently`

---

### Commit 13 — `virtio-devices: Implement bounce data-plane worker`

Implement the dispatch methods per §2.5–§2.6 (~170 LOC): eventfd drain +
mirror + kick; call drain + complete + interrupt + global stall retry;
`on_pause` drain loop with `BOUNCE_DRAIN_TIMEOUT` bounded wait; initial
sweep at loop start. Unignore commit-12 tests.

---

### Commit 14 — `virtio-devices: Add bounce state to VhostUserCommon interface`

**Goal:** The container tying pool/fds/shadow queues to a device, feature
masking, and lifecycle decision helpers — interface + ignored tests.
Major files: `bounce/mod.rs`, `vhost_user/mod.rs`.

**Interface** (~90 LOC):

```rust
// bounce/mod.rs
pub struct BounceConfig { pub pool_size: Option<u64> }
pub struct BounceState {
    pub pool: Arc<Mutex<BouncePool>>,
    pub fds: Vec<BounceQueueFds>,
    pub inflight_total: Arc<AtomicUsize>, // maintained by the worker
}
impl BounceState {
    pub fn new(cfg: &BounceConfig, num_queues: usize, queue_size: u16)
        -> Result<Self, BounceError>;
}
pub fn mask_bounce_features(avail_features: u64) -> u64;

// vhost_user/mod.rs
pub struct VhostUserCommon { /* + pub bounce: Option<BounceState> */ }
```

**Tests (ignored until commit 15):**
- `mask_bounce_features_clears_indirect_event_idx_in_order`
- `mask_bounce_features_preserves_other_bits`
  (`DEFAULT_VIRTIO_FEATURES` minus exactly those three)
- `bounce_state_new_default_pool_size` / `_with_override`
- `bounce_state_new_creates_one_fd_pair_per_queue`
- `start_dirty_log_rejected_with_bounce` (construct `VhostUserCommon`
  with `bounce: Some(..)`, `vu: None` → expect
  `MigratableError::StartDirtyLog`)
- `snapshot_rejected_with_nonzero_inflight` (set `inflight_total` to 1;
  `VhostUserCommon::snapshot` errs; zero → ok)

---

### Commit 15 — `virtio-devices: Activate bounce data plane in VhostUserCommon`

**Goal:** Full lifecycle integration (~190 LOC). Major file:
`vhost_user/mod.rs`.

- `VhostUserCommon::activate`: when `bounce` is `Some`, build
  `ShadowQueue`s (actual sizes from `queues`, `reset_session(base)` with
  the same base value passed to `set_vring_base`), call `zero_rings`,
  pass `BounceSetup` into `setup_vhost_user`, construct the
  `BounceEpollHandler` from the *real* guest queue eventfds while the
  daemon gets the shadow fds, and return both handlers (change the return
  type to carry an `Option<BounceEpollHandler>`).
- Devices' `activate` (done per-device in commits 17/19/20/21, but the
  shared helper lands here): spawn the bounce worker as a second thread
  (`{id}_bounce`, dup'd kill/pause eventfds) and resize `paused_sync` to
  `Barrier::new(3)` when bounce is on (net + ctrl queue: 4) — mirror the
  `net.rs` ctrl-thread pattern exactly.
- `start_dirty_log` → `Err` when bounce (implements commit-14 test).
- `snapshot` → inflight check (implements commit-14 test).
- `reset`/`shutdown`: nothing pool-specific beyond thread teardown via the
  existing kill/join paths (pool drops with the device).

Unignore commit-14 tests. Worker-level behavior is already covered by
commit-12/13 tests; add here (not ignored):
- `activate_returns_bounce_handler_only_when_enabled` — exercised at the
  `VhostUserCommon::activate` level if constructible without a live
  daemon; if it is not (it needs a connected `VhostUserHandle`), document
  that in the commit message and rely on the commit-18 loopback test for
  coverage of this glue. Do not build a mock vhost-user server just for
  this.

---

### Commit 16 — `vmm: Add bounce options to disk config`

**Goal:** CLI/config surface for `--disk` (declarative; tests land
passing in the same commit). Major files: `vmm/src/vm_config.rs`
(`DiskConfig { pub bounce: bool, pub bounce_pool_size: Option<u64> }`,
serde defaults), `vmm/src/config.rs` (parser: `.add("bounce")`
`.add("bounce_pool_size")`, `Toggle` + `ByteSized` conversion, update the
disk syntax string near the existing `vhost_user=on|off` text, and
validation), `vmm/src/api/openapi/cloud-hypervisor.yaml` (DiskConfig
schema). (~80 LOC.)

Validation rules (in `DiskConfig::validate` / equivalent):
- `bounce=on` requires `vhost_user=on` → new `ValidationError` variant.
- `bounce=on` with `pci_common.iommu=true` → rejected (until commit 31).
- `bounce_pool_size` without `bounce=on` → rejected.

**Tests:** `disk_parse_bounce_defaults_off`, `disk_parse_bounce_on`,
`disk_parse_bounce_pool_size_bytesized` (`bounce_pool_size=16M`),
`disk_validate_bounce_requires_vhost_user`,
`disk_validate_bounce_rejects_iommu`,
`disk_validate_pool_size_requires_bounce`, plus a serde round-trip in the
existing config test style.

---

### Commit 17 — `vmm: Plumb bounce config into vhost-user-blk`

**Goal:** End-to-end enablement for blk. Major files:
`vu_common_ctrl.rs` (`VhostUserConfig { ..., pub bounce:
Option<BounceConfig> }`), `vhost_user/blk.rs` (build `BounceState` in
`Blk::new`, apply `mask_bounce_features` to `avail_features` *before*
`negotiate_features_vhost_user`, spawn the bounce worker in `activate` per
the commit-15 pattern), `vmm/src/device_manager.rs` (populate
`VhostUserConfig.bounce` from `DiskConfig`). (~90 LOC.)

**Tests:** blk `new()` requires a live socket, so unit coverage here is:
`vhost_user_config_bounce_default_none` plus a non-ignored test of the
masking call path if `Blk`'s feature computation is factorable into a
pure function (`blk_avail_features(num_queues, bounce: bool)` — factor it
out; test that bounce clears the three ring bits and everything else
matches the non-bounce value). Full-stack behavior comes in commit 18.

---

### Commit 18 — `virtio-devices: Add vhost-user-blk bounce loopback test`

**Goal:** Test-only commit (no production LOC): a real end-to-end test of
Blk + bounce against the in-tree backend. Major files:
`virtio-devices/tests/vhost_user_bounce_blk.rs` (new),
`virtio-devices/Cargo.toml` (dev-dependency on `vhost_user_block` —
in-workspace, dev-only).

Spawn `vhost_user_block::start_block_backend("path=<tmp raw
image>,socket=<tmp sock>")` on a thread; construct `Blk::new` with
`bounce: Some(default)`; drive `VirtioDevice::activate` with test guest
memory, `GuestRingBuilder` queues, and `TestInterrupt`; then, acting as
the guest: write a 4 KiB block (readable header desc + data + writable
status byte per virtio-blk request layout), kick, await interrupt, assert
status `VIRTIO_BLK_S_OK` and that the bytes landed in the image file;
then read it back through a second request and compare. Also assert the
image file contents are reachable *only* via the pool (sanity: guest
buffer addresses never appear in the shadow ring — walk it with
`FakeDaemon::read_chain`-style helpers). If `start_block_backend`'s API
shape makes in-process reuse impossible, fall back to a minimal in-test
backend built on the `vhost-user-backend` workspace crate; do not shell
out to a prebuilt binary.

---

### Commit 19 — `vmm: Enable bounce for vhost-user-fs`

`FsConfig { bounce, bounce_pool_size }` + parser + validation (bounce
needs no `vhost_user=on` gate — fs is always vhost-user; iommu rule
applies; **no** DAX exclusivity — document in the commit message why DAX
is orthogonal, §1.3), openapi, `Fs::new`/`activate` plumbing + masking,
device_manager. (~100 LOC.) Tests mirror commit 16's list for fs, plus
`fs_bounce_with_cache_size_accepted`.

---

### Commit 20 — `vmm: Enable bounce for vhost-user-net`

Same shape for `NetConfig` + `net.rs`. (~110 LOC.) Note: only the data
queues go through the daemon; the ctrl queue stays CH-emulated and
unbounced (assert in a comment; the ctrl queue already never reaches
`setup_vhost_user`). `paused_sync` sizing: with ctrl thread + vhost
thread + bounce worker it becomes `Barrier::new(4)` — test
`net_bounce_barrier_accounts_for_all_threads` if the sizing logic is
factorable; otherwise verify via the reconnect/pause integration test in
commit 33. Tests mirror commit 16 for net (`net_parse_bounce_*`,
`net_validate_bounce_requires_vhost_user`, iommu rejection).

---

### Commit 21 — `vmm: Enable bounce for generic vhost-user`

Same shape for `GenericVhostUserConfig` + `generic_vhost_user.rs`
(~90 LOC), including its cache/shared-memory region (same DAX-orthogonal
reasoning as fs). Tests mirror commit 19.

---

### Commit 22 — `virtio-devices: Add restore priming interface`

**Goal:** Snapshot/restore correctness per §2.6 — interface + ignored
tests. Major files: `bounce/shadow_queue.rs`, `bounce/worker.rs`.

Interface (~40 LOC): `ShadowQueue::reset_session` already exists; add
`pub fn verify_drained(&self) -> bool` and worker support for
starting from a restored base (the initial sweep of commit 13 already
mirrors pending entries; what's new is asserting/wiring the drained-pause
invariant end to end and the restore path through
`VhostUserCommon::activate` with `vring_bases: Some(..)`).

**Tests (ignored until commit 23):**
- `restore_worker_mirrors_entries_between_base_and_avail_idx` (guest ring
  restored with avail idx 5, used idx 3, daemon base 3 → exactly chains
  3,4 get mirrored on startup sweep; shadow avail idx becomes 5)
- `restore_with_wrapped_indices`
- `restore_with_base_equal_avail_idx_is_noop`
- `pause_then_snapshot_state_has_zero_inflight` (drive I/O, pause with
  cooperative fake daemon, assert `inflight_total == 0` and guest used
  idx == avail idx)
- `pause_with_wedged_daemon_times_out_and_snapshot_fails` (fake daemon
  never completes; pause returns after `BOUNCE_DRAIN_TIMEOUT` — shrink
  the const for tests via `#[cfg(test)]` value or a struct field;
  snapshot errs)

### Commit 23 — `virtio-devices: Implement restore priming`

Make commit-22 tests pass (~80 LOC): `reset_session(base)` +
initial-sweep interplay, `verify_drained`, `inflight_total` maintenance in
the worker, snapshot gate already landed in 15 (now actually reachable).
Unignore tests.

---

### Commit 24 — `virtio-devices: Add bounce reconnect interface`

**Goal:** §2.7 — interface + ignored tests. Major files:
`bounce/shadow_queue.rs`, `vhost_user/mod.rs` (reconnect path).

Interface (~50 LOC): `ShadowQueue::rebuild_for_reconnect(&mut self, pool:
&mut BouncePool, new_base: u16) -> u16 /* returns new shadow avail idx */`
(re-publishes all in-flight chains in original submission order — keep
submission order via a monotonic sequence number in `InflightChain`), and
the coordination point: `VhostUserEpollHandler` gains access to the
bounce worker's shared state (`Arc<Mutex<...>>` around the worker's
shadow/pool — restructure so both the worker loop and the reconnect
thread lock the same state; keep lock scopes tight and document the lock
order: pool before shadow, or a single combined mutex — prefer one
`Mutex<BounceShared>` holding pool + shadow queues to make deadlock
impossible).

**Tests (ignored until commit 25):**
- `rebuild_republishes_inflight_in_submission_order`
- `rebuild_with_empty_inflight_publishes_nothing`
- `rebuild_preserves_pool_extents_and_data` (data written pre-crash is
  still what the re-published chain references)
- `rebuild_then_completion_completes_once` (complete after rebuild; guest
  sees exactly one used entry)
- `worker_and_reconnect_share_state_without_deadlock` (reconnect-style
  rebuild called from another thread while worker is live)

### Commit 25 — `virtio-devices: Implement bounce reconnect`

Wire `reconnect_inner` to quiesce + `zero_rings` + `rebuild_for_reconnect`
per queue + pass `BounceSetup` to `reinitialize_vhost_user` with the new
bases (~120 LOC). Unignore tests. Note in the commit message: re-executed
in-flight requests have the same at-least-once semantics as existing
reconnect without backend inflight state.

---

### Commit 26 — `virtio-devices: Add indirect descriptor bounce interface`

Ignored tests + plumbing for `VIRTIO_F_RING_INDIRECT_DESC` (~30 LOC of
signature/const changes; the mask still includes the bit until 27).

**Design (decided): pool-side indirect tables, never flattening.** An
indirect chain consumes exactly **one** shadow descriptor slot (with
`F_INDIRECT` set, pointing at a pool extent holding the rewritten
table), preserving the queue-depth property that indirect descriptors
exist to provide. Flattening into direct shadow descriptors was
considered and rejected: it would consume N shadow slots per chain and
collapse the effective in-flight depth by ~N× for multi-segment
workloads (Linux uses indirect for nearly every multi-segment request
once negotiated), silently throttling exactly the requests that matter.
The pool-table cost is one extra small extent per chain (16 × N bytes)
and a shared descriptor-serialization helper parameterized by its write
target (shadow table slot vs. pool extent).

Implementation note: virtio-queue's `DescriptorChain` iteration
transparently resolves indirect chains (yielding the flattened entries,
which is exactly what mirroring needs for segment capture), but it does
not report *that* the chain was indirect — detect that by loading the
head slot's raw descriptor from the guest desc table and checking
`F_INDIRECT` before walking.

**Tests (ignored until commit 27):**
- `indirect_chain_mirrored_via_pool_indirect_table` (guest indirect table
  is copied into a pool extent with rewritten addrs; the single shadow
  descriptor keeps `F_INDIRECT` and points at the pool table;
  `FakeDaemon::read_chain` grows indirect-table support to verify)
- `indirect_chain_consumes_one_shadow_slot` (queue_size indirect chains
  of 8 segments each can all be in flight simultaneously, arena
  permitting — the queue-depth property above)
- `indirect_table_size_not_multiple_of_16_marks_broken`
- `indirect_table_longer_than_queue_size_marks_broken`
- `nested_indirect_marks_broken` (indirect entry with `F_INDIRECT`)
- `indirect_writable_entries_copy_back`
- `indirect_allocation_failure_stalls_atomically` (table + buffers all
  rolled back)
- `indirect_table_extent_freed_and_scrubbed_on_completion`
- `mask_no_longer_clears_indirect` (flips the commit-14 mask test —
  update that test in 27, not here)

### Commit 27 — `virtio-devices: Implement indirect descriptor bouncing`

Implementation (~170 LOC): detect `F_INDIRECT` on the head descriptor,
validate the table (size multiple of 16, ≤ queue_size entries, no nested
indirect), allocate one pool extent for the table plus extents for each
buffer (all-or-nothing with the existing rollback path — the table
extent joins `InflightChain::pool_extents` so completion frees and
scrubs it too), copy device-readable buffer contents, write the
rewritten table into the pool via the shared descriptor-serialization
helper, and publish a single `F_INDIRECT` shadow descriptor. Remove the
bit from `mask_bounce_features`, update the mask unit tests, unignore
commit-26 tests.

### Commit 28 — `virtio-devices: Add event-idx interface for bounce`

Ignored tests for `VIRTIO_F_RING_EVENT_IDX` (~20 LOC changes):
- `guest_interrupt_suppressed_until_used_event` (guest sets used_event =
  N; completions ≤ N don't request interrupt; crossing N does) — four
  wrap-boundary cases mirroring the `vring_need_event` spec math (all via
  `Queue::needs_notification`, so these are behavioral tests of *our*
  call sequence, not of virtio-queue internals)
- `avail_event_kept_current_so_guest_always_kicks`
  (after each mirror batch, guest-visible avail_event == guest avail
  idx — via `Queue::enable_notification` return handling)
- `shadow_rings_never_carry_event_idx_suppression` (shadow avail flags 0,
  shadow used_event area untouched/zero)
- `notification_race_recheck` (`enable_notification` returning true →
  another mirror pass before sleeping; simulate the race by publishing an
  entry between mirror and enable)

### Commit 29 — `virtio-devices: Implement event-idx support for bounce`

Set `queue.set_event_idx(acked)` for the guest-side queues, use
`needs_notification`/`enable_notification` in the worker loop (including
the race re-check pattern used by CH's emulated net/blk handlers), remove
the bit from `mask_bounce_features`, update mask tests, unignore. (~90 LOC.)

### Commit 30 — `virtio-devices: Add vIOMMU translation interface for bounce`

Ignored tests (~30 LOC changes): thread an
`Option<Arc<dyn AccessPlatform>>` into `ShadowQueue` (mirroring how
`block.rs` passes it to `Request::parse`):
- `mirror_translates_desc_addresses_via_access_platform` (mock
  `AccessPlatform` adding a fixed offset; copy-in reads from translated
  GPA)
- `copyback_uses_translated_addresses`
- `translation_failure_marks_queue_broken`
- `no_access_platform_means_identity` (existing tests still pass — no new
  test, just an invariant note)

### Commit 31 — `virtio-devices: Implement vIOMMU support for bounce`

Apply `AccessPlatform::translate_gva` to descriptor addresses during
mirroring (ring addresses are already translated by the transport before
`activate`), plumb `common.access_platform()` from the devices, and
**relax the vmm validation** from commits 16/19/20/21 (delete the iommu
rejection + flip those validation tests to acceptance). Unignore
commit-30 tests. (~80 LOC across virtio-devices + vmm.)

---

### Commit 32 — `docs: Document vhost-user bounce buffer pool`

New `docs/vhost-user-bounce.md`: what it does, why (motivations §1.2),
CLI examples for all four device types, pool sizing guidance (default
formula, how to read the stall `error!` log and pick
`bounce_pool_size`), interaction matrix (migration unsupported, snapshot
supported, DAX/vIOMMU/reconnect notes), and a short "how it works"
section linking to this plan. Update the `--disk`/`--net`/`--fs` option
tables wherever the existing docs enumerate them (grep for
`vhost_user=on` under `docs/`).

### Commit 33 — `tests: Add vhost-user bounce integration tests`

Test-only. In `cloud-hypervisor/tests/` (built via the `devcli_testenv`
cfg — verify compilation with clippy, which includes those paths per
`AGENTS.md`): clone the existing vhost-user-blk boot test with
`bounce=on` (boot, mount, dd write/read, verify integrity), a
vhost-user-net `bounce=on` ping/iperf smoke, a snapshot/restore cycle of
a bounce=on blk VM, and a daemon-kill/reconnect case if the existing
suite has a reconnect precedent to clone. These run only in the
privileged CI harness; the commit gate is compilation + review.

---

## 5. Feature interaction matrix (post-series behavior)

| Interaction | Behavior |
|---|---|
| `bounce=on` + live migration | `start_dirty_log` fails; migration aborts cleanly. |
| `bounce=on` + snapshot/restore | Supported; pause drains; snapshot fails if a wedged daemon left in-flight requests. |
| `bounce=on` + memory hotplug | Guest RAM changes are invisible to the daemon (no-op); pool unaffected. |
| `bounce=on` + `iommu=on` | Supported from commit 31 (rejected by validation before that). |
| `bounce=on` + fs DAX / generic cache | Allowed; cache windows are daemon→guest mappings outside the mem table. |
| `bounce=on` + daemon reconnect | Supported from commit 25; in-flight requests are re-executed (at-least-once). |
| `bounce=on` + INFLIGHT_SHMFD | Still negotiated (harmless); CH's own in-flight table is authoritative for re-submission. |
| `bounce=off` | Every code path identical to before the series (verified by untouched existing tests). |

## 6. Executor gotchas

- **Never** hand the daemon anything derived from guest memory when
  bounce is on: audit every `mem`/`get_host_address_range` use inside the
  `setup_vhost_user` bounce branch.
- The `queues` vector in `activate` contains the *guest* eventfds; with
  bounce they go to the worker's epoll, and only `BounceQueueFds` cross
  the socket. Getting this backwards deadlocks silently.
- `u16` ring indices: use `std::num::Wrapping` everywhere; slot =
  `idx.0 % actual_queue_size`.
- Shadow-side stores must go through the pool's `GuestMemoryMmap`
  (`Bytes::store` for indexes with explicit `Ordering`); guest-side ring
  bookkeeping goes through `virtio_queue::Queue` which handles its own
  ordering.
- Pool `alloc` returns pool GPAs (`GuestAddress`), which equal file
  offsets, which equal `host_base + offset`. Keep the three coordinate
  systems straight; `bounce_vring_config` is the only place host
  addresses appear.
- `go_to_previous_position()` only rewinds one chain; the stall path must
  therefore pop at most one chain past the last success (pop → try-alloc
  → rollback+rewind on failure → return), never batch-pop.
- Don't forget `Barrier` resizing when adding the second worker thread
  (net with ctrl queue needs 4) — a wrong count hangs `pause()` forever.
- Run `cargo +nightly fmt --all` (nightly is required; stable rustfmt
  reorders imports differently and will fight CI).
- When a test needs to observe "logged once", prefer asserting the
  internal episode flag/counter rather than capturing log output.

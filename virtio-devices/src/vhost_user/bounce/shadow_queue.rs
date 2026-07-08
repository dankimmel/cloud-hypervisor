// Copyright 2026 Cloud Hypervisor Contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shadow queue translation: mirrors a guest virtqueue into a bounce
//! pool shadow ring for the backend, and completions back again.
//!
//! Design invariants (see `docs/vhost-user-bounce-plan.md` §2.3):
//!
//! - The shadow avail/used *index counters* advance in lockstep with the
//!   guest ring's, so `SET_VRING_BASE` semantics are unchanged.
//! - Shadow *descriptor slots* are allocated by the VMM from a per-queue
//!   free stack; used elements coming back from the backend carry shadow
//!   heads that are translated to guest heads via the in-flight table.
//! - Ring flags and event-idx fields are never mirrored: the shadow ring
//!   stays in always-notify mode in both directions, and guest-side
//!   interrupt suppression is applied by the VMM when completing.
//! - All guest-controlled data is read exactly once, validated, and
//!   captured; completions use the captured state (immune to concurrent
//!   guest descriptor-table rewrites).

use std::num::Wrapping;
use std::sync::atomic::Ordering;

use log::error;
use virtio_bindings::virtio_ring::{
    VRING_AVAIL_F_NO_INTERRUPT, VRING_DESC_F_INDIRECT, VRING_DESC_F_NEXT, VRING_DESC_F_WRITE,
};
use virtio_queue::desc::split::Descriptor;
use virtio_queue::{Queue, QueueOwnedT, QueueT};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryError};

use super::allocator::BOUNCE_ALLOC_ALIGN;
use super::pool::{BouncePool, RingOffsets};
use crate::GuestMemoryMmap;

/// Chunk size for staged guest<->pool copies. Staging through a scratch
/// buffer keeps every access inside the safe vm-memory slice APIs while
/// still handling guest buffers that span region boundaries.
const COPY_CHUNK: usize = 16 * 1024;

/// Static configuration of one shadow queue.
#[derive(Clone, Copy)]
pub struct ShadowQueueConfig {
    /// Queue index within the device.
    pub queue_index: usize,
    /// Actual (negotiated) queue size; at most the pool layout's maximum.
    pub queue_size: u16,
}

/// Result of one [`ShadowQueue::mirror_avail`] call.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MirrorOutcome {
    /// Chains newly published to the shadow ring. Kick the backend when
    /// this is non-zero.
    pub chains: usize,
    /// The next pending chain could not be translated for lack of pool
    /// space or shadow descriptor slots; the queue stalls (consuming
    /// nothing further) until completions free resources.
    pub stalled: bool,
}

/// Result of one [`ShadowQueue::complete_used`] call.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CompleteOutcome {
    /// Chains completed back into the guest used ring.
    pub chains: usize,
    /// Whether the guest should be interrupted for this progress.
    pub needs_interrupt: bool,
}

/// One captured guest buffer segment of an in-flight chain.
struct Segment {
    guest_addr: GuestAddress,
    pool_addr: GuestAddress,
    len: u32,
    writable: bool,
}

/// A chain currently owned by the backend.
struct InflightChain {
    guest_head: u16,
    segments: Vec<Segment>,
    /// Shadow descriptor slots used by this chain, head first.
    slots: Vec<u16>,
}

/// Mirrors one guest virtqueue into a shadow ring inside the pool.
pub struct ShadowQueue {
    queue_index: usize,
    size: u16,
    ring: RingOffsets,
    /// Free shadow descriptor slots (LIFO).
    free_slots: Vec<u16>,
    /// In-flight chains indexed by shadow head slot.
    inflight: Vec<Option<InflightChain>>,
    inflight_count: usize,
    shadow_avail_idx: Wrapping<u16>,
    /// Next shadow used entry to consume.
    next_used: Wrapping<u16>,
    /// Scratch buffer for chunked guest<->pool copies.
    scratch: Vec<u8>,
    broken: bool,
    stalled: bool,
    /// Set once the current stall episode has been logged.
    stall_logged: bool,
}

impl ShadowQueue {
    /// Create the shadow of a guest queue whose rings live at `ring`
    /// inside the pool.
    pub fn new(cfg: ShadowQueueConfig, ring: RingOffsets) -> Self {
        let size = cfg.queue_size;
        ShadowQueue {
            queue_index: cfg.queue_index,
            size,
            ring,
            free_slots: (0..size).rev().collect(),
            inflight: (0..size).map(|_| None).collect(),
            inflight_count: 0,
            shadow_avail_idx: Wrapping(0),
            next_used: Wrapping(0),
            scratch: Vec::new(),
            broken: false,
            stalled: false,
            stall_logged: false,
        }
    }

    /// Re-initialize counters for a fresh backend session starting at
    /// `base` (device activation or snapshot restore). Assumes the shadow
    /// rings have been zeroed and no chain is in flight.
    pub fn reset_session(&mut self, base: u16) {
        debug_assert_eq!(self.inflight_count, 0);
        self.free_slots = (0..self.size).rev().collect();
        self.inflight = (0..self.size).map(|_| None).collect();
        self.inflight_count = 0;
        self.shadow_avail_idx = Wrapping(base);
        self.next_used = Wrapping(base);
        self.broken = false;
        self.stalled = false;
        self.stall_logged = false;
    }

    /// Translate new guest avail entries into the shadow ring: allocate
    /// pool extents, copy device-readable data in, publish rewritten
    /// descriptor chains.
    pub fn mirror_avail(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        guest_q: &mut Queue,
        pool: &mut BouncePool,
    ) -> MirrorOutcome {
        let mut out = MirrorOutcome::default();
        if self.broken {
            return out;
        }

        'chains: while let Some(chain) = guest_q.pop_descriptor_chain(guest_mem) {
            let guest_head = chain.head_index();

            // Detect indirect chains before walking them: virtio-queue's
            // iterator transparently resolves indirect tables, which the
            // bounce path does not support (yet).
            match self.head_flags(guest_mem, guest_q.desc_table(), guest_head) {
                Ok(flags) if flags & VRING_DESC_F_INDIRECT as u16 != 0 => {
                    self.mark_broken("chain uses indirect descriptors, unsupported with bounce");
                    break 'chains;
                }
                Ok(_) => {}
                Err(e) => {
                    self.mark_broken(&format!("descriptor table inaccessible: {e}"));
                    break 'chains;
                }
            }

            // Walk the chain. The iterator stops silently on loops,
            // overlong chains and unreadable descriptor tables; in all
            // those cases the last yielded descriptor still claims a
            // successor, which is how they are told apart from a clean
            // end of chain.
            let mut descs: Vec<Descriptor> = Vec::new();
            let mut open_ended = false;
            for desc in chain {
                open_ended = desc.has_next();
                descs.push(desc);
            }
            if descs.is_empty() || open_ended {
                self.mark_broken("malformed descriptor chain");
                break 'chains;
            }
            for desc in &descs {
                if desc.len() != 0 && !guest_mem.check_range(desc.addr(), desc.len() as usize) {
                    self.mark_broken("descriptor buffer outside guest memory");
                    break 'chains;
                }
            }

            let needed: u64 = descs
                .iter()
                .filter(|d| d.len() != 0)
                .map(|d| u64::from(d.len()).next_multiple_of(BOUNCE_ALLOC_ALIGN))
                .sum();

            // Reserve shadow descriptor slots and pool extents,
            // all-or-nothing: on failure roll everything back, rewind the
            // guest queue cursor and stall until completions free space.
            if self.free_slots.len() < descs.len() {
                guest_q.go_to_previous_position();
                self.enter_stall(needed, pool.buffer_capacity());
                out.stalled = true;
                break 'chains;
            }
            let mut extents: Vec<GuestAddress> = Vec::with_capacity(descs.len());
            for desc in &descs {
                let extent = if desc.len() == 0 {
                    Some(GuestAddress(0))
                } else {
                    pool.alloc(u64::from(desc.len()))
                };
                match extent {
                    Some(addr) => extents.push(addr),
                    None => {
                        self.rollback_extents(pool, &descs, &extents);
                        guest_q.go_to_previous_position();
                        self.enter_stall(needed, pool.buffer_capacity());
                        out.stalled = true;
                        break 'chains;
                    }
                }
            }

            // Copy device-readable data into the pool.
            for (desc, extent) in descs.iter().zip(&extents) {
                if desc.len() == 0 || desc.is_write_only() {
                    continue;
                }
                if let Err(e) = self.copy_chunked(
                    |buf, offset| guest_mem.read_slice(buf, desc.addr().unchecked_add(offset)),
                    |buf, offset| pool.mem().write_slice(buf, extent.unchecked_add(offset)),
                    desc.len(),
                ) {
                    self.rollback_extents(pool, &descs, &extents);
                    self.mark_broken(&format!("guest buffer copy failed: {e}"));
                    break 'chains;
                }
            }

            // Write the rewritten chain into the shadow descriptor table.
            let count = descs.len();
            let mut slots = Vec::with_capacity(count);
            for _ in 0..count {
                // Availability was checked above.
                slots.push(self.free_slots.pop().unwrap());
            }
            for (i, (desc, extent)) in descs.iter().zip(&extents).enumerate() {
                let mut flags = 0u16;
                if desc.is_write_only() {
                    flags |= VRING_DESC_F_WRITE as u16;
                }
                let next = if i + 1 < count {
                    flags |= VRING_DESC_F_NEXT as u16;
                    slots[i + 1]
                } else {
                    0
                };
                let shadow = Descriptor::new(extent.raw_value(), desc.len(), flags, next);
                let addr = GuestAddress(self.ring.desc + u64::from(slots[i]) * 16);
                // Writes into the pool cannot fail (fixed, mapped, in
                // bounds); treat failure as an internal error.
                if pool.mem().write_obj(shadow, addr).is_err() {
                    self.mark_broken("shadow descriptor write failed");
                    break 'chains;
                }
            }

            // Publish the avail entry (the index store below makes the
            // whole batch visible to the backend).
            let pos = self.shadow_avail_idx.0 % self.size;
            let entry_addr = GuestAddress(self.ring.avail + 4 + u64::from(pos) * 2);
            if pool.mem().write_obj(slots[0], entry_addr).is_err() {
                self.mark_broken("shadow avail entry write failed");
                break 'chains;
            }
            self.shadow_avail_idx += 1;

            let segments = descs
                .iter()
                .zip(&extents)
                .map(|(d, a)| Segment {
                    guest_addr: d.addr(),
                    pool_addr: *a,
                    len: d.len(),
                    writable: d.is_write_only(),
                })
                .collect();
            let head_slot = usize::from(slots[0]);
            debug_assert!(self.inflight[head_slot].is_none());
            self.inflight[head_slot] = Some(InflightChain {
                guest_head,
                segments,
                slots,
            });
            self.inflight_count += 1;

            out.chains += 1;
            self.stalled = false;
            self.stall_logged = false;
        }

        if out.chains > 0 {
            // Release-store the new shadow avail index: everything written
            // above becomes visible to the backend no later than this.
            let idx_addr = GuestAddress(self.ring.avail + 2);
            if pool
                .mem()
                .store(self.shadow_avail_idx.0, idx_addr, Ordering::Release)
                .is_err()
            {
                self.mark_broken("shadow avail index store failed");
            }
        }
        out
    }

    /// Read the raw flags of the descriptor at `head` in the guest
    /// descriptor table (before any chain walking).
    fn head_flags(
        &self,
        guest_mem: &GuestMemoryMmap,
        desc_table: u64,
        head: u16,
    ) -> Result<u16, GuestMemoryError> {
        // flags is the u16 at offset 12 of the 16-byte descriptor.
        guest_mem.load(
            GuestAddress(desc_table + u64::from(head) * 16 + 12),
            Ordering::Relaxed,
        )
    }

    /// Free the extents allocated so far for a chain that will not be
    /// published. `extents` parallels the leading elements of `descs`.
    fn rollback_extents(
        &mut self,
        pool: &mut BouncePool,
        descs: &[Descriptor],
        extents: &[GuestAddress],
    ) {
        for (desc, extent) in descs.iter().zip(extents) {
            if desc.len() != 0 {
                // Freeing a just-allocated extent cannot fail.
                let res = pool.free(*extent, u64::from(desc.len()));
                debug_assert!(res.is_ok());
            }
        }
    }

    /// Staged copy of `len` bytes through the scratch buffer; `read` and
    /// `write` receive (chunk, offset) pairs.
    fn copy_chunked(
        &mut self,
        mut read: impl FnMut(&mut [u8], u64) -> Result<(), GuestMemoryError>,
        mut write: impl FnMut(&[u8], u64) -> Result<(), GuestMemoryError>,
        len: u32,
    ) -> Result<(), GuestMemoryError> {
        if self.scratch.is_empty() {
            self.scratch.resize(COPY_CHUNK, 0);
        }
        let len = u64::from(len);
        let mut done = 0u64;
        while done < len {
            let chunk = (len - done).min(COPY_CHUNK as u64) as usize;
            read(&mut self.scratch[..chunk], done)?;
            write(&self.scratch[..chunk], done)?;
            done += chunk as u64;
        }
        Ok(())
    }

    /// Enter (or stay in) a stall. Permanently unsatisfiable chains are
    /// reported once per episode.
    fn enter_stall(&mut self, needed: u64, capacity: u64) {
        self.stalled = true;
        if needed > capacity && !self.stall_logged {
            error!(
                "vhost-user bounce queue {}: descriptor chain needs {needed} arena bytes \
                 but the pool arena is only {capacity} bytes; the queue will stall until \
                 device reset (increase bounce_pool_size)",
                self.queue_index
            );
            self.stall_logged = true;
        }
    }

    /// Record a fatal guest protocol violation; the queue stops
    /// processing in both directions until device reset.
    fn mark_broken(&mut self, reason: &str) {
        if !self.broken {
            error!(
                "vhost-user bounce queue {}: {reason}; queue disabled until device reset",
                self.queue_index
            );
            self.broken = true;
        }
    }

    /// Consume new shadow used entries: copy device-written data back to
    /// the captured guest buffers, free + scrub pool extents, publish
    /// guest used entries.
    pub fn complete_used(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        guest_q: &mut Queue,
        pool: &mut BouncePool,
    ) -> CompleteOutcome {
        let mut out = CompleteOutcome::default();
        if self.broken {
            return out;
        }

        let idx_addr = GuestAddress(self.ring.used + 2);
        let Ok(shadow_used_idx) = pool.mem().load::<u16>(idx_addr, Ordering::Acquire) else {
            self.mark_broken("shadow used index load failed");
            return out;
        };

        while self.next_used != Wrapping(shadow_used_idx) {
            let pos = self.next_used.0 % self.size;
            let elem_addr = self.ring.used + 4 + u64::from(pos) * 8;
            let (Ok(id), Ok(len)) = (
                pool.mem().read_obj::<u32>(GuestAddress(elem_addr)),
                pool.mem().read_obj::<u32>(GuestAddress(elem_addr + 4)),
            ) else {
                self.mark_broken("shadow used element read failed");
                break;
            };

            // Translate the shadow head back to the captured chain.
            let chain = if id < u32::from(self.size) {
                self.inflight[id as usize].take()
            } else {
                None
            };
            let Some(chain) = chain else {
                self.mark_broken("backend completed an unknown or stale used id");
                break;
            };
            self.inflight_count -= 1;

            // Never trust the backend's written length beyond the
            // chain's device-writable capacity.
            let writable_total: u64 = chain
                .segments
                .iter()
                .filter(|s| s.writable)
                .map(|s| u64::from(s.len))
                .sum();
            let len = u64::from(len).min(writable_total) as u32;

            // Copy device-written data back to the captured guest
            // addresses, walking writable segments in chain order.
            let mut remaining = len;
            let mut copy_failed = false;
            for seg in chain.segments.iter().filter(|s| s.writable) {
                if remaining == 0 {
                    break;
                }
                let n = remaining.min(seg.len);
                if n == 0 {
                    continue;
                }
                if let Err(e) = self.copy_chunked(
                    |buf, offset| {
                        pool.mem()
                            .read_slice(buf, seg.pool_addr.unchecked_add(offset))
                    },
                    |buf, offset| guest_mem.write_slice(buf, seg.guest_addr.unchecked_add(offset)),
                    n,
                ) {
                    self.mark_broken(&format!("guest buffer write-back failed: {e}"));
                    copy_failed = true;
                    break;
                }
                remaining -= n;
            }
            self.release_chain(pool, &chain);
            if copy_failed {
                break;
            }

            if guest_q.add_used(guest_mem, chain.guest_head, len).is_err() {
                self.mark_broken("guest used ring publish failed");
                break;
            }
            out.chains += 1;
            self.next_used += 1;
        }

        if out.chains > 0 {
            out.needs_interrupt = self.guest_needs_interrupt(guest_mem, guest_q);
        }
        out
    }

    /// Free a completed (or aborted) chain's pool extents and recycle
    /// its shadow descriptor slots.
    fn release_chain(&mut self, pool: &mut BouncePool, chain: &InflightChain) {
        for seg in &chain.segments {
            if seg.len != 0 {
                // Freeing a captured extent cannot fail.
                let res = pool.free(seg.pool_addr, u64::from(seg.len));
                debug_assert!(res.is_ok());
            }
        }
        self.free_slots.extend_from_slice(&chain.slots);
    }

    /// Whether the guest wants an interrupt for freshly published used
    /// entries. `needs_notification` provides the ordering fence and the
    /// EVENT_IDX logic when that feature is enabled; without it the
    /// advisory VRING_AVAIL_F_NO_INTERRUPT flag is honored directly
    /// (virtio-queue does not implement it).
    fn guest_needs_interrupt(&mut self, guest_mem: &GuestMemoryMmap, guest_q: &mut Queue) -> bool {
        let base = guest_q.needs_notification(guest_mem).unwrap_or(true);
        let flags: u16 = guest_mem
            .load(GuestAddress(guest_q.avail_ring()), Ordering::Relaxed)
            .unwrap_or(0);
        base && (flags & VRING_AVAIL_F_NO_INTERRUPT as u16) == 0
    }

    /// Chains currently owned by the backend.
    pub fn inflight_count(&self) -> usize {
        self.inflight_count
    }

    /// True when no chain is in flight, i.e. every request handed to the
    /// backend has been copied back to the guest. A snapshot is only
    /// consistent once every queue reports drained.
    pub fn verify_drained(&self) -> bool {
        todo!("implemented in docs/vhost-user-bounce-plan.md commit 23")
    }

    /// A spec violation was detected; the queue no longer processes
    /// anything (until device reset).
    pub fn is_broken(&self) -> bool {
        self.broken
    }

    /// The queue is waiting for completions to free pool resources.
    pub fn is_stalled(&self) -> bool {
        self.stalled
    }

    /// Whether the current stall episode has been logged (test hook).
    #[cfg(test)]
    pub(crate) fn stall_logged(&self) -> bool {
        self.stall_logged
    }
}

#[cfg(test)]
mod tests {
    use virtio_bindings::virtio_ring::{
        VRING_AVAIL_F_NO_INTERRUPT, VRING_DESC_F_INDIRECT, VRING_DESC_F_NEXT,
    };
    use vm_memory::{Address, Bytes};

    use super::super::pool::PoolLayout;
    use super::super::test_utils::*;
    use super::*;

    /// Everything a shadow queue test needs: guest memory with a ring
    /// builder, a queue, a pool with `arena` buffer bytes, a fake
    /// backend, and the shadow queue under test.
    struct Harness {
        mem: GuestMemoryMmap,
        ring: GuestRingBuilder,
        q: Queue,
        pool: BouncePool,
        daemon: FakeDaemon,
        sq: ShadowQueue,
    }

    fn harness(queue_size: u16, arena: u64) -> Harness {
        let mem = guest_mem();
        let ring = GuestRingBuilder::new(queue_size);
        let q = ring.queue();
        let pool = BouncePool::new(&PoolLayout {
            num_queues: 1,
            queue_size,
            buffer_capacity: arena,
        })
        .unwrap();
        let sq = ShadowQueue::new(
            ShadowQueueConfig {
                queue_index: 0,
                queue_size,
            },
            pool.ring_offsets(0),
        );
        Harness {
            mem,
            ring,
            q,
            pool,
            daemon: FakeDaemon::new(1, queue_size),
            sq,
        }
    }

    fn fill(mem: &GuestMemoryMmap, addr: u64, len: u32, byte: u8) {
        mem.write_slice(&vec![byte; len as usize], GuestAddress(addr))
            .unwrap();
    }

    fn read_back(mem: &GuestMemoryMmap, addr: u64, len: u32) -> Vec<u8> {
        let mut buf = vec![0u8; len as usize];
        mem.read_slice(&mut buf, GuestAddress(addr)).unwrap();
        buf
    }

    fn mirror(h: &mut Harness) -> MirrorOutcome {
        h.sq.mirror_avail(&h.mem, &mut h.q, &mut h.pool)
    }

    fn complete(h: &mut Harness) -> CompleteOutcome {
        h.sq.complete_used(&h.mem, &mut h.q, &mut h.pool)
    }

    // ---- Mirroring (unignored in plan commit 6) ----

    #[test]
    fn mirror_single_readable_descriptor_copies_data_and_publishes() {
        let mut h = harness(8, 8192);
        let buf = h.ring.alloc_buf(512);
        fill(&h.mem, buf, 512, 0x5a);
        let head = h.ring.chain(&h.mem, &[(buf, 512, false)]);
        h.ring.publish(&h.mem, head);

        let out = mirror(&mut h);
        assert_eq!(
            out,
            MirrorOutcome {
                chains: 1,
                stalled: false
            }
        );
        assert_eq!(h.sq.inflight_count(), 1);
        assert_eq!(h.daemon.avail_idx(&h.pool, 0), 1);

        let shadow_head = h.daemon.pop_avail(&h.pool, 0);
        let chain = h.daemon.read_chain(&h.pool, 0, shadow_head);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].len(), 512);
        assert!(!chain[0].is_write_only());
        assert!(chain[0].addr().raw_value() >= h.pool.arena_base());
        assert_eq!(
            read_back(h.pool.mem(), chain[0].addr().raw_value(), 512),
            vec![0x5a; 512]
        );
    }

    #[test]
    fn mirror_writable_descriptor_allocates_but_does_not_copy() {
        let mut h = harness(8, 8192);
        let buf = h.ring.alloc_buf(256);
        fill(&h.mem, buf, 256, 0xab);
        let head = h.ring.chain(&h.mem, &[(buf, 256, true)]);
        h.ring.publish(&h.mem, head);

        assert_eq!(mirror(&mut h).chains, 1);
        let shadow_head = h.daemon.pop_avail(&h.pool, 0);
        let chain = h.daemon.read_chain(&h.pool, 0, shadow_head);
        assert!(chain[0].is_write_only());
        // Guest data must not leak into the pool for writable buffers.
        assert_eq!(
            read_back(h.pool.mem(), chain[0].addr().raw_value(), 256),
            vec![0u8; 256]
        );
    }

    #[test]
    fn mirror_chain_preserves_order_flags_and_linkage() {
        let mut h = harness(8, 8192);
        let (a, b, c) = (
            h.ring.alloc_buf(0x100),
            h.ring.alloc_buf(0x200),
            h.ring.alloc_buf(0x40),
        );
        fill(&h.mem, a, 0x100, 1);
        let head = h.ring.chain(
            &h.mem,
            &[(a, 0x100, false), (b, 0x200, true), (c, 0x40, true)],
        );
        h.ring.publish(&h.mem, head);

        assert_eq!(mirror(&mut h).chains, 1);
        let shadow_head = h.daemon.pop_avail(&h.pool, 0);
        let chain = h.daemon.read_chain(&h.pool, 0, shadow_head);
        assert_eq!(chain.len(), 3);
        assert_eq!(
            chain.iter().map(|d| d.len()).collect::<Vec<_>>(),
            vec![0x100, 0x200, 0x40]
        );
        assert_eq!(
            chain.iter().map(|d| d.is_write_only()).collect::<Vec<_>>(),
            vec![false, true, true]
        );
    }

    #[test]
    fn mirror_multiple_chains_in_one_call() {
        let mut h = harness(8, 8192);
        for _ in 0..3 {
            let buf = h.ring.alloc_buf(64);
            let head = h.ring.chain(&h.mem, &[(buf, 64, false)]);
            h.ring.publish(&h.mem, head);
        }
        let out = mirror(&mut h);
        assert_eq!(
            out,
            MirrorOutcome {
                chains: 3,
                stalled: false
            }
        );
        assert_eq!(h.daemon.avail_idx(&h.pool, 0), 3);
        let heads: Vec<u16> = (0..3).map(|_| h.daemon.pop_avail(&h.pool, 0)).collect();
        assert_eq!(heads.len(), 3);
        assert!(heads.windows(2).all(|w| w[0] != w[1]));
    }

    #[test]
    fn mirror_idle_when_no_new_entries() {
        let mut h = harness(8, 8192);
        let buf = h.ring.alloc_buf(64);
        let head = h.ring.chain(&h.mem, &[(buf, 64, false)]);
        h.ring.publish(&h.mem, head);
        assert_eq!(mirror(&mut h).chains, 1);
        assert_eq!(
            mirror(&mut h),
            MirrorOutcome {
                chains: 0,
                stalled: false
            }
        );
    }

    #[test]
    fn mirror_zero_length_descriptor() {
        let mut h = harness(8, 8192);
        let (a, b) = (h.ring.alloc_buf(64), h.ring.alloc_buf(64));
        let head = h.ring.chain(&h.mem, &[(a, 0, false), (b, 16, true)]);
        h.ring.publish(&h.mem, head);
        assert_eq!(mirror(&mut h).chains, 1);
        // Only the 16-byte segment consumes arena space (rounded to 64).
        assert_eq!(h.pool.free_bytes(), h.pool.buffer_capacity() - 64);
        let shadow_head = h.daemon.pop_avail(&h.pool, 0);
        let chain = h.daemon.read_chain(&h.pool, 0, shadow_head);
        assert_eq!(chain[0].len(), 0);
        assert_eq!(chain[1].len(), 16);
    }

    #[test]
    fn mirror_does_not_forward_guest_no_interrupt_flag() {
        let mut h = harness(8, 8192);
        h.ring
            .set_avail_flags(&h.mem, VRING_AVAIL_F_NO_INTERRUPT as u16);
        let buf = h.ring.alloc_buf(64);
        let head = h.ring.chain(&h.mem, &[(buf, 64, false)]);
        h.ring.publish(&h.mem, head);
        assert_eq!(mirror(&mut h).chains, 1);
        assert_eq!(h.daemon.avail_flags(&h.pool, 0), 0);
    }

    #[test]
    fn mirror_uses_shadow_allocated_slots() {
        let mut h = harness(8, 8192);
        // Burn guest descriptor slots 0..5 on unpublished chains so the
        // published chain's guest head is 5.
        for _ in 0..5 {
            let buf = h.ring.alloc_buf(16);
            h.ring.chain(&h.mem, &[(buf, 16, false)]);
        }
        let buf = h.ring.alloc_buf(16);
        let head = h.ring.chain(&h.mem, &[(buf, 16, false)]);
        assert_eq!(head, 5);
        h.ring.publish(&h.mem, head);
        assert_eq!(mirror(&mut h).chains, 1);
        // Shadow slots come from the VMM's own free stack, starting at 0.
        assert_eq!(h.daemon.pop_avail(&h.pool, 0), 0);
    }

    #[test]
    fn mirror_indirect_flag_marks_queue_broken() {
        let mut h = harness(8, 8192);
        let table = h.ring.alloc_buf(64);
        h.ring
            .desc(&h.mem, 0, table, 16, VRING_DESC_F_INDIRECT as u16, 0);
        h.ring.publish(&h.mem, 0);
        assert_eq!(
            mirror(&mut h),
            MirrorOutcome {
                chains: 0,
                stalled: false
            }
        );
        assert!(h.sq.is_broken());
        // Broken queues consume nothing further.
        let buf = h.ring.alloc_buf(64);
        let head = h.ring.chain(&h.mem, &[(buf, 64, false)]);
        h.ring.publish(&h.mem, head);
        assert_eq!(mirror(&mut h).chains, 0);
    }

    #[test]
    fn mirror_chain_longer_than_queue_marks_queue_broken() {
        let mut h = harness(4, 8192);
        let buf = h.ring.alloc_buf(64);
        // 0 -> 1 -> 2 -> 3 -> 0: a descriptor loop.
        for slot in 0u16..4 {
            h.ring.desc(
                &h.mem,
                slot,
                buf,
                16,
                VRING_DESC_F_NEXT as u16,
                (slot + 1) % 4,
            );
        }
        h.ring.publish(&h.mem, 0);
        assert_eq!(mirror(&mut h).chains, 0);
        assert!(h.sq.is_broken());
    }

    #[test]
    fn mirror_desc_addr_outside_guest_memory_marks_queue_broken() {
        let mut h = harness(8, 8192);
        let head = h.ring.chain(&h.mem, &[(0xdead_0000_0000, 64, false)]);
        h.ring.publish(&h.mem, head);
        assert_eq!(mirror(&mut h).chains, 0);
        assert!(h.sq.is_broken());
        assert_eq!(h.pool.free_bytes(), h.pool.buffer_capacity());
    }

    // ---- Backpressure (unignored in plan commit 6) ----

    #[test]
    fn mirror_stalls_when_arena_exhausted_and_rolls_back() {
        let mut h = harness(8, 256);
        let a = h.ring.alloc_buf(192);
        let head = h.ring.chain(&h.mem, &[(a, 192, false)]);
        h.ring.publish(&h.mem, head);
        assert_eq!(
            mirror(&mut h),
            MirrorOutcome {
                chains: 1,
                stalled: false
            }
        );

        let b = h.ring.alloc_buf(128);
        let head = h.ring.chain(&h.mem, &[(b, 128, false)]);
        h.ring.publish(&h.mem, head);
        let out = mirror(&mut h);
        assert_eq!(
            out,
            MirrorOutcome {
                chains: 0,
                stalled: true
            }
        );
        assert!(h.sq.is_stalled());
        // Rollback: no partial allocation, nothing extra in flight.
        assert_eq!(h.pool.free_bytes(), 256 - 192);
        assert_eq!(h.sq.inflight_count(), 1);
        assert_eq!(h.daemon.avail_idx(&h.pool, 0), 1);
    }

    #[test]
    fn mirror_stall_is_all_or_nothing_across_chains() {
        let mut h = harness(8, 256);
        let a = h.ring.alloc_buf(128);
        let head = h.ring.chain(&h.mem, &[(a, 128, false)]);
        h.ring.publish(&h.mem, head);
        let b = h.ring.alloc_buf(192);
        let head = h.ring.chain(&h.mem, &[(b, 192, false)]);
        h.ring.publish(&h.mem, head);

        let out = mirror(&mut h);
        assert_eq!(
            out,
            MirrorOutcome {
                chains: 1,
                stalled: true
            }
        );
        assert_eq!(h.daemon.avail_idx(&h.pool, 0), 1);
        assert_eq!(h.pool.free_bytes(), 256 - 128);
    }

    #[test]
    fn mirror_oversized_chain_sets_permanent_stall_and_logs_once() {
        let mut h = harness(8, 256);
        let a = h.ring.alloc_buf(512);
        let head = h.ring.chain(&h.mem, &[(a, 512, false)]);
        h.ring.publish(&h.mem, head);
        assert_eq!(
            mirror(&mut h),
            MirrorOutcome {
                chains: 0,
                stalled: true
            }
        );
        assert!(h.sq.is_stalled());
        assert!(h.sq.stall_logged());
        // Still stalled on retry; the episode is only logged once.
        assert_eq!(
            mirror(&mut h),
            MirrorOutcome {
                chains: 0,
                stalled: true
            }
        );
        assert!(h.sq.stall_logged());
    }

    #[test]
    fn mirror_slot_exhaustion_stalls() {
        // A compliant guest cannot exhaust shadow slots (shadow slot
        // consumption equals guest descriptor consumption and the
        // capacities match), but a guest publishing the same chain head
        // several times can: each duplicate gets its own shadow slots.
        let mut h = harness(4, 1 << 20);
        let (a, b) = (h.ring.alloc_buf(64), h.ring.alloc_buf(64));
        let head = h.ring.chain(&h.mem, &[(a, 64, false), (b, 64, false)]);
        for _ in 0..3 {
            h.ring.publish(&h.mem, head);
        }
        // Two duplicates consume all four shadow slots; the third stalls.
        let out = mirror(&mut h);
        assert_eq!(
            out,
            MirrorOutcome {
                chains: 2,
                stalled: true
            }
        );
    }

    // ---- Completion (unignored in plan commit 7) ----

    #[test]
    fn complete_copies_back_writable_data_and_publishes_guest_used() {
        let mut h = harness(8, 8192);
        let (req, resp) = (h.ring.alloc_buf(64), h.ring.alloc_buf(256));
        fill(&h.mem, req, 64, 0x11);
        let head = h.ring.chain(&h.mem, &[(req, 64, false), (resp, 256, true)]);
        h.ring.publish(&h.mem, head);
        assert_eq!(mirror(&mut h).chains, 1);

        h.daemon.serve_one(&h.pool, 0, 0x77);
        let out = complete(&mut h);
        assert_eq!(out.chains, 1);
        assert!(out.needs_interrupt);
        assert_eq!(read_back(&h.mem, resp, 256), vec![0x77; 256]);
        assert_eq!(h.ring.used_idx(&h.mem), 1);
        assert_eq!(h.ring.used_elem(&h.mem, 0), (u32::from(head), 256));
        assert_eq!(h.sq.inflight_count(), 0);
    }

    #[test]
    fn complete_respects_daemon_len_cap() {
        let mut h = harness(8, 8192);
        let resp = h.ring.alloc_buf(256);
        fill(&h.mem, resp, 256, 0xee); // sentinel
        let head = h.ring.chain(&h.mem, &[(resp, 256, true)]);
        h.ring.publish(&h.mem, head);
        assert_eq!(mirror(&mut h).chains, 1);

        let shadow_head = h.daemon.pop_avail(&h.pool, 0);
        let chain = h.daemon.read_chain(&h.pool, 0, shadow_head);
        h.pool
            .mem()
            .write_slice(&[0x33; 256], chain[0].addr())
            .unwrap();
        h.daemon.complete(&h.pool, 0, shadow_head, 4);

        assert_eq!(complete(&mut h).chains, 1);
        let got = read_back(&h.mem, resp, 256);
        assert_eq!(&got[..4], &[0x33; 4]);
        assert_eq!(&got[4..], &[0xee; 252][..]);
        assert_eq!(h.ring.used_elem(&h.mem, 0), (u32::from(head), 4));
    }

    #[test]
    fn complete_caps_len_at_writable_total() {
        let mut h = harness(8, 8192);
        let (req, resp) = (h.ring.alloc_buf(64), h.ring.alloc_buf(128));
        let head = h.ring.chain(&h.mem, &[(req, 64, false), (resp, 128, true)]);
        h.ring.publish(&h.mem, head);
        assert_eq!(mirror(&mut h).chains, 1);

        let shadow_head = h.daemon.pop_avail(&h.pool, 0);
        // The daemon lies: reports more written than the writable total.
        h.daemon.complete(&h.pool, 0, shadow_head, 9999);
        assert_eq!(complete(&mut h).chains, 1);
        assert_eq!(h.ring.used_elem(&h.mem, 0), (u32::from(head), 128));
    }

    #[test]
    fn complete_readonly_chain_copies_nothing() {
        let mut h = harness(8, 8192);
        let req = h.ring.alloc_buf(64);
        fill(&h.mem, req, 64, 0x44);
        let head = h.ring.chain(&h.mem, &[(req, 64, false)]);
        h.ring.publish(&h.mem, head);
        assert_eq!(mirror(&mut h).chains, 1);

        h.daemon.serve_one(&h.pool, 0, 0x99);
        assert_eq!(complete(&mut h).chains, 1);
        assert_eq!(read_back(&h.mem, req, 64), vec![0x44; 64]);
        assert_eq!(h.ring.used_elem(&h.mem, 0), (u32::from(head), 0));
    }

    #[test]
    fn complete_frees_and_scrubs_extents_and_recycles_slots() {
        let mut h = harness(2, 8192);
        let resp = h.ring.alloc_buf(128);
        let head = h.ring.chain(&h.mem, &[(resp, 128, true)]);
        h.ring.publish(&h.mem, head);
        assert_eq!(mirror(&mut h).chains, 1);
        let shadow_head = h.daemon.pop_avail(&h.pool, 0);
        let chain = h.daemon.read_chain(&h.pool, 0, shadow_head);
        let pool_addr = chain[0].addr();
        h.pool.mem().write_slice(&[0x55; 128], pool_addr).unwrap();
        h.daemon.complete(&h.pool, 0, shadow_head, 128);
        assert_eq!(complete(&mut h).chains, 1);

        assert_eq!(h.pool.free_bytes(), h.pool.buffer_capacity());
        assert_eq!(
            read_back(h.pool.mem(), pool_addr.raw_value(), 128),
            vec![0u8; 128]
        );

        // The freed slot can immediately serve another chain (queue size
        // 2, so exhaustion would show if slots leaked).
        for _ in 0..4 {
            let buf = h.ring.alloc_buf(64);
            let head = h.ring.chain(&h.mem, &[(buf, 64, true)]);
            h.ring.publish(&h.mem, head);
            assert_eq!(mirror(&mut h).chains, 1);
            h.daemon.serve_one(&h.pool, 0, 1);
            assert_eq!(complete(&mut h).chains, 1);
        }
    }

    #[test]
    fn complete_out_of_order_completions() {
        let mut h = harness(8, 8192);
        let mut heads = Vec::new();
        let mut bufs = Vec::new();
        for _ in 0..2 {
            let buf = h.ring.alloc_buf(64);
            let head = h.ring.chain(&h.mem, &[(buf, 64, true)]);
            h.ring.publish(&h.mem, head);
            heads.push(head);
            bufs.push(buf);
        }
        assert_eq!(mirror(&mut h).chains, 2);
        let s0 = h.daemon.pop_avail(&h.pool, 0);
        let s1 = h.daemon.pop_avail(&h.pool, 0);

        // Complete the second submission first.
        h.daemon.complete(&h.pool, 0, s1, 64);
        assert_eq!(complete(&mut h).chains, 1);
        assert_eq!(h.ring.used_elem(&h.mem, 0), (u32::from(heads[1]), 64));

        h.daemon.complete(&h.pool, 0, s0, 64);
        assert_eq!(complete(&mut h).chains, 1);
        assert_eq!(h.ring.used_elem(&h.mem, 1), (u32::from(heads[0]), 64));
        assert_eq!(h.ring.used_idx(&h.mem), 2);
    }

    #[test]
    fn complete_multiple_in_one_call() {
        let mut h = harness(8, 8192);
        for _ in 0..3 {
            let buf = h.ring.alloc_buf(64);
            let head = h.ring.chain(&h.mem, &[(buf, 64, true)]);
            h.ring.publish(&h.mem, head);
        }
        assert_eq!(mirror(&mut h).chains, 3);
        for _ in 0..3 {
            h.daemon.serve_one(&h.pool, 0, 9);
        }
        let out = complete(&mut h);
        assert_eq!(out.chains, 3);
        assert_eq!(h.ring.used_idx(&h.mem), 3);
    }

    #[test]
    fn complete_idle_when_no_new_used() {
        let mut h = harness(8, 8192);
        assert_eq!(
            complete(&mut h),
            CompleteOutcome {
                chains: 0,
                needs_interrupt: false
            }
        );
    }

    #[test]
    fn mirror_and_complete_wrap_indices() {
        let mut h = harness(4, 8192);
        // Drive enough traffic through a tiny queue to wrap the ring
        // positions many times over.
        for round in 0..40u32 {
            let buf = h.ring.alloc_buf(64);
            fill(&h.mem, buf, 64, round as u8);
            let head = h.ring.chain(&h.mem, &[(buf, 64, true)]);
            h.ring.publish(&h.mem, head);
            assert_eq!(mirror(&mut h).chains, 1, "round {round}");
            h.daemon.serve_one(&h.pool, 0, round as u8);
            assert_eq!(complete(&mut h).chains, 1, "round {round}");
            assert_eq!(read_back(&h.mem, buf, 64), vec![round as u8; 64]);
        }
        assert_eq!(h.ring.used_idx(&h.mem), 40);
        assert_eq!(h.pool.free_bytes(), h.pool.buffer_capacity());
    }

    #[test]
    fn complete_unknown_id_marks_queue_broken() {
        let mut h = harness(8, 8192);
        h.daemon.complete(&h.pool, 0, 3, 0);
        let out = complete(&mut h);
        assert_eq!(out.chains, 0);
        assert!(h.sq.is_broken());
    }

    #[test]
    fn complete_stale_duplicate_id_marks_queue_broken() {
        let mut h = harness(8, 8192);
        let buf = h.ring.alloc_buf(64);
        let head = h.ring.chain(&h.mem, &[(buf, 64, true)]);
        h.ring.publish(&h.mem, head);
        assert_eq!(mirror(&mut h).chains, 1);
        let shadow_head = h.daemon.pop_avail(&h.pool, 0);
        h.daemon.complete(&h.pool, 0, shadow_head, 64);
        assert_eq!(complete(&mut h).chains, 1);
        // The daemon completes the same shadow head again.
        h.daemon.complete(&h.pool, 0, shadow_head, 64);
        assert_eq!(complete(&mut h).chains, 0);
        assert!(h.sq.is_broken());
    }

    #[test]
    fn complete_honors_guest_no_interrupt_flag() {
        let mut h = harness(8, 8192);
        h.ring
            .set_avail_flags(&h.mem, VRING_AVAIL_F_NO_INTERRUPT as u16);
        let buf = h.ring.alloc_buf(64);
        let head = h.ring.chain(&h.mem, &[(buf, 64, true)]);
        h.ring.publish(&h.mem, head);
        assert_eq!(mirror(&mut h).chains, 1);
        h.daemon.serve_one(&h.pool, 0, 1);
        let out = complete(&mut h);
        assert_eq!(out.chains, 1);
        assert!(!out.needs_interrupt);

        // With the flag cleared, completions do interrupt.
        h.ring.set_avail_flags(&h.mem, 0);
        let buf = h.ring.alloc_buf(64);
        let head = h.ring.chain(&h.mem, &[(buf, 64, true)]);
        h.ring.publish(&h.mem, head);
        assert_eq!(mirror(&mut h).chains, 1);
        h.daemon.serve_one(&h.pool, 0, 2);
        assert!(complete(&mut h).needs_interrupt);
    }

    #[test]
    fn complete_uses_captured_segments_not_live_desc_table() {
        let mut h = harness(8, 8192);
        let (buf1, buf2) = (h.ring.alloc_buf(64), h.ring.alloc_buf(64));
        fill(&h.mem, buf2, 64, 0xcc); // sentinel in the decoy buffer
        let head = h.ring.chain(&h.mem, &[(buf1, 64, true)]);
        h.ring.publish(&h.mem, head);
        assert_eq!(mirror(&mut h).chains, 1);

        // The (misbehaving) guest redirects the descriptor after submit.
        h.ring.desc(&h.mem, head, buf2, 64, 0, 0);

        h.daemon.serve_one(&h.pool, 0, 0x77);
        assert_eq!(complete(&mut h).chains, 1);
        // Copy-back lands at the captured address, not the rewritten one.
        assert_eq!(read_back(&h.mem, buf1, 64), vec![0x77; 64]);
        assert_eq!(read_back(&h.mem, buf2, 64), vec![0xcc; 64]);
    }

    #[test]
    fn broken_queue_complete_is_idle() {
        let mut h = harness(8, 8192);
        h.daemon.complete(&h.pool, 0, 5, 0);
        assert_eq!(complete(&mut h).chains, 0);
        assert!(h.sq.is_broken());
        // Even valid-looking completions are ignored once broken.
        h.daemon.complete(&h.pool, 0, 0, 0);
        assert_eq!(
            complete(&mut h),
            CompleteOutcome {
                chains: 0,
                needs_interrupt: false
            }
        );
    }

    // ---- Lifecycle & accounting (unignored in plan commit 8) ----

    #[test]
    fn reset_session_starts_counters_at_base() {
        let mut h = harness(8, 8192);
        h.ring.set_start(&h.mem, 3);
        h.q = h.ring.queue();
        h.sq.reset_session(3);
        h.daemon = FakeDaemon::new(1, 8);
        h.daemon.set_start(0, 3);
        // Pretend the shadow avail idx was restored to base 3.
        let buf = h.ring.alloc_buf(64);
        let head = h.ring.chain(&h.mem, &[(buf, 64, true)]);
        h.ring.publish(&h.mem, head);
        assert_eq!(mirror(&mut h).chains, 1);
        assert_eq!(h.daemon.avail_idx(&h.pool, 0), 4);
        h.daemon.serve_one(&h.pool, 0, 5);
        assert_eq!(complete(&mut h).chains, 1);
        assert_eq!(h.ring.used_idx(&h.mem), 4);
        assert_eq!(h.sq.inflight_count(), 0);
    }

    // ---- Restore priming (plan commit 23) ----

    #[test]
    #[ignore = "implemented in docs/vhost-user-bounce-plan.md commit 23"]
    fn verify_drained_reflects_inflight() {
        let mut h = harness(8, 8192);
        assert!(h.sq.verify_drained());
        let buf = h.ring.alloc_buf(64);
        let head = h.ring.chain(&h.mem, &[(buf, 64, true)]);
        h.ring.publish(&h.mem, head);
        assert_eq!(mirror(&mut h).chains, 1);
        assert!(!h.sq.verify_drained());
        h.daemon.serve_one(&h.pool, 0, 1);
        assert_eq!(complete(&mut h).chains, 1);
        assert!(h.sq.verify_drained());
    }

    #[test]
    #[ignore = "implemented in docs/vhost-user-bounce-plan.md commit 23"]
    fn restore_mirror_between_base_and_avail_idx() {
        // A queue restored with avail idx 5, used idx 3, backend base 3
        // must mirror exactly the two chains 3 and 4 on the first sweep.
        let mut h = harness(8, 8192);
        h.ring.set_start(&h.mem, 3);
        // Publish two chains, advancing avail idx from 3 to 5.
        let mut heads = Vec::new();
        for _ in 0..2 {
            let buf = h.ring.alloc_buf(64);
            let head = h.ring.chain(&h.mem, &[(buf, 64, true)]);
            h.ring.publish(&h.mem, head);
            heads.push(head);
        }
        h.q = h.ring.queue();
        h.sq.reset_session(3);
        h.daemon = FakeDaemon::new(1, 8);
        h.daemon.set_start(0, 3);

        let out = mirror(&mut h);
        assert_eq!(out.chains, 2);
        assert_eq!(h.daemon.avail_idx(&h.pool, 0), 5);
        assert!(!h.sq.verify_drained());
    }

    #[test]
    #[ignore = "implemented in docs/vhost-user-bounce-plan.md commit 23"]
    fn restore_base_equal_avail_idx_is_noop() {
        let mut h = harness(8, 8192);
        h.ring.set_start(&h.mem, 7);
        h.q = h.ring.queue();
        h.sq.reset_session(7);
        h.daemon = FakeDaemon::new(1, 8);
        h.daemon.set_start(0, 7);
        // Nothing published since the base, so the sweep mirrors nothing.
        assert_eq!(mirror(&mut h).chains, 0);
        assert!(h.sq.verify_drained());
    }

    #[test]
    #[ignore = "implemented in docs/vhost-user-bounce-plan.md commit 23"]
    fn restore_with_wrapped_indices() {
        // Base near u16::MAX so the restored indices wrap during mirroring.
        let base = u16::MAX - 1;
        let mut h = harness(8, 8192);
        h.ring.set_start(&h.mem, base);
        for _ in 0..3 {
            let buf = h.ring.alloc_buf(64);
            let head = h.ring.chain(&h.mem, &[(buf, 64, true)]);
            h.ring.publish(&h.mem, head);
        }
        h.q = h.ring.queue();
        h.sq.reset_session(base);
        h.daemon = FakeDaemon::new(1, 8);
        h.daemon.set_start(0, base);
        assert_eq!(mirror(&mut h).chains, 3);
        // base + 3 wraps past u16::MAX to 1.
        assert_eq!(h.daemon.avail_idx(&h.pool, 0), base.wrapping_add(3));
    }

    #[test]
    fn stall_recovery_after_completion_frees_space() {
        let mut h = harness(8, 256);
        let a = h.ring.alloc_buf(192);
        let head = h.ring.chain(&h.mem, &[(a, 192, true)]);
        h.ring.publish(&h.mem, head);
        assert_eq!(mirror(&mut h).chains, 1);

        let b = h.ring.alloc_buf(128);
        let head_b = h.ring.chain(&h.mem, &[(b, 128, true)]);
        h.ring.publish(&h.mem, head_b);
        assert_eq!(
            mirror(&mut h),
            MirrorOutcome {
                chains: 0,
                stalled: true
            }
        );
        assert!(h.sq.is_stalled());

        // Completion frees 192 bytes; the retry then succeeds.
        h.daemon.serve_one(&h.pool, 0, 1);
        assert_eq!(complete(&mut h).chains, 1);
        let out = mirror(&mut h);
        assert_eq!(
            out,
            MirrorOutcome {
                chains: 1,
                stalled: false
            }
        );
        assert!(!h.sq.is_stalled());
        assert!(!h.sq.stall_logged());
    }

    #[test]
    fn soak_10k_requests_accounting_converges() {
        let mut h = harness(8, 4096);
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut submitted = 0u32;
        for _ in 0..10_000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let len = 1 + ((seed >> 33) % 1024) as u32;
            let buf = h.ring.alloc_buf(len);
            let head = h.ring.chain(&h.mem, &[(buf, len, (seed & 1) == 1)]);
            h.ring.publish(&h.mem, head);
            let out = mirror(&mut h);
            assert!(!h.sq.is_broken());
            submitted += out.chains as u32;
            // Periodically drain everything in flight to unstall.
            if h.sq.is_stalled() || h.sq.inflight_count() >= 6 {
                while h.sq.inflight_count() > 0 {
                    h.daemon.serve_one(&h.pool, 0, seed as u8);
                    complete(&mut h);
                }
                submitted += mirror(&mut h).chains as u32;
            }
            // The builder recycles guest buffer space.
            h.ring.reset_bufs();
        }
        // Drain the tail: complete everything in flight and mirror any
        // entries still pending from stalls near the end.
        loop {
            while h.sq.inflight_count() > 0 {
                h.daemon.serve_one(&h.pool, 0, 0);
                complete(&mut h);
            }
            let out = mirror(&mut h);
            submitted += out.chains as u32;
            if out.chains == 0 && !out.stalled {
                break;
            }
        }
        assert_eq!(submitted, 10_000);
        assert_eq!(h.pool.free_bytes(), h.pool.buffer_capacity());
        assert!(!h.sq.is_broken());
        assert_eq!(h.sq.inflight_count(), 0);
    }

    #[test]
    fn interleaved_two_queue_pool_sharing() {
        // One pool shared by two queues of the same device, each with its
        // own guest ring.
        let mem = guest_mem();
        let mut pool = BouncePool::new(&PoolLayout {
            num_queues: 2,
            queue_size: 8,
            buffer_capacity: 256,
        })
        .unwrap();
        let mut ring0 = GuestRingBuilder::new(8);
        let mut ring1 = GuestRingBuilder::new_at(8, 0x80000);
        let mut q0 = ring0.queue();
        let mut q1 = ring1.queue();
        let mut sq0 = ShadowQueue::new(
            ShadowQueueConfig {
                queue_index: 0,
                queue_size: 8,
            },
            pool.ring_offsets(0),
        );
        let mut sq1 = ShadowQueue::new(
            ShadowQueueConfig {
                queue_index: 1,
                queue_size: 8,
            },
            pool.ring_offsets(1),
        );
        let mut daemon = FakeDaemon::new(2, 8);

        // Queue 0 takes the whole arena.
        let a = ring0.alloc_buf(256);
        let head = ring0.chain(&mem, &[(a, 256, true)]);
        ring0.publish(&mem, head);
        assert_eq!(sq0.mirror_avail(&mem, &mut q0, &mut pool).chains, 1);
        assert_eq!(pool.free_bytes(), 0);

        // Queue 1 stalls for space.
        let b = ring1.alloc_buf(128);
        let head_b = ring1.chain(&mem, &[(b, 128, true)]);
        ring1.publish(&mem, head_b);
        let out = sq1.mirror_avail(&mem, &mut q1, &mut pool);
        assert_eq!(
            out,
            MirrorOutcome {
                chains: 0,
                stalled: true
            }
        );

        // Completing queue 0's chain frees space for queue 1.
        daemon.serve_one(&pool, 0, 7);
        assert_eq!(sq0.complete_used(&mem, &mut q0, &mut pool).chains, 1);
        let out = sq1.mirror_avail(&mem, &mut q1, &mut pool);
        assert_eq!(
            out,
            MirrorOutcome {
                chains: 1,
                stalled: false
            }
        );
    }
}

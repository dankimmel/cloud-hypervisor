// Copyright 2026 Cloud Hypervisor Contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared test utilities for the bounce module: a guest-side split ring
//! builder (acting as the driver) and a fake vhost-user backend that
//! operates on a [`BouncePool`]'s shadow rings (acting as the daemon).

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use virtio_queue::desc::split::Descriptor;
use virtio_queue::{Queue, QueueT};
use vm_memory::{Address, Bytes, GuestAddress};
use vmm_sys_util::eventfd::EventFd;

use super::pool::BouncePool;
use crate::{GuestMemoryMmap, VirtioInterrupt, VirtioInterruptType};

pub(crate) const GUEST_MEM_SIZE: usize = 0x100_000;

/// Anonymous guest memory for tests: one region at GPA 0.
pub(crate) fn guest_mem() -> GuestMemoryMmap {
    GuestMemoryMmap::from_ranges(&[(GuestAddress(0), GUEST_MEM_SIZE)]).unwrap()
}

/// Builds and manipulates a guest-owned split virtqueue, playing the role
/// of the guest driver.
pub(crate) struct GuestRingBuilder {
    queue_size: u16,
    desc_table: u64,
    avail_ring: u64,
    used_ring: u64,
    buf_base: u64,
    start: u16,
    next_desc: u16,
    avail_idx: u16,
    next_buf: u64,
}

impl GuestRingBuilder {
    pub(crate) fn new(queue_size: u16) -> Self {
        Self::new_at(queue_size, 0)
    }

    /// Lay the ring out at `base` so multiple rings can coexist in one
    /// guest memory (each ring block uses 0x80000 bytes of address space).
    pub(crate) fn new_at(queue_size: u16, base: u64) -> Self {
        GuestRingBuilder {
            queue_size,
            desc_table: base + 0x1000,
            avail_ring: base + 0x3000,
            used_ring: base + 0x4000,
            buf_base: base + 0x10000,
            start: 0,
            next_desc: 0,
            avail_idx: 0,
            next_buf: base + 0x10000,
        }
    }

    /// Recycle the guest buffer address space (for soak tests).
    pub(crate) fn reset_bufs(&mut self) {
        self.next_buf = self.buf_base;
    }

    /// Fast-forward the ring to start at index `base` (as after a
    /// restore): the avail/used indexes begin at `base` and queues
    /// created afterwards resume from there.
    pub(crate) fn set_start(&mut self, mem: &GuestMemoryMmap, base: u16) {
        self.start = base;
        self.avail_idx = base;
        mem.store(base, GuestAddress(self.avail_ring + 2), Ordering::Release)
            .unwrap();
        mem.store(base, GuestAddress(self.used_ring + 2), Ordering::Release)
            .unwrap();
    }

    /// Configure a virtio-queue `Queue` matching this ring, optionally
    /// with EVENT_IDX enabled (as the guest would negotiate it).
    pub(crate) fn queue_with(&self, event_idx: bool) -> Queue {
        let mut q = Queue::new(self.queue_size).unwrap();
        q.try_set_desc_table_address(GuestAddress(self.desc_table))
            .unwrap();
        q.try_set_avail_ring_address(GuestAddress(self.avail_ring))
            .unwrap();
        q.try_set_used_ring_address(GuestAddress(self.used_ring))
            .unwrap();
        q.set_next_avail(self.start);
        q.set_next_used(self.start);
        q.set_event_idx(event_idx);
        q.set_ready(true);
        q
    }

    /// Configure a virtio-queue `Queue` matching this ring.
    pub(crate) fn queue(&self) -> Queue {
        self.queue_with(false)
    }

    /// Write the guest's `used_event` (in the avail ring): the device
    /// should interrupt only once the used index passes this value.
    pub(crate) fn set_used_event(&self, mem: &GuestMemoryMmap, val: u16) {
        let addr = self.avail_ring + 4 + u64::from(self.queue_size) * 2;
        mem.write_obj(val, GuestAddress(addr)).unwrap();
    }

    /// Read the device-written `avail_event` (in the used ring): the guest
    /// kicks once its avail index passes this value.
    pub(crate) fn avail_event(&self, mem: &GuestMemoryMmap) -> u16 {
        let addr = self.used_ring + 4 + u64::from(self.queue_size) * 8;
        mem.read_obj(GuestAddress(addr)).unwrap()
    }

    /// Reserve a buffer of `len` bytes in guest memory.
    pub(crate) fn alloc_buf(&mut self, len: u32) -> u64 {
        let addr = self.next_buf;
        self.next_buf += u64::from(len).next_multiple_of(64);
        assert!(self.next_buf <= self.buf_base + 0x70000);
        addr
    }

    /// Write one descriptor at `slot`.
    pub(crate) fn desc(
        &self,
        mem: &GuestMemoryMmap,
        slot: u16,
        addr: u64,
        len: u32,
        flags: u16,
        next: u16,
    ) {
        let desc = Descriptor::new(addr, len, flags, next);
        mem.write_obj(desc, GuestAddress(self.desc_table + u64::from(slot) * 16))
            .unwrap();
    }

    /// Build a descriptor chain out of `(addr, len, writable)` segments
    /// using sequential descriptor slots; returns the head index. The
    /// chain is not made available until [`Self::publish`] is called.
    pub(crate) fn chain(&mut self, mem: &GuestMemoryMmap, segs: &[(u64, u32, bool)]) -> u16 {
        use virtio_bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
        assert!(!segs.is_empty());
        let head = self.next_desc;
        for (i, (addr, len, writable)) in segs.iter().enumerate() {
            let slot = self.next_desc;
            self.next_desc = (self.next_desc + 1) % self.queue_size;
            let mut flags = 0u16;
            if *writable {
                flags |= VRING_DESC_F_WRITE as u16;
            }
            if i + 1 < segs.len() {
                flags |= VRING_DESC_F_NEXT as u16;
            }
            self.desc(mem, slot, *addr, *len, flags, self.next_desc);
        }
        head
    }

    /// Build an indirect descriptor chain: an indirect table laid out in
    /// guest memory holding one entry per segment, and a single head
    /// descriptor with `F_INDIRECT` pointing at it. Returns the head slot.
    pub(crate) fn indirect_chain(
        &mut self,
        mem: &GuestMemoryMmap,
        segs: &[(u64, u32, bool)],
    ) -> u16 {
        use virtio_bindings::virtio_ring::{
            VRING_DESC_F_INDIRECT, VRING_DESC_F_NEXT, VRING_DESC_F_WRITE,
        };
        assert!(!segs.is_empty());
        // Reserve guest space for the indirect table (16 bytes/entry).
        let table = self.alloc_buf((segs.len() * 16) as u32);
        for (i, (addr, len, writable)) in segs.iter().enumerate() {
            let mut flags = 0u16;
            if *writable {
                flags |= VRING_DESC_F_WRITE as u16;
            }
            if i + 1 < segs.len() {
                flags |= VRING_DESC_F_NEXT as u16;
            }
            let entry = Descriptor::new(*addr, *len, flags, (i + 1) as u16);
            mem.write_obj(entry, GuestAddress(table + (i * 16) as u64))
                .unwrap();
        }
        // Single head descriptor referencing the table.
        let head = self.next_desc;
        self.next_desc = (self.next_desc + 1) % self.queue_size;
        self.desc(
            mem,
            head,
            table,
            (segs.len() * 16) as u32,
            VRING_DESC_F_INDIRECT as u16,
            0,
        );
        head
    }

    /// Publish `head` in the avail ring and bump the avail index.
    pub(crate) fn publish(&mut self, mem: &GuestMemoryMmap, head: u16) {
        let pos = self.avail_idx % self.queue_size;
        mem.write_obj(head, GuestAddress(self.avail_ring + 4 + u64::from(pos) * 2))
            .unwrap();
        self.avail_idx = self.avail_idx.wrapping_add(1);
        mem.store(
            self.avail_idx,
            GuestAddress(self.avail_ring + 2),
            Ordering::Release,
        )
        .unwrap();
    }

    /// Set the guest avail ring flags (e.g. VRING_AVAIL_F_NO_INTERRUPT).
    pub(crate) fn set_avail_flags(&self, mem: &GuestMemoryMmap, flags: u16) {
        mem.store(flags, GuestAddress(self.avail_ring), Ordering::Release)
            .unwrap();
    }

    /// Read the guest used ring index (the device publishes this).
    pub(crate) fn used_idx(&self, mem: &GuestMemoryMmap) -> u16 {
        mem.load(GuestAddress(self.used_ring + 2), Ordering::Acquire)
            .unwrap()
    }

    /// Read the used ring element at ring position `pos` as (id, len).
    pub(crate) fn used_elem(&self, mem: &GuestMemoryMmap, pos: u16) -> (u32, u32) {
        let base = self.used_ring + 4 + u64::from(pos % self.queue_size) * 8;
        (
            mem.read_obj(GuestAddress(base)).unwrap(),
            mem.read_obj(GuestAddress(base + 4)).unwrap(),
        )
    }
}

/// Operates on the shadow rings inside a [`BouncePool`] the way a
/// vhost-user backend would.
pub(crate) struct FakeDaemon {
    queue_size: u16,
    next_avail: Vec<u16>,
    next_used: Vec<u16>,
}

impl FakeDaemon {
    pub(crate) fn new(num_queues: usize, queue_size: u16) -> Self {
        FakeDaemon {
            queue_size,
            next_avail: vec![0; num_queues],
            next_used: vec![0; num_queues],
        }
    }

    /// Resume queue `q` from ring index `base`, as after SET_VRING_BASE.
    pub(crate) fn set_start(&mut self, q: usize, base: u16) {
        self.next_avail[q] = base;
        self.next_used[q] = base;
    }

    /// Read the shadow avail index for queue `q`.
    pub(crate) fn avail_idx(&self, pool: &BouncePool, q: usize) -> u16 {
        let offs = pool.ring_offsets(q);
        pool.mem()
            .load(GuestAddress(offs.avail + 2), Ordering::Acquire)
            .unwrap()
    }

    /// Read the shadow avail ring flags for queue `q`.
    pub(crate) fn avail_flags(&self, pool: &BouncePool, q: usize) -> u16 {
        let offs = pool.ring_offsets(q);
        pool.mem()
            .load(GuestAddress(offs.avail), Ordering::Acquire)
            .unwrap()
    }

    /// Pop the next shadow avail entry (the shadow head index) for `q`.
    /// Panics if nothing is available.
    pub(crate) fn pop_avail(&mut self, pool: &BouncePool, q: usize) -> u16 {
        assert_ne!(
            self.avail_idx(pool, q),
            self.next_avail[q],
            "no avail entry"
        );
        let offs = pool.ring_offsets(q);
        let pos = self.next_avail[q] % self.queue_size;
        self.next_avail[q] = self.next_avail[q].wrapping_add(1);
        pool.mem()
            .read_obj(GuestAddress(offs.avail + 4 + u64::from(pos) * 2))
            .unwrap()
    }

    /// Read the shadow descriptor at `slot` for queue `q`.
    pub(crate) fn read_desc(&self, pool: &BouncePool, q: usize, slot: u16) -> Descriptor {
        let offs = pool.ring_offsets(q);
        pool.mem()
            .read_obj(GuestAddress(offs.desc + u64::from(slot) * 16))
            .unwrap()
    }

    /// Follow a shadow descriptor chain starting at `head`, resolving a
    /// pool-side indirect table (a single `F_INDIRECT` head descriptor)
    /// the way a real backend would.
    pub(crate) fn read_chain(&self, pool: &BouncePool, q: usize, head: u16) -> Vec<Descriptor> {
        use virtio_bindings::virtio_ring::VRING_DESC_F_INDIRECT;
        let head_desc = self.read_desc(pool, q, head);
        if head_desc.flags() & VRING_DESC_F_INDIRECT as u16 != 0 {
            // Walk the indirect table at the head's pool address.
            let count = head_desc.len() as usize / 16;
            let mut descs = Vec::with_capacity(count);
            for i in 0..count {
                let entry: Descriptor = pool
                    .mem()
                    .read_obj(head_desc.addr().unchecked_add((i * 16) as u64))
                    .unwrap();
                let last = !entry.has_next();
                descs.push(entry);
                if last {
                    break;
                }
            }
            return descs;
        }
        let mut descs = Vec::new();
        let mut slot = head;
        loop {
            let desc = self.read_desc(pool, q, slot);
            let has_next = desc.has_next();
            slot = desc.next();
            descs.push(desc);
            if !has_next {
                return descs;
            }
            assert!(descs.len() <= self.queue_size as usize, "chain loop");
        }
    }

    /// Publish a used element for the chain headed by shadow slot `head`,
    /// reporting `len` written bytes.
    pub(crate) fn complete(&mut self, pool: &BouncePool, q: usize, head: u16, len: u32) {
        let offs = pool.ring_offsets(q);
        let pos = self.next_used[q] % self.queue_size;
        let base = offs.used + 4 + u64::from(pos) * 8;
        pool.mem()
            .write_obj(u32::from(head), GuestAddress(base))
            .unwrap();
        pool.mem().write_obj(len, GuestAddress(base + 4)).unwrap();
        self.next_used[q] = self.next_used[q].wrapping_add(1);
        pool.mem()
            .store(
                self.next_used[q],
                GuestAddress(offs.used + 2),
                Ordering::Release,
            )
            .unwrap();
    }

    /// Convenience: pop one avail entry, read its chain, write `fill`
    /// into every device-writable segment, and complete it reporting the
    /// number of bytes written. Returns the shadow head.
    pub(crate) fn serve_one(&mut self, pool: &BouncePool, q: usize, fill: u8) -> u16 {
        let head = self.pop_avail(pool, q);
        let chain = self.read_chain(pool, q, head);
        let mut written = 0u32;
        for desc in chain.iter().filter(|d| d.is_write_only()) {
            let data = vec![fill; desc.len() as usize];
            pool.mem().write_slice(&data, desc.addr()).unwrap();
            written += desc.len();
        }
        self.complete(pool, q, head, written);
        head
    }
}

/// A `VirtioInterrupt` for worker tests: records which queues were
/// triggered and signals a per-queue eventfd so a test can wait for an
/// interrupt with a bounded timeout.
pub(crate) struct TestInterrupt {
    evts: Vec<EventFd>,
}

impl TestInterrupt {
    pub(crate) fn new(num_queues: usize) -> Arc<Self> {
        Arc::new(TestInterrupt {
            evts: (0..num_queues)
                .map(|_| EventFd::new(libc::EFD_NONBLOCK).unwrap())
                .collect(),
        })
    }

    /// Wait up to `timeout` for queue `q` to be interrupted at least once.
    pub(crate) fn wait_interrupt(&self, q: usize, timeout: Duration) -> bool {
        wait_readable(self.evts[q].as_raw_fd(), timeout)
    }
}

impl VirtioInterrupt for TestInterrupt {
    fn trigger(&self, int_type: VirtioInterruptType) -> io::Result<()> {
        if let VirtioInterruptType::Queue(q) = int_type {
            self.evts[q as usize].write(1)?;
        }
        Ok(())
    }

    fn set_notifier(
        &self,
        _int_type: u32,
        _notifier: Option<EventFd>,
        _vm: &dyn hypervisor::Vm,
    ) -> io::Result<()> {
        Ok(())
    }
}

/// Poll `fd` for readability up to `timeout`; true if it became readable.
pub(crate) fn wait_readable(fd: RawFd, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        let ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: FFI call with a valid single-element pollfd.
        let ret = unsafe { libc::poll(&mut pfd, 1, ms) };
        if ret > 0 {
            return true;
        }
        if ret == 0 {
            return false;
        }
        // EINTR: retry until the deadline.
    }
}

/// Write `len` copies of `byte` into guest memory at `addr`.
pub(crate) fn fill_guest(mem: &GuestMemoryMmap, addr: u64, len: u32, byte: u8) {
    mem.write_slice(&vec![byte; len as usize], GuestAddress(addr))
        .unwrap();
}

/// Read `len` bytes from guest memory at `addr`.
pub(crate) fn read_guest(mem: &GuestMemoryMmap, addr: u64, len: u32) -> Vec<u8> {
    let mut buf = vec![0u8; len as usize];
    mem.read_slice(&mut buf, GuestAddress(addr)).unwrap();
    buf
}

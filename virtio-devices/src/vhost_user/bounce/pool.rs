// Copyright 2026 Cloud Hypervisor Contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The bounce pool: a memfd-backed memory region shared with the
//! vhost-user backend in place of guest RAM.
//!
//! The pool is exposed as a single-region [`GuestMemoryMmap`] at guest
//! physical address 0 — from the backend's perspective it is the entire
//! guest. It contains one shadow virtqueue (descriptor table, avail ring,
//! used ring) per device queue, followed by a buffer arena managed by
//! [`BounceAllocator`].

use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::{ffi, io};

use vm_memory::{Address, Bytes, FileOffset, GuestAddress, GuestMemory, GuestMemoryRegion};

use super::BounceError;
use super::allocator::{BOUNCE_ALLOC_ALIGN, BounceAllocator};
use crate::{GuestMemoryMmap, GuestRegionMmap, MmapRegion};

/// Page size used for pool internal alignment. vhost-user assumes 4kiB
/// pages (see `VHOST_LOG_PAGE`), independent of the host page size.
pub(crate) const POOL_PAGE_SIZE: u64 = 4096;

/// Sizing parameters for a bounce pool.
pub struct PoolLayout {
    /// Number of shadow queues to lay out.
    pub num_queues: usize,
    /// Maximum queue size (ring blocks are sized for this; the actual
    /// negotiated queue size may be smaller).
    pub queue_size: u16,
    /// Buffer arena capacity in bytes.
    pub buffer_capacity: u64,
}

/// Default buffer arena capacity: deliberately over-provisioned so that a
/// page-scatter driver keeping every queue slot busy with one-page
/// descriptors never stalls (x4 headroom for multi-page descriptors).
pub fn default_buffer_capacity(num_queues: usize, queue_size: u16) -> u64 {
    4 * num_queues as u64 * queue_size as u64 * POOL_PAGE_SIZE
}

/// Size in bytes of a split-ring descriptor table of `queue_size` entries.
pub fn desc_table_size(queue_size: u16) -> u64 {
    16 * queue_size as u64
}

/// Size in bytes of a split-ring avail ring of `queue_size` entries,
/// including the trailing `used_event` field (present when
/// `VIRTIO_F_RING_EVENT_IDX` is negotiated; reserving it unconditionally
/// costs 2 bytes and keeps the layout feature-independent).
pub fn avail_ring_size(queue_size: u16) -> u64 {
    6 + 2 * queue_size as u64 + 2
}

/// Size in bytes of a split-ring used ring of `queue_size` entries,
/// including the trailing `avail_event` field (see [`avail_ring_size`]).
pub fn used_ring_size(queue_size: u16) -> u64 {
    6 + 8 * queue_size as u64 + 2
}

/// Pool-relative offsets of one shadow queue's rings.
#[derive(Clone, Copy, Debug)]
pub struct RingOffsets {
    pub desc: u64,
    pub avail: u64,
    pub used: u64,
}

/// A memfd-backed bounce pool: shadow rings followed by a buffer arena.
pub struct BouncePool {
    /// Single-region guest memory view of the pool, at GPA 0.
    mem: GuestMemoryMmap,
    ring_offsets: Vec<RingOffsets>,
    arena_base: u64,
    size: u64,
    allocator: BounceAllocator,
}

fn align_up(value: u64, align: u64) -> u64 {
    value.next_multiple_of(align)
}

impl BouncePool {
    /// Create a pool: memfd (sealed against resizing), one mapping,
    /// zeroed contents, rings laid out per `layout`.
    pub fn new(layout: &PoolLayout) -> Result<Self, BounceError> {
        let qs = layout.queue_size;
        let mut ring_offsets = Vec::with_capacity(layout.num_queues);
        let mut cursor = 0u64;
        for _ in 0..layout.num_queues {
            let desc = align_up(cursor, POOL_PAGE_SIZE);
            let avail = desc + desc_table_size(qs);
            let used = align_up(avail + avail_ring_size(qs), 4);
            ring_offsets.push(RingOffsets { desc, avail, used });
            cursor = used + used_ring_size(qs);
        }
        let arena_base = align_up(cursor, POOL_PAGE_SIZE);
        let size = align_up(arena_base + layout.buffer_capacity, POOL_PAGE_SIZE);

        let name = ffi::CString::new("cloud_hypervisor_bounce_pool").unwrap();
        let file = create_sealed_memfd(&name, size).map_err(|e| match e {
            SealedMemfdError::Create(e) => BounceError::MemfdCreate(e),
            SealedMemfdError::SetSize(e) => BounceError::SetFileSize(e),
            SealedMemfdError::Seal(e) => BounceError::SetSeals(e),
        })?;

        let mapping = MmapRegion::build(
            Some(FileOffset::new(file, 0)),
            size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
        )
        .map_err(BounceError::NewMmapRegion)?;
        // A region based at GPA 0 cannot overflow the address space
        // check performed by GuestRegionMmap::new, hence the unwrap.
        let region = GuestRegionMmap::new(mapping, GuestAddress(0)).unwrap();
        let mem =
            GuestMemoryMmap::from_regions(vec![region]).map_err(BounceError::PoolGuestMemory)?;

        Ok(BouncePool {
            mem,
            ring_offsets,
            arena_base,
            size,
            allocator: BounceAllocator::new(layout.buffer_capacity),
        })
    }

    /// The pool as guest memory (single region at GPA 0). This is what
    /// the shadow rings live in and what buffer copies target.
    pub fn mem(&self) -> &GuestMemoryMmap {
        &self.mem
    }

    /// Total pool size in bytes (rings + arena), i.e. the size of the
    /// region shared with the backend.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Ring offsets of shadow queue `queue`.
    pub fn ring_offsets(&self, queue: usize) -> RingOffsets {
        self.ring_offsets[queue]
    }

    /// Pool-relative offset where the buffer arena starts.
    pub fn arena_base(&self) -> u64 {
        self.arena_base
    }

    /// Host virtual address of pool offset 0, as sent to the backend in
    /// the memory table and used to compute shadow ring addresses.
    pub fn host_base(&self) -> u64 {
        // The pool always contains GPA 0; unwrap can't fail.
        self.mem.get_host_address(GuestAddress(0)).unwrap() as u64
    }

    /// The memfd backing the pool, for the backend memory table.
    pub fn memfd(&self) -> RawFd {
        // The pool is built from a file-backed region; unwraps can't fail.
        self.mem
            .find_region(GuestAddress(0))
            .unwrap()
            .file_offset()
            .unwrap()
            .file()
            .as_raw_fd()
    }

    /// Buffer arena capacity in bytes.
    pub fn buffer_capacity(&self) -> u64 {
        self.allocator.capacity()
    }

    /// Buffer arena bytes currently free.
    pub fn free_bytes(&self) -> u64 {
        self.allocator.free_bytes()
    }

    /// Allocate `len` arena bytes; returns the extent's pool GPA.
    pub fn alloc(&mut self, len: u64) -> Option<GuestAddress> {
        self.allocator
            .alloc(len)
            .map(|offset| GuestAddress(self.arena_base + offset))
    }

    /// Free (and zero) the extent previously returned by [`Self::alloc`]
    /// for the same (address, requested len) pair.
    pub fn free(&mut self, addr: GuestAddress, len: u64) -> Result<(), BounceError> {
        let offset =
            addr.raw_value()
                .checked_sub(self.arena_base)
                .ok_or(BounceError::InvalidFree {
                    offset: addr.raw_value(),
                    len,
                })?;
        self.allocator.free(offset, len)?;
        // Scrub the full rounded extent so the backend can never observe
        // stale data from a previous request, including alignment padding.
        self.zero_range(addr.raw_value(), len.next_multiple_of(BOUNCE_ALLOC_ALIGN))
    }

    /// Zero the shadow ring area (not the arena), e.g. before
    /// (re-)initializing a backend session.
    pub fn zero_rings(&mut self) -> Result<(), BounceError> {
        self.zero_range(0, self.arena_base)
    }

    fn zero_range(&self, offset: u64, len: u64) -> Result<(), BounceError> {
        static ZEROES: [u8; 4096] = [0u8; 4096];
        let mut written = 0u64;
        while written < len {
            let chunk = (len - written).min(ZEROES.len() as u64) as usize;
            self.mem
                .write_slice(&ZEROES[..chunk], GuestAddress(offset + written))
                .map_err(BounceError::PoolMemory)?;
            written += chunk as u64;
        }
        Ok(())
    }
}

/// Which step of sealed memfd creation failed.
pub(crate) enum SealedMemfdError {
    Create(io::Error),
    SetSize(io::Error),
    Seal(io::Error),
}

/// Create a memfd of `size` bytes, sealed against growing and shrinking.
///
/// Consolidates the memfd_create/from_raw_fd/F_ADD_SEALS sequence that
/// previously lived in `vu_common_ctrl.rs` for the dirty-log shm region,
/// which now calls this helper too. This is the only unsafe code in the
/// bounce series and it is a relocation, not an addition.
pub(crate) fn create_sealed_memfd(name: &ffi::CStr, size: u64) -> Result<File, SealedMemfdError> {
    // SAFETY: FFI call with valid arguments
    let res = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if res < 0 {
        return Err(SealedMemfdError::Create(io::Error::last_os_error()));
    }
    // SAFETY: memfd_create just returned this valid, owned descriptor.
    let file = unsafe { File::from_raw_fd(res as RawFd) };

    file.set_len(size).map_err(SealedMemfdError::SetSize)?;

    // SAFETY: FFI call with valid arguments
    let res = unsafe {
        libc::fcntl(
            file.as_raw_fd(),
            libc::F_ADD_SEALS,
            libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
        )
    };
    if res < 0 {
        return Err(SealedMemfdError::Seal(io::Error::last_os_error()));
    }

    Ok(file)
}

#[cfg(test)]
mod tests {
    use vm_memory::{Address, Bytes};

    use super::*;

    fn layout(num_queues: usize, queue_size: u16, buffer_capacity: u64) -> PoolLayout {
        PoolLayout {
            num_queues,
            queue_size,
            buffer_capacity,
        }
    }

    #[test]
    fn default_buffer_capacity_formula() {
        for (nq, qs) in [(1usize, 128u16), (4, 256), (8, 1024)] {
            assert_eq!(
                default_buffer_capacity(nq, qs),
                4 * nq as u64 * qs as u64 * 4096
            );
        }
    }

    #[test]
    fn layout_ring_sizes_match_virtio_spec() {
        // Sizes per the virtio 1.x split ring layout, including the
        // event-idx trailing fields.
        assert_eq!(desc_table_size(256), 16 * 256);
        assert_eq!(avail_ring_size(256), 6 + 2 * 256 + 2);
        assert_eq!(used_ring_size(256), 6 + 8 * 256 + 2);
        let pool = BouncePool::new(&layout(1, 256, 4096)).unwrap();
        let offs = pool.ring_offsets(0);
        assert_eq!(offs.avail - offs.desc, desc_table_size(256));
        assert!(offs.used - offs.avail >= avail_ring_size(256));
        assert!(pool.arena_base() - offs.used >= used_ring_size(256));
    }

    #[test]
    fn layout_ring_blocks_are_page_aligned_and_disjoint() {
        let pool = BouncePool::new(&layout(3, 256, 8192)).unwrap();
        let mut prev_end = 0u64;
        for q in 0..3 {
            let offs = pool.ring_offsets(q);
            assert_eq!(offs.desc % 4096, 0, "queue {q} block not page aligned");
            assert!(offs.desc >= prev_end, "queue {q} overlaps previous");
            assert_eq!(offs.desc % 16, 0);
            assert_eq!(offs.avail % 2, 0);
            assert_eq!(offs.used % 4, 0);
            assert!(offs.desc + desc_table_size(256) <= offs.avail);
            assert!(offs.avail + avail_ring_size(256) <= offs.used);
            prev_end = offs.used + used_ring_size(256);
        }
        assert_eq!(pool.arena_base() % 4096, 0);
        assert!(pool.arena_base() >= prev_end);
        assert!(pool.size() >= pool.arena_base() + pool.buffer_capacity());
        assert_eq!(pool.size() % 4096, 0);
    }

    #[test]
    fn new_pool_memory_is_zeroed() {
        let pool = BouncePool::new(&layout(2, 128, 8192)).unwrap();
        for addr in [
            0u64,
            pool.ring_offsets(1).used,
            pool.arena_base(),
            pool.size() - 8,
        ] {
            assert_eq!(pool.mem().read_obj::<u64>(GuestAddress(addr)).unwrap(), 0);
        }
    }

    #[test]
    fn pool_mem_is_single_region_at_gpa_zero_with_fd() {
        let pool = BouncePool::new(&layout(1, 128, 4096)).unwrap();
        assert_eq!(pool.mem().iter().count(), 1);
        let region = pool.mem().find_region(GuestAddress(0)).unwrap();
        use vm_memory::GuestMemoryRegion;
        assert_eq!(region.start_addr(), GuestAddress(0));
        assert_eq!(region.len(), pool.size());
        assert!(region.file_offset().is_some());
        assert!(pool.memfd() >= 0);
    }

    #[test]
    fn alloc_returns_gpa_inside_arena() {
        let mut pool = BouncePool::new(&layout(1, 128, 8192)).unwrap();
        let addr = pool.alloc(100).unwrap();
        assert!(addr.raw_value() >= pool.arena_base());
        assert!(addr.raw_value() + 100 <= pool.size());
    }

    #[test]
    fn alloc_free_roundtrip_scrubs_extent() {
        let mut pool = BouncePool::new(&layout(1, 128, 8192)).unwrap();
        let addr = pool.alloc(256).unwrap();
        pool.mem().write_slice(&[0xabu8; 256], addr).unwrap();
        pool.free(addr, 256).unwrap();
        let mut buf = [0xffu8; 256];
        pool.mem().read_slice(&mut buf, addr).unwrap();
        assert_eq!(buf, [0u8; 256]);
    }

    #[test]
    fn free_bytes_tracks_allocator() {
        let mut pool = BouncePool::new(&layout(1, 128, 8192)).unwrap();
        assert_eq!(pool.free_bytes(), pool.buffer_capacity());
        let addr = pool.alloc(100).unwrap();
        assert_eq!(pool.free_bytes(), pool.buffer_capacity() - 128);
        pool.free(addr, 100).unwrap();
        assert_eq!(pool.free_bytes(), pool.buffer_capacity());
    }

    #[test]
    fn zero_rings_clears_only_ring_area() {
        let mut pool = BouncePool::new(&layout(2, 128, 8192)).unwrap();
        let ring_addr = GuestAddress(pool.ring_offsets(1).desc);
        pool.mem().write_obj::<u64>(0xdead_beef, ring_addr).unwrap();
        let buf_addr = pool.alloc(64).unwrap();
        pool.mem().write_obj::<u64>(0xfeed_face, buf_addr).unwrap();
        pool.zero_rings().unwrap();
        assert_eq!(pool.mem().read_obj::<u64>(ring_addr).unwrap(), 0);
        assert_eq!(pool.mem().read_obj::<u64>(buf_addr).unwrap(), 0xfeed_face);
    }

    #[test]
    fn host_base_offset_math() {
        let pool = BouncePool::new(&layout(1, 128, 4096)).unwrap();
        let offs = pool.ring_offsets(0);
        let host_desc = pool
            .mem()
            .get_host_address(GuestAddress(offs.desc))
            .unwrap() as u64;
        assert_eq!(pool.host_base() + offs.desc, host_desc);
    }

    #[test]
    fn memfd_is_sealed() {
        let pool = BouncePool::new(&layout(1, 128, 4096)).unwrap();
        use vm_memory::{GuestMemory, GuestMemoryRegion};
        let region = pool.mem().find_region(GuestAddress(0)).unwrap();
        let file = region.file_offset().unwrap().file().try_clone().unwrap();
        // Growing and shrinking must both fail thanks to the seals.
        assert!(file.set_len(pool.size() * 2).is_err());
        assert!(file.set_len(4096).is_err());
    }
}

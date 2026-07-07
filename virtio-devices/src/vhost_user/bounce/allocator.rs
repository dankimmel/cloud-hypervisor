// Copyright 2026 Cloud Hypervisor Contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Offset allocator for the bounce pool buffer arena.

use super::BounceError;

/// Alignment granule for arena extents, in bytes. Every returned offset
/// and every internal extent boundary is a multiple of this value.
pub const BOUNCE_ALLOC_ALIGN: u64 = 64;

/// A first-fit offset allocator over a contiguous arena of bytes.
///
/// The allocator only tracks offsets; it never touches memory. Offsets
/// are relative to the start of the arena. Requested lengths are rounded
/// up to [`BOUNCE_ALLOC_ALIGN`] internally, and `free` performs the same
/// rounding so callers pass the original requested length back.
pub struct BounceAllocator {
    /// Usable arena size (rounded down to the alignment granule).
    capacity: u64,
    /// Free extents as (offset, len), sorted by offset, never empty
    /// ranges, never adjacent (adjacent extents are coalesced on free).
    // TODO: expect(dead_code) is removed when the next commit implements
    // alloc()/free() (docs/vhost-user-bounce-plan.md commit 2).
    #[expect(dead_code)]
    free_list: Vec<(u64, u64)>,
    /// Total free bytes, always the sum of `free_list` lengths.
    free_bytes: u64,
}

impl BounceAllocator {
    /// Create an allocator over an arena of `capacity` bytes. Capacities
    /// that are not multiples of [`BOUNCE_ALLOC_ALIGN`] are rounded down.
    pub fn new(capacity: u64) -> Self {
        let capacity = capacity - (capacity % BOUNCE_ALLOC_ALIGN);
        BounceAllocator {
            capacity,
            free_list: vec![(0, capacity)],
            free_bytes: capacity,
        }
    }

    /// Allocate `len` bytes (rounded up to the alignment granule) and
    /// return the extent's offset, or `None` if no free extent is large
    /// enough. Zero-length allocations are rejected: callers special-case
    /// zero-length descriptors and never reach the allocator.
    pub fn alloc(&mut self, _len: u64) -> Option<u64> {
        todo!("implemented in docs/vhost-user-bounce-plan.md commit 2")
    }

    /// Free the extent previously returned by [`Self::alloc`] for the
    /// same (offset, requested len) pair, coalescing with free neighbors.
    ///
    /// Extents that are out of bounds or overlap free space are rejected
    /// with [`BounceError::InvalidFree`].
    pub fn free(&mut self, _offset: u64, _len: u64) -> Result<(), BounceError> {
        todo!("implemented in docs/vhost-user-bounce-plan.md commit 2")
    }

    /// Total bytes currently free (not necessarily contiguous).
    pub fn free_bytes(&self) -> u64 {
        self.free_bytes
    }

    /// Usable arena size in bytes.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "implemented in docs/vhost-user-bounce-plan.md commit 2"]
    fn alloc_returns_aligned_offset_within_capacity() {
        let mut a = BounceAllocator::new(1024);
        let off = a.alloc(100).unwrap();
        assert_eq!(off % BOUNCE_ALLOC_ALIGN, 0);
        assert!(off + 100 <= a.capacity());
    }

    #[test]
    #[ignore = "implemented in docs/vhost-user-bounce-plan.md commit 2"]
    fn alloc_zero_len_rejected() {
        let mut a = BounceAllocator::new(1024);
        assert_eq!(a.alloc(0), None);
        assert_eq!(a.free_bytes(), 1024);
    }

    #[test]
    #[ignore = "implemented in docs/vhost-user-bounce-plan.md commit 2"]
    fn alloc_rounds_len_up_to_alignment() {
        let mut a = BounceAllocator::new(1024);
        let _ = a.alloc(1).unwrap();
        assert_eq!(a.free_bytes(), 1024 - BOUNCE_ALLOC_ALIGN);
    }

    #[test]
    #[ignore = "implemented in docs/vhost-user-bounce-plan.md commit 2"]
    fn alloc_exhaustion_returns_none_without_side_effects() {
        let mut a = BounceAllocator::new(256);
        let off = a.alloc(200).unwrap(); // rounds to 256, takes everything
        assert_eq!(a.free_bytes(), 0);
        assert_eq!(a.alloc(1), None);
        assert_eq!(a.free_bytes(), 0);
        a.free(off, 200).unwrap();
        assert_eq!(a.alloc(256), Some(0));
    }

    #[test]
    #[ignore = "implemented in docs/vhost-user-bounce-plan.md commit 2"]
    fn free_then_alloc_reuses_space() {
        let mut a = BounceAllocator::new(1024);
        let x = a.alloc(128).unwrap();
        let _y = a.alloc(128).unwrap();
        a.free(x, 128).unwrap();
        assert_eq!(a.alloc(128), Some(x));
    }

    #[test]
    #[ignore = "implemented in docs/vhost-user-bounce-plan.md commit 2"]
    fn free_coalesces_with_previous_and_next() {
        let mut a = BounceAllocator::new(768);
        let x = a.alloc(256).unwrap();
        let y = a.alloc(256).unwrap();
        let z = a.alloc(256).unwrap();
        assert_eq!((x, y, z), (0, 256, 512));
        // Free the middle, then both neighbors; everything must coalesce
        // back into one extent covering the whole arena.
        a.free(y, 256).unwrap();
        a.free(x, 256).unwrap();
        a.free(z, 256).unwrap();
        assert_eq!(a.free_bytes(), 768);
        assert_eq!(a.alloc(768), Some(0));
    }

    #[test]
    #[ignore = "implemented in docs/vhost-user-bounce-plan.md commit 2"]
    fn alloc_first_fit_is_deterministic() {
        let mut a = BounceAllocator::new(1024);
        let _a0 = a.alloc(256).unwrap(); // @0
        let b = a.alloc(128).unwrap(); // @256
        let _c = a.alloc(256).unwrap(); // @384
        let d = a.alloc(384).unwrap(); // @640
        assert_eq!((b, d), (256, 640));
        a.free(b, 128).unwrap();
        a.free(d, 384).unwrap();
        // Both gaps fit 64 bytes; first-fit must take the lower offset.
        assert_eq!(a.alloc(64), Some(256));
        // 256 bytes only fits in the second gap now.
        assert_eq!(a.alloc(256), Some(640));
    }

    #[test]
    #[ignore = "implemented in docs/vhost-user-bounce-plan.md commit 2"]
    fn free_bytes_accounting_over_interleaved_ops() {
        let mut a = BounceAllocator::new(64 * 1024);
        let mut live: Vec<(u64, u64)> = Vec::new();
        let mut model_free = a.capacity();
        // Deterministic pseudo-random sequence (LCG).
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        for i in 0..500 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let len = 1 + (seed >> 33) % 4096;
            let rounded = len.next_multiple_of(BOUNCE_ALLOC_ALIGN);
            if i % 3 != 2 || live.is_empty() {
                if let Some(off) = a.alloc(len) {
                    live.push((off, len));
                    model_free -= rounded;
                }
            } else {
                let idx = (seed as usize) % live.len();
                let (off, len) = live.swap_remove(idx);
                a.free(off, len).unwrap();
                model_free += len.next_multiple_of(BOUNCE_ALLOC_ALIGN);
            }
            assert_eq!(a.free_bytes(), model_free, "iteration {i}");
        }
        for (off, len) in live.drain(..) {
            a.free(off, len).unwrap();
        }
        assert_eq!(a.free_bytes(), a.capacity());
    }

    #[test]
    #[ignore = "implemented in docs/vhost-user-bounce-plan.md commit 2"]
    fn invalid_free_unallocated_range_rejected() {
        let mut a = BounceAllocator::new(1024);
        // Nothing was ever allocated: the range is free, so freeing it
        // overlaps free space and must be rejected.
        assert!(matches!(
            a.free(0, 64),
            Err(BounceError::InvalidFree { offset: 0, len: 64 })
        ));
        // Out of bounds is also invalid.
        let off = a.alloc(64).unwrap();
        assert!(a.free(1024, 64).is_err());
        assert!(a.free(off, 2048).is_err());
        assert_eq!(a.free_bytes(), 1024 - 64);
    }

    #[test]
    #[ignore = "implemented in docs/vhost-user-bounce-plan.md commit 2"]
    fn invalid_free_overlapping_free_range_rejected() {
        let mut a = BounceAllocator::new(1024);
        let x = a.alloc(128).unwrap();
        let _y = a.alloc(128).unwrap();
        a.free(x, 128).unwrap();
        // x..x+128 is free again; a free spanning it (or part of it)
        // overlaps free space.
        assert!(a.free(x, 256).is_err());
        assert!(a.free(x + 64, 64).is_err());
        assert_eq!(a.free_bytes(), 1024 - 128);
    }

    #[test]
    #[ignore = "implemented in docs/vhost-user-bounce-plan.md commit 2"]
    fn full_drain_restores_initial_state() {
        let mut a = BounceAllocator::new(4096);
        let mut extents = Vec::new();
        for len in [64u64, 100, 1, 512, 640, 4096] {
            if let Some(off) = a.alloc(len) {
                extents.push((off, len));
            }
        }
        assert!(!extents.is_empty());
        for (off, len) in extents.drain(..) {
            a.free(off, len).unwrap();
        }
        assert_eq!(a.free_bytes(), a.capacity());
        assert_eq!(a.alloc(4096), Some(0));
    }
}

// Copyright 2026 Cloud Hypervisor Contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounce buffer pool support for vhost-user devices.
//!
//! With bouncing enabled, the vhost-user backend is never given access to
//! guest RAM. Instead it receives a single memfd-backed "bounce pool"
//! region containing VMM-managed shadow virtqueues, and a per-device
//! worker thread copies request data between guest memory and the pool in
//! both directions. There are no vhost-user protocol changes and the
//! feature is strictly opt-in per device.
//!
//! See `docs/vhost-user-bounce-plan.md` for the full design.

pub mod allocator;
pub mod pool;
pub mod shadow_queue;
#[cfg(test)]
pub(crate) mod test_utils;

use std::io;

pub use allocator::{BOUNCE_ALLOC_ALIGN, BounceAllocator};
pub use pool::{BouncePool, PoolLayout, RingOffsets, default_buffer_capacity};
pub use shadow_queue::{CompleteOutcome, MirrorOutcome, ShadowQueue, ShadowQueueConfig};
use thiserror::Error;
use vm_memory::mmap::MmapRegionError;
use vm_memory::{GuestMemoryError, GuestRegionCollectionError};

/// Errors from the bounce buffer pool machinery.
#[derive(Error, Debug)]
pub enum BounceError {
    #[error("Invalid free of pool extent at offset {offset} len {len}")]
    InvalidFree { offset: u64, len: u64 },
    #[error("Failed creating bounce pool memfd")]
    MemfdCreate(#[source] io::Error),
    #[error("Failed sizing bounce pool memfd")]
    SetFileSize(#[source] io::Error),
    #[error("Failed sealing bounce pool memfd")]
    SetSeals(#[source] io::Error),
    #[error("Failed mmapping bounce pool")]
    NewMmapRegion(#[source] MmapRegionError),
    #[error("Failed creating bounce pool guest memory")]
    PoolGuestMemory(#[source] GuestRegionCollectionError),
    #[error("Bounce pool memory access failed")]
    PoolMemory(#[source] GuestMemoryError),
}

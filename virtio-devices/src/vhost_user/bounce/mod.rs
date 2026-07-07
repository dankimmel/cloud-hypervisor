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
pub mod worker;

use std::io;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

pub use allocator::{BOUNCE_ALLOC_ALIGN, BounceAllocator};
pub use pool::{BouncePool, PoolLayout, RingOffsets, default_buffer_capacity};
pub use shadow_queue::{CompleteOutcome, MirrorOutcome, ShadowQueue, ShadowQueueConfig};
use thiserror::Error;
use vm_memory::mmap::MmapRegionError;
use vm_memory::{GuestMemoryError, GuestRegionCollectionError};
use vmm_sys_util::eventfd::EventFd;
pub use worker::{BounceEpollHandler, BounceShared};

/// Per-device configuration for bounce mode, parsed from the CLI.
#[derive(Clone, Debug, Default)]
pub struct BounceConfig {
    /// Buffer arena size in bytes; `None` uses the default sizing.
    pub pool_size: Option<u64>,
}

/// Per-device bounce state owned by `VhostUserCommon`.
///
/// The pool is created up front (sized for the transport-maximum queue
/// size); the per-queue shadow queues are filled in at activation, when
/// the negotiated queue sizes and vring bases are known.
pub struct BounceState {
    /// Pool plus shadow queues, shared with the data-plane worker.
    pub shared: Arc<Mutex<BounceShared>>,
    /// Shadow kick/call eventfd pair per queue.
    pub fds: Vec<BounceQueueFds>,
    /// Total chains currently owned by the backend across all queues,
    /// maintained by the worker; snapshotting is refused while nonzero.
    pub inflight_total: Arc<AtomicUsize>,
}

impl BounceState {
    /// Create the pool and per-queue eventfds for a device with
    /// `num_queues` queues of maximum size `queue_size`.
    pub fn new(
        cfg: &BounceConfig,
        num_queues: usize,
        queue_size: u16,
    ) -> Result<Self, BounceError> {
        let buffer_capacity = cfg
            .pool_size
            .unwrap_or_else(|| default_buffer_capacity(num_queues, queue_size));
        let pool = BouncePool::new(&PoolLayout {
            num_queues,
            queue_size,
            buffer_capacity,
        })?;
        let fds = (0..num_queues)
            .map(|_| BounceQueueFds::new())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(BounceState {
            shared: Arc::new(Mutex::new(BounceShared {
                pool,
                shadow: Vec::new(),
            })),
            fds,
            inflight_total: Arc::new(AtomicUsize::new(0)),
        })
    }
}

/// Clear the virtio ring features that bounce mode does not (yet)
/// support, so neither the guest nor the backend ever negotiates them.
/// Applied to a device's available features before feature negotiation.
pub fn mask_bounce_features(avail_features: u64) -> u64 {
    avail_features
        & !(1 << crate::VIRTIO_F_RING_INDIRECT_DESC)
        & !(1 << crate::VIRTIO_F_RING_EVENT_IDX)
        & !(1 << crate::VIRTIO_F_IN_ORDER)
}

/// The eventfds wiring one shadow queue to the backend: the VMM kicks
/// `shadow_kick` after publishing shadow avail entries, and the backend
/// signals `shadow_call` after publishing shadow used entries. These are
/// what the backend receives via SET_VRING_KICK/SET_VRING_CALL instead
/// of the guest's ioeventfd and irqfd.
pub struct BounceQueueFds {
    pub shadow_kick: EventFd,
    pub shadow_call: EventFd,
}

impl BounceQueueFds {
    pub fn new() -> Result<Self, BounceError> {
        Ok(BounceQueueFds {
            shadow_kick: EventFd::new(libc::EFD_NONBLOCK).map_err(BounceError::CreateEventFd)?,
            shadow_call: EventFd::new(libc::EFD_NONBLOCK).map_err(BounceError::CreateEventFd)?,
        })
    }
}

/// Errors from the bounce buffer pool machinery.
#[derive(Error, Debug)]
pub enum BounceError {
    #[error("Failed creating bounce eventfd")]
    CreateEventFd(#[source] io::Error),
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

#[cfg(test)]
mod tests {
    use std::os::unix::io::AsRawFd;

    use super::*;

    #[test]
    fn bounce_queue_fds_are_distinct_eventfds() {
        let fds = BounceQueueFds::new().unwrap();
        assert_ne!(fds.shadow_kick.as_raw_fd(), fds.shadow_call.as_raw_fd());
        fds.shadow_kick.write(1).unwrap();
        assert_eq!(fds.shadow_kick.read().unwrap(), 1);
        fds.shadow_call.write(3).unwrap();
        assert_eq!(fds.shadow_call.read().unwrap(), 3);
    }

    #[test]
    fn mask_bounce_features_clears_indirect_event_idx_in_order() {
        let all = (1 << crate::VIRTIO_F_RING_INDIRECT_DESC)
            | (1 << crate::VIRTIO_F_RING_EVENT_IDX)
            | (1 << crate::VIRTIO_F_IN_ORDER);
        assert_eq!(mask_bounce_features(all), 0);
    }

    #[test]
    fn mask_bounce_features_preserves_other_bits() {
        let masked = mask_bounce_features(super::super::DEFAULT_VIRTIO_FEATURES);
        let expected = super::super::DEFAULT_VIRTIO_FEATURES
            & !(1 << crate::VIRTIO_F_RING_INDIRECT_DESC)
            & !(1 << crate::VIRTIO_F_RING_EVENT_IDX)
            & !(1 << crate::VIRTIO_F_IN_ORDER);
        assert_eq!(masked, expected);
        // The event-idx and in-order bits are not part of the default set,
        // but indirect-desc is, so masking must actually change the value.
        assert_ne!(masked, super::super::DEFAULT_VIRTIO_FEATURES);
    }

    #[test]
    fn bounce_state_new_default_pool_size() {
        let state = BounceState::new(&BounceConfig::default(), 4, 256).unwrap();
        let cap = state.shared.lock().unwrap().pool.buffer_capacity();
        assert_eq!(cap, default_buffer_capacity(4, 256));
    }

    #[test]
    fn bounce_state_new_with_override() {
        let cfg = BounceConfig {
            pool_size: Some(1 << 20),
        };
        let state = BounceState::new(&cfg, 2, 128).unwrap();
        assert_eq!(state.shared.lock().unwrap().pool.buffer_capacity(), 1 << 20);
    }

    #[test]
    fn bounce_state_new_creates_one_fd_pair_per_queue() {
        use std::sync::atomic::Ordering;
        let state = BounceState::new(&BounceConfig::default(), 3, 128).unwrap();
        assert_eq!(state.fds.len(), 3);
        assert_eq!(state.inflight_total.load(Ordering::Relaxed), 0);
    }
}

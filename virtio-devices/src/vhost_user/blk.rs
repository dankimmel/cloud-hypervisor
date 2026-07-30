// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::result;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier, Mutex};

use block::VirtioBlockConfig;
use block::zoned::{
    VIRTIO_BLK_CONFIG_BASE_LEN, VirtioBlockZonedConfig, ZonedExposure, assemble_config_space,
    check_restore_compat, config_space_len, gate_features, zoned_negotiated,
};
use log::{error, info};
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use vhost::vhost_user::message::{
    VhostUserConfigFlags, VhostUserProtocolFeatures, VhostUserVirtioFeatures,
};
use vhost::vhost_user::{FrontendReqHandler, VhostUserFrontend, VhostUserFrontendReqHandler};
use virtio_bindings::virtio_blk::{
    VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_F_CONFIG_WCE, VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_FLUSH,
    VIRTIO_BLK_F_GEOMETRY, VIRTIO_BLK_F_MQ, VIRTIO_BLK_F_RO, VIRTIO_BLK_F_SEG_MAX,
    VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_WRITE_ZEROES, VIRTIO_BLK_F_ZONED,
};
use vm_memory::ByteValued;
use vm_migration::protocol::MemoryRangeTable;
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

use super::super::{ActivateResult, VirtioCommon, VirtioDevice, VirtioDeviceType};
use super::vu_common_ctrl::{VhostUserConfig, VhostUserHandle};
use super::{DEFAULT_VIRTIO_FEATURES, Error, Result};
use crate::device::ActivationContext;
use crate::seccomp_filters::Thread;
use crate::vhost_user::{VhostUserCommon, VhostUserState};
use crate::{GuestRegionMmap, VIRTIO_F_ACCESS_PLATFORM};

const DEFAULT_QUEUE_NUMBER: usize = 1;

/// Snapshot representation of a vhost-user-blk device's configuration space.
///
/// `base` is flattened so that snapshots taken before zoned support existed,
/// which stored the base configuration space directly, still deserialise into
/// this type with `zoned` defaulting to absent.
#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
pub struct BlkConfigState {
    /// The base configuration space, as exposed by every block device.
    #[serde(flatten)]
    pub base: VirtioBlockConfig,
    /// The zoned configuration-space tail, present only for a device that
    /// exposes `VIRTIO_BLK_F_ZONED` to the guest.
    #[serde(default)]
    pub zoned: Option<VirtioBlockZonedConfig>,
}

pub type State = VhostUserState<BlkConfigState>;

struct BackendReqHandler {}
impl VhostUserFrontendReqHandler for BackendReqHandler {}

pub struct Blk {
    vu_common: VhostUserCommon,
    id: String,
    config: VirtioBlockConfig,
    /// Zoned characteristics, present only when `VIRTIO_BLK_F_ZONED` is exposed
    /// to the guest. Kept separate from `config` so that the guest-visible
    /// configuration space of non-zoned devices is unchanged.
    zoned: Option<VirtioBlockZonedConfig>,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
    access_platform_enabled: bool,
}

impl Blk {
    /// Create a new vhost-user-blk device
    pub fn new(
        id: String,
        vu_cfg: VhostUserConfig,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        access_platform_enabled: bool,
        state: Option<State>,
    ) -> Result<Blk> {
        let num_queues = vu_cfg.num_queues;

        let mut vu = VhostUserHandle::connect_vhost_user(
            false,
            &vu_cfg.socket,
            num_queues as u64,
            false,
            None,
        )?;

        let (
            avail_features,
            acked_features,
            acked_protocol_features,
            vu_num_queues,
            config,
            zoned,
            paused,
            vring_bases,
        ) = if let Some(state) = state {
            info!("Restoring vhost-user-block {id}");

            let backend_features = vu.set_protocol_features_vhost_user(
                state.acked_features,
                state.acked_protocol_features,
            )?;

            // Refuse the restore outright if the guest was using a zoned device
            // and this backend cannot serve one. The guest holds zone state and
            // will keep issuing zone-management commands, and a negotiated
            // feature cannot be withdrawn from a running guest.
            check_restore_compat(state.avail_features, backend_features)
                .map_err(Error::ZonedConfig)?;

            vu.restore_state(&state)?;

            (
                state.avail_features,
                state.acked_features,
                state.acked_protocol_features,
                state.vu_num_queues,
                state.config.base,
                state.config.zoned,
                true,
                state.vring_bases,
            )
        } else {
            // Filling device and vring features VMM supports.
            let mut avail_features = (1 << VIRTIO_BLK_F_SIZE_MAX)
                | (1 << VIRTIO_BLK_F_SEG_MAX)
                | (1 << VIRTIO_BLK_F_GEOMETRY)
                | (1 << VIRTIO_BLK_F_RO)
                | (1 << VIRTIO_BLK_F_BLK_SIZE)
                | (1 << VIRTIO_BLK_F_FLUSH)
                | (1 << VIRTIO_BLK_F_TOPOLOGY)
                | (1 << VIRTIO_BLK_F_CONFIG_WCE)
                | (1 << VIRTIO_BLK_F_DISCARD)
                | (1 << VIRTIO_BLK_F_WRITE_ZEROES)
                // Offered unconditionally: negotiation clears it again for any
                // backend that does not support zoned disks, and it is withdrawn
                // from the guest-facing feature set further below unless the
                // backend is actually serving one.
                | (1 << VIRTIO_BLK_F_ZONED)
                | DEFAULT_VIRTIO_FEATURES;

            if num_queues > 1 {
                avail_features |= 1 << VIRTIO_BLK_F_MQ;
            }

            let avail_protocol_features = VhostUserProtocolFeatures::CONFIG
                | VhostUserProtocolFeatures::MQ
                | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
                | VhostUserProtocolFeatures::REPLY_ACK
                | VhostUserProtocolFeatures::INFLIGHT_SHMFD
                | VhostUserProtocolFeatures::LOG_SHMFD
                | VhostUserProtocolFeatures::DEVICE_STATE;

            let (acked_features, acked_protocol_features) =
                vu.negotiate_features_vhost_user(avail_features, avail_protocol_features)?;

            let backend_num_queues =
                if acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() != 0 {
                    vu.socket_handle()
                        .get_queue_num()
                        .map_err(Error::VhostUserGetQueueMaxNum)? as usize
                } else {
                    DEFAULT_QUEUE_NUMBER
                };

            if num_queues > backend_num_queues {
                error!(
                    "vhost-user-blk requested too many queues ({num_queues}) since the backend only supports {backend_num_queues}\n"
                );
                return Err(Error::BadQueueNum);
            }

            // Ask for the longer, zoned configuration space only when the
            // backend advertised VIRTIO_BLK_F_ZONED. A GET_CONFIG reply must
            // match the requested length exactly, so requesting it
            // unconditionally would fail device init on every backend that
            // serves only the base configuration space.
            let backend_is_zoned = zoned_negotiated(acked_features);
            let config_len = config_space_len(backend_is_zoned);
            let config_space: Vec<u8> = vec![0u8; config_len];
            let (_, config_space) = vu
                .socket_handle()
                .get_config(
                    0,
                    config_len as u32,
                    VhostUserConfigFlags::WRITABLE,
                    config_space.as_slice(),
                )
                .map_err(Error::VhostUserGetConfig)?;
            let mut config = VirtioBlockConfig::default();
            if let Some(backend_config) =
                VirtioBlockConfig::from_slice(&config_space[..VIRTIO_BLK_CONFIG_BASE_LEN])
            {
                config = *backend_config;
                config.num_queues = num_queues as u16;
            }

            // A backend that advertises the feature may still be serving a
            // conventional disk, in which case the feature is withdrawn rather
            // than failing the device.
            let (zoned, exposure) = if backend_is_zoned {
                let tail = VirtioBlockZonedConfig::from_le_bytes(
                    &config_space[VIRTIO_BLK_CONFIG_BASE_LEN..],
                )
                .map_err(Error::ZonedConfig)?;
                let exposure = tail.validate().map_err(Error::ZonedConfig)?;
                if exposure.is_exposed() {
                    info!(
                        "vhost-user-blk {id}: exposing zoned device, {} sectors per zone",
                        tail.zone_sectors
                    );
                } else {
                    info!(
                        "vhost-user-blk {id}: backend advertises VIRTIO_BLK_F_ZONED but reports a \
                         conventional disk; exposing it as a non-zoned device"
                    );
                }
                (exposure.is_exposed().then_some(tail), exposure)
            } else {
                (None, ZonedExposure::NotAdvertised)
            };

            (
                // Withhold VIRTIO_BLK_F_ZONED from the guest unless the backend
                // is actually serving a zoned disk. Because ack_features() masks
                // the guest's acknowledgement against this set, a withheld
                // feature can never reach the backend either.
                gate_features(acked_features, exposure),
                // If part of the available features that have been acked,
                // the PROTOCOL_FEATURES bit must be already set through
                // the VIRTIO acked features as we know the guest would
                // never ack it, thus the feature would be lost.
                acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits(),
                acked_protocol_features,
                num_queues,
                config,
                zoned,
                false,
                None,
            )
        };

        Ok(Blk {
            vu_common: VhostUserCommon {
                virtio_common: VirtioCommon {
                    device_type: VirtioDeviceType::Block as u32,
                    queue_sizes: vec![vu_cfg.queue_size; num_queues],
                    avail_features,
                    acked_features,
                    paused_sync: Some(Arc::new(Barrier::new(2))),
                    min_queues: DEFAULT_QUEUE_NUMBER as u16,
                    paused: Arc::new(AtomicBool::new(paused)),
                    ..Default::default()
                },
                vu: Some(Arc::new(Mutex::new(vu))),
                acked_protocol_features,
                socket_path: vu_cfg.socket,
                vu_num_queues,
                vring_bases,
                ..Default::default()
            },
            id,
            config,
            zoned,
            seccomp_action,
            exit_evt,
            access_platform_enabled,
        })
    }

    fn state(&self) -> result::Result<State, MigratableError> {
        self.vu_common.state(BlkConfigState {
            base: self.config,
            zoned: self.zoned,
        })
    }
}

impl Drop for Blk {
    fn drop(&mut self) {
        self.vu_common.shutdown();
    }
}

impl VirtioDevice for Blk {
    fn device_type(&self) -> u32 {
        self.vu_common.virtio_common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.vu_common.virtio_common.queue_sizes
    }

    fn features(&self) -> u64 {
        let mut features = self.vu_common.virtio_common.avail_features;
        if self.access_platform_enabled {
            features |= 1u64 << VIRTIO_F_ACCESS_PLATFORM;
        }
        features
    }

    fn ack_features(&mut self, value: u64) {
        self.vu_common.virtio_common.ack_features(value);
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Assembled per read rather than cached, because write_config() can
        // change the base configuration space at any time. Config reads only
        // happen while the guest driver probes the device, so this is not a hot
        // path. A non-zoned device yields the base configuration space
        // unchanged, exactly as before.
        let config = assemble_config_space(self.config.as_slice(), self.zoned.as_ref());
        self.read_config_from_slice(&config, offset, data);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        // The "writeback" field is the only mutable field
        let writeback_offset =
            (&raw const self.config.writeback as u64) - (&raw const self.config as u64);
        if offset != writeback_offset || data.len() != size_of_val(&self.config.writeback) {
            error!(
                "Attempt to write to read-only field: offset {:x} length {}",
                offset,
                data.len()
            );
            return;
        }

        self.config.writeback = data[0];
        if let Some(vu) = &self.vu_common.vu
            && let Err(e) = vu
                .lock()
                .unwrap()
                .socket_handle()
                .set_config(offset as u32, VhostUserConfigFlags::WRITABLE, data)
                .map_err(Error::VhostUserSetConfig)
        {
            error!(
                "Failed setting vhost-user-blk configuration for socket {} at offset 0x{offset:x} with length {}: {e:?}",
                self.vu_common.socket_path,
                data.len()
            );
        }
    }

    fn activate(&mut self, context: ActivationContext) -> ActivateResult {
        let ActivationContext {
            mem,
            interrupt_cb,
            queues,
            device_status,
        } = context;
        self.vu_common
            .virtio_common
            .activate(&queues, interrupt_cb.clone())?;

        let backend_req_handler: Option<FrontendReqHandler<BackendReqHandler>> = None;

        // Run a dedicated thread for handling potential reconnections with
        // the backend.
        let (kill_evt, pause_evt) = self.vu_common.virtio_common.dup_eventfds()?;

        let mut handler = self.vu_common.activate(
            mem,
            &queues,
            interrupt_cb.clone(),
            self.vu_common.virtio_common.acked_features,
            backend_req_handler,
            kill_evt,
            pause_evt,
        )?;

        // A reconnected backend that no longer offers VIRTIO_BLK_F_ZONED cannot
        // serve a guest that is already driving zones, so require it to keep
        // advertising the feature for as long as the device exposes it.
        if self.zoned.is_some() {
            handler.required_backend_features |= 1u64 << VIRTIO_BLK_F_ZONED;
        }

        let paused = self.vu_common.virtio_common.paused.clone();
        let paused_sync = self.vu_common.virtio_common.paused_sync.clone();

        self.vu_common.spawn_worker(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioVhostBlock,
            &self.exit_evt,
            device_status.clone(),
            interrupt_cb.clone(),
            move || handler.run(&paused, paused_sync.as_ref().unwrap()),
        )?;

        Ok(())
    }

    fn reset(&mut self) {
        self.vu_common.reset(&self.id);
    }

    fn shutdown(&mut self) {
        self.vu_common.shutdown();
    }

    fn add_memory_region(
        &mut self,
        region: &Arc<GuestRegionMmap>,
    ) -> result::Result<(), crate::Error> {
        self.vu_common.add_memory_region(region)
    }
}

impl Pausable for Blk {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.pause()?;
        self.vu_common.virtio_common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.virtio_common.resume()?;
        self.vu_common.resume()
    }
}

impl Snapshottable for Blk {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        self.vu_common.snapshot(&self.state()?)
    }
}
impl Transportable for Blk {}

impl Migratable for Blk {
    fn start_dirty_log(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.start_dirty_log()
    }

    fn stop_dirty_log(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.stop_dirty_log()
    }

    fn dirty_log(&mut self) -> result::Result<MemoryRangeTable, MigratableError> {
        self.vu_common.dirty_log()
    }

    fn start_migration(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.start_migration()
    }

    fn complete_migration(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.complete_migration()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zoned_tail() -> VirtioBlockZonedConfig {
        VirtioBlockZonedConfig {
            zone_sectors: 0x1_0000,
            max_open_zones: 32,
            max_active_zones: 64,
            max_append_sectors: 2048,
            write_granularity: 4096,
            model: 1,
            ..Default::default()
        }
    }

    /// Snapshots taken before zoned support existed serialised the base
    /// configuration space directly, with no `zoned` key. Flattening `base`
    /// keeps those snapshots loadable.
    #[test]
    fn legacy_snapshot_config_still_deserialises() {
        let legacy = serde_json::to_string(&VirtioBlockConfig {
            capacity: 0x1234,
            num_queues: 2,
            ..Default::default()
        })
        .unwrap();

        let state: BlkConfigState = serde_json::from_str(&legacy).unwrap();

        // Braces force a copy out of the packed struct.
        assert_eq!({ state.base.capacity }, 0x1234);
        assert_eq!({ state.base.num_queues }, 2);
        assert!(state.zoned.is_none());
    }

    #[test]
    fn non_zoned_config_state_round_trips() {
        let state = BlkConfigState {
            base: VirtioBlockConfig {
                capacity: 42,
                ..Default::default()
            },
            zoned: None,
        };

        let restored: BlkConfigState =
            serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();

        assert_eq!({ restored.base.capacity }, 42);
        assert!(restored.zoned.is_none());
    }

    #[test]
    fn zoned_config_state_round_trips() {
        let state = BlkConfigState {
            base: VirtioBlockConfig {
                capacity: 0x8000,
                ..Default::default()
            },
            zoned: Some(zoned_tail()),
        };

        let restored: BlkConfigState =
            serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();

        assert_eq!({ restored.base.capacity }, 0x8000);
        assert_eq!(restored.zoned.unwrap(), zoned_tail());
    }

    /// The base fields must stay at the top level of the serialised form, or a
    /// snapshot written by this build would not load into one that flattens.
    #[test]
    fn zoned_is_a_sibling_of_the_flattened_base_fields() {
        let json = serde_json::to_string(&BlkConfigState {
            base: VirtioBlockConfig::default(),
            zoned: Some(zoned_tail()),
        })
        .unwrap();

        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let map = value.as_object().unwrap();
        assert!(map.contains_key("capacity"));
        assert!(map.contains_key("zoned"));
    }
}

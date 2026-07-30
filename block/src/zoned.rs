// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Zoned block device (`VIRTIO_BLK_F_ZONED`) configuration-space support.
//!
//! # Why this lives outside [`crate::VirtioBlockConfig`]
//!
//! The virtio 1.2 specification places the zoned characteristics at the *end*
//! of the virtio-blk configuration space, after the secure-erase fields:
//!
//! ```text
//!  offset  size  field
//!  ------  ----  -------------------------------------------------
//!       0    60  base config (capacity .. write_zeroes_may_unmap)
//!      60    12  max_secure_erase_sectors / _seg / _sector_alignment
//!      72    24  zoned characteristics
//!  ------  ----
//!              96 total
//! ```
//!
//! Cloud Hypervisor's [`crate::VirtioBlockConfig`] covers only the first 60
//! bytes, and it is shared by the built-in file-backed block device, the
//! `vhost_user_block` backend, and the migration state of both. Growing that
//! struct would therefore:
//!
//! 1. change the length Cloud Hypervisor requests from *every* vhost-user-blk
//!    backend (the vhost-user `GET_CONFIG` reply must match the requested size
//!    exactly, so existing non-zoned backends would fail device init),
//! 2. grow the guest-visible config space of unrelated non-zoned devices, and
//! 3. perturb the on-disk snapshot format of the built-in block device.
//!
//! Instead the zoned tail is modelled separately here and concatenated onto the
//! base config only for devices that actually negotiated `VIRTIO_BLK_F_ZONED`.
//!
//! # Endianness
//!
//! Virtio configuration space is little-endian regardless of host byte order,
//! so this module serialises explicitly via `to_le_bytes`/`from_le_bytes`
//! rather than reinterpreting struct memory. This keeps the module free of
//! `unsafe` and correct on big-endian hosts.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use virtio_bindings::virtio_blk::{
    VIRTIO_BLK_F_ZONED, VIRTIO_BLK_Z_HA, VIRTIO_BLK_Z_HM, VIRTIO_BLK_Z_NONE,
};

/// Length of the base virtio-blk configuration space, i.e. the part covered by
/// [`crate::VirtioBlockConfig`].
pub const VIRTIO_BLK_CONFIG_BASE_LEN: usize = 60;

/// Length of the secure-erase fields that sit between the base config and the
/// zoned characteristics.
pub const VIRTIO_BLK_CONFIG_SECURE_ERASE_LEN: usize = 12;

/// Length of the `virtio_blk_zoned_characteristics` structure.
pub const VIRTIO_BLK_CONFIG_ZONED_LEN: usize = 24;

/// Length of the tail appended to the base config for a zoned device: the
/// secure-erase fields plus the zoned characteristics.
pub const VIRTIO_BLK_CONFIG_TAIL_LEN: usize =
    VIRTIO_BLK_CONFIG_SECURE_ERASE_LEN + VIRTIO_BLK_CONFIG_ZONED_LEN;

/// Total configuration-space length of a zoned virtio-blk device.
pub const VIRTIO_BLK_CONFIG_ZONED_TOTAL_LEN: usize =
    VIRTIO_BLK_CONFIG_BASE_LEN + VIRTIO_BLK_CONFIG_TAIL_LEN;

/// Offset of the `virtio_blk_zoned_characteristics` structure within the
/// configuration space.
pub const VIRTIO_BLK_CONFIG_ZONED_OFFSET: usize =
    VIRTIO_BLK_CONFIG_BASE_LEN + VIRTIO_BLK_CONFIG_SECURE_ERASE_LEN;

/// Errors that make a backend's zoned configuration unusable.
#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum ZonedError {
    /// The zoned tail returned by the backend was not the expected length.
    #[error("zoned config tail has wrong length: expected {expected} bytes, got {got}")]
    TailLength { expected: usize, got: usize },
    /// The backend reported a zoned model this build does not understand.
    ///
    /// Refused rather than downgraded: an unrecognised model may still require
    /// zone-aware access, and presenting such a disk to the guest as a regular
    /// block device could corrupt it.
    #[error(
        "backend reported unknown zoned model {0}; refusing to expose the device \
         rather than risk presenting a zone-managed disk as a regular one"
    )]
    UnknownModel(u8),
    /// A host-managed device reported a zone size of zero.
    #[error("host-managed zoned backend reported a zone size of zero sectors")]
    ZeroZoneSectors,
    /// A host-managed device reported a zone size that is not a power of two.
    ///
    /// The Linux virtio-blk driver rejects such a device, so this is caught
    /// here to produce a comprehensible error instead of an opaque guest-side
    /// probe failure.
    #[error("host-managed zoned backend reported a non-power-of-two zone size of {0} sectors")]
    UnalignedZoneSectors(u32),
    /// A host-managed device reported that zone append is unsupported.
    #[error("host-managed zoned backend reported zero max append sectors")]
    ZeroMaxAppendSectors,
    /// A host-managed device reported a write granularity of zero.
    #[error("host-managed zoned backend reported a write granularity of zero")]
    ZeroWriteGranularity,
    /// A zoned device is being restored onto a backend that is not zoned.
    #[error(
        "cannot restore a zoned virtio-blk device: the destination vhost-user backend \
         does not advertise VIRTIO_BLK_F_ZONED"
    )]
    RestoreBackendNotZoned,
}

/// Whether, and why, `VIRTIO_BLK_F_ZONED` should be exposed to the guest.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ZonedExposure {
    /// The backend is zoned; advertise `VIRTIO_BLK_F_ZONED` to the guest.
    Expose,
    /// The backend did not advertise `VIRTIO_BLK_F_ZONED`.
    NotAdvertised,
    /// The backend advertised `VIRTIO_BLK_F_ZONED` but reports the zoned model
    /// as `VIRTIO_BLK_Z_NONE`, i.e. it is capable of serving zoned disks but
    /// this particular disk is not one. Treated as a plain block device.
    ModelNone,
}

impl ZonedExposure {
    /// Whether `VIRTIO_BLK_F_ZONED` should be advertised to the guest.
    pub fn is_exposed(&self) -> bool {
        matches!(self, ZonedExposure::Expose)
    }
}

/// The tail of a zoned virtio-blk configuration space.
///
/// Carries the secure-erase fields as well as the zoned characteristics: Cloud
/// Hypervisor never negotiates `VIRTIO_BLK_F_SECURE_ERASE`, but those bytes
/// occupy the gap before the zoned section and are passed through from the
/// backend verbatim so that the zoned fields land at their specified offsets.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtioBlockZonedConfig {
    /// `max_secure_erase_sectors`; passed through, never negotiated.
    pub max_secure_erase_sectors: u32,
    /// `max_secure_erase_seg`; passed through, never negotiated.
    pub max_secure_erase_seg: u32,
    /// `secure_erase_sector_alignment`; passed through, never negotiated.
    pub secure_erase_sector_alignment: u32,
    /// Size of each zone, in 512-byte sectors.
    pub zone_sectors: u32,
    /// Maximum number of simultaneously open zones; zero means unlimited.
    pub max_open_zones: u32,
    /// Maximum number of simultaneously active zones; zero means unlimited.
    pub max_active_zones: u32,
    /// Maximum number of sectors a single zone-append request may write.
    pub max_append_sectors: u32,
    /// Write granularity, in bytes.
    pub write_granularity: u32,
    /// Zoned model: one of `VIRTIO_BLK_Z_NONE`, `_HM`, or `_HA`.
    pub model: u8,
}

/// Not a zoned disk. Legal even when the backend advertises
/// `VIRTIO_BLK_F_ZONED`: a backend able to serve zoned disks may still be
/// configured with a conventional one.
const MODEL_NONE: u8 = VIRTIO_BLK_Z_NONE as u8;
/// Host-managed: writes within a zone must be sequential, and the guest needs
/// the zone geometry to drive the disk at all.
const MODEL_HM: u8 = VIRTIO_BLK_Z_HM as u8;
/// Host-aware: accepts non-sequential writes, so it is safe to drive as a
/// conventional disk.
const MODEL_HA: u8 = VIRTIO_BLK_Z_HA as u8;

/// Field offsets within the configuration-space tail, i.e. relative to
/// [`VIRTIO_BLK_CONFIG_BASE_LEN`].
mod tail_offset {
    pub const MAX_SECURE_ERASE_SECTORS: usize = 0;
    pub const MAX_SECURE_ERASE_SEG: usize = 4;
    pub const SECURE_ERASE_SECTOR_ALIGNMENT: usize = 8;
    pub const ZONE_SECTORS: usize = 12;
    pub const MAX_OPEN_ZONES: usize = 16;
    pub const MAX_ACTIVE_ZONES: usize = 20;
    pub const MAX_APPEND_SECTORS: usize = 24;
    pub const WRITE_GRANULARITY: usize = 28;
    pub const MODEL: usize = 32;
    // Offsets 33..36 are `unused2` and must read as zero.
}

/// Read a little-endian `u32` at `offset`.
///
/// The caller must have already checked that `buf` is long enough; the copy
/// below panics only on a programming error in this module.
fn read_le_u32(buf: &[u8], offset: usize) -> u32 {
    let mut field = [0u8; 4];
    field.copy_from_slice(&buf[offset..offset + 4]);
    u32::from_le_bytes(field)
}

/// Write `value` as little-endian at `offset`.
fn write_le_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

impl VirtioBlockZonedConfig {
    /// Parse the configuration-space tail as returned by a vhost-user backend.
    ///
    /// `tail` must be exactly [`VIRTIO_BLK_CONFIG_TAIL_LEN`] bytes, i.e. the
    /// bytes at offset [`VIRTIO_BLK_CONFIG_BASE_LEN`] onwards.
    pub fn from_le_bytes(tail: &[u8]) -> Result<Self, ZonedError> {
        if tail.len() != VIRTIO_BLK_CONFIG_TAIL_LEN {
            return Err(ZonedError::TailLength {
                expected: VIRTIO_BLK_CONFIG_TAIL_LEN,
                got: tail.len(),
            });
        }

        Ok(Self {
            max_secure_erase_sectors: read_le_u32(tail, tail_offset::MAX_SECURE_ERASE_SECTORS),
            max_secure_erase_seg: read_le_u32(tail, tail_offset::MAX_SECURE_ERASE_SEG),
            secure_erase_sector_alignment: read_le_u32(
                tail,
                tail_offset::SECURE_ERASE_SECTOR_ALIGNMENT,
            ),
            zone_sectors: read_le_u32(tail, tail_offset::ZONE_SECTORS),
            max_open_zones: read_le_u32(tail, tail_offset::MAX_OPEN_ZONES),
            max_active_zones: read_le_u32(tail, tail_offset::MAX_ACTIVE_ZONES),
            max_append_sectors: read_le_u32(tail, tail_offset::MAX_APPEND_SECTORS),
            write_granularity: read_le_u32(tail, tail_offset::WRITE_GRANULARITY),
            model: tail[tail_offset::MODEL],
        })
    }

    /// Serialise to the little-endian configuration-space tail.
    pub fn to_le_bytes(&self) -> [u8; VIRTIO_BLK_CONFIG_TAIL_LEN] {
        let mut tail = [0u8; VIRTIO_BLK_CONFIG_TAIL_LEN];

        write_le_u32(
            &mut tail,
            tail_offset::MAX_SECURE_ERASE_SECTORS,
            self.max_secure_erase_sectors,
        );
        write_le_u32(
            &mut tail,
            tail_offset::MAX_SECURE_ERASE_SEG,
            self.max_secure_erase_seg,
        );
        write_le_u32(
            &mut tail,
            tail_offset::SECURE_ERASE_SECTOR_ALIGNMENT,
            self.secure_erase_sector_alignment,
        );
        write_le_u32(&mut tail, tail_offset::ZONE_SECTORS, self.zone_sectors);
        write_le_u32(&mut tail, tail_offset::MAX_OPEN_ZONES, self.max_open_zones);
        write_le_u32(
            &mut tail,
            tail_offset::MAX_ACTIVE_ZONES,
            self.max_active_zones,
        );
        write_le_u32(
            &mut tail,
            tail_offset::MAX_APPEND_SECTORS,
            self.max_append_sectors,
        );
        write_le_u32(
            &mut tail,
            tail_offset::WRITE_GRANULARITY,
            self.write_granularity,
        );
        tail[tail_offset::MODEL] = self.model;

        tail
    }

    /// Check that the reported characteristics describe a device the guest can
    /// actually drive, and report whether it should be exposed as zoned.
    ///
    /// Host-aware devices are accepted without geometry checks: the Linux
    /// driver presents them as regular block devices, so their zoned fields are
    /// advisory.
    pub fn validate(&self) -> Result<ZonedExposure, ZonedError> {
        match self.model {
            MODEL_NONE => Ok(ZonedExposure::ModelNone),
            // Host-aware disks accept ordinary writes anywhere, and the Linux
            // driver deliberately presents them as regular block devices, so
            // the geometry fields below are advisory and not worth failing on.
            MODEL_HA => Ok(ZonedExposure::Expose),
            MODEL_HM => {
                // A host-managed disk is only usable if the guest can derive a
                // zone layout from these fields. The Linux virtio-blk driver
                // refuses to probe a device that reports any of them as zero,
                // or a zone size that is not a power of two, so checking here
                // turns an opaque guest-side probe failure into a clear
                // VMM-side error naming the offending field.
                if self.zone_sectors == 0 {
                    return Err(ZonedError::ZeroZoneSectors);
                }
                if !self.zone_sectors.is_power_of_two() {
                    return Err(ZonedError::UnalignedZoneSectors(self.zone_sectors));
                }
                if self.max_append_sectors == 0 {
                    return Err(ZonedError::ZeroMaxAppendSectors);
                }
                if self.write_granularity == 0 {
                    return Err(ZonedError::ZeroWriteGranularity);
                }
                // max_open_zones and max_active_zones are unconstrained: zero
                // is the specified encoding for "no limit".
                Ok(ZonedExposure::Expose)
            }
            other => Err(ZonedError::UnknownModel(other)),
        }
    }
}

/// Whether `VIRTIO_BLK_F_ZONED` is set in `features`.
pub fn zoned_negotiated(_features: u64) -> bool {
    unimplemented!("implemented in a follow-up commit")
}

/// Length of configuration space to request from a vhost-user-blk backend.
///
/// Requesting the zoned length from a backend that is not zoned would fail, as
/// the vhost-user `GET_CONFIG` reply must match the requested size exactly.
pub fn config_space_len(_zoned: bool) -> usize {
    unimplemented!("implemented in a follow-up commit")
}

/// Strip `VIRTIO_BLK_F_ZONED` from the guest-facing feature set unless the
/// backend is actually serving a zoned disk.
pub fn gate_features(_avail_features: u64, _exposure: ZonedExposure) -> u64 {
    unimplemented!("implemented in a follow-up commit")
}

/// Reject a restore that would silently drop zoned semantics.
///
/// A guest that negotiated `VIRTIO_BLK_F_ZONED` before migration holds zone
/// state and issues zone-management commands; resuming it against a backend
/// that cannot serve them would fail in ways the guest cannot recover from, so
/// this fails the restore outright.
pub fn check_restore_compat(
    _state_avail_features: u64,
    _backend_features: u64,
) -> Result<(), ZonedError> {
    unimplemented!("implemented in a follow-up commit")
}

/// Concatenate the base configuration space with the zoned tail, if any.
///
/// Passing `None` yields the base configuration space unchanged, which is what
/// every non-zoned device continues to expose to the guest.
pub fn assemble_config_space(base: &[u8], tail: Option<&VirtioBlockZonedConfig>) -> Vec<u8> {
    let Some(tail) = tail else {
        return base.to_vec();
    };

    let mut config = Vec::with_capacity(base.len() + VIRTIO_BLK_CONFIG_TAIL_LEN);
    config.extend_from_slice(base);
    config.extend_from_slice(&tail.to_le_bytes());
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VirtioBlockConfig;

    /// A host-managed configuration that should pass validation.
    fn valid_hm() -> VirtioBlockZonedConfig {
        VirtioBlockZonedConfig {
            zone_sectors: 0x1_0000,
            max_open_zones: 32,
            max_active_zones: 64,
            max_append_sectors: 2048,
            write_granularity: 4096,
            model: VIRTIO_BLK_Z_HM as u8,
            ..Default::default()
        }
    }

    // ---------------------------------------------------------------------
    // Layout
    // ---------------------------------------------------------------------

    #[test]
    fn base_len_matches_virtio_block_config() {
        assert_eq!(VIRTIO_BLK_CONFIG_BASE_LEN, size_of::<VirtioBlockConfig>());
    }

    #[test]
    fn layout_constants_are_consistent() {
        assert_eq!(VIRTIO_BLK_CONFIG_TAIL_LEN, 36);
        assert_eq!(VIRTIO_BLK_CONFIG_ZONED_TOTAL_LEN, 96);
        assert_eq!(VIRTIO_BLK_CONFIG_ZONED_OFFSET, 72);
        assert_eq!(
            VIRTIO_BLK_CONFIG_ZONED_OFFSET + VIRTIO_BLK_CONFIG_ZONED_LEN,
            VIRTIO_BLK_CONFIG_ZONED_TOTAL_LEN
        );
    }

    #[test]
    fn to_le_bytes_places_fields_at_spec_offsets() {
        let cfg = VirtioBlockZonedConfig {
            max_secure_erase_sectors: 0x0403_0201,
            max_secure_erase_seg: 0x0807_0605,
            secure_erase_sector_alignment: 0x0c0b_0a09,
            zone_sectors: 0x100f_0e0d,
            max_open_zones: 0x1413_1211,
            max_active_zones: 0x1817_1615,
            max_append_sectors: 0x1c1b_1a19,
            write_granularity: 0x201f_1e1d,
            model: 0x21,
        };
        let bytes = cfg.to_le_bytes();

        // Little-endian, ascending, with no padding between fields.
        let expected: [u8; VIRTIO_BLK_CONFIG_TAIL_LEN] = [
            0x01, 0x02, 0x03, 0x04, // max_secure_erase_sectors
            0x05, 0x06, 0x07, 0x08, // max_secure_erase_seg
            0x09, 0x0a, 0x0b, 0x0c, // secure_erase_sector_alignment
            0x0d, 0x0e, 0x0f, 0x10, // zone_sectors
            0x11, 0x12, 0x13, 0x14, // max_open_zones
            0x15, 0x16, 0x17, 0x18, // max_active_zones
            0x19, 0x1a, 0x1b, 0x1c, // max_append_sectors
            0x1d, 0x1e, 0x1f, 0x20, // write_granularity
            0x21, // model
            0x00, 0x00, 0x00, // unused2
        ];
        assert_eq!(bytes, expected);
    }

    #[test]
    fn zoned_section_starts_at_offset_72_of_config_space() {
        let cfg = VirtioBlockZonedConfig {
            zone_sectors: 0xdead_beef,
            ..valid_hm()
        };
        let full = assemble_config_space(&[0u8; VIRTIO_BLK_CONFIG_BASE_LEN], Some(&cfg));

        let at_zoned = &full[VIRTIO_BLK_CONFIG_ZONED_OFFSET..VIRTIO_BLK_CONFIG_ZONED_OFFSET + 4];
        assert_eq!(at_zoned, 0xdead_beefu32.to_le_bytes());
    }

    #[test]
    fn model_lands_at_config_space_offset_92() {
        let cfg = VirtioBlockZonedConfig {
            model: VIRTIO_BLK_Z_HM as u8,
            ..valid_hm()
        };
        let full = assemble_config_space(&[0u8; VIRTIO_BLK_CONFIG_BASE_LEN], Some(&cfg));
        assert_eq!(full[92], VIRTIO_BLK_Z_HM as u8);
    }

    #[test]
    fn to_le_bytes_reserved_bytes_are_zero() {
        let bytes = valid_hm().to_le_bytes();
        assert_eq!(&bytes[33..36], &[0, 0, 0]);
    }

    #[test]
    fn byte_round_trip_is_lossless() {
        let cfg = VirtioBlockZonedConfig {
            max_secure_erase_sectors: 1,
            max_secure_erase_seg: 2,
            secure_erase_sector_alignment: 3,
            zone_sectors: 0x8000,
            max_open_zones: 5,
            max_active_zones: 6,
            max_append_sectors: 7,
            write_granularity: 8,
            model: VIRTIO_BLK_Z_HA as u8,
        };
        let parsed = VirtioBlockZonedConfig::from_le_bytes(&cfg.to_le_bytes()).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn from_le_bytes_decodes_little_endian() {
        let mut tail = [0u8; VIRTIO_BLK_CONFIG_TAIL_LEN];
        // zone_sectors is at tail offset 12.
        tail[12..16].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        tail[32] = VIRTIO_BLK_Z_HM as u8;

        let cfg = VirtioBlockZonedConfig::from_le_bytes(&tail).unwrap();
        assert_eq!(cfg.zone_sectors, 0x1234_5678);
        assert_eq!(cfg.model, VIRTIO_BLK_Z_HM as u8);
    }

    #[test]
    fn from_le_bytes_ignores_reserved_bytes() {
        let mut tail = valid_hm().to_le_bytes();
        tail[33..36].copy_from_slice(&[0xff, 0xff, 0xff]);
        assert_eq!(
            VirtioBlockZonedConfig::from_le_bytes(&tail).unwrap(),
            valid_hm()
        );
    }

    #[test]
    fn from_le_bytes_rejects_short_input() {
        let err = VirtioBlockZonedConfig::from_le_bytes(&[0u8; 35]).unwrap_err();
        assert_eq!(
            err,
            ZonedError::TailLength {
                expected: VIRTIO_BLK_CONFIG_TAIL_LEN,
                got: 35,
            }
        );
    }

    #[test]
    fn from_le_bytes_rejects_long_input() {
        let err = VirtioBlockZonedConfig::from_le_bytes(&[0u8; 37]).unwrap_err();
        assert_eq!(
            err,
            ZonedError::TailLength {
                expected: VIRTIO_BLK_CONFIG_TAIL_LEN,
                got: 37,
            }
        );
    }

    #[test]
    fn from_le_bytes_rejects_empty_input() {
        VirtioBlockZonedConfig::from_le_bytes(&[]).unwrap_err();
    }

    // ---------------------------------------------------------------------
    // Validation
    // ---------------------------------------------------------------------

    #[test]
    fn host_managed_valid_config_is_exposed() {
        assert_eq!(valid_hm().validate().unwrap(), ZonedExposure::Expose);
    }

    #[test]
    fn host_managed_rejects_zero_zone_sectors() {
        let cfg = VirtioBlockZonedConfig {
            zone_sectors: 0,
            ..valid_hm()
        };
        assert_eq!(cfg.validate().unwrap_err(), ZonedError::ZeroZoneSectors);
    }

    #[test]
    fn host_managed_rejects_non_power_of_two_zone_sectors() {
        let cfg = VirtioBlockZonedConfig {
            zone_sectors: 0x1_0001,
            ..valid_hm()
        };
        assert_eq!(
            cfg.validate().unwrap_err(),
            ZonedError::UnalignedZoneSectors(0x1_0001)
        );
    }

    #[test]
    fn host_managed_accepts_minimal_power_of_two_zone_size() {
        let cfg = VirtioBlockZonedConfig {
            zone_sectors: 1,
            ..valid_hm()
        };
        assert_eq!(cfg.validate().unwrap(), ZonedExposure::Expose);
    }

    #[test]
    fn host_managed_rejects_zero_max_append_sectors() {
        let cfg = VirtioBlockZonedConfig {
            max_append_sectors: 0,
            ..valid_hm()
        };
        assert_eq!(
            cfg.validate().unwrap_err(),
            ZonedError::ZeroMaxAppendSectors
        );
    }

    #[test]
    fn host_managed_rejects_zero_write_granularity() {
        let cfg = VirtioBlockZonedConfig {
            write_granularity: 0,
            ..valid_hm()
        };
        assert_eq!(
            cfg.validate().unwrap_err(),
            ZonedError::ZeroWriteGranularity
        );
    }

    #[test]
    fn host_managed_allows_unlimited_open_and_active_zones() {
        let cfg = VirtioBlockZonedConfig {
            max_open_zones: 0,
            max_active_zones: 0,
            ..valid_hm()
        };
        assert_eq!(cfg.validate().unwrap(), ZonedExposure::Expose);
    }

    #[test]
    fn host_aware_skips_geometry_checks() {
        // The Linux driver presents host-aware devices as regular block
        // devices, so nonsensical geometry must not fail the device.
        let cfg = VirtioBlockZonedConfig {
            zone_sectors: 0,
            max_append_sectors: 0,
            write_granularity: 0,
            model: VIRTIO_BLK_Z_HA as u8,
            ..Default::default()
        };
        assert_eq!(cfg.validate().unwrap(), ZonedExposure::Expose);
    }

    #[test]
    fn model_none_is_not_exposed() {
        let cfg = VirtioBlockZonedConfig {
            model: VIRTIO_BLK_Z_NONE as u8,
            ..valid_hm()
        };
        assert_eq!(cfg.validate().unwrap(), ZonedExposure::ModelNone);
    }

    #[test]
    fn unknown_model_is_rejected() {
        let cfg = VirtioBlockZonedConfig {
            model: 3,
            ..valid_hm()
        };
        assert_eq!(cfg.validate().unwrap_err(), ZonedError::UnknownModel(3));
    }

    // ---------------------------------------------------------------------
    // Feature gating
    // ---------------------------------------------------------------------

    #[test]
    #[ignore = "not yet implemented"]
    fn zoned_negotiated_detects_the_bit() {
        assert!(zoned_negotiated(1u64 << VIRTIO_BLK_F_ZONED));
        assert!(!zoned_negotiated(0));
        assert!(!zoned_negotiated(!(1u64 << VIRTIO_BLK_F_ZONED)));
    }

    #[test]
    #[ignore = "not yet implemented"]
    fn config_space_len_depends_on_zoned() {
        assert_eq!(config_space_len(false), VIRTIO_BLK_CONFIG_BASE_LEN);
        assert_eq!(config_space_len(true), VIRTIO_BLK_CONFIG_ZONED_TOTAL_LEN);
    }

    #[test]
    #[ignore = "not yet implemented"]
    fn gate_features_keeps_bit_when_exposed() {
        let features = 1u64 << VIRTIO_BLK_F_ZONED;
        assert_eq!(
            gate_features(features, ZonedExposure::Expose),
            1u64 << VIRTIO_BLK_F_ZONED
        );
    }

    #[test]
    #[ignore = "not yet implemented"]
    fn gate_features_strips_bit_when_not_advertised() {
        let features = 1u64 << VIRTIO_BLK_F_ZONED;
        assert_eq!(gate_features(features, ZonedExposure::NotAdvertised), 0);
    }

    #[test]
    #[ignore = "not yet implemented"]
    fn gate_features_strips_bit_for_model_none() {
        let features = 1u64 << VIRTIO_BLK_F_ZONED;
        assert_eq!(gate_features(features, ZonedExposure::ModelNone), 0);
    }

    #[test]
    #[ignore = "not yet implemented"]
    fn gate_features_leaves_other_bits_untouched() {
        let others = !(1u64 << VIRTIO_BLK_F_ZONED);
        assert_eq!(gate_features(others, ZonedExposure::NotAdvertised), others);
        assert_eq!(gate_features(others, ZonedExposure::ModelNone), others);
        assert_eq!(gate_features(others, ZonedExposure::Expose), others);
    }

    #[test]
    #[ignore = "not yet implemented"]
    fn gate_features_is_idempotent() {
        let features = 1u64 << VIRTIO_BLK_F_ZONED;
        let once = gate_features(features, ZonedExposure::NotAdvertised);
        assert_eq!(gate_features(once, ZonedExposure::NotAdvertised), once);
    }

    #[test]
    fn exposure_is_exposed_only_for_expose() {
        assert!(ZonedExposure::Expose.is_exposed());
        assert!(!ZonedExposure::NotAdvertised.is_exposed());
        assert!(!ZonedExposure::ModelNone.is_exposed());
    }

    // ---------------------------------------------------------------------
    // Restore compatibility
    // ---------------------------------------------------------------------

    #[test]
    #[ignore = "not yet implemented"]
    fn restore_non_zoned_onto_non_zoned_backend_is_allowed() {
        check_restore_compat(0, 0).unwrap();
    }

    #[test]
    #[ignore = "not yet implemented"]
    fn restore_non_zoned_onto_zoned_backend_is_allowed() {
        check_restore_compat(0, 1u64 << VIRTIO_BLK_F_ZONED).unwrap();
    }

    #[test]
    #[ignore = "not yet implemented"]
    fn restore_zoned_onto_zoned_backend_is_allowed() {
        let zoned = 1u64 << VIRTIO_BLK_F_ZONED;
        check_restore_compat(zoned, zoned).unwrap();
    }

    #[test]
    #[ignore = "not yet implemented"]
    fn restore_zoned_onto_non_zoned_backend_is_rejected() {
        let err = check_restore_compat(1u64 << VIRTIO_BLK_F_ZONED, 0).unwrap_err();
        assert_eq!(err, ZonedError::RestoreBackendNotZoned);
    }

    #[test]
    #[ignore = "not yet implemented"]
    fn restore_compat_ignores_unrelated_features() {
        let unrelated = 0xffu64;
        check_restore_compat(unrelated, 0).unwrap();
    }

    // ---------------------------------------------------------------------
    // Config-space assembly
    // ---------------------------------------------------------------------

    #[test]
    fn assemble_without_tail_returns_base_unchanged() {
        let base: Vec<u8> = (0..VIRTIO_BLK_CONFIG_BASE_LEN as u8).collect();
        let out = assemble_config_space(&base, None);
        assert_eq!(out, base);
        assert_eq!(out.len(), VIRTIO_BLK_CONFIG_BASE_LEN);
    }

    #[test]
    fn assemble_with_tail_produces_full_zoned_length() {
        let base = vec![0u8; VIRTIO_BLK_CONFIG_BASE_LEN];
        let out = assemble_config_space(&base, Some(&valid_hm()));
        assert_eq!(out.len(), VIRTIO_BLK_CONFIG_ZONED_TOTAL_LEN);
    }

    #[test]
    fn assemble_preserves_base_bytes() {
        let base: Vec<u8> = (0..VIRTIO_BLK_CONFIG_BASE_LEN as u8).collect();
        let out = assemble_config_space(&base, Some(&valid_hm()));
        assert_eq!(&out[..VIRTIO_BLK_CONFIG_BASE_LEN], &base[..]);
    }

    #[test]
    fn assemble_appends_tail_verbatim() {
        let cfg = valid_hm();
        let out = assemble_config_space(&[0u8; VIRTIO_BLK_CONFIG_BASE_LEN], Some(&cfg));
        assert_eq!(&out[VIRTIO_BLK_CONFIG_BASE_LEN..], &cfg.to_le_bytes()[..]);
    }

    #[test]
    fn assemble_passes_secure_erase_fields_through() {
        let cfg = VirtioBlockZonedConfig {
            max_secure_erase_sectors: 0xaabb_ccdd,
            ..valid_hm()
        };
        let out = assemble_config_space(&[0u8; VIRTIO_BLK_CONFIG_BASE_LEN], Some(&cfg));
        assert_eq!(
            &out[VIRTIO_BLK_CONFIG_BASE_LEN..VIRTIO_BLK_CONFIG_BASE_LEN + 4],
            0xaabb_ccddu32.to_le_bytes()
        );
    }
}

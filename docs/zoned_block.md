# Zoned block devices (`VIRTIO_BLK_F_ZONED`)

Cloud Hypervisor can expose a zoned virtio-blk device to the guest when the
storage is provided by a **vhost-user-blk backend**. Zoned support is not
available for the built-in file-backed block device (`--disk path=...`), which
always presents a conventional disk.

## Enabling it

There is no command-line option to turn zoned support on. It is negotiated, and
Cloud Hypervisor only advertises `VIRTIO_BLK_F_ZONED` to the guest when the
backend both advertises the feature *and* reports an actually zoned disk:

1. Cloud Hypervisor offers `VIRTIO_BLK_F_ZONED` to every vhost-user-blk backend.
   Normal feature negotiation clears it again for backends that do not support
   it, so this is transparent to existing backends.
2. Only if the backend acked the feature does Cloud Hypervisor request the
   longer, zoned configuration space (96 bytes instead of 60). This second step
   is conditional on purpose: a vhost-user `GET_CONFIG` reply must match the
   requested length exactly, so asking every backend for the zoned layout would
   break backends that serve only the base configuration space.
3. The reported zoned characteristics are validated (see below). If the backend
   reports a zoned model of `NONE` — a backend that *can* serve zoned disks but
   is configured with a conventional one — the feature is withheld from the
   guest and the disk is presented as a normal block device.

So a device is zoned exactly when the backend says it is. Configuring a
vhost-user-blk backend against a zoned namespace is all that is required.

## Backend requirements

For a **host-managed** (`VIRTIO_BLK_Z_HM`) disk, the backend must report:

| Field | Requirement |
| --- | --- |
| `zone_sectors` | Non-zero and a power of two |
| `max_append_sectors` | Non-zero |
| `write_granularity` | Non-zero |
| `max_open_zones`, `max_active_zones` | Any value; zero means "no limit" |

These mirror what the Linux virtio-blk driver itself demands, so a backend that
violates them would fail to probe in the guest anyway. Cloud Hypervisor rejects
the device at startup instead, with an error naming the offending field.

**Host-aware** (`VIRTIO_BLK_Z_HA`) disks are accepted without those checks. The
Linux driver deliberately presents host-aware disks as conventional block
devices, so their geometry fields are advisory.

A zoned model that this build does not recognise is rejected rather than
downgraded, because such a disk may still require zone-aware access and
presenting it to the guest as conventional could corrupt it.

## Guest requirements

The guest kernel needs virtio-blk zoned support, which landed in Linux 6.2.
Older guests will not see the zoned characteristics even when the device
advertises them.

## Live migration and reconnection

**Zone write pointers live in the backend, not in Cloud Hypervisor.** Cloud
Hypervisor tracks no per-zone state of its own: the position of each zone's
write pointer, and which zones are open or active, are known only to the
backend. This has two consequences.

* **Migration.** Migrating a VM with a zoned device only preserves zone state if
  the backend participates in state transfer via
  `VHOST_USER_PROTOCOL_F_DEVICE_STATE`. If the destination backend starts from a
  different zone state than the source left behind, the guest's cached view of
  the write pointers will be stale, and subsequent writes can fail with unaligned
  write-pointer errors. Preserving zone state across a migration is the
  backend's responsibility.

* **Restore onto a non-zoned backend fails.** Restoring a snapshot whose guest
  had negotiated `VIRTIO_BLK_F_ZONED` onto a backend that does not advertise the
  feature is refused outright. A negotiated feature cannot be withdrawn from a
  running guest, and such a guest would keep issuing zone-management commands the
  backend could not serve.

* **Reconnection.** If a backend disconnects and reconnects while the guest is
  driving zones, the reconnected backend must still advertise
  `VIRTIO_BLK_F_ZONED`; the reconnect fails if it does not. Note that
  reconnection does not by itself resynchronise zone write pointers, which is
  again up to the backend.

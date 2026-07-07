// Copyright 2026 Cloud Hypervisor Contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The bounce data-plane worker: a per-device thread that sits between
//! the guest and the vhost-user backend when bouncing is enabled.
//!
//! On a guest kick it mirrors newly available descriptor chains into the
//! pool shadow ring and kicks the backend; on a backend call it copies
//! completed data back to guest memory, injects the guest interrupt, and
//! retries any queues that were stalled for pool space. On pause it
//! drains outstanding completions so the device parks with guest memory
//! consistent (see `docs/vhost-user-bounce-plan.md` §2.5-2.6).

use std::os::unix::io::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use log::error;
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic};
use vmm_sys_util::eventfd::EventFd;

use super::BounceQueueFds;
use super::pool::BouncePool;
use super::shadow_queue::ShadowQueue;
use crate::{
    EPOLL_HELPER_EVENT_LAST, EpollHelper, EpollHelperError, EpollHelperHandler, GuestMemoryMmap,
    VirtioInterrupt, VirtioInterruptType,
};

/// Maximum time the worker waits for the backend to drain outstanding
/// completions during a pause before giving up (a wedged backend must
/// not block pause forever; the resulting non-empty in-flight state is
/// caught when snapshotting).
pub const BOUNCE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Pool plus the per-queue shadow state, behind one mutex so the worker
/// loop and (later) the reconnect path never lock them in a conflicting
/// order.
pub struct BounceShared {
    pub pool: BouncePool,
    pub shadow: Vec<ShadowQueue>,
}

/// Per-device bounce data-plane worker.
pub struct BounceEpollHandler {
    pub shared: Arc<Mutex<BounceShared>>,
    pub guest_mem: GuestMemoryAtomic<GuestMemoryMmap>,
    /// Guest queues with their kick (ioeventfd) eventfds, indexed like
    /// `shared.shadow` and `fds`.
    pub queues: Vec<(usize, virtio_queue::Queue, EventFd)>,
    pub fds: Vec<BounceQueueFds>,
    pub interrupt: Arc<dyn VirtioInterrupt>,
    pub kill_evt: EventFd,
    pub pause_evt: EventFd,
    pub drain_timeout: Duration,
}

/// First epoll token used by the worker for its per-queue events.
const QUEUE_EVENT_BASE: u16 = EPOLL_HELPER_EVENT_LAST + 1;

/// Epoll token for the guest kick eventfd of queue `i`.
fn guest_kick_token(i: usize) -> u16 {
    QUEUE_EVENT_BASE + 2 * i as u16
}

/// Epoll token for the backend call eventfd of queue `i`.
fn backend_call_token(i: usize) -> u16 {
    QUEUE_EVENT_BASE + 2 * i as u16 + 1
}

impl BounceEpollHandler {
    /// Register the per-queue eventfds and run the epoll loop until the
    /// device is killed.
    pub fn run(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
    ) -> Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        for i in 0..self.queues.len() {
            helper.add_event(self.queues[i].2.as_raw_fd(), guest_kick_token(i))?;
            helper.add_event(self.fds[i].shadow_call.as_raw_fd(), backend_call_token(i))?;
        }
        // On startup, mirror anything already available (e.g. entries
        // published across a snapshot/restore, or a kick lost before the
        // worker registered its eventfd).
        self.initial_sweep();
        helper.run(paused, paused_sync, self)?;
        Ok(())
    }

    /// Mirror every queue's currently-available chains once, kicking the
    /// backend where progress was made.
    fn initial_sweep(&mut self) {
        for i in 0..self.queues.len() {
            self.mirror_and_kick(i);
        }
    }

    /// Handle a guest kick on queue `i`: drain the eventfd, mirror new
    /// chains, and kick the backend if any were published.
    fn on_guest_kick(&mut self, i: usize) {
        let _ = self.queues[i].2.read();
        self.mirror_and_kick(i);
    }

    /// Handle a backend call on queue `i`: drain the eventfd, copy
    /// completions back to the guest and interrupt it, then retry every
    /// queue now that pool space may have been freed (mirroring an idle
    /// queue is cheap and only kicks the backend if it publishes work).
    fn on_backend_call(&mut self, i: usize) {
        let _ = self.fds[i].shadow_call.read();
        self.complete_and_interrupt(i);
        for q in 0..self.queues.len() {
            self.mirror_and_kick(q);
        }
    }

    /// Mirror newly available chains of queue `i` into the shadow ring
    /// and kick the backend if anything was published.
    fn mirror_and_kick(&mut self, i: usize) {
        let mem = self.guest_mem.memory();
        let mut guard = self.shared.lock().unwrap();
        let BounceShared { pool, shadow } = &mut *guard;
        let outcome = shadow[i].mirror_avail(&mem, &mut self.queues[i].1, pool);
        drop(guard);
        if outcome.chains > 0 {
            let _ = self.fds[i].shadow_kick.write(1);
        }
    }

    /// Copy queue `i`'s completions back to guest memory and interrupt
    /// the guest if it wants one. Returns the number of chains completed.
    fn complete_and_interrupt(&mut self, i: usize) -> usize {
        let mem = self.guest_mem.memory();
        let mut guard = self.shared.lock().unwrap();
        let BounceShared { pool, shadow } = &mut *guard;
        let outcome = shadow[i].complete_used(&mem, &mut self.queues[i].1, pool);
        drop(guard);
        if outcome.needs_interrupt {
            let qidx = self.queues[i].0 as u16;
            let _ = self.interrupt.trigger(VirtioInterruptType::Queue(qidx));
        }
        outcome.chains
    }
}

impl EpollHelperHandler for BounceEpollHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> Result<(), EpollHelperError> {
        let token = event.data as u16;
        let rel = token.wrapping_sub(QUEUE_EVENT_BASE);
        let i = (rel / 2) as usize;
        if i < self.queues.len() {
            if rel.is_multiple_of(2) {
                self.on_guest_kick(i);
            } else {
                self.on_backend_call(i);
            }
        }
        Ok(())
    }

    fn on_pause(&mut self, _helper: &mut EpollHelper) {
        // Drain outstanding completions back to guest memory so the
        // device parks consistent. The backend's vrings were already
        // disabled by VhostUserCommon::pause, so the in-flight set only
        // shrinks from here.
        let deadline = Instant::now() + self.drain_timeout;
        loop {
            for i in 0..self.queues.len() {
                let _ = self.fds[i].shadow_call.read();
                self.complete_and_interrupt(i);
            }
            let inflight: usize = {
                let guard = self.shared.lock().unwrap();
                guard.shadow.iter().map(|s| s.inflight_count()).sum()
            };
            if inflight == 0 {
                break;
            }
            if Instant::now() >= deadline {
                error!(
                    "vhost-user bounce pause drain timed out with {inflight} request(s) \
                     still in flight; a snapshot taken now will be rejected"
                );
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::thread;

    use super::super::pool::PoolLayout;
    use super::super::shadow_queue::ShadowQueueConfig;
    use super::super::test_utils::*;
    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(5);

    /// A running worker plus everything a test needs to play guest and
    /// backend against it.
    struct WorkerHarness {
        mem: GuestMemoryMmap,
        rings: Vec<GuestRingBuilder>,
        guest_kicks: Vec<EventFd>,
        shared: Arc<Mutex<BounceShared>>,
        pool_fds: Vec<BounceQueueFds>,
        daemon: FakeDaemon,
        interrupt: Arc<TestInterrupt>,
        kill_evt: EventFd,
        pause_evt: EventFd,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
        handle: Option<thread::JoinHandle<()>>,
    }

    fn build(num_queues: usize, queue_size: u16, arena: u64) -> WorkerHarness {
        let mem = guest_mem();
        let pool = BouncePool::new(&PoolLayout {
            num_queues,
            queue_size,
            buffer_capacity: arena,
        })
        .unwrap();
        let mut rings = Vec::new();
        let mut shadow = Vec::new();
        for i in 0..num_queues {
            rings.push(GuestRingBuilder::new_at(queue_size, (i as u64) * 0x80000));
            shadow.push(ShadowQueue::new(
                ShadowQueueConfig {
                    queue_index: i,
                    queue_size,
                },
                pool.ring_offsets(i),
            ));
        }
        let guest_kicks: Vec<EventFd> = (0..num_queues)
            .map(|_| EventFd::new(libc::EFD_NONBLOCK).unwrap())
            .collect();
        let pool_fds: Vec<BounceQueueFds> = (0..num_queues)
            .map(|_| BounceQueueFds::new().unwrap())
            .collect();
        WorkerHarness {
            mem,
            rings,
            guest_kicks,
            shared: Arc::new(Mutex::new(BounceShared { pool, shadow })),
            pool_fds,
            daemon: FakeDaemon::new(num_queues, queue_size),
            interrupt: TestInterrupt::new(num_queues),
            kill_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            pause_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            paused: Arc::new(AtomicBool::new(false)),
            paused_sync: Arc::new(Barrier::new(2)),
            handle: None,
        }
    }

    impl WorkerHarness {
        fn start(&mut self) {
            let queues: Vec<(usize, virtio_queue::Queue, EventFd)> = (0..self.rings.len())
                .map(|i| {
                    (
                        i,
                        self.rings[i].queue(),
                        self.guest_kicks[i].try_clone().unwrap(),
                    )
                })
                .collect();
            let fds: Vec<BounceQueueFds> = self
                .pool_fds
                .iter()
                .map(|f| BounceQueueFds {
                    shadow_kick: f.shadow_kick.try_clone().unwrap(),
                    shadow_call: f.shadow_call.try_clone().unwrap(),
                })
                .collect();
            let mut handler = BounceEpollHandler {
                shared: self.shared.clone(),
                guest_mem: GuestMemoryAtomic::new(self.mem.clone()),
                queues,
                fds,
                interrupt: self.interrupt.clone(),
                kill_evt: self.kill_evt.try_clone().unwrap(),
                pause_evt: self.pause_evt.try_clone().unwrap(),
                drain_timeout: TIMEOUT,
            };
            let paused = self.paused.clone();
            let paused_sync = self.paused_sync.clone();
            self.handle = Some(thread::spawn(move || {
                handler.run(&paused, &paused_sync).unwrap();
            }));
        }

        fn kick_guest(&self, q: usize) {
            self.guest_kicks[q].write(1).unwrap();
        }

        /// Wait for the backend to be kicked on queue `q`.
        fn wait_backend_kick(&self, q: usize) -> bool {
            wait_readable(self.pool_fds[q].shadow_kick.as_raw_fd(), TIMEOUT)
        }

        fn signal_backend_call(&self, q: usize) {
            self.pool_fds[q].shadow_call.write(1).unwrap();
        }

        fn stop(&mut self) {
            self.kill_evt.write(1).unwrap();
            if let Some(h) = self.handle.take() {
                h.join().unwrap();
            }
        }
    }

    #[test]
    fn guest_kick_mirrors_and_kicks_daemon() {
        let mut h = build(1, 8, 8192);
        h.start();
        let buf = h.rings[0].alloc_buf(64);
        fill_guest(&h.mem, buf, 64, 0x5a);
        let head = h.rings[0].chain(&h.mem, &[(buf, 64, false)]);
        h.rings[0].publish(&h.mem, head);
        h.kick_guest(0);

        assert!(h.wait_backend_kick(0), "backend was not kicked");
        {
            let guard = h.shared.lock().unwrap();
            let shadow_head = h.daemon.pop_avail(&guard.pool, 0);
            let chain = h.daemon.read_chain(&guard.pool, 0, shadow_head);
            assert_eq!(chain.len(), 1);
        }
        h.stop();
    }

    #[test]
    fn daemon_call_copies_back_and_interrupts() {
        let mut h = build(1, 8, 8192);
        h.start();
        let resp = h.rings[0].alloc_buf(128);
        let head = h.rings[0].chain(&h.mem, &[(resp, 128, true)]);
        h.rings[0].publish(&h.mem, head);
        h.kick_guest(0);
        assert!(h.wait_backend_kick(0));

        {
            let mut guard = h.shared.lock().unwrap();
            let pool = &mut guard.pool;
            h.daemon.serve_one(pool, 0, 0x77);
        }
        h.signal_backend_call(0);
        assert!(h.interrupt.wait_interrupt(0, TIMEOUT), "no guest interrupt");
        assert_eq!(read_guest(&h.mem, resp, 128), vec![0x77; 128]);
        assert_eq!(h.rings[0].used_idx(&h.mem), 1);
        h.stop();
    }

    #[test]
    fn end_to_end_echo_roundtrip() {
        let mut h = build(1, 8, 8192);
        h.start();
        let (req, resp) = (h.rings[0].alloc_buf(64), h.rings[0].alloc_buf(64));
        fill_guest(&h.mem, req, 64, 0x42);
        let head = h.rings[0].chain(&h.mem, &[(req, 64, false), (resp, 64, true)]);
        h.rings[0].publish(&h.mem, head);
        h.kick_guest(0);
        assert!(h.wait_backend_kick(0));

        // The backend echoes the request bytes into the response buffer.
        {
            let mut guard = h.shared.lock().unwrap();
            let pool = &mut guard.pool;
            let shadow_head = h.daemon.pop_avail(pool, 0);
            let chain = h.daemon.read_chain(pool, 0, shadow_head);
            let src = chain[0].addr();
            let dst = chain[1].addr();
            let mut b = vec![0u8; 64];
            use vm_memory::Bytes;
            pool.mem().read_slice(&mut b, src).unwrap();
            pool.mem().write_slice(&b, dst).unwrap();
            h.daemon.complete(pool, 0, shadow_head, 64);
        }
        h.signal_backend_call(0);
        assert!(h.interrupt.wait_interrupt(0, TIMEOUT));
        assert_eq!(read_guest(&h.mem, resp, 64), vec![0x42; 64]);
        h.stop();
    }

    #[test]
    fn completion_retries_stalled_queue_across_queue_boundary() {
        // Queue 0 fills the arena, queue 1 stalls; completing queue 0
        // must let the worker mirror queue 1 without a fresh guest kick.
        let mut h = build(2, 8, 256);
        h.start();
        let a = h.rings[0].alloc_buf(256);
        let head0 = h.rings[0].chain(&h.mem, &[(a, 256, true)]);
        h.rings[0].publish(&h.mem, head0);
        h.kick_guest(0);
        assert!(h.wait_backend_kick(0));

        let b = h.rings[1].alloc_buf(128);
        let head1 = h.rings[1].chain(&h.mem, &[(b, 128, true)]);
        h.rings[1].publish(&h.mem, head1);
        h.kick_guest(1);
        // Queue 1 stalls: no backend kick expected yet.
        assert!(!h.wait_backend_kick(1));

        // Complete queue 0; the freed space unblocks queue 1.
        {
            let guard = h.shared.lock().unwrap();
            h.daemon.serve_one(&guard.pool, 0, 1);
        }
        h.signal_backend_call(0);
        assert!(
            h.wait_backend_kick(1),
            "queue 1 not retried after completion"
        );
        h.stop();
    }

    #[test]
    fn pause_drains_pending_completions_before_barrier() {
        let mut h = build(1, 8, 8192);
        h.start();
        let resp = h.rings[0].alloc_buf(64);
        let head = h.rings[0].chain(&h.mem, &[(resp, 64, true)]);
        h.rings[0].publish(&h.mem, head);
        h.kick_guest(0);
        assert!(h.wait_backend_kick(0));

        // Backend completes but the worker is NOT signalled via the call
        // eventfd; the pause drain must still flush it.
        {
            let guard = h.shared.lock().unwrap();
            h.daemon.serve_one(&guard.pool, 0, 0x88);
        }
        h.paused.store(true, Ordering::SeqCst);
        h.pause_evt.write(1).unwrap();
        h.paused_sync.wait();
        assert_eq!(read_guest(&h.mem, resp, 64), vec![0x88; 64]);
        assert_eq!(h.rings[0].used_idx(&h.mem), 1);

        h.paused.store(false, Ordering::SeqCst);
        h.handle.as_ref().unwrap().thread().unpark();
        h.stop();
    }

    #[test]
    fn kill_event_terminates_worker_promptly() {
        let mut h = build(1, 8, 8192);
        h.start();
        // No traffic; killing must return promptly.
        h.stop();
    }

    #[test]
    fn worker_initial_sweep_mirrors_preexisting_avail_entries() {
        // Publish before the worker starts and never kick: the startup
        // sweep must still mirror the entry.
        let mut h = build(1, 8, 8192);
        let buf = h.rings[0].alloc_buf(64);
        let head = h.rings[0].chain(&h.mem, &[(buf, 64, false)]);
        h.rings[0].publish(&h.mem, head);
        h.start();
        assert!(h.wait_backend_kick(0), "initial sweep did not mirror");
        h.stop();
    }

    #[test]
    fn two_queues_route_events_independently() {
        let mut h = build(2, 8, 8192);
        h.start();
        for q in 0..2 {
            let buf = h.rings[q].alloc_buf(64);
            let head = h.rings[q].chain(&h.mem, &[(buf, 64, false)]);
            h.rings[q].publish(&h.mem, head);
            h.kick_guest(q);
            assert!(h.wait_backend_kick(q), "queue {q} not kicked");
        }
        h.stop();
    }
}

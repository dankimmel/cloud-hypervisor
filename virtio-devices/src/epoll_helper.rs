// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{io, result, thread};

use log::debug;
use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;

pub struct EpollHelper {
    pause_evt: EventFd,
    epoll_file: File,
}

#[derive(Error, Debug)]
pub enum EpollHelperError {
    #[error("Failed to create Fd")]
    CreateFd(#[source] io::Error),
    #[error("Failed to epoll_ctl")]
    Ctl(#[source] io::Error),
    #[error("IO error")]
    IoError(#[source] io::Error),
    #[error("Failed to epoll_wait")]
    Wait(#[source] io::Error),
    #[error("Failed to get virtio-queue index")]
    QueueRingIndex(#[source] virtio_queue::Error),
    #[error("Failed to handle virtio device events")]
    HandleEvent(#[source] anyhow::Error),
    #[error("Failed to handle timeout")]
    HandleTimeout(#[source] anyhow::Error),
}

pub const EPOLL_HELPER_EVENT_PAUSE: u16 = 0;
pub const EPOLL_HELPER_EVENT_KILL: u16 = 1;
pub const EPOLL_HELPER_EVENT_LAST: u16 = 15;

pub trait EpollHelperHandler {
    // Handle one event at a time. The EpollHelper iterates over a list of
    // events that have been returned by epoll_wait(). For each event, the
    // current method is invoked to let the implementation decide how to process
    // the incoming event.
    fn handle_event(
        &mut self,
        helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> Result<(), EpollHelperError>;

    // This method is only invoked if the EpollHelper was configured to call
    // epoll_wait() with a valid timeout (different from -1), meaning the call
    // won't block forever. When the timeout is reached, and if no even has been
    // triggered, this function will be called to let the implementation decide
    // how to interpret such situation. By default, it provides a no-op
    // implementation.
    fn handle_timeout(&mut self, _helper: &mut EpollHelper) -> Result<(), EpollHelperError> {
        Ok(())
    }

    // Invoked when a pause event is observed, before the thread
    // acknowledges the pause at the synchronization barrier and parks.
    // Lets implementations flush pending work so they park in a
    // consistent state (e.g. the vhost-user bounce worker drains
    // completed requests back to guest memory). By default, a no-op.
    fn on_pause(&mut self, _helper: &mut EpollHelper) {}

    // In some situations, it might be useful to know the full list of events
    // triggered while waiting on epoll_wait(). And having this list provided
    // prior to the iterations over each event might help make some informed
    // decisions. This function should not replace handle_event(), otherwise it
    // would completely defeat the purpose of having the loop being factorized
    // through the EpollHelper structure.
    fn event_list(
        &mut self,
        _helper: &mut EpollHelper,
        _events: &[epoll::Event],
    ) -> Result<(), EpollHelperError> {
        Ok(())
    }
}

impl EpollHelper {
    pub fn new(kill_evt: &EventFd, pause_evt: &EventFd) -> result::Result<Self, EpollHelperError> {
        // Create the epoll file descriptor
        let epoll_fd = epoll::create(true).map_err(EpollHelperError::CreateFd)?;
        // Use 'File' to enforce closing on 'epoll_fd'
        // SAFETY: epoll_fd is a valid fd
        let epoll_file = unsafe { File::from_raw_fd(epoll_fd) };

        let mut helper = Self {
            pause_evt: pause_evt.try_clone().unwrap(),
            epoll_file,
        };

        helper.add_event(kill_evt.as_raw_fd(), EPOLL_HELPER_EVENT_KILL)?;
        helper.add_event(pause_evt.as_raw_fd(), EPOLL_HELPER_EVENT_PAUSE)?;
        Ok(helper)
    }

    pub fn add_event(&mut self, fd: RawFd, id: u16) -> result::Result<(), EpollHelperError> {
        self.add_event_custom(fd, id, epoll::Events::EPOLLIN)
    }

    pub fn add_event_custom(
        &mut self,
        fd: RawFd,
        id: u16,
        evts: epoll::Events,
    ) -> result::Result<(), EpollHelperError> {
        epoll::ctl(
            self.epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd,
            epoll::Event::new(evts, id.into()),
        )
        .map_err(EpollHelperError::Ctl)
    }

    pub fn mod_event_custom(
        &mut self,
        fd: RawFd,
        id: u16,
        evts: epoll::Events,
    ) -> result::Result<(), EpollHelperError> {
        epoll::ctl(
            self.epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_MOD,
            fd,
            epoll::Event::new(evts, id.into()),
        )
        .map_err(EpollHelperError::Ctl)
    }

    pub fn del_event_custom(
        &mut self,
        fd: RawFd,
        id: u16,
        evts: epoll::Events,
    ) -> result::Result<(), EpollHelperError> {
        epoll::ctl(
            self.epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_DEL,
            fd,
            epoll::Event::new(evts, id.into()),
        )
        .map_err(EpollHelperError::Ctl)
    }

    pub fn run(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
        handler: &mut dyn EpollHelperHandler,
    ) -> result::Result<(), EpollHelperError> {
        self.run_with_timeout(paused, paused_sync, handler, -1, false)
    }

    #[cfg(not(fuzzing))]
    pub fn run_with_timeout(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
        handler: &mut dyn EpollHelperHandler,
        timeout: i32,
        enable_event_list: bool,
    ) -> result::Result<(), EpollHelperError> {
        const EPOLL_EVENTS_LEN: usize = 100;
        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];

        // Before jumping into the epoll loop, check if the device is expected
        // to be in a paused state. This is helpful for the restore code path
        // as the device thread should not start processing anything before the
        // device has been resumed.
        while paused.load(Ordering::SeqCst) {
            thread::park();
        }

        loop {
            let num_events =
                match epoll::wait(self.epoll_file.as_raw_fd(), timeout, &mut events[..]) {
                    Ok(res) => res,
                    Err(e) => {
                        if e.kind() == io::ErrorKind::Interrupted {
                            // It's well defined from the epoll_wait() syscall
                            // documentation that the epoll loop can be interrupted
                            // before any of the requested events occurred or the
                            // timeout expired. In both those cases, epoll_wait()
                            // returns an error of type EINTR, but this should not
                            // be considered as a regular error. Instead it is more
                            // appropriate to retry, by calling into epoll_wait().
                            continue;
                        }
                        return Err(EpollHelperError::Wait(e));
                    }
                };

            if num_events == 0 {
                // This case happens when the timeout is reached before any of
                // the registered events is triggered.
                handler.handle_timeout(self)?;
                continue;
            }

            if enable_event_list {
                handler.event_list(self, &events[..num_events])?;
            }

            for event in events.iter().take(num_events) {
                let ev_type = event.data as u16;

                match ev_type {
                    EPOLL_HELPER_EVENT_KILL => {
                        debug!("KILL_EVENT received, stopping epoll loop");
                        return Ok(());
                    }
                    EPOLL_HELPER_EVENT_PAUSE => {
                        debug!("PAUSE_EVENT received, pausing epoll loop");

                        // Give the handler a chance to flush pending work
                        // before the pause is acknowledged.
                        handler.on_pause(self);

                        // Acknowledge the pause is effective by using the
                        // paused_sync barrier.
                        paused_sync.wait();

                        // We loop here to handle spurious park() returns.
                        // Until we have not resumed, the paused boolean will
                        // be true.
                        while paused.load(Ordering::SeqCst) {
                            thread::park();
                        }

                        // Drain pause event after the device has been resumed.
                        // This ensures the pause event has been seen by each
                        // thread related to this virtio device.
                        let _ = self.pause_evt.read();
                    }
                    _ => {
                        handler.handle_event(self, event)?;
                    }
                }
            }
        }
    }

    #[cfg(fuzzing)]
    // Require to have a 'queue_evt' being kicked before calling
    // and return when no epoll events are active
    pub fn run_with_timeout(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
        handler: &mut dyn EpollHelperHandler,
        _timeout: i32,
        _enable_event_list: bool,
    ) -> result::Result<(), EpollHelperError> {
        const EPOLL_EVENTS_LEN: usize = 100;
        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];

        loop {
            let num_events = match epoll::wait(self.epoll_file.as_raw_fd(), 0, &mut events[..]) {
                Ok(res) => res,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        // It's well defined from the epoll_wait() syscall
                        // documentation that the epoll loop can be interrupted
                        // before any of the requested events occurred or the
                        // timeout expired. In both those cases, epoll_wait()
                        // returns an error of type EINTR, but this should not
                        // be considered as a regular error. Instead it is more
                        // appropriate to retry, by calling into epoll_wait().
                        continue;
                    }
                    return Err(EpollHelperError::Wait(e));
                }
            };

            // Return when no epoll events are active
            if num_events == 0 {
                return Ok(());
            }

            for event in events.iter().take(num_events) {
                let ev_type = event.data as u16;

                match ev_type {
                    EPOLL_HELPER_EVENT_KILL => {
                        debug!("KILL_EVENT received, stopping epoll loop");
                        return Ok(());
                    }
                    EPOLL_HELPER_EVENT_PAUSE => {
                        debug!("PAUSE_EVENT received, pausing epoll loop");

                        // Acknowledge the pause is effective by using the
                        // paused_sync barrier.
                        paused_sync.wait();

                        // We loop here to handle spurious park() returns.
                        // Until we have not resumed, the paused boolean will
                        // be true.
                        while paused.load(Ordering::SeqCst) {
                            thread::park();
                        }

                        // Drain pause event after the device has been resumed.
                        // This ensures the pause event has been seen by each
                        // thread related to this virtio device.
                        let _ = self.pause_evt.read();
                    }
                    _ => {
                        handler.handle_event(self, event)?;
                    }
                }
            }
        }
    }
}

impl AsRawFd for EpollHelper {
    fn as_raw_fd(&self) -> RawFd {
        self.epoll_file.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    use super::*;

    const READY_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;

    struct PauseFlagHandler {
        ready_evt: EventFd,
        ready: Arc<AtomicBool>,
        on_pause_ran: Arc<AtomicBool>,
    }

    impl EpollHelperHandler for PauseFlagHandler {
        fn handle_event(
            &mut self,
            _helper: &mut EpollHelper,
            event: &epoll::Event,
        ) -> Result<(), EpollHelperError> {
            if event.data as u16 == READY_EVENT {
                // Processing this event proves the worker has reached the
                // epoll loop, so the pause below cannot race the pre-loop
                // guard.
                let _ = self.ready_evt.read();
                self.ready.store(true, Ordering::SeqCst);
            }
            Ok(())
        }

        fn on_pause(&mut self, _helper: &mut EpollHelper) {
            self.on_pause_ran.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn on_pause_runs_before_barrier_release() {
        let kill_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let pause_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let ready_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let paused = Arc::new(AtomicBool::new(false));
        let paused_sync = Arc::new(Barrier::new(2));
        let ready = Arc::new(AtomicBool::new(false));
        let on_pause_ran = Arc::new(AtomicBool::new(false));

        let worker = {
            let kill_evt = kill_evt.try_clone().unwrap();
            let pause_evt = pause_evt.try_clone().unwrap();
            let ready_evt = ready_evt.try_clone().unwrap();
            let paused = paused.clone();
            let paused_sync = paused_sync.clone();
            let ready = ready.clone();
            let on_pause_ran = on_pause_ran.clone();
            thread::spawn(move || {
                let mut helper = EpollHelper::new(&kill_evt, &pause_evt).unwrap();
                helper
                    .add_event(ready_evt.as_raw_fd(), READY_EVENT)
                    .unwrap();
                let mut handler = PauseFlagHandler {
                    ready_evt,
                    ready,
                    on_pause_ran,
                };
                helper.run(&paused, &paused_sync, &mut handler).unwrap();
            })
        };

        // Make sure the worker is inside the epoll loop before pausing, so
        // the pause cannot deadlock against the pre-loop paused guard.
        ready_evt.write(1).unwrap();
        while !ready.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(1));
        }

        // Pause the worker the way VirtioCommon::pause does.
        paused.store(true, Ordering::SeqCst);
        pause_evt.write(1).unwrap();
        paused_sync.wait();
        // The barrier released, so the hook must already have run.
        assert!(on_pause_ran.load(Ordering::SeqCst));

        // Resume and terminate the worker.
        paused.store(false, Ordering::SeqCst);
        worker.thread().unpark();
        kill_evt.write(1).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn default_on_pause_is_noop() {
        struct Bare;
        impl EpollHelperHandler for Bare {
            fn handle_event(
                &mut self,
                _helper: &mut EpollHelper,
                _event: &epoll::Event,
            ) -> Result<(), EpollHelperError> {
                Ok(())
            }
        }
        // The default implementation compiles and does nothing.
        let kill_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let pause_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let mut helper = EpollHelper::new(&kill_evt, &pause_evt).unwrap();
        Bare.on_pause(&mut helper);
    }
}

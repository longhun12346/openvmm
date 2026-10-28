// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Detects WHP builds on which registering doorbell events terminates the
//! process. Some older WinHvPlatform builds fast-fail when a second doorbell is
//! registered at a different guest address, which cannot be survived in-process,
//! so the check runs in the probe helper executable.

use crate::DoorbellMatch;
use crate::PartitionConfig;
use crate::PartitionProperty;
use crate::api;
use std::io;
use std::os::windows::prelude::*;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::Instant;
use windows_sys::Win32::System::Diagnostics::Debug::SEM_FAILCRITICALERRORS;
use windows_sys::Win32::System::Diagnostics::Debug::SEM_NOGPFAULTERRORBOX;
use windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode;
use windows_sys::Win32::System::Threading::CreateEventW;

pub(crate) const ARGUMENT: &str = "--doorbell";
const TIMEOUT: Duration = Duration::from_secs(15);

/// Whether doorbell events can be used on this host.
pub(crate) fn usable() -> bool {
    static USABLE: OnceLock<bool> = OnceLock::new();
    *USABLE.get_or_init(|| {
        // Hosts with notification ports have the current doorbell implementation;
        // only older ones are tried out.
        if api::is_supported::WHvCreateNotificationPort() {
            return true;
        }
        match probe_in_helper() {
            Ok(usable) => {
                if !usable {
                    eprintln!("WHP doorbell events are unusable on this host; disabling them");
                }
                usable
            }
            Err(err) => {
                eprintln!("WHP doorbell probe could not run ({err}); disabling doorbell events");
                false
            }
        }
    })
}

fn probe_in_helper() -> io::Result<bool> {
    let mut child = Command::new(crate::legacy_cpuid::process::helper_path()?)
        .arg(ARGUMENT)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .spawn()?;
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status.success());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Helper side: registers doorbells at two different guest addresses, the
/// pattern that device models produce. A crash or error means "unusable".
pub(crate) fn run() -> io::Result<()> {
    // SAFETY: only changes this process's error reporting.
    unsafe { SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX) };
    let fail = |err: crate::WHvError| io::Error::other(err.to_string());
    let mut config = PartitionConfig::new().map_err(fail)?;
    config
        .set_property(PartitionProperty::ProcessorCount(1))
        .map_err(fail)?;
    let partition = config.create().map_err(fail)?;
    partition.create_vp(0).create().map_err(fail)?;
    for address in [0x1050, 0x2050] {
        // SAFETY: creating an unnamed event with default security.
        let event = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        let doorbell = DoorbellMatch {
            guest_address: address,
            value: Some(0),
            length: Some(4),
        };
        // SAFETY: the event stays open for the life of this process.
        unsafe { partition.register_doorbell(&doorbell, event as RawHandle) }.map_err(fail)?;
    }
    Ok(())
}

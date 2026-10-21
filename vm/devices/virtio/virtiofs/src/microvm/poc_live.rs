// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! **Proof-of-concept scaffolding** for runtime microVM aggregate children.
//!
//! This is not the product control plane. It lets an experiment drive
//! [`VirtioFs::add_microvm_child`] and [`VirtioFs::remove_microvm_child`] in a
//! running VMM without changing the frozen control-session protocol: when the
//! environment variable `NVX_POC_LIVE_SHARE_DIR` names a directory, a thread
//! polls it for request files and writes a result file for each.
//!
//! - `<stem>.add`: line 1 is the child name, line 2 is `ro` or `rw`, and line 3
//!   is the absolute host path (a directory, or a regular file if it ends in
//!   a path that names one).
//! - `<stem>.remove`: line 1 is the child name.
//! - `<stem>.result`: `ok`, or `error: <reason>`. The request file is deleted
//!   once it is handled.
//!
//! The directory must be private to the VMM's user; nothing here
//! authenticates the writer. The real design carries these requests over the
//! authenticated control console instead.

use crate::VirtioFs;
use crate::VirtioFsInner;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Weak;
use std::time::Duration;

const ENV_DIR: &str = "NVX_POC_LIVE_SHARE_DIR";
const POLL: Duration = Duration::from_millis(100);

/// Starts the polling thread for `fs` if the experiment is enabled.
pub(crate) fn start_if_enabled(fs: &VirtioFs) {
    let Some(dir) = std::env::var_os(ENV_DIR).filter(|dir| !dir.is_empty()) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let weak: Weak<VirtioFsInner> = Arc::downgrade(&fs.inner);
    tracing::warn!(
        dir = %dir.display(),
        "PoC runtime virtio-fs child trigger is enabled; do not use outside experiments"
    );
    let spawned = std::thread::Builder::new()
        .name("nvx-poc-live-share".into())
        .spawn(move || {
            loop {
                std::thread::sleep(POLL);
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                handle_requests(&VirtioFs { inner }, &dir);
            }
        });
    if let Err(error) = spawned {
        tracing::error!(%error, "failed to start the PoC runtime virtio-fs child trigger");
    }
}

fn handle_requests(fs: &VirtioFs, dir: &Path) {
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return;
    };
    let mut requests: Vec<PathBuf> = read_dir
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("add" | "remove")
            )
        })
        .collect();
    requests.sort();
    for request in requests {
        let outcome = std::fs::read_to_string(&request)
            .map_err(|error| format!("cannot read the request: {error}"))
            .and_then(|text| apply(fs, request.extension().and_then(|e| e.to_str()), &text));
        let result = match &outcome {
            Ok(()) => "ok".to_owned(),
            Err(reason) => format!("error: {reason}"),
        };
        tracing::info!(request = %request.display(), %result, "handled PoC runtime child request");
        // Write the result before removing the request, so that a client that
        // waits for the request to disappear finds the result.
        let _ = std::fs::write(request.with_extension("result"), result);
        let _ = std::fs::remove_file(&request);
    }
}

fn apply(fs: &VirtioFs, kind: Option<&str>, text: &str) -> Result<(), String> {
    let mut lines = text.lines();
    let name = lines.next().unwrap_or("").trim();
    match kind {
        Some("add") => {
            let read_only = match lines.next().unwrap_or("").trim() {
                "ro" => true,
                "rw" => false,
                other => return Err(format!("mode must be 'ro' or 'rw', not '{other}'")),
            };
            let path = lines.next().unwrap_or("").trim_end_matches(['\r', '\n']);
            if path.is_empty() {
                return Err("the host path is missing".into());
            }
            let file = Path::new(path).is_file();
            fs.add_microvm_child(name, path, read_only, file, vec![], vec![], vec![])
                .map_err(|error| format!("{error:#}"))
        }
        Some("remove") => fs
            .remove_microvm_child(name)
            .map_err(|error| format!("{error:?}")),
        _ => Err("unknown request".into()),
    }
}

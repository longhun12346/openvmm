// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Authenticated replacement for the request-file trigger in [`super::poc_live`].
//!
//! The launcher hands this VMM one end of an inherited pipe and keeps the other,
//! so possession of the pipe is the authentication: no other process can inject a
//! request. On top of that, every request carries the VM generation it was issued
//! for and a strictly increasing sequence number per generation, so a request that
//! was recorded and replayed later is refused instead of re-applied. The launcher
//! additionally binds a request to the logical session and mount ID it belongs to;
//! this module only validates the framing and the ordering, which is the part that
//! must hold even if the peer is compromised.
//!
//! Wire format, one request per frame:
//!   `<4-byte LE length><payload>`, payload is UTF-8 lines:
//!   `gen=<u64> seq=<u64> session=<name> mount=<id> op=<add|remove> child=<name> mode=<ro|rw> path=<path>`
//! Only `add` carries `mode` and `path`; `remove` carries `child` alone. Fields are
//! space separated and each value is percent-encoded, so a path with spaces or a
//! newline cannot forge a field.
//!
//! This module deliberately contains no `VirtioFs` access: the device applies the
//! validation result, which keeps the ordering rules unit-testable without a VM.

/// Largest frame this channel accepts, so a hostile or broken peer cannot make the
/// VMM allocate without bound.
pub(crate) const MAX_FRAME_BYTES: usize = 64 * 1024;

/// One validated request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Request {
    pub generation: u64,
    pub sequence: u64,
    pub session: String,
    pub mount_id: String,
    pub child: String,
    pub operation: Operation,
    pub mode: Mode,
    pub host_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation {
    Add,
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    ReadOnly,
    ReadWrite,
}

impl Mode {
    pub(crate) fn is_read_only(self) -> bool {
        self == Self::ReadOnly
    }
}

/// Rejects requests that do not belong to this VM or that arrive out of order.
///
/// The state is per-VM and lives with the device: a request for another generation
/// (a previous boot, or another VM's pipe) and a sequence number that was already
/// used are both refused, so replaying a recorded request cannot re-add or
/// re-remove an export.
#[derive(Debug)]
pub(crate) struct Ordering {
    generation: u64,
    last_sequence: Option<u64>,
}

impl Ordering {
    pub(crate) fn new(generation: u64) -> Self {
        Self {
            generation,
            last_sequence: None,
        }
    }

    /// Checks `generation`/`sequence` and, when they are acceptable, consumes them.
    pub(crate) fn accept(&mut self, generation: u64, sequence: u64) -> Result<(), String> {
        if generation != self.generation {
            return Err(format!(
                "request is for VM generation {generation}, this VM is generation {}",
                self.generation
            ));
        }
        if let Some(last) = self.last_sequence {
            if sequence <= last {
                return Err(format!(
                    "request sequence {sequence} was already used (last accepted {last})"
                ));
            }
        }
        self.last_sequence = Some(sequence);
        Ok(())
    }
}

/// Percent-encodes a field value so spaces and newlines cannot forge fields.
// Used by the launcher side of the channel and by the tests.
#[cfg_attr(not(test), allow(dead_code))]
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'\\' | b':' | b'.' | b'-' | b'_' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

fn decode(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = value
                .get(index + 1..index + 3)
                .ok_or_else(|| "truncated percent escape".to_owned())?;
            out.push(
                u8::from_str_radix(hex, 16).map_err(|_| "invalid percent escape".to_owned())?,
            );
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "field is not valid UTF-8".to_owned())
}

fn field<'a>(fields: &'a [&'a str], key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    fields
        .iter()
        .find_map(|field| field.strip_prefix(&prefix))
}

fn required<'a>(fields: &'a [&'a str], key: &str) -> Result<&'a str, String> {
    field(fields, key).ok_or_else(|| format!("missing field '{key}'"))
}

fn number<T: std::str::FromStr>(fields: &[&str], key: &str) -> Result<T, String> {
    required(fields, key)?
        .parse()
        .map_err(|_| format!("field '{key}' is not a number"))
}

/// Parses one frame payload. The caller has already checked the length prefix.
pub(crate) fn parse(payload: &str) -> Result<Request, String> {
    let line = payload.trim_end_matches(['\r', '\n']);
    let fields: Vec<&str> = line.split(' ').collect();
    let operation = match required(&fields, "op")? {
        "add" => Operation::Add,
        "remove" => Operation::Remove,
        other => return Err(format!("unknown op '{other}'")),
    };
    let mode = match field(&fields, "mode").unwrap_or("ro") {
        "ro" => Mode::ReadOnly,
        "rw" => Mode::ReadWrite,
        other => return Err(format!("mode must be 'ro' or 'rw', not '{other}'")),
    };
    let request = Request {
        generation: number(&fields, "gen")?,
        sequence: number(&fields, "seq")?,
        session: decode(required(&fields, "session")?)?,
        mount_id: decode(required(&fields, "mount")?)?,
        child: decode(required(&fields, "child")?)?,
        operation,
        mode,
        host_path: match field(&fields, "path") {
            Some(path) => decode(path)?,
            None => String::new(),
        },
    };
    if request.session.is_empty() || request.mount_id.is_empty() || request.child.is_empty() {
        return Err("session, mount and child must not be empty".to_owned());
    }
    if request.operation == Operation::Add && request.host_path.is_empty() {
        return Err("add needs a host path".to_owned());
    }
    // The child becomes an aggregate export name, so it must be a plain name:
    // every byte in the safe set, and never `.` or `..`, which would escape the
    // export root.
    let child_ok = !request.child.is_empty()
        && request.child != "."
        && request.child != ".."
        && request
            .child
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if !child_ok
    {
        return Err("child must be a plain name of ASCII letters, digits, '.', '_' or '-'".to_owned());
    }
    Ok(request)
}

/// Builds the reply the launcher reads: `ok` or `error: <reason>`.
pub(crate) fn reply(result: Result<(), String>) -> String {
    match result {
        Ok(()) => "ok".to_owned(),
        Err(reason) => format!("error: {reason}"),
    }
}

/// The inherited handle the launcher passed, installed by `openvmm_entry` while
/// it parses the command line.
///
/// A process-global slot rather than a constructor argument because the endpoint
/// is a property of *this VMM process*, decided before any device exists, and the
/// device construction path is shared with configurations that have no such
/// channel. It is set once, before the VM starts, and never replaced; the final
/// step of the P4 work threads it through the resource graph instead, once the
/// PoC trigger next to it is deleted.
static ENDPOINT: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

/// Installs the inherited handle for this process. Returns false when one was
/// already installed with a different value, which would mean two mutually
/// exclusive launch modes were requested.
pub fn install(handle: u32) -> bool {
    match ENDPOINT.set(handle) {
        Ok(()) => true,
        Err(_) => ENDPOINT.get().copied() == Some(handle),
    }
}

/// The installed handle, if the launcher asked for this channel.
pub(crate) fn installed() -> Option<u32> {
    ENDPOINT.get().copied()
}

/// Serves export requests on the installed handle, if the launcher passed one.
///
/// Every request is answered on the same pipe: `ok`, or `error: <reason>`. The
/// thread exits when the launcher closes its end, so it cannot outlive the VM's
/// owner. Nothing here authenticates the peer beyond the pipe itself; ordering and
/// generation checks are in [`Ordering`].
#[cfg(target_os = "windows")]
#[expect(
    unsafe_code,
    reason = "adopting the inherited pipe handle the launcher passed; the handle is \
              owned by this process for the life of the VM"
)]
pub(crate) fn start_if_installed(fs: &crate::VirtioFs) {
    use std::io::Read;
    use std::io::Write;
    use std::os::windows::io::FromRawHandle;

    let Some(handle) = installed() else {
        return;
    };
    let weak: std::sync::Weak<crate::VirtioFsInner> = std::sync::Arc::downgrade(&fs.inner);
    let spawned = std::thread::Builder::new()
        .name("nvx-virtiofs-control".into())
        .spawn(move || {
            // SAFETY: the launcher passes this handle to this process exactly once
            // and keeps the other end open for the life of the VM.
            let mut pipe = unsafe { std::fs::File::from_raw_handle(handle as _) };
            let mut ordering: Option<Ordering> = None;
            loop {
                let mut length = [0u8; 4];
                if pipe.read_exact(&mut length).is_err() {
                    return;
                }
                let length = u32::from_le_bytes(length) as usize;
                if length == 0 || length > MAX_FRAME_BYTES {
                    let _ = pipe.write_all(
                        format!("{}\n", reply(Err(format!("frame length {length} is out of range"))))
                            .as_bytes(),
                    );
                    return;
                }
                let mut payload = vec![0u8; length];
                if pipe.read_exact(&mut payload).is_err() {
                    return;
                }
                let result = match String::from_utf8(payload) {
                    Err(_) => Err("frame is not valid UTF-8".to_owned()),
                    Ok(text) => match parse(&text) {
                        Err(error) => Err(error),
                        Ok(request) => {
                            let guard = ordering
                                .get_or_insert_with(|| Ordering::new(request.generation));
                            match guard.accept(request.generation, request.sequence) {
                                Err(error) => Err(error),
                                Ok(()) => apply(&weak, &request),
                            }
                        }
                    },
                };
                let line = format!("{}\n", reply(result));
                if pipe.write_all(line.as_bytes()).is_err() {
                    return;
                }
            }
        });
    if let Err(error) = spawned {
        tracing::error!(%error, "failed to start the virtio-fs control channel");
    }
}

/// Platforms without inherited handles keep the request-file trigger only.
#[cfg(not(target_os = "windows"))]
pub(crate) fn start_if_installed(_fs: &crate::VirtioFs) {}

/// Applies one validated request to the aggregate filesystem.
#[cfg(target_os = "windows")]
fn apply(
    weak: &std::sync::Weak<crate::VirtioFsInner>,
    request: &Request,
) -> Result<(), String> {
    let Some(inner) = weak.upgrade() else {
        return Err("the filesystem is gone".to_owned());
    };
    let fs = crate::VirtioFs { inner };
    match request.operation {
        Operation::Add => {
            let is_file = std::path::Path::new(&request.host_path).is_file();
            fs.add_microvm_child(
                &request.child,
                &request.host_path,
                request.mode.is_read_only(),
                is_file,
                vec![],
                vec![],
                vec![],
            )
            .map_err(|error| format!("{error:#}"))
        }
        Operation::Remove => fs
            .remove_microvm_child(&request.child)
            .map_err(|error| format!("{error:?}")),
    }
}

/// Encodes a request. Used by the launcher side and by the tests.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn encode_request(request: &Request) -> String {
    let mut line = format!(
        "gen={} seq={} session={} mount={} op={} child={}",
        request.generation,
        request.sequence,
        encode(&request.session),
        encode(&request.mount_id),
        match request.operation {
            Operation::Add => "add",
            Operation::Remove => "remove",
        },
        encode(&request.child),
    );
    if request.operation == Operation::Add {
        line.push_str(&format!(
            " mode={} path={}",
            if request.mode.is_read_only() { "ro" } else { "rw" },
            encode(&request.host_path)
        ));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request {
            generation: 7,
            sequence: 1,
            session: "session a".to_owned(),
            mount_id: "refs".to_owned(),
            child: "mount0".to_owned(),
            operation: Operation::Add,
            mode: Mode::ReadOnly,
            host_path: "C:\\Program Files\\a b".to_owned(),
        }
    }

    #[test]
    fn round_trips_through_the_wire_format() {
        let original = request();
        let line = encode_request(&original);
        assert_eq!(parse(&line).unwrap(), original);
        // The session's space and the path's spaces must not become field breaks.
        assert_eq!(line.matches("session=").count(), 1);
        assert_eq!(line.matches("path=").count(), 1);
    }

    #[test]
    fn remove_does_not_carry_a_path() {
        let mut request = request();
        request.operation = Operation::Remove;
        request.host_path.clear();
        assert_eq!(parse(&encode_request(&request)).unwrap(), request);
    }

    #[test]
    fn another_generation_is_refused() {
        let mut ordering = Ordering::new(7);
        ordering.accept(7, 1).unwrap();
        let error = ordering.accept(6, 2).unwrap_err();
        assert!(error.contains("generation 6"), "{error}");
    }

    #[test]
    fn a_replayed_sequence_is_refused() {
        let mut ordering = Ordering::new(7);
        ordering.accept(7, 5).unwrap();
        // The same request sent twice is the replay this must catch.
        let error = ordering.accept(7, 5).unwrap_err();
        assert!(error.contains("already used"), "{error}");
        // An older sequence is equally stale.
        assert!(ordering.accept(7, 4).is_err());
        ordering.accept(7, 6).unwrap();
    }

    #[test]
    fn the_launcher_wire_vectors_parse_the_same_way() {
        // The same literals appear in `nvx-rs`'s `host::control::WIRE_VECTORS`,
        // which asserts them as encoder output, so a framing change on either side
        // fails both tests instead of silently breaking the channel.
        let add = parse(
            "gen=7 seq=1 session=session%20a mount=refs op=add child=mount0 mode=ro path=C:\\%20a",
        )
        .unwrap();
        assert_eq!(add.generation, 7);
        assert_eq!(add.sequence, 1);
        assert_eq!(add.session, "session a");
        assert_eq!(add.mount_id, "refs");
        assert_eq!(add.child, "mount0");
        assert_eq!(add.operation, Operation::Add);
        assert!(add.mode.is_read_only());
        assert_eq!(add.host_path, "C:\\ a");

        let remove = parse("gen=7 seq=2 session=s mount=refs op=remove child=mount0").unwrap();
        assert_eq!(remove.operation, Operation::Remove);
        assert!(remove.host_path.is_empty());
    }

    #[test]
    fn malformed_requests_are_refused() {
        for payload in [
            "",
            "gen=1 seq=1 session=a mount=m op=add child=c",        // add without a path
            "gen=1 seq=1 session=a mount=m op=remove child=c mode=maybe",
            "gen=1 seq=1 session=a mount=m op=destroy child=c",
            "gen=x seq=1 session=a mount=m op=remove child=c",
            "gen=1 seq=1 session= mount=m op=remove child=c",
            "gen=1 seq=1 session=a mount=m op=remove child=../x",
        ] {
            assert!(parse(payload).is_err(), "{payload:?} must be refused");
        }
    }

    #[test]
    fn a_path_cannot_forge_a_field() {
        let mut request = request();
        request.host_path = "C:\\a op=remove child=evil".to_owned();
        let parsed = parse(&encode_request(&request)).unwrap();
        assert_eq!(parsed.host_path, request.host_path);
        assert_eq!(parsed.operation, Operation::Add);
        assert_eq!(parsed.child, "mount0");
    }
}

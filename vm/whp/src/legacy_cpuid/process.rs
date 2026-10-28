// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A bounded pipe protocol for the isolated legacy CPUID probe. Some legacy
//! WHP builds reject mapping RAM into a second partition in the same process.

use super::Probe;
use super::SavedProperty;
use crate::PartitionProperty;
use crate::Processor;
use crate::Register64;
use crate::Result;
use crate::WHvError;
use crate::abi;
use crate::check_hresult;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::windows::process::CommandExt;
use std::process::Child;
use std::process::ChildStdin;
use std::process::ChildStdout;
use std::process::Command;
use std::process::Stdio;

const MAGIC: &[u8; 8] = b"NVXP\x01\0\0\0";

#[derive(Debug)]
pub(super) struct Client {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
}

fn io_error(error: io::Error) -> WHvError {
    eprintln!("legacy CPUID helper communication failed: {error}");
    WHvError::ERROR_NOT_SUPPORTED
}

/// The path of the probe helper executable: `OPENVMM_WHP_CPUID_HELPER`, or
/// `whp-legacy-cpuid-probe.exe` next to the running executable.
pub(crate) fn helper_path() -> io::Result<std::path::PathBuf> {
    match std::env::var_os("OPENVMM_WHP_CPUID_HELPER") {
        Some(path) => Ok(path.into()),
        None => {
            let mut directory = std::env::current_exe()?;
            directory.pop();
            // Cargo's test executables live in the deps subdirectory.
            if directory.file_name().is_some_and(|name| name == "deps") {
                directory.pop();
            }
            Ok(directory.join("whp-legacy-cpuid-probe.exe"))
        }
    }
}

impl Client {
    pub(super) fn new(properties: &[(u32, SavedProperty)]) -> Result<Self> {
        Self::start(properties).map_err(io_error)
    }

    fn start(properties: &[(u32, SavedProperty)]) -> io::Result<Self> {
        let mut child = Command::new(helper_path()?)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .spawn()?;
        let input = child.stdin.take().expect("piped stdin");
        let output = child.stdout.take().expect("piped stdout");
        let mut client = Self {
            child,
            input,
            output,
        };
        client.input.write_all(MAGIC)?;
        client
            .input
            .write_all(&(properties.len() as u32).to_le_bytes())?;
        for (code, property) in properties {
            let data = encode(property);
            client.input.write_all(&code.to_le_bytes())?;
            client.input.write_all(&(data.len() as u32).to_le_bytes())?;
            client.input.write_all(&data)?;
        }
        client.input.flush()?;
        let mut status = [0; 4];
        client.output.read_exact(&mut status)?;
        check_hresult(i32::from_le_bytes(status)).map_err(io::Error::from)?;
        Ok(client)
    }

    pub(super) fn query(
        &mut self,
        source: &Processor<'_>,
        function: u32,
        index: u32,
    ) -> Result<abi::WHV_CPUID_OUTPUT> {
        let state = [
            source.get_register(Register64::Cr4)?,
            source.get_register(Register64::XCr0)?,
            source.get_register(Register64::ApicBase)?,
        ];
        let mut request = Vec::with_capacity(36);
        for value in [source.index, function, index] {
            request.extend_from_slice(&value.to_le_bytes());
        }
        for value in state {
            request.extend_from_slice(&value.to_le_bytes());
        }
        let mut reply = [0; 20];
        (|| -> io::Result<()> {
            self.input.write_all(&request)?;
            self.input.flush()?;
            self.output.read_exact(&mut reply)
        })()
        .map_err(io_error)?;
        check_hresult(i32::from_le_bytes(reply[..4].try_into().unwrap()))?;
        let value = |offset| u32::from_le_bytes(reply[offset..offset + 4].try_into().unwrap());
        Ok(abi::WHV_CPUID_OUTPUT {
            Eax: value(4),
            Ebx: value(8),
            Ecx: value(12),
            Edx: value(16),
        })
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn words(values: impl IntoIterator<Item = u32>) -> Vec<u8> {
    values.into_iter().flat_map(u32::to_le_bytes).collect()
}

fn encode(property: &SavedProperty) -> Vec<u8> {
    use PartitionProperty as P;
    match property.value() {
        P::ProcessorCount(v) | P::PhysicalAddressWidth(v) => v.to_le_bytes().to_vec(),
        P::ProcessorFeatures(v) => v.bank0.0.to_le_bytes().to_vec(),
        P::ProcessorFeaturesBanks(v) => {
            let mut data = words([2, 0]);
            data.extend_from_slice(&v.bank0.0.to_le_bytes());
            data.extend_from_slice(&v.bank1.0.to_le_bytes());
            data
        }
        P::ProcessorClFlushSize(v) => vec![v],
        P::ProcessorXsaveFeatures(v) => v.0.to_le_bytes().to_vec(),
        P::LocalApicEmulationMode(v) => v.0.to_le_bytes().to_vec(),
        P::PerfmonFeatures(v) => v.0.to_le_bytes().to_vec(),
        P::CpuidResultList(values) => words(
            values
                .iter()
                .flat_map(|v| [v.Function, 0, 0, 0, v.Eax, v.Ebx, v.Ecx, v.Edx]),
        ),
        P::CpuidResultList2(values) => words(values.iter().flat_map(|v| {
            [
                v.Function,
                v.Index,
                v.VpIndex,
                v.Flags.0,
                v.Output.Eax,
                v.Output.Ebx,
                v.Output.Ecx,
                v.Output.Edx,
                v.Mask.Eax,
                v.Mask.Ebx,
                v.Mask.Ecx,
                v.Mask.Edx,
            ]
        })),
        _ => unreachable!("only explicitly saved properties reach the helper"),
    }
}

fn read_u32(reader: &mut impl Read) -> io::Result<u32> {
    let mut bytes = [0; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid legacy CPUID probe request",
    )
}

pub(super) fn property_code(code: u32) -> Option<abi::WHV_PARTITION_PROPERTY_CODE> {
    Some(match code {
        0x1fff => abi::WHvPartitionPropertyCodeProcessorCount,
        0x1011 => abi::WHvPartitionPropertyCodePhysicalAddressWidth,
        0x1005 => abi::WHvPartitionPropertyCodeLocalApicEmulationMode,
        0x1001 => abi::WHvPartitionPropertyCodeProcessorFeatures,
        0x1006 => abi::WHvPartitionPropertyCodeProcessorXsaveFeatures,
        0x100e => abi::WHvPartitionPropertyCodeProcessorPerfmonFeatures,
        0x1002 => abi::WHvPartitionPropertyCodeProcessorClFlushSize,
        0x100a => abi::WHvPartitionPropertyCodeProcessorFeaturesBanks,
        0x1004 => abi::WHvPartitionPropertyCodeCpuidResultList,
        0x100d => abi::WHvPartitionPropertyCodeCpuidResultList2,
        _ => return None,
    })
}

pub(crate) fn run() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let mut magic = [0; 8];
    input.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(invalid());
    }
    let count = read_u32(&mut input)?;
    if count > 64 {
        return Err(invalid());
    }
    let mut properties = Vec::new();
    let mut total = 0usize;
    for _ in 0..count {
        let code = read_u32(&mut input)?;
        let size = read_u32(&mut input)? as usize;
        total = total.checked_add(size).ok_or_else(invalid)?;
        let valid = match code {
            0x1fff | 0x1011 | 0x1005 => size == 4,
            0x1001 | 0x1006 | 0x100e => size == 8,
            0x1002 => size == 1,
            0x100a => size == 24,
            0x1004 => size.is_multiple_of(32),
            0x100d => size.is_multiple_of(48),
            _ => false,
        };
        if !valid || total > 1024 * 1024 {
            return Err(invalid());
        }
        let mut data = vec![0; size];
        input.read_exact(&mut data)?;
        properties.push((code, data));
    }
    let mut probe = match Probe::new(&properties) {
        Ok(probe) => {
            output.write_all(&0i32.to_le_bytes())?;
            probe
        }
        Err(err) => {
            output.write_all(&err.code().to_le_bytes())?;
            output.flush()?;
            return Ok(());
        }
    };
    output.flush()?;
    loop {
        let mut request = [0; 36];
        match input.read_exact(&mut request) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        }
        let word = |offset| u32::from_le_bytes(request[offset..offset + 4].try_into().unwrap());
        let long = |offset| u64::from_le_bytes(request[offset..offset + 8].try_into().unwrap());
        let result = probe.query_raw(word(0), word(4), word(8), [long(12), long(20), long(28)]);
        let values = match result {
            Ok(value) => [0, value.Eax, value.Ebx, value.Ecx, value.Edx],
            Err(err) => [err.code() as u32, 0, 0, 0, 0],
        };
        output.write_all(&words(values))?;
        output.flush()?;
    }
}

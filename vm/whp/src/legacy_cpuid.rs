// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Experimental CPUID queries for WHP versions without the query API.
//!
//! Opt in with OPENVMM_WHP_LEGACY_CPUID=1. Run only a fixed CPUID/OUT
//! instruction sequence in a separate process and partition. Never execute probe code in
//! the workload partition or substitute the host's CPUID for the guest's.

pub(crate) mod process;

use crate::Partition;
use crate::PartitionConfig;
use crate::PartitionProperty;
use crate::Processor;
use crate::Register64;
use crate::RegisterSegment;
use crate::Result;
use crate::WHvError;
use crate::abi;
use crate::api;
use crate::check_hresult;
use std::sync::OnceLock;
use std::time::Duration;
use windows_sys::Win32::System::Memory::MEM_COMMIT;
use windows_sys::Win32::System::Memory::MEM_RELEASE;
use windows_sys::Win32::System::Memory::MEM_RESERVE;
use windows_sys::Win32::System::Memory::PAGE_READWRITE;
use windows_sys::Win32::System::Memory::VirtualAlloc;
use windows_sys::Win32::System::Memory::VirtualFree;

pub(crate) fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("OPENVMM_WHP_LEGACY_CPUID").is_some_and(|v| v == "1"))
}

#[derive(Debug)]
enum SavedProperty {
    Scalar(PartitionProperty<'static>),
    Results(Vec<abi::WHV_X64_CPUID_RESULT>),
    Results2(Vec<abi::WHV_X64_CPUID_RESULT2>),
}

impl SavedProperty {
    fn value(&self) -> PartitionProperty<'_> {
        match self {
            Self::Scalar(value) => *value,
            Self::Results(values) => PartitionProperty::CpuidResultList(values),
            Self::Results2(values) => PartitionProperty::CpuidResultList2(values),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct Compatibility {
    properties: Vec<(u32, SavedProperty)>,
    unsupported: bool,
    probe: Option<Box<process::Client>>,
}

impl Compatibility {
    pub(crate) fn record(&mut self, property: PartitionProperty<'_>) {
        use PartitionProperty as P;
        use SavedProperty as S;
        let (key, value) = match property {
            P::ProcessorCount(v) => (0x1fff, S::Scalar(P::ProcessorCount(v))),
            P::ProcessorFeatures(v) if v.bank1.0 != 0 => {
                (0x100a, S::Scalar(P::ProcessorFeaturesBanks(v)))
            }
            P::ProcessorFeatures(v) => (0x1001, S::Scalar(P::ProcessorFeatures(v))),
            P::ProcessorFeaturesBanks(v) => (0x100a, S::Scalar(P::ProcessorFeaturesBanks(v))),
            P::ProcessorClFlushSize(v) => (0x1002, S::Scalar(P::ProcessorClFlushSize(v))),
            P::ProcessorXsaveFeatures(v) => (0x1006, S::Scalar(P::ProcessorXsaveFeatures(v))),
            P::LocalApicEmulationMode(v) => (0x1005, S::Scalar(P::LocalApicEmulationMode(v))),
            P::CpuidResultList(v) => (0x1004, S::Results(v.to_vec())),
            P::CpuidResultList2(v) => (0x100d, S::Results2(v.to_vec())),
            P::PhysicalAddressWidth(v) => (0x1011, S::Scalar(P::PhysicalAddressWidth(v))),
            P::PerfmonFeatures(v) => (0x100e, S::Scalar(P::PerfmonFeatures(v))),
            P::NestedVirtualization(true) | P::AllowDeviceAssignment(true) => {
                self.unsupported = true;
                self.probe = None;
                return;
            }
            P::SyntheticProcessorFeatures(v) if v.bank0.0 != 0 => {
                self.unsupported = true;
                self.probe = None;
                return;
            }
            // Exit routing and clocks do not change the CPUID results. The
            // probe deliberately handles CPUID in WHP, and exits at OUT.
            _ => return,
        };
        self.properties.retain(|(old, _)| *old != key);
        self.properties.push((key, value));
        self.probe = None;
    }

    pub(crate) fn query(
        &mut self,
        source: &Processor<'_>,
        function: u32,
        index: u32,
    ) -> Result<abi::WHV_CPUID_OUTPUT> {
        if self.unsupported {
            return Err(WHvError::ERROR_NOT_SUPPORTED);
        }
        if self.probe.is_none() {
            self.probe = Some(Box::new(process::Client::new(&self.properties)?));
        }
        self.probe.as_mut().unwrap().query(source, function, index)
    }
}

#[derive(Debug)]
struct Page(std::ptr::NonNull<std::ffi::c_void>);

// SAFETY: this allocation has a single owner, only accessed while holding the
// compatibility mutex; its mapping is destroyed before it is freed.
unsafe impl Send for Page {}

impl Page {
    fn new() -> Result<Self> {
        // A dedicated allocation avoids sharing a heap reservation between
        // partitions on legacy WHP.
        let address = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                4096,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        let address = std::ptr::NonNull::new(address).ok_or_else(|| {
            let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            WHvError(std::num::NonZeroI32::new((0x80070000 | (error & 0xffff)) as i32).unwrap())
        })?;
        let page = Self(address);
        // SAFETY: the dedicated writable allocation is at least four bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(
                [0x0fu8, 0xa2, 0xe6, 0x80].as_ptr(),
                page.0.as_ptr().cast(),
                4,
            );
        }
        Ok(page)
    }
}

impl Drop for Page {
    fn drop(&mut self) {
        // SAFETY: this is the original allocation base and the mapping is gone.
        unsafe {
            VirtualFree(self.0.as_ptr(), 0, MEM_RELEASE);
        }
    }
}

#[derive(Debug)]
struct Probe {
    // Drop the partition (including its mapping) before freeing the page.
    partition: Partition,
    _page: Page,
}

impl Probe {
    fn new(properties: &[(u32, Vec<u8>)]) -> Result<Self> {
        let mut config = PartitionConfig::new()?;
        let mut vp_count = None;
        for (code, data) in properties {
            if *code == 0x1fff {
                vp_count = Some(u32::from_le_bytes(
                    data.as_slice()
                        .try_into()
                        .map_err(|_| WHvError::ERROR_NOT_SUPPORTED)?,
                ));
            }
            // SAFETY: the helper validates each property code and byte size.
            // WHP validates values before setting up the partition.
            unsafe {
                check_hresult(api::WHvSetPartitionProperty(
                    config.partition.handle,
                    process::property_code(*code).ok_or(WHvError::ERROR_NOT_SUPPORTED)?,
                    data.as_ptr(),
                    data.len() as u32,
                ))?;
            }
        }
        let count = vp_count.ok_or(WHvError::ERROR_NOT_SUPPORTED)?;
        // This local experiment is limited to the NVX-supported topology.
        if !(1..=8).contains(&count) {
            return Err(WHvError::ERROR_NOT_SUPPORTED);
        }
        config.set_property(PartitionProperty::ExtendedVmExits(
            abi::WHV_EXTENDED_VM_EXITS(0),
        ))?;
        let partition = config.create()?;
        for vp in 0..count {
            partition.create_vp(vp).create()?;
        }
        // OUT exits even when the in-hypervisor APIC handles HLT internally.
        let page = Page::new()?;
        // SAFETY: a page-aligned, committed allocation, kept alive until after
        // the partition is deleted. The guest mapping is read/execute only.
        unsafe {
            check_hresult(api::WHvMapGpaRange(
                partition.handle,
                page.0.as_ptr(),
                0,
                4096,
                abi::WHV_MAP_GPA_RANGE_FLAGS(5),
            ))
            .inspect_err(|err| eprintln!("legacy CPUID probe memory mapping failed: {err}"))?;
        }
        Ok(Self {
            partition,
            _page: page,
        })
    }

    fn query_raw(
        &mut self,
        vp_index: u32,
        function: u32,
        index: u32,
        state: [u64; 3],
    ) -> Result<abi::WHV_CPUID_OUTPUT> {
        let vp = self.partition.vp(vp_index);
        // CPUID OSXSAVE, OSPKE, XSAVE size, and APIC enablement depend on
        // vCPU state. Copy those inputs for every query; do not cache them.
        let cr4 = state[0] & ((1 << 18) | (1 << 22));
        vp.set_register(Register64::Cr4, cr4)?;
        vp.set_register(Register64::XCr0, state[1])?;
        vp.set_register(Register64::ApicBase, state[2])?;
        vp.set_register(
            RegisterSegment::Cs,
            abi::WHV_X64_SEGMENT_REGISTER {
                Base: 0,
                Limit: 0xffff,
                Selector: 0,
                Attributes: 0x9b,
            },
        )?;
        vp.set_register(Register64::Cr0, 0x10)?;
        vp.set_register(Register64::Rip, 0)?;
        vp.set_register(Register64::Rflags, 2)?;
        vp.set_register(Register64::Rax, u64::from(function))?;
        vp.set_register(Register64::Rcx, u64::from(index))?;
        // Keep the probe in the runnable state.
        vp.set_register(Register64::InternalActivityState, 0)?;
        let mut context = std::mem::MaybeUninit::<abi::WHV_RUN_VP_EXIT_CONTEXT>::zeroed();
        let result = std::thread::scope(|scope| {
            let (finished, wait) = std::sync::mpsc::channel();
            let watchdog_vp = &vp;
            scope.spawn(move || {
                if matches!(
                    wait.recv_timeout(Duration::from_secs(2)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ) {
                    let _ = watchdog_vp.cancel_run();
                }
            });
            // SAFETY: initialized context of the ABI size; this mutex-owned
            // probe's vCPU is never run concurrently.
            let result = unsafe {
                check_hresult(api::WHvRunVirtualProcessor(
                    self.partition.handle,
                    vp_index,
                    context.as_mut_ptr(),
                    size_of::<abi::WHV_RUN_VP_EXIT_CONTEXT>() as u32,
                ))
            };
            let _ = finished.send(());
            result
        });
        result?;
        // SAFETY: WHP successfully initialized the exit context.
        let context = unsafe { context.assume_init() };
        if context.ExitReason != abi::WHvRunVpExitReasonX64IoPortAccess {
            eprintln!(
                "legacy CPUID probe unexpected exit {:?} for {function:#x}/{index:#x}",
                context.ExitReason,
            );
            if context.ExitReason == abi::WHvRunVpExitReasonMemoryAccess {
                // SAFETY: the exit discriminator identifies this union member.
                eprintln!("legacy CPUID memory exit: {:?}", unsafe {
                    context.u.MemoryAccess
                });
            }
            return Err(WHvError::ERROR_NOT_SUPPORTED);
        }
        Ok(abi::WHV_CPUID_OUTPUT {
            Eax: vp.get_register(Register64::Rax)? as u32,
            Ebx: vp.get_register(Register64::Rbx)? as u32,
            Ecx: vp.get_register(Register64::Rcx)? as u32,
            Edx: vp.get_register(Register64::Rdx)? as u32,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[test]
    #[ignore = "requires WHP"]
    fn legacy_query_preserves_source_and_repeats() {
        let mut config = PartitionConfig::new().unwrap();
        config
            .set_property(PartitionProperty::ProcessorCount(1))
            .unwrap();
        config
            .set_property(PartitionProperty::LocalApicEmulationMode(
                abi::WHvX64LocalApicEmulationModeXApic,
            ))
            .unwrap();
        // Keep a mapped workload partition alive while the helper runs. Older
        // WHP rejects a second mapped partition in the same process.
        let source_page = Page::new().unwrap();
        let partition = config.create().unwrap();
        partition.create_vp(0).create().unwrap();
        // SAFETY: the page is dedicated, and outlives the partition.
        unsafe {
            partition
                .map_range(
                    None,
                    source_page.0.as_ptr().cast(),
                    4096,
                    0,
                    abi::WHV_MAP_GPA_RANGE_FLAGS(7),
                )
                .unwrap();
        }
        let vp = partition.vp(0);
        vp.set_register(Register64::Rax, 0x12345678).unwrap();
        vp.set_register(Register64::Rip, 0xabc).unwrap();
        let mut compat = partition.legacy_cpuid.lock();
        for _ in 0..3 {
            let output = compat.query(&vp, 0, 0).unwrap();
            assert!(output.Eax > 0);
            let width = compat.query(&vp, 0x80000008, 0).unwrap();
            assert!((32..=52).contains(&(width.Eax & 0xff)));
        }
        assert_eq!(vp.get_register(Register64::Rax).unwrap(), 0x12345678);
        assert_eq!(vp.get_register(Register64::Rip).unwrap(), 0xabc);
    }

    #[test]
    #[ignore = "requires WHP with CpuidResultList2 (not available on Windows 10)"]
    fn legacy_query_respects_subleaf_and_vp_result_table() {
        let mut config = PartitionConfig::new().unwrap();
        config
            .set_property(PartitionProperty::ProcessorCount(2))
            .unwrap();
        config
            .set_property(PartitionProperty::LocalApicEmulationMode(
                abi::WHvX64LocalApicEmulationModeXApic,
            ))
            .unwrap();
        let expected = abi::WHV_CPUID_OUTPUT {
            Eax: 0x11223344,
            Ebx: 0x55667788,
            Ecx: 0x1234,
            Edx: 0x5678,
        };
        config
            .set_property(PartitionProperty::CpuidResultList2(&[
                abi::WHV_X64_CPUID_RESULT2 {
                    Function: 7,
                    Index: 1,
                    VpIndex: 1,
                    Flags: abi::WHV_X64_CPUID_RESULT2_FLAGS(3),
                    Output: expected,
                    Mask: abi::WHV_CPUID_OUTPUT {
                        Eax: u32::MAX,
                        Ebx: u32::MAX,
                        Ecx: u32::MAX,
                        Edx: u32::MAX,
                    },
                },
            ]))
            .unwrap();
        let partition = config.create().unwrap();
        for index in 0..2 {
            partition.create_vp(index).create().unwrap();
        }
        let mut compat = partition.legacy_cpuid.lock();
        let output = compat.query(&partition.vp(1), 7, 1).unwrap();
        assert_eq!(
            [output.Eax, output.Ebx, output.Ecx, output.Edx],
            [expected.Eax, expected.Ebx, expected.Ecx, expected.Edx],
        );
        let other = compat.query(&partition.vp(0), 7, 1).unwrap();
        assert_ne!(other.Eax, expected.Eax);
    }

    #[test]
    #[ignore = "requires WHP"]
    fn legacy_query_respects_legacy_result_table() {
        let mut config = PartitionConfig::new().unwrap();
        config
            .set_property(PartitionProperty::ProcessorCount(1))
            .unwrap();
        config
            .set_property(PartitionProperty::LocalApicEmulationMode(
                abi::WHvX64LocalApicEmulationModeXApic,
            ))
            .unwrap();
        config
            .set_property(PartitionProperty::CpuidResultList(&[
                abi::WHV_X64_CPUID_RESULT {
                    Function: 7,
                    Reserved: [0; 3],
                    Eax: 0x1234,
                    Ebx: 0x5678,
                    Ecx: 0x9abc,
                    Edx: 0xdef0,
                },
            ]))
            .unwrap();
        let partition = config.create().unwrap();
        partition.create_vp(0).create().unwrap();
        let output = partition
            .legacy_cpuid
            .lock()
            .query(&partition.vp(0), 7, 0)
            .unwrap();
        assert_eq!(
            [output.Eax, output.Ebx, output.Ecx, output.Edx],
            [0x1234, 0x5678, 0x9abc, 0xdef0]
        );
    }
}

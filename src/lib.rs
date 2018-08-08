#![cfg(windows)]
#![allow(dead_code, non_camel_case_types, non_snake_case, non_upper_case_globals)]



extern crate winapi as win32;



use {
    win32::shared::ntdef::HANDLE,
    win32::shared::ntdef::LARGE_INTEGER,
    win32::shared::ntdef::LONG,
    win32::shared::ntdef::NTSTATUS,
    win32::shared::ntdef::PCWSTR,
    win32::shared::ntdef::PULONG,
    win32::shared::ntdef::PUNICODE_STRING,
    win32::shared::ntdef::PVOID,
    win32::shared::ntdef::UCHAR,
    win32::shared::ntdef::ULONG,
    win32::shared::ntdef::ULONGLONG,
    win32::shared::ntdef::UNICODE_STRING,
    win32::shared::ntdef::USHORT,
    win32::shared::basetsd::SIZE_T,
};



extern "system" {
    pub fn NtLoadDriver(
        DriverServiceName: PUNICODE_STRING,
    ) -> NTSTATUS;

    pub fn NtUnloadDriver(
        DriverServiceName: PUNICODE_STRING,
    ) -> NTSTATUS;

    pub fn NtQuerySystemInformation(
        SystemInformationClass:  u32,
        SystemInformation:       PVOID,
        SystemInformationLength: ULONG,
        ReturnLength:            PULONG,
    ) -> NTSTATUS;

    pub fn RtlInitUnicodeString(
        DestinationString: PUNICODE_STRING,
        SourceString:      PCWSTR,
    );
}



#[repr(C)]
#[derive(Clone)]
pub struct RTL_PROCESS_MODULE_INFORMATION {
    pub Section:          HANDLE,
    pub MappedBase:       PVOID,
    pub ImageBase:        PVOID,
    pub ImageSize:        ULONG,
    pub Flags:            ULONG,
    pub LoadOrderIndex:   USHORT,
    pub InitOrderIndex:   USHORT,
    pub LoadCount:        USHORT,
    pub OffsetToFileName: USHORT,
    pub FullPathName:     [UCHAR; 256],
}

#[repr(C)]
#[derive(Clone)]
pub struct RTL_PROCESS_MODULES {
    pub NumberOfModules: ULONG,
    pub Modules:         [RTL_PROCESS_MODULE_INFORMATION; 0],
}

pub type KPRIORITY                       = ULONG;
pub type PRTL_PROCESS_MODULE_INFORMATION = *mut RTL_PROCESS_MODULE_INFORMATION;
pub type PRTL_PROCESS_MODULES            = *mut RTL_PROCESS_MODULES;

#[repr(C)]
#[derive(Clone)]
pub struct SYSTEM_PROCESS_INFORMATION {
    pub NextEntryOffset:              ULONG,
    pub NumberOfThreads:              ULONG,
    pub WorkingSetPrivateSize:        LARGE_INTEGER,
    pub HardFaultCount:               ULONG,
    pub NumberOfThreadsHighWatermark: ULONG,
    pub CycleTime:                    ULONGLONG,
    pub CreateTime:                   LARGE_INTEGER,
    pub UserTime:                     LARGE_INTEGER,
    pub KernelTime:                   LARGE_INTEGER,
    pub ImageName:                    UNICODE_STRING,
    pub BasePriority:                 KPRIORITY,
    pub UniqueProcessId:              HANDLE,
    pub InheritedFromUniqueProcessId: PVOID,
    pub HandleCount:                  ULONG,
    pub SessionId:                    ULONG,
    pub UniqueProcessKey:             ULONG,
    pub PeakVirtualSize:              SIZE_T,
    pub VirtualSize:                  SIZE_T,
    pub PageFaultCount:               ULONG,
    pub PeakWorkingSetSize:           SIZE_T,
    pub WorkingSetSize:               SIZE_T,
    pub Reserved5:                    PVOID,
    pub QuotaPagedPoolUsage:          SIZE_T,
    pub Reserved6:                    PVOID,
    pub QuotaNonPagedPoolUsage:       SIZE_T,
    pub PagefileUsage:                SIZE_T,
    pub PeakPagefileUsage:            SIZE_T,
    pub PrivatePageCount:             SIZE_T,
    pub ReadOperationCount:           LARGE_INTEGER,
    pub WriteOperationCount:          LARGE_INTEGER,
    pub OtherOperationCount:          LARGE_INTEGER,
    pub ReadTransferCount:            LARGE_INTEGER,
    pub WriteTransferCount:           LARGE_INTEGER,
    pub OtherTransferCount:           LARGE_INTEGER,
}

#[repr(C)]
#[derive(Clone)]
pub struct CLIENT_ID {
    pub UniqueProcess: HANDLE,
    pub UniqueThread:  HANDLE,
}

#[repr(C)]
#[derive(Clone)]
pub struct SYSTEM_THREAD_INFORMATION {
    pub KernelTime:      LARGE_INTEGER,
    pub UserTime:        LARGE_INTEGER,
    pub CreateTime:      LARGE_INTEGER,
    pub WaitTime:        ULONG,
    pub StartAddress:    PVOID,
    pub ClientId:        CLIENT_ID,
    pub Priority:        KPRIORITY,
    pub BasePriority:    LONG,
    pub ContextSwitches: ULONG,
    pub ThreadState:     ULONG,
    pub WaitReason:      ULONG,
}

pub const SystemBasicInformation:                                u32 = 0x00;
pub const SystemProcessorInformation:                            u32 = 0x01;
pub const SystemPerformanceInformation:                          u32 = 0x02;
pub const SystemTimeOfDayInformation:                            u32 = 0x03;
pub const SystemPathInformation:                                 u32 = 0x04;
pub const SystemProcessInformation:                              u32 = 0x05;
pub const SystemCallCountInformation:                            u32 = 0x06;
pub const SystemDeviceInformation:                               u32 = 0x07;
pub const SystemProcessorPerformanceInformation:                 u32 = 0x08;
pub const SystemFlagsInformation:                                u32 = 0x09;
pub const SystemCallTimeInformation:                             u32 = 0x0A;
pub const SystemModuleInformation:                               u32 = 0x0B;
pub const SystemLocksInformation:                                u32 = 0x0C;
pub const SystemStackTraceInformation:                           u32 = 0x0D;
pub const SystemPagedPoolInformation:                            u32 = 0x0E;
pub const SystemNonPagedPoolInformation:                         u32 = 0x0F;
pub const SystemHandleInformation:                               u32 = 0x10;
pub const SystemObjectInformation:                               u32 = 0x11;
pub const SystemPageFileInformation:                             u32 = 0x12;
pub const SystemVdmInstemulInformation:                          u32 = 0x13;
pub const SystemVdmBopInformation:                               u32 = 0x14;
pub const SystemFileCacheInformation:                            u32 = 0x15;
pub const SystemPoolTagInformation:                              u32 = 0x16;
pub const SystemInterruptInformation:                            u32 = 0x17;
pub const SystemDpcBehaviorInformation:                          u32 = 0x18;
pub const SystemFullMemoryInformation:                           u32 = 0x19;
pub const SystemLoadGdiDriverInformation:                        u32 = 0x1A;
pub const SystemUnloadGdiDriverInformation:                      u32 = 0x1B;
pub const SystemTimeAdjustmentInformation:                       u32 = 0x1C;
pub const SystemSummaryMemoryInformation:                        u32 = 0x1D;
pub const SystemMirrorMemoryInformation:                         u32 = 0x1E;
pub const SystemPerformanceTraceInformation:                     u32 = 0x1F;
pub const SystemObsolete0:                                       u32 = 0x20;
pub const SystemExceptionInformation:                            u32 = 0x21;
pub const SystemCrashDumpStateInformation:                       u32 = 0x22;
pub const SystemKernelDebuggerInformation:                       u32 = 0x23;
pub const SystemContextSwitchInformation:                        u32 = 0x24;
pub const SystemRegistryQuotaInformation:                        u32 = 0x25;
pub const SystemExtendedServiceTableInformation:                 u32 = 0x26;
pub const SystemPrioritySeparation:                              u32 = 0x27;
pub const SystemVerifierAddDriverInformation:                    u32 = 0x28;
pub const SystemVerifierRemoveDriverInformation:                 u32 = 0x29;
pub const SystemProcessorIdleInformation:                        u32 = 0x2A;
pub const SystemLegacyDriverInformation:                         u32 = 0x2B;
pub const SystemCurrentTimeZoneInformation:                      u32 = 0x2C;
pub const SystemLookasideInformation:                            u32 = 0x2D;
pub const SystemTimeSlipNotification:                            u32 = 0x2E;
pub const SystemSessionCreate:                                   u32 = 0x2F;
pub const SystemSessionDetach:                                   u32 = 0x30;
pub const SystemSessionInformation:                              u32 = 0x31;
pub const SystemRangeStartInformation:                           u32 = 0x32;
pub const SystemVerifierInformation:                             u32 = 0x33;
pub const SystemVerifierThunkExtend:                             u32 = 0x34;
pub const SystemSessionProcessInformation:                       u32 = 0x35;
pub const SystemLoadGdiDriverInSystemSpace:                      u32 = 0x36;
pub const SystemNumaProcessorMap:                                u32 = 0x37;
pub const SystemPrefetcherInformation:                           u32 = 0x38;
pub const SystemExtendedProcessInformation:                      u32 = 0x39;
pub const SystemRecommendedSharedDataAlignment:                  u32 = 0x3A;
pub const SystemComPlusPackage:                                  u32 = 0x3B;
pub const SystemNumaAvailableMemory:                             u32 = 0x3C;
pub const SystemProcessorPowerInformation:                       u32 = 0x3D;
pub const SystemEmulationBasicInformation:                       u32 = 0x3E;
pub const SystemEmulationProcessorInformation:                   u32 = 0x3F;
pub const SystemExtendedHandleInformation:                       u32 = 0x40;
pub const SystemLostDelayedWriteInformation:                     u32 = 0x41;
pub const SystemBigPoolInformation:                              u32 = 0x42;
pub const SystemSessionPoolTagInformation:                       u32 = 0x43;
pub const SystemSessionMappedViewInformation:                    u32 = 0x44;
pub const SystemHotpatchInformation:                             u32 = 0x45;
pub const SystemObjectSecurityMode:                              u32 = 0x46;
pub const SystemWatchdogTimerHandler:                            u32 = 0x47;
pub const SystemWatchdogTimerInformation:                        u32 = 0x48;
pub const SystemLogicalProcessorInformation:                     u32 = 0x49;
pub const SystemWow64SharedInformationObsolete:                  u32 = 0x4A;
pub const SystemRegisterFirmwareTableInformationHandler:         u32 = 0x4B;
pub const SystemFirmwareTableInformation:                        u32 = 0x4C;
pub const SystemModuleInformationEx:                             u32 = 0x4D;
pub const SystemVerifierTriageInformation:                       u32 = 0x4E;
pub const SystemSuperfetchInformation:                           u32 = 0x4F;
pub const SystemMemoryListInformation:                           u32 = 0x50;
pub const SystemFileCacheInformationEx:                          u32 = 0x51;
pub const SystemThreadPriorityClientIdInformation:               u32 = 0x52;
pub const SystemProcessorIdleCycleTimeInformation:               u32 = 0x53;
pub const SystemVerifierCancellationInformation:                 u32 = 0x54;
pub const SystemProcessorPowerInformationEx:                     u32 = 0x55;
pub const SystemRefTraceInformation:                             u32 = 0x56;
pub const SystemSpecialPoolInformation:                          u32 = 0x57;
pub const SystemProcessIdInformation:                            u32 = 0x58;
pub const SystemErrorPortInformation:                            u32 = 0x59;
pub const SystemBootEnvironmentInformation:                      u32 = 0x5A;
pub const SystemHypervisorInformation:                           u32 = 0x5B;
pub const SystemVerifierInformationEx:                           u32 = 0x5C;
pub const SystemTimeZoneInformation:                             u32 = 0x5D;
pub const SystemImageFileExecutionOptionsInformation:            u32 = 0x5E;
pub const SystemCoverageInformation:                             u32 = 0x5F;
pub const SystemPrefetchPatchInformation:                        u32 = 0x60;
pub const SystemVerifierFaultsInformation:                       u32 = 0x61;
pub const SystemSystemPartitionInformation:                      u32 = 0x62;
pub const SystemSystemDiskInformation:                           u32 = 0x63;
pub const SystemProcessorPerformanceDistribution:                u32 = 0x64;
pub const SystemNumaProximityNodeInformation:                    u32 = 0x65;
pub const SystemDynamicTimeZoneInformation:                      u32 = 0x66;
pub const SystemCodeIntegrityInformation:                        u32 = 0x67;
pub const SystemProcessorMicrocodeUpdateInformation:             u32 = 0x68;
pub const SystemProcessorBrandString:                            u32 = 0x69;
pub const SystemVirtualAddressInformation:                       u32 = 0x6A;
pub const SystemLogicalProcessorAndGroupInformation:             u32 = 0x6B;
pub const SystemProcessorCycleTimeInformation:                   u32 = 0x6C;
pub const SystemStoreInformation:                                u32 = 0x6D;
pub const SystemRegistryAppendString:                            u32 = 0x6E;
pub const SystemAitSamplingValue:                                u32 = 0x6F;
pub const SystemVhdBootInformation:                              u32 = 0x70;
pub const SystemCpuQuotaInformation:                             u32 = 0x71;
pub const SystemNativeBasicInformation:                          u32 = 0x72;
pub const SystemErrorPortTimeouts:                               u32 = 0x73;
pub const SystemLowPriorityIoInformation:                        u32 = 0x74;
pub const SystemBootEntropyInformation:                          u32 = 0x75;
pub const SystemVerifierCountersInformation:                     u32 = 0x76;
pub const SystemPagedPoolInformationEx:                          u32 = 0x77;
pub const SystemSystemPtesInformationEx:                         u32 = 0x78;
pub const SystemNodeDistanceInformation:                         u32 = 0x79;
pub const SystemAcpiAuditInformation:                            u32 = 0x7A;
pub const SystemBasicPerformanceInformation:                     u32 = 0x7B;
pub const SystemQueryPerformanceCounterInformation:              u32 = 0x7C;
pub const SystemSessionBigPoolInformation:                       u32 = 0x7D;
pub const SystemBootGraphicsInformation:                         u32 = 0x7E;
pub const SystemScrubPhysicalMemoryInformation:                  u32 = 0x7F;
pub const SystemBadPageInformation:                              u32 = 0x80;
pub const SystemProcessorProfileControlArea:                     u32 = 0x81;
pub const SystemCombinePhysicalMemoryInformation:                u32 = 0x82;
pub const SystemEntropyInterruptTimingInformation:               u32 = 0x83;
pub const SystemConsoleInformation:                              u32 = 0x84;
pub const SystemPlatformBinaryInformation:                       u32 = 0x85;
pub const SystemPolicyInformation:                               u32 = 0x86;
pub const SystemHypervisorProcessorCountInformation:             u32 = 0x87;
pub const SystemDeviceDataInformation:                           u32 = 0x88;
pub const SystemDeviceDataEnumerationInformation:                u32 = 0x89;
pub const SystemMemoryTopologyInformation:                       u32 = 0x8A;
pub const SystemMemoryChannelInformation:                        u32 = 0x8B;
pub const SystemBootLogoInformation:                             u32 = 0x8C;
pub const SystemProcessorPerformanceInformationEx:               u32 = 0x8D;
pub const SystemSpare0:                                          u32 = 0x8E;
pub const SystemSecureBootPolicyInformation:                     u32 = 0x8F;
pub const SystemPageFileInformationEx:                           u32 = 0x90;
pub const SystemSecureBootInformation:                           u32 = 0x91;
pub const SystemEntropyInterruptTimingRawInformation:            u32 = 0x92;
pub const SystemPortableWorkspaceEfiLauncherInformation:         u32 = 0x93;
pub const SystemFullProcessInformation:                          u32 = 0x94;
pub const SystemKernelDebuggerInformationEx:                     u32 = 0x95;
pub const SystemBootMetadataInformation:                         u32 = 0x96;
pub const SystemSoftRebootInformation:                           u32 = 0x97;
pub const SystemElamCertificateInformation:                      u32 = 0x98;
pub const SystemOfflineDumpConfigInformation:                    u32 = 0x99;
pub const SystemProcessorFeaturesInformation:                    u32 = 0x9A;
pub const SystemRegistryReconciliationInformation:               u32 = 0x9B;
pub const SystemEdidInformation:                                 u32 = 0x9C;
pub const SystemManufacturingInformation:                        u32 = 0x9D;
pub const SystemEnergyEstimationConfigInformation:               u32 = 0x9E;
pub const SystemHypervisorDetailInformation:                     u32 = 0x9F;
pub const SystemProcessorCycleStatsInformation:                  u32 = 0xA0;
pub const SystemVmGenerationCountInformation:                    u32 = 0xA1;
pub const SystemTrustedPlatformModuleInformation:                u32 = 0xA2;
pub const SystemKernelDebuggerFlags:                             u32 = 0xA3;
pub const SystemCodeIntegrityPolicyInformation:                  u32 = 0xA4;
pub const SystemIsolatedUserModeInformation:                     u32 = 0xA5;
pub const SystemHardwareSecurityTestInterfaceResultsInformation: u32 = 0xA6;
pub const SystemSingleModuleInformation:                         u32 = 0xA7;
pub const SystemAllowedCpuSetsInformation:                       u32 = 0xA8;
pub const SystemDmaProtectionInformation:                        u32 = 0xA9;
pub const SystemInterruptCpuSetsInformation:                     u32 = 0xAA;
pub const SystemSecureBootPolicyFullInformation:                 u32 = 0xAB;
pub const SystemCodeIntegrityPolicyFullInformation:              u32 = 0xAC;
pub const SystemAffinitizedInterruptProcessorInformation:        u32 = 0xAD;
pub const SystemRootSiloInformation:                             u32 = 0xAE;
pub const SystemCpuSetInformation:                               u32 = 0xAF;
pub const SystemCpuSetTagInformation: u32 = 0xB0;
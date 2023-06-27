// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*!
 * Functions to convert a given ELF formatted binary into a format suitable for
 * loading in CantripOS.
 *
 * The format of a CantripOS binary consists of a series of sections each prefixed
 * by the following SectionHeader:
 *    magic: u64    Magic number
 *    vaddr: u64    Virtual address of section (bytes)
 *    entry: u64    Entry point; valid only when SECTION_ENTRY is set in flags
 *    flags: u32    See below
 *    fsize: u32    Length of data that follows (bytes)
 *    msize: u32    Size of memory region (bytes)
 *    align: u32    Section data alignment (bytes)
 *    ftype: u32    File type (see below)
 *    crc32: u32    CRC32 of the data that follows
 *
 * Section header flags (mostly from ELF program section):
 *    SECTION_READ: u32 = 0x1; // Data are readable
 *    SECTION_WRITE: u32 = 0x2; // Data are writeable
 *    SECTION_EXEC: u32 = 0x4; // Data are executable
 *    SECTION_ENTRY: u32 = 0x8; // Entry point valid
 *
 * All values are written big-endian.
 *
 * To ingest this data:
 *    1. Read a page
 *    2. Interpret the section header to find where the data should land
 *    3. Copy fsize bytes of data to vaddr
 *    4. (optionally) zero-pad fsize - msize bytes
 *    5. Repeat until EOD or an invalid section header (typically the MAGIC
 *       number check).
 */

use core::mem::size_of;
use core::ptr;
use core::slice;
use crc::crc32;
use crc::Hasher32;
use log::*;
use std::fs::File;
use std::io::Seek;
use std::io::Write;
use xmas_elf::program::ProgramHeader;
use xmas_elf::program::SegmentData;
use xmas_elf::program::Type;
use xmas_elf::ElfFile;

/// Predicate to determine if an ELF program header is a loadble type.
fn is_load_type(seg: &ProgramHeader) -> bool {
    if let Ok(t) = seg.get_type() {
        t == Type::Load
    } else {
        false
    }
}

// TODO(sleffler): use runtime defs
const MAGIC: u64 = 0x0405_1957_1014_1955;

const SECTION_READ: u32 = 0x1; // Data are readable
const SECTION_WRITE: u32 = 0x2; // Data are writeable
const SECTION_EXEC: u32 = 0x4; // Data are executable
const SECTION_ENTRY: u32 = 0x8; // Entry point valid

const FTYPE_APPLICATION: u32 = 0x0405_1957; // CantripOS application
const FTYPE_SPRINGBOK: u32 = 0x1014_1955; // Springbok model
const FTYPE_KELVIN: u32 = 0x0124_1998; // Kelvin model

/// Given a set of ELF flags, convert into a set of flags for a section
/// recognizable by the CantripOS ProcessManager's loader.
fn to_section_flags(elf_flags: xmas_elf::program::Flags) -> u32 {
    let mut flags: u32 = 0;

    if elf_flags.is_read() {
        flags |= SECTION_READ as u32
    }
    if elf_flags.is_write() {
        flags |= SECTION_WRITE as u32
    }
    if elf_flags.is_execute() {
        flags |= SECTION_EXEC as u32
    }

    flags
}

#[repr(packed)]
#[allow(dead_code)]
struct SectionHeader {
    magic: u64,
    vaddr: u64,
    entry: u64, // Entry point when SECTION_ENTRY set
    flags: u32, // Derived from ELF program section flags
    fsize: u32,
    msize: u32,
    align: u32, // Section data alignment (bytes)
    ftype: u32, // File type
    crc32: u32,
}

impl SectionHeader {
    fn new(
        ftype: u32,
        vaddr: u64,
        flags: u32,
        entry: u64,
        align: usize,
        crc: u32,
        fsize: usize,
        msize: usize,
    ) -> Self {
        SectionHeader {
            magic: MAGIC.to_be(),
            vaddr: vaddr.to_be(),
            entry: if (flags & (SECTION_ENTRY as u32)) != 0 {
                (entry as u64).to_be()
            } else {
                0
            },
            flags: (flags as u32).to_be(),
            fsize: (fsize as u32).to_be(),
            msize: (msize as u32).to_be(),
            align: (align as u32).to_be(),
            ftype: ftype.to_be(),
            crc32: crc.to_be(),
        }
    }

    fn as_slice(&self) -> &[u8] {
        unsafe {
            // NB: this depends on repr(packed)
            slice::from_raw_parts(ptr::addr_of!(self.magic) as _, size_of::<SectionHeader>())
        }
    }

    /// Writes section header followed by |bytes|.
    fn write(&self, out: &mut File, bytes: &[u8]) -> Result<usize, std::io::Error> {
        assert_eq!(u32::from_be(self.fsize) as usize, bytes.len());
        out.write(self.as_slice()).and_then(|_| out.write(bytes))
    }
}

#[derive(Debug)]
pub enum ConversionError {
    SegmentOutsideTCM(u64),
    SectionTooBig(u64, usize),
    IOError(std::io::Error),
    OtherError(&'static str),
}

impl ConversionError {
    #[allow(dead_code)]
    pub fn as_str(&self) -> String {
        match &*self {
            ConversionError::SegmentOutsideTCM(vaddr) =>
                format!("segment at {:#x} outside TCM", vaddr),
            ConversionError::SectionTooBig(vaddr, size) =>
                format!("section at {:#x} too big for TCM (size was {})", vaddr, size),
            ConversionError::IOError(err) => err.to_string(),
            ConversionError::OtherError(str) => String::from(*str),
        }
    }
}

impl From<&'static str> for ConversionError {
    fn from(s: &'static str) -> ConversionError {
        ConversionError::OtherError(s)
    }
}

impl From<std::io::Error> for ConversionError {
    fn from(e: std::io::Error) -> ConversionError {
        ConversionError::IOError(e)
    }
}

pub mod springbok {
/// Springbok support.

use super::*;

/// Maximum memory size for TCM, used for model loading
const TCM_SIZE: usize = 0x1000000;

/// The virtualized address of each loadable WMMU section (go/sparrow-vc-memory).
const TEXT_VADDR: u64 = 0x80000000;
const CONST_DATA_VADDR: u64 = 0x81000000;
const MODEL_OUTPUT_VADDR: u64 = 0x82000000;
const STATIC_DATA_VADDR: u64 = 0x83000000;
const TEMP_DATA_VADDR: u64 = 0x85000000;

/// Helpful conversion from a ModelSection to a string name of that address
fn vaddr_as_str(vaddr: u64) -> &'static str {
    match vaddr {
        TEXT_VADDR => ".text",
        CONST_DATA_VADDR => ".data",
        MODEL_OUTPUT_VADDR => ".model_output",
        STATIC_DATA_VADDR => ".static",
        TEMP_DATA_VADDR => ".bss",
        _ => "<unknown>",
    }
}

/// Predicate to determine if a given vaddr is loadable in the TCM
fn is_vaddr_in_tcm(vaddr: u64) -> bool {
    matches!(vaddr, TEXT_VADDR | CONST_DATA_VADDR | MODEL_OUTPUT_VADDR | STATIC_DATA_VADDR
             | TEMP_DATA_VADDR)
}

/// Converts an ELF-format ML (Springbok) model into CantripOS' loadable format.
///
/// Returns the number of bytes written.
pub fn model(elf: &ElfFile, output_file: &mut File) -> Result<u64, ConversionError> {
    let entry = elf.header.pt2.entry_point();
    info!("ELF entry point is {:#x}", entry);

    for seg in elf.program_iter().filter(super::is_load_type) {
        let fsize = seg.file_size() as usize;
        let msize = seg.mem_size() as usize;
        let align = seg.align() as usize;
        let mut flags = to_section_flags(seg.flags());
        let vaddr = seg.virtual_addr();
        let segment_name = vaddr_as_str(vaddr);

        debug!("Processing new section [vaddr={:#x}, fsize={:#x}, msize={:#x}, align={:#x}, flags={:#b}]",
               vaddr, fsize, msize, align, flags);
        if fsize > TCM_SIZE {
            return Err(ConversionError::SectionTooBig(vaddr, fsize));
        }

        if let SegmentData::Undefined(bytes) = seg.get_data(elf)? {
            if !is_vaddr_in_tcm(vaddr) {
                return Err(ConversionError::SegmentOutsideTCM(vaddr));
            }

            if seg.virtual_addr() == TEXT_VADDR {
                debug!(
                    "Marking segment {} as entrypoint [vaddr={:#x}, entry={:#x}]",
                    segment_name, vaddr, entry
                );
                flags |= SECTION_ENTRY;
            }

            debug!(
                "Processing {} segment [len={}, addr={:#x}, msize={}]",
                segment_name,
                bytes.len(),
                vaddr,
                msize
            );

            let mut digest = crc32::Digest::new(crc32::IEEE);
            digest.write(bytes);
            let section = SectionHeader::new(
                FTYPE_SPRINGBOK,
                seg.virtual_addr(),
                flags,
                entry,
                align,
                digest.sum32(),
                fsize,
                msize,
            );

            section.write(output_file, bytes)?;
            info!(
                "Wrote {} segment of {} bytes at {:#x} msize {}",
                segment_name,
                bytes.len(),
                seg.virtual_addr(),
                msize
            );
        }
    }

    Ok(output_file.stream_position()?)
}

} // springbok

pub mod kelvin {
/// Kelvin support.

use super::*;

/// Maximum memory size for TCM, used for model loading
const TCM_SIZE: usize = 0x400000;

/// Converts an ELF-format Kelvin workload into CantripOS' loadable format.
///
/// Returns the number of bytes written.
pub fn model(elf: &ElfFile, output_file: &mut File) -> Result<u64, ConversionError> {
    let entry = elf.header.pt2.entry_point() as usize;
    info!("ELF entry point is {:#x}", entry);

    for seg in elf.program_iter().filter(super::is_load_type) {
        let fsize = seg.file_size() as usize;
        let msize = seg.mem_size() as usize;
        let align = seg.align() as usize;
        let mut flags = to_section_flags(seg.flags());
        let vaddr = seg.virtual_addr() as usize;
        let segment_name = "LOAD"; // XXX

        debug!("Processing new section [vaddr={:#x}, fsize={:#x}, msize={:#x}, align={:#x}, flags={:#b}]",
               vaddr, fsize, msize, align, flags);

        if let SegmentData::Undefined(bytes) = seg.get_data(elf)? {
            if vaddr + msize >= TCM_SIZE {
                return Err(ConversionError::SegmentOutsideTCM(vaddr as u64));
            }

            if vaddr <= entry &&  entry < vaddr + msize {
                debug!(
                    "Marking segment {} as entrypoint [vaddr={:#x}, entry={:#x}]",
                    segment_name, vaddr, entry
                );
                flags |= SECTION_ENTRY;
            }

            debug!(
                "Processing {} segment [len={}, addr={:#x}, msize={}]",
                segment_name,
                bytes.len(),
                vaddr,
                msize
            );

            let mut digest = crc32::Digest::new(crc32::IEEE);
            digest.write(bytes);
            let section = SectionHeader::new(
                FTYPE_KELVIN,
                seg.virtual_addr(),
                flags,
                entry as u64,
                align,
                digest.sum32(),
                fsize,
                msize,
            );

            section.write(output_file, bytes)?;
            info!(
                "Wrote {} segment of {} bytes at {:#x} msize {}",
                segment_name,
                bytes.len(),
                seg.virtual_addr(),
                msize
            );
        }
    }

    Ok(output_file.stream_position()?)
}

} // kelvin

/// Converts an ELF-format application binary into CantripOS' loadable format.
///
/// Returns the number of bytes written.
pub fn application(elf: &ElfFile, output_file: &mut File) -> Result<u64, ConversionError> {
    let entry = elf.header.pt2.entry_point();
    info!("ELF entry point is {:#x}", entry);

    // Iterate through all ELF sections, filtering out anything that isn't
    // loadable.
    for seg in elf.program_iter().filter(is_load_type) {
        let vaddr = seg.virtual_addr();
        let fsize = seg.file_size() as usize;
        let msize = seg.mem_size() as usize;
        let align = seg.align() as usize;
        let mut flags = to_section_flags(seg.flags());

        debug!("Processing new section [vaddr={:#x}, fsize={:#x}, msize={:#x}, align={:#x}, flags={:#b}]",
               vaddr, fsize, msize, align, flags);

        // If the entry point for this application is in this section, ensure we
        // mark as such in the flags.
        if vaddr <= entry && entry < vaddr + (msize as u64) {
            debug!("Marking as entrypoint [vaddr={:#x}, entry={:#x}]", vaddr, entry);
            flags |= SECTION_ENTRY;
        }

        if let SegmentData::Undefined(bytes) = seg.get_data(elf)? {
            let mut digest = crc32::Digest::new(crc32::IEEE);
            digest.write(bytes);
            let header = SectionHeader::new(
                FTYPE_APPLICATION,
                seg.virtual_addr(),
                flags,
                entry,
                align,
                digest.sum32(),
                fsize,
                msize,
            );

            header.write(output_file, bytes)?;

            info!(
                "Wrote segment of {} bytes at {:#x} msize {}",
                fsize,
                seg.virtual_addr(),
                msize
            );
        }
    }

    Ok(output_file.stream_position()?)
}

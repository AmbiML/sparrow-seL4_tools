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

//! Convert ELF files to the CantripOS format used for loading models and
//! applications.

use clap::Parser;
use log::*;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::path::Path;
use xmas_elf::ElfFile;

mod convert;

#[derive(clap::ValueEnum, Clone)]
enum FileType {
    App = 0,
    Model,
}

#[derive(Parser)]
#[clap(version, about, long_about = None)]
struct Args {
    /// Which type of file to convert from, be it application or model. Note:
    /// all files must be in ELF format.
    #[clap(short, value_enum)]
    file_type: FileType,

    /// The path of the file to convert.
    #[clap(short, value_parser)]
    input_path: PathBuf,

    /// The path of the file to output to.
    #[clap(short, value_parser)]
    output_path: PathBuf,

    /// Increase logging verbosity, Multiple instances stack.
    #[clap(short, action = clap::ArgAction::Count)]
    verbosity: u8,

    /// Silence all output
    #[clap(short)]
    quiet: bool,
}

/// Helper function to open a file and load in the bytes as a Vec.
fn open_and_read_file(name: &Path) -> Vec<u8> {
    let mut f = File::open(name).unwrap();
    let mut buf = Vec::new();
    assert!(f.read_to_end(&mut buf).unwrap() > 0);
    buf
}

fn main() -> Result<(), convert::ConversionError> {
    let args = Args::parse();

    stderrlog::new()
        .module(module_path!())
        .quiet(args.quiet)
        .verbosity(args.verbosity as usize)
        .timestamp(stderrlog::Timestamp::Off)
        .init()
        .unwrap();

    let mut output_file = File::create(args.output_path.as_path()).unwrap();
    let contents = open_and_read_file(&args.input_path);
    let elf = ElfFile::new(contents.as_slice()).unwrap();

    match args.file_type {
        FileType::App => {
            let count = convert::application(&elf, &mut output_file)?;
            info!("Wrote {} bytes.", count);
        }
        FileType::Model => {
            let count = convert::model(&elf, &mut output_file)?;
            info!("Wrote {} bytes.", count);
        }
    }

    Ok(())
}

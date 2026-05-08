use std::{env, fs, io::Write, path::PathBuf, process};

use eyre::{eyre, Result, WrapErr};
use openvm_sdk::{
    config::{AggregationSystemParams, AppConfig},
    Sdk, StdIn,
};
use openvm_sdk_config::SdkVmConfig;

const SSZ_OUTPUT_LEN: usize = 41;
const NUM_PUBLIC_VALUES: usize = 64;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <elf_path> <input_file> [-o <output_file>]", args[0]);
        process::exit(1);
    }

    let elf_path = PathBuf::from(&args[1]);
    let input_path = PathBuf::from(&args[2]);

    let mut output_path: Option<PathBuf> = None;
    let mut i = 3;
    while i < args.len() {
        if args[i] == "-o" && i + 1 < args.len() {
            output_path = Some(PathBuf::from(&args[i + 1]));
            i += 2;
        } else {
            i += 1;
        }
    }

    // Build VM config: rv64i + rv64m + io, with 64 public value bytes.
    let mut vm_config = SdkVmConfig::riscv64();
    let updated_system = vm_config.as_ref().clone().with_public_values(NUM_PUBLIC_VALUES);
    *vm_config.as_mut() = updated_system;

    // Deserialize a minimal TOML to get the correct default system_params (STARK proof params).
    // We only care about the app_vm_config here; system_params are not used in execute().
    let minimal_toml = "[app_vm_config.rv64i]\n[app_vm_config.rv64m]\n[app_vm_config.io]\n";
    let mut app_config: AppConfig<SdkVmConfig> = toml::from_str(minimal_toml)
        .wrap_err("building app config")?;
    app_config.app_vm_config = vm_config;

    let sdk = Sdk::new(app_config, AggregationSystemParams::default())?;

    // Feed the raw input file as a single hint-stream entry.
    let input_bytes = fs::read(&input_path)
        .wrap_err_with(|| format!("reading {}", input_path.display()))?;
    let stdin = StdIn::from_bytes(&input_bytes);

    // Pass raw ELF bytes; ExecutableFormat::from(Vec<u8>) calls Elf::decode internally.
    let elf_bytes = fs::read(&elf_path)
        .wrap_err_with(|| format!("reading {}", elf_path.display()))?;

    let public_values = sdk.execute(elf_bytes, stdin)?;

    if public_values.len() < SSZ_OUTPUT_LEN {
        return Err(eyre!(
            "public values too short: {} bytes, expected >= {}",
            public_values.len(),
            SSZ_OUTPUT_LEN
        ));
    }
    let output = &public_values[..SSZ_OUTPUT_LEN];

    match output_path {
        Some(ref path) => {
            fs::write(path, output)
                .wrap_err_with(|| format!("writing {}", path.display()))?;
            eprintln!("Output written to {}", path.display());
        }
        None => {
            std::io::stdout().write_all(output)?;
        }
    }

    Ok(())
}

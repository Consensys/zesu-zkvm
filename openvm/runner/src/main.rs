use std::{env, fs, io::Write, path::PathBuf, process};

use eyre::{eyre, Result, WrapErr};
use openvm_sdk::{
    config::{AggregationSystemParams, AppConfig},
    openvm_circuit::{
        arch::{
            execution_mode::MeteredCostCtx, VmExecutionConfig, VmExecutor,
        },
        system::memory::merkle::public_values::extract_public_values,
    },
    Sdk, StdIn, F,
};
use openvm_sdk_config::SdkVmConfig;

const SSZ_OUTPUT_LEN: usize = 105;
const NUM_PUBLIC_VALUES: usize = 112;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let mut elf_path: Option<PathBuf> = None;
    let mut input_path: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut metered = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-X" => { metered = true; }
            "-e" if i + 1 < args.len() => { elf_path   = Some(PathBuf::from(&args[i + 1])); i += 1; }
            "-i" if i + 1 < args.len() => { input_path = Some(PathBuf::from(&args[i + 1])); i += 1; }
            "-o" if i + 1 < args.len() => { output_path = Some(PathBuf::from(&args[i + 1])); i += 1; }
            other => { eprintln!("unknown argument: {}", other); process::exit(1); }
        }
        i += 1;
    }

    let elf_path = elf_path.unwrap_or_else(|| {
        eprintln!("Usage: {} -e <elf_path> -i <input_file> [-X] [-o <output_file>]", args[0]);
        process::exit(1);
    });
    let input_path = input_path.unwrap_or_else(|| {
        eprintln!("Usage: {} -e <elf_path> -i <input_file> [-X] [-o <output_file>]", args[0]);
        process::exit(1);
    });

    // Build VM config: rv64i + rv64m + io, with 64 public value bytes.
    // NOTE: requires a fork of openvm with rv64 support (SdkVmConfig::riscv64).
    let mut vm_config = SdkVmConfig::riscv64();
    let updated_system = vm_config.as_ref().clone().with_public_values(NUM_PUBLIC_VALUES);
    *vm_config.as_mut() = updated_system;

    // Deserialize a minimal TOML to get the correct default system_params.
    // We only care about the app_vm_config here; system_params are not used in execute().
    let minimal_toml = "[app_vm_config.rv64i]\n[app_vm_config.rv64m]\n[app_vm_config.io]\n";
    let mut app_config: AppConfig<SdkVmConfig> = toml::from_str(minimal_toml)
        .wrap_err("building app config")?;
    app_config.app_vm_config = vm_config.clone();

    let sdk = Sdk::new(app_config, AggregationSystemParams::default())?;

    // Feed the raw input file as a single hint-stream entry.
    let input_bytes = fs::read(&input_path)
        .wrap_err_with(|| format!("reading {}", input_path.display()))?;
    let stdin = StdIn::from_bytes(&input_bytes);

    // Pass raw ELF bytes; ExecutableFormat::from(Vec<u8>) calls Elf::decode internally.
    let elf_bytes = fs::read(&elf_path)
        .wrap_err_with(|| format!("reading {}", elf_path.display()))?;

    let (public_values, instret) = if metered {
        execute_metered(&sdk, vm_config, elf_bytes, stdin)?
    } else {
        let pv = sdk.execute(elf_bytes, stdin)?;
        (pv, 0u64)
    };

    // -X: emit a COST DISTRIBUTION table on stderr for bench tool metrics scraping.
    // INSTRUCTIONS is the retired instruction count — a deterministic complexity metric
    // unaffected by host CPU load or parallelism. TOTAL mirrors it for parsers that
    // only check TOTAL.
    if metered {
        eprintln!("COST DISTRIBUTION");
        eprintln!("INSTRUCTIONS {:>24} 100.00%", instret);
        eprintln!("TOTAL        {:>24} 100.00%", instret);
    }

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
        }
        None => {
            std::io::stdout().write_all(output)?;
        }
    }

    Ok(())
}

/// Execute with instruction-count metering, without triggering AppProvingKey keygen.
///
/// Uses VmExecutor directly (the same executor Sdk::execute() uses) with a
/// MeteredCostCtx whose AIR widths are all zero — this makes cost=0 but leaves
/// instret accurate. The executor_idx_to_air_idx mapping points every executor to
/// slot 0 of the dummy widths array; since width[0]=0, no cost accumulates and
/// no out-of-bounds access occurs.
fn execute_metered(
    sdk: &Sdk,
    vm_config: SdkVmConfig,
    elf_bytes: Vec<u8>,
    stdin: StdIn,
) -> Result<(Vec<u8>, u64)> {
    // Determine the number of executors for this config. All executor indices are
    // in [0, num_executors), so a same-length all-zero mapping is always in-bounds.
    let inventory = <SdkVmConfig as VmExecutionConfig<F>>::create_executors(&vm_config)
        .map_err(|e| eyre!("create executors: {e}"))?;
    let num_executors = inventory.executors.len();
    let executor_idx_to_air_idx = vec![0usize; num_executors];

    // Single zero-width slot: on_height_change(0, delta) → cost += 0*0 = 0.
    let ctx = MeteredCostCtx::new(vec![0usize; 1]);

    // Build executor directly — no keygen.
    let executor: VmExecutor<F, SdkVmConfig> = VmExecutor::new(vm_config)
        .map_err(|e| eyre!("build executor: {e}"))?;

    // Transpile ELF using the SDK's configured transpiler (rv64i + rv64m + io).
    let exe = sdk.convert_to_exe(elf_bytes)
        .map_err(|e| eyre!("convert ELF: {e}"))?;

    let interpreter = executor
        .metered_cost_instance(&exe, &executor_idx_to_air_idx)
        .map_err(|e| eyre!("build interpreter: {e}"))?;

    let (ctx, final_state) = interpreter
        .execute_metered_cost(stdin, ctx)
        .map_err(|e| eyre!("execute: {e}"))?;

    // MemoryImage = AddressMap; final_state.memory.memory is the MemoryImage.
    let public_values = extract_public_values(NUM_PUBLIC_VALUES, &final_state.memory.memory);

    Ok((public_values, ctx.instret))
}

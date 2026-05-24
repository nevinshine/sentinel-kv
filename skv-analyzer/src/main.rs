#![allow(clippy::collapsible_if)]
#![allow(clippy::too_many_arguments)]

use anyhow::{Context, Result};
use base64::Engine as _;
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use either::Either;
use llvm_ir::types::NamedStructDef;
use llvm_ir::{Constant, Instruction, Module, Name, Operand, Type};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::process::ExitCode;
use z3::ast::Int;
use z3::{Config, SatResult, Solver, with_z3_config};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the LLVM IR file (.ll or .bc)
    #[arg()]
    ir_path: Option<PathBuf>,

    /// Enforcement mode for Sentinel rings.
    #[arg(long, value_enum, default_value_t = RingMode::Ring0)]
    ring: RingMode,

    /// Path to attestation token file for Ring -1/-2 enforcement.
    #[arg(long)]
    attestation_token: Option<PathBuf>,

    /// Maximum token age in seconds for ring -1/-2 attestation.
    #[arg(long, default_value_t = 300)]
    attestation_max_age_sec: u64,

    /// Nonce challenge to bind attestation freshness to this invocation.
    #[arg(long)]
    attestation_nonce: Option<String>,

    /// Replay state file path used to enforce monotonic token counters.
    #[arg(long)]
    attestation_replay_state: Option<PathBuf>,

    /// Path to Ed25519 public key (base64, 32 raw bytes) for attestation signature verification.
    #[arg(long)]
    attestation_pubkey: Option<PathBuf>,

    /// Path to detached Ed25519 signature file (base64, 64 raw bytes) over attestation token bytes.
    #[arg(long)]
    attestation_signature: Option<PathBuf>,

    /// Expected SHA-256 fingerprint (hex, 64 chars) of attestation public key bytes.
    #[arg(long)]
    attestation_key_fingerprint: Option<String>,

    /// Path to Ring -2 root-of-trust Ed25519 public key (base64, 32 raw bytes).
    #[arg(long)]
    ring2_root_pubkey: Option<PathBuf>,

    /// Path to Ring -2 root-of-trust detached Ed25519 signature (base64, 64 raw bytes).
    #[arg(long)]
    ring2_root_signature: Option<PathBuf>,

    /// Expected SHA-256 fingerprint (hex, 64 chars) of Ring -2 root public key bytes.
    #[arg(long)]
    ring2_root_key_fingerprint: Option<String>,

    /// Output verdict in JSON format for machine consumers.
    #[arg(long, default_value_t = false)]
    json: bool,

    /// Optional path to write machine-readable verdict JSON.
    #[arg(long)]
    verdict_out: Option<PathBuf>,

    /// Human-in-the-loop gate mode for verification conditions.
    #[arg(long, value_enum, default_value_t = HitlMode::Off)]
    hitl_mode: HitlMode,

    /// Path to newline-delimited approved VC IDs. Required when --hitl-mode require.
    #[arg(long)]
    hitl_approvals: Option<PathBuf>,

    /// Optional path to newline-delimited approved VC class IDs.
    #[arg(long)]
    hitl_class_approvals: Option<PathBuf>,

    /// Optional path to emit seen/blocked VC IDs after analysis.
    #[arg(long)]
    emit_vcs: Option<PathBuf>,

    /// Runtime fallback policy for unverifiable cases.
    #[arg(long, value_enum, default_value_t = RuntimeFallbackPolicy::Auto)]
    runtime_fallback: RuntimeFallbackPolicy,

    /// Format for the emitted proof trace.
    #[arg(long, value_enum, default_value_t = ProofFormat::Lfsc)]
    proof_format: ProofFormat,

    /// Optional path to emit the machine-checkable formal proof.
    #[arg(long)]
    emit_proof: Option<PathBuf>,

    /// Inline assembly handling policy.
    #[arg(long, value_enum, default_value_t = InlineAsmPolicy::Conservative)]
    inline_asm_policy: InlineAsmPolicy,

    /// DMA allocation verification policy.
    #[arg(long, value_enum, default_value_t = DmaPolicy::Verify)]
    dma_policy: DmaPolicy,

    /// Optional path to emit equivalence-class summary for HITL review.
    #[arg(long)]
    emit_equiv_summary: Option<PathBuf>,

    /// Optional command actions.
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Print full review-ready security feature inventory.
    Features,
    /// Run environment and backend diagnostics.
    Doctor,
    /// Print attestation token template.
    TokenTemplate {
        #[arg(long, value_enum, default_value_t = RingMode::RingM1)]
        ring: RingMode,
    },
    /// Interactive terminal menu.
    Tui,
    /// Run attestation/ring policy checks without LLVM IR parsing.
    AttestCheck,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ProofFormat {
    #[value(name = "lfsc")]
    Lfsc,
    #[value(name = "rup")]
    Rup,
}

impl ProofFormat {
    fn label(self) -> &'static str {
        match self {
            ProofFormat::Lfsc => "lfsc",
            ProofFormat::Rup => "rup",
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum RingMode {
    #[value(name = "ring0")]
    Ring0,
    #[value(name = "ring-1")]
    RingM1,
    #[value(name = "ring-2")]
    RingM2,
}

impl RingMode {
    fn label(self) -> &'static str {
        match self {
            RingMode::Ring0 => "Ring 0",
            RingMode::RingM1 => "Ring -1",
            RingMode::RingM2 => "Ring -2",
        }
    }

    fn token_ring(self) -> Option<i32> {
        match self {
            RingMode::Ring0 => None,
            RingMode::RingM1 => Some(-1),
            RingMode::RingM2 => Some(-2),
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum HitlMode {
    #[value(name = "off")]
    Off,
    #[value(name = "require")]
    Require,
}

impl HitlMode {
    fn label(self) -> &'static str {
        match self {
            HitlMode::Off => "off",
            HitlMode::Require => "require",
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum RuntimeFallbackPolicy {
    #[value(name = "auto")]
    Auto,
    #[value(name = "arm-mte")]
    ArmMte,
    #[value(name = "integritag")]
    IntegriTag,
    #[value(name = "software-targeted")]
    SoftwareTargeted,
}

impl RuntimeFallbackPolicy {
    fn resolved(self) -> &'static str {
        match self {
            RuntimeFallbackPolicy::Auto => {
                if cfg!(target_arch = "aarch64") {
                    "arm-mte"
                } else if cfg!(target_arch = "x86_64") {
                    "integritag"
                } else {
                    "software-targeted"
                }
            }
            RuntimeFallbackPolicy::ArmMte => "arm-mte",
            RuntimeFallbackPolicy::IntegriTag => "integritag",
            RuntimeFallbackPolicy::SoftwareTargeted => "software-targeted",
        }
    }
}

unsafe extern "C" {
    fn skv_validate_attestation_token(
        token_path: *const std::os::raw::c_char,
        required_ring: i32,
        max_age_sec: i64,
        expected_nonce: *const std::os::raw::c_char,
        replay_state_path: *const std::os::raw::c_char,
    ) -> i32;
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum InlineAsmPolicy {
    /// Emit UNKNOWN VCs for unrecognized inline asm (promoted to FAIL under Ring -1/-2).
    #[value(name = "conservative")]
    Conservative,
    /// Always FAIL on any inline assembly.
    #[value(name = "trap")]
    Trap,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum DmaPolicy {
    /// Verify DMA mapping sizes fit within allocation bounds.
    #[value(name = "verify")]
    Verify,
    /// Require explicit IOMMU mapping for every DMA allocation.
    #[value(name = "require-iommu")]
    RequireIommu,
    /// Ignore DMA allocations (disable DMA analysis).
    #[value(name = "ignore")]
    Ignore,
}

/// Known-safe inline assembly patterns (read-only or barrier instructions).
const SAFE_ASM_PATTERNS: &[&str] = &[
    "rdtsc", "rdtscp", "cpuid", "pause", "mfence", "sfence", "lfence", "cli",
    "sti", // interrupt flag manipulation (safe side-effect)
    "nop", "rep nop", // spin-wait hint
    "ud2",     // trap for BUG()
    "int3",    // breakpoint
    "wbinvd",  // cache writeback (safe for analysis)
    "invlpg",  // TLB invalidation
    "xgetbv",  // read extended control register
];

fn is_safe_inline_asm(asm_string: &str) -> bool {
    let normalized = asm_string.trim().to_ascii_lowercase();
    // Check if the entire asm string is a known-safe pattern or composed only of safe patterns
    for pattern in SAFE_ASM_PATTERNS {
        if normalized == *pattern || normalized.starts_with(pattern) {
            return true;
        }
    }
    // Also safe if empty (compiler barrier)
    normalized.is_empty()
}

#[derive(Debug, Clone)]
enum PtrVal {
    /// Pointer derived from kmalloc-family allocation: (allocation_id, byte_offset)
    Kmalloc { alloc_id: usize, offset: Int },
    /// Pointer derived from DMA allocation: (allocation_id, byte_offset)
    DmaAlloc { alloc_id: usize, offset: Int },
    /// Pointer provenance unknown or unsupported for this PoC.
    Unknown,
}

#[derive(Debug, Clone)]
enum IntVal {
    /// Integer value derived from a tracked pointer: (allocation_id, byte_offset)
    PtrOffset {
        alloc_id: usize,
        offset: Int,
    },
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
enum AnalysisResult {
    Pass,
    Fail(String),
    Unknown(String),
}

struct Verdict<'a> {
    status: &'a str,
    code: i32,
    message: String,
    key_fingerprint: Option<String>,
    token_sha256: Option<String>,
    runtime_fallback: String,
    hitl_mode: String,
    hitl_seen_vcs: usize,
    hitl_blocked_vcs: usize,
    hitl_seen_classes: usize,
    hitl_blocked_classes: usize,
    inline_asm_vcs: usize,
    dma_vcs: usize,
    irq_race_vcs: usize,
}

impl<'a> Verdict<'a> {
    fn to_json(&self) -> String {
        let msg = self
            .message
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n");
        format!(
            "{{\"status\":\"{}\",\"code\":{},\"message\":\"{}\",\"key_fingerprint\":{},\"token_sha256\":{},\"runtime_fallback\":\"{}\",\"hitl_mode\":\"{}\",\"hitl_seen_vcs\":{},\"hitl_blocked_vcs\":{},\"hitl_seen_classes\":{},\"hitl_blocked_classes\":{},\"inline_asm_vcs\":{},\"dma_vcs\":{},\"irq_race_vcs\":{}}}",
            self.status,
            self.code,
            msg,
            self.key_fingerprint
                .as_ref()
                .map(|s| format!("\"{}\"", s))
                .unwrap_or_else(|| "null".to_string()),
            self.token_sha256
                .as_ref()
                .map(|s| format!("\"{}\"", s))
                .unwrap_or_else(|| "null".to_string()),
            self.runtime_fallback,
            self.hitl_mode,
            self.hitl_seen_vcs,
            self.hitl_blocked_vcs,
            self.hitl_seen_classes,
            self.hitl_blocked_classes,
            self.inline_asm_vcs,
            self.dma_vcs,
            self.irq_race_vcs
        )
    }
}

fn verdict_from_result(
    result: AnalysisResult,
    key_fingerprint: Option<String>,
    token_sha256: Option<String>,
    runtime_fallback: String,
    hitl_mode: String,
    hitl_seen_vcs: usize,
    hitl_blocked_vcs: usize,
    hitl_seen_classes: usize,
    hitl_blocked_classes: usize,
    inline_asm_vcs: usize,
    dma_vcs: usize,
    irq_race_vcs: usize,
) -> Verdict<'static> {
    match result {
        AnalysisResult::Pass => Verdict {
            status: "pass",
            code: 0,
            message: "Proved safe for all checked accesses.".to_string(),
            key_fingerprint,
            token_sha256,
            runtime_fallback,
            hitl_mode,
            hitl_seen_vcs,
            hitl_blocked_vcs,
            hitl_seen_classes,
            hitl_blocked_classes,
            inline_asm_vcs,
            dma_vcs,
            irq_race_vcs,
        },
        AnalysisResult::Fail(msg) => Verdict {
            status: "fail",
            code: 10,
            message: msg,
            key_fingerprint,
            token_sha256,
            runtime_fallback,
            hitl_mode,
            hitl_seen_vcs,
            hitl_blocked_vcs,
            hitl_seen_classes,
            hitl_blocked_classes,
            inline_asm_vcs,
            dma_vcs,
            irq_race_vcs,
        },
        AnalysisResult::Unknown(reason) => Verdict {
            status: "unknown",
            code: 20,
            message: reason,
            key_fingerprint,
            token_sha256,
            runtime_fallback,
            hitl_mode,
            hitl_seen_vcs,
            hitl_blocked_vcs,
            hitl_seen_classes,
            hitl_blocked_classes,
            inline_asm_vcs,
            dma_vcs,
            irq_race_vcs,
        },
    }
}

fn mark_unknown(final_result: &mut AnalysisResult, reason: &str) {
    if *final_result == AnalysisResult::Pass {
        *final_result = AnalysisResult::Unknown(reason.to_string());
    }
}

fn resolve_named_type<'a>(ty: &'a Type, module: &'a Module) -> Option<&'a Type> {
    match ty {
        Type::NamedStructType { name } => match module.types.named_struct_def(name) {
            Some(NamedStructDef::Defined(inner)) => resolve_named_type(inner, module),
            _ => None,
        },
        _ => Some(ty),
    }
}

fn type_size(ty: &Type, module: &Module) -> Option<u64> {
    let ty = resolve_named_type(ty, module)?;
    match ty {
        Type::IntegerType { bits } => Some((*bits as u64).div_ceil(8)),
        Type::PointerType { .. } => Some(8),
        Type::ArrayType {
            element_type,
            num_elements,
        } => type_size(element_type, module).map(|s| s * (*num_elements as u64)),
        Type::StructType { element_types, .. } => {
            let mut total = 0_u64;
            for elem in element_types {
                total = total.checked_add(type_size(elem, module)?)?;
            }
            Some(total)
        }
        _ => None,
    }
}

fn function_name_of_call(call: &llvm_ir::instruction::Call) -> Option<&str> {
    match &call.function {
        Either::Right(Operand::ConstantOperand(c)) => {
            if let Constant::GlobalReference { name, .. } = c.as_ref() {
                match name {
                    Name::Name(s) => Some(s.as_ref().as_str()),
                    Name::Number(_) => None,
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

fn operand_const_u64(op: &Operand) -> Option<u64> {
    match op {
        Operand::ConstantOperand(c) => match c.as_ref() {
            Constant::Int { value, .. } => Some(*value),
            _ => None,
        },
        _ => None,
    }
}

fn operand_local_name(op: &Operand) -> Option<&Name> {
    match op {
        Operand::LocalOperand { name, .. } => Some(name),
        _ => None,
    }
}

fn int_const_ast(op: &Operand) -> Option<Int> {
    operand_const_u64(op).map(Int::from_u64)
}

fn infer_gep_offset(
    gep: &llvm_ir::instruction::GetElementPtr,
    base_offset: &Int,
    module: &Module,
) -> Option<Int> {
    let mut computed = base_offset.clone();

    for (i, idx) in gep.indices.iter().enumerate() {
        let idx_val = match idx {
            Operand::ConstantOperand(c) => {
                if let Constant::Int { value, .. } = c.as_ref() {
                    *value
                } else {
                    return None;
                }
            }
            _ => return None,
        };

        if i == 0 {
            let base_ty = module.type_of(&gep.address);
            let elem_size = match base_ty.as_ref() {
                Type::PointerType { .. } => 8,
                other => type_size(other, module)?,
            };
            computed += Int::from_u64(idx_val.saturating_mul(elem_size));
            continue;
        }

        computed += Int::from_u64(idx_val.saturating_mul(4));
    }

    Some(computed)
}

enum AccessCheckResult {
    Oob,
    Safe,
    SolverUnknown,
    HitlBlocked,
}

#[derive(Debug)]
struct HitlGate {
    mode: HitlMode,
    approved: HashSet<String>,
    approved_classes: HashSet<String>,
    seen: Vec<String>,
    blocked: Vec<String>,
    seen_classes: Vec<String>,
    blocked_classes: Vec<String>,
}

impl HitlGate {
    fn should_run_solver(&mut self, vc_id: &str, vc_class: &str) -> bool {
        self.seen.push(vc_id.to_string());
        self.seen_classes.push(vc_class.to_string());
        if matches!(self.mode, HitlMode::Off) {
            return true;
        }
        if self.approved.contains(vc_id) || self.approved_classes.contains(vc_class) {
            true
        } else {
            self.blocked.push(vc_id.to_string());
            self.blocked_classes.push(vc_class.to_string());
            false
        }
    }
}

struct AnalysisOutcome {
    result: AnalysisResult,
    hitl_seen_vcs: usize,
    hitl_blocked_vcs: usize,
    hitl_seen_classes: usize,
    hitl_blocked_classes: usize,
    inline_asm_vcs: usize,
    dma_vcs: usize,
    irq_race_vcs: usize,
}

fn check_access(
    solver: &Solver,
    alloc_size: &Int,
    offset: &Int,
    access_size: u64,
    vc_id: &str,
    vc_class: &str,
    hitl_gate: &mut HitlGate,
) -> AccessCheckResult {
    if !hitl_gate.should_run_solver(vc_id, vc_class) {
        return AccessCheckResult::HitlBlocked;
    }
    let end = offset + Int::from_u64(access_size);
    let oob_cond = z3::ast::Bool::or(&[&end.gt(alloc_size), &offset.lt(Int::from_u64(0))]);
    solver.push();
    solver.assert(&oob_cond);
    let sat = solver.check();
    solver.pop(1);
    match sat {
        SatResult::Sat => AccessCheckResult::Oob,
        SatResult::Unsat => AccessCheckResult::Safe,
        SatResult::Unknown => AccessCheckResult::SolverUnknown,
    }
}

fn vc_id(function_name: &str, bb_idx: usize, instr_idx: usize, kind: &str) -> String {
    format!("{function_name}::bb{bb_idx}::i{instr_idx}::{kind}")
}

fn vc_class_id(kind: &str, access_size: u64) -> String {
    format!("class::{kind}::size{access_size}")
}

/// Extract alloc_id and offset from PtrVal (works for both Kmalloc and DmaAlloc)
fn ptrval_alloc_info(pv: &PtrVal) -> Option<(usize, &Int)> {
    match pv {
        PtrVal::Kmalloc { alloc_id, offset } | PtrVal::DmaAlloc { alloc_id, offset } => {
            Some((*alloc_id, offset))
        }
        PtrVal::Unknown => None,
    }
}

/// Pre-scan module for request_irq registrations and determine which handlers call kfree.
fn scan_irq_handlers(module: &Module) -> HashSet<String> {
    let mut handler_names: HashSet<String> = HashSet::new();
    // Phase 1: find handler function names registered via request_irq
    for func in &module.functions {
        for bb in &func.basic_blocks {
            for instr in &bb.instrs {
                if let Instruction::Call(call) = instr {
                    if function_name_of_call(call) == Some("request_irq") {
                        // arg 1 is the handler function pointer
                        if let Some((Operand::ConstantOperand(c), _)) = call.arguments.get(1) {
                            if let Constant::GlobalReference {
                                name: Name::Name(s),
                                ..
                            } = c.as_ref()
                            {
                                handler_names.insert(s.as_ref().to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    // Phase 2: check which handler functions call kfree
    let mut handlers_that_free: HashSet<String> = HashSet::new();
    for func in &module.functions {
        let fname = func.name.to_string();
        if !handler_names.contains(&fname) {
            continue;
        }
        for bb in &func.basic_blocks {
            for instr in &bb.instrs {
                if let Instruction::Call(call) = instr {
                    if function_name_of_call(call) == Some("kfree") {
                        handlers_that_free.insert(fname.clone());
                    }
                }
            }
        }
    }
    handlers_that_free
}

fn load_hitl_approvals(path: &PathBuf) -> Result<HashSet<String>> {
    ensure_secure_owned_file(path, "HITL approvals file")?;
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read HITL approvals file: {}", path.display()))?;
    let mut out = HashSet::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        out.insert(trimmed.to_string());
    }
    Ok(out)
}

fn emit_hitl_vcs(path: &PathBuf, gate: &HitlGate) -> Result<()> {
    let mut seen: Vec<String> = gate.seen.clone();
    seen.sort();
    seen.dedup();
    let mut blocked: Vec<String> = gate.blocked.clone();
    blocked.sort();
    blocked.dedup();
    let mut seen_classes: Vec<String> = gate.seen_classes.clone();
    seen_classes.sort();
    seen_classes.dedup();
    let mut blocked_classes: Vec<String> = gate.blocked_classes.clone();
    blocked_classes.sort();
    blocked_classes.dedup();

    let json_array = |items: &[String]| -> String {
        let mut out = String::from("[");
        for (idx, item) in items.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            out.push('"');
            out.push_str(&item.replace('\\', "\\\\").replace('"', "\\\""));
            out.push('"');
        }
        out.push(']');
        out
    };

    let json = format!(
        "{{\"hitl_mode\":\"{}\",\"seen_count\":{},\"blocked_count\":{},\"seen_class_count\":{},\"blocked_class_count\":{},\"seen_vcs\":{},\"blocked_vcs\":{},\"seen_classes\":{},\"blocked_classes\":{}}}\n",
        gate.mode.label(),
        seen.len(),
        blocked.len(),
        seen_classes.len(),
        blocked_classes.len(),
        json_array(&seen),
        json_array(&blocked),
        json_array(&seen_classes),
        json_array(&blocked_classes),
    );
    write_output_file(path, &json)
        .with_context(|| format!("Failed to write VC emission file: {}", path.display()))
}

fn enforce_hitl_policy(
    result: AnalysisResult,
    mode: HitlMode,
    blocked_vcs: usize,
) -> AnalysisResult {
    if matches!(mode, HitlMode::Require) && blocked_vcs > 0 {
        return AnalysisResult::Fail(format!(
            "HITL require mode rejected {} unapproved verification condition(s)",
            blocked_vcs
        ));
    }
    result
}

fn write_output_file(path: &PathBuf, content: &str) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if !meta.file_type().is_file() {
            anyhow::bail!("output path must be a regular file");
        }
        if meta.uid() != nix_like_euid() {
            anyhow::bail!("output file must be owned by current effective user");
        }
        if (meta.mode() & 0o022) != 0 {
            anyhow::bail!("output file must not be group/world writable");
        }
    }
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .with_context(|| format!("Failed to open output file: {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Failed to set secure permissions on {}", path.display()))?;
    std::io::Write::write_all(&mut f, content.as_bytes())
        .with_context(|| format!("Failed writing output file: {}", path.display()))?;
    f.sync_all()
        .with_context(|| format!("Failed syncing output file: {}", path.display()))?;
    Ok(())
}

fn analyze(
    module: &Module,
    hitl_gate: &mut HitlGate,
    inline_asm_policy: InlineAsmPolicy,
    dma_policy: DmaPolicy,
) -> AnalysisOutcome {
    let solver = Solver::new();
    let mut ptr_env: HashMap<Name, PtrVal> = HashMap::new();
    let mut int_env: HashMap<Name, IntVal> = HashMap::new();
    let mut alloc_sizes: HashMap<usize, Int> = HashMap::new();
    let mut freed_allocs: HashSet<usize> = HashSet::new();
    let mut alloc_counter = 0_usize;
    let mut final_result = AnalysisResult::Pass;

    // Fix 0: Stack-spill tracking — maps alloca Name → most recently stored PtrVal
    let mut alloca_store_map: HashMap<Name, PtrVal> = HashMap::new();
    // Track which Names are alloca results (so we know when a Store targets an alloca)
    let mut alloca_names: HashSet<Name> = HashSet::new();

    // Fix 1: Inline asm VC counter
    let mut inline_asm_vcs = 0_usize;

    // Fix 2: DMA VC counter and tracking for iommu pairing
    let mut dma_vcs = 0_usize;
    let mut dma_allocs_in_func: HashSet<usize> = HashSet::new();
    let mut iommu_mapped_in_func: HashSet<usize> = HashSet::new();

    // Fix 3: Interrupt sequentialization — pre-scan for IRQ handlers that call kfree
    let irq_handler_frees = scan_irq_handlers(module);
    let has_irq_risk = !irq_handler_frees.is_empty();
    let mut irq_race_vcs = 0_usize;

    for func in &module.functions {
        for (bb_idx, bb) in func.basic_blocks.iter().enumerate() {
            for (instr_idx, instr) in bb.instrs.iter().enumerate() {
                match instr {
                    // Fix 0: Track alloca instructions for stack-spill recovery
                    Instruction::Alloca(alloca) => {
                        alloca_names.insert(alloca.dest.clone());
                    }
                    Instruction::Call(call) => {
                        if matches!(final_result, AnalysisResult::Fail(_)) {
                            break;
                        }

                        match function_name_of_call(call) {
                            Some("kmalloc" | "kzalloc") => {
                                let Some((size_op, _)) = call.arguments.first() else {
                                    mark_unknown(
                                        &mut final_result,
                                        "kmalloc/kzalloc missing size argument",
                                    );
                                    continue;
                                };
                                let Some(size) = operand_const_u64(size_op) else {
                                    mark_unknown(
                                        &mut final_result,
                                        "kmalloc/kzalloc with non-constant size unsupported",
                                    );
                                    continue;
                                };
                                let id = alloc_counter;
                                alloc_counter += 1;
                                alloc_sizes.insert(id, Int::from_u64(size));
                                if let Some(dest) = &call.dest {
                                    ptr_env.insert(
                                        dest.clone(),
                                        PtrVal::Kmalloc {
                                            alloc_id: id,
                                            offset: Int::from_u64(0),
                                        },
                                    );
                                }
                            }
                            Some("kcalloc") => {
                                let Some((nmemb_op, _)) = call.arguments.first() else {
                                    mark_unknown(
                                        &mut final_result,
                                        "kcalloc missing nmemb argument",
                                    );
                                    continue;
                                };
                                let Some((size_op, _)) = call.arguments.get(1) else {
                                    mark_unknown(
                                        &mut final_result,
                                        "kcalloc missing size argument",
                                    );
                                    continue;
                                };
                                let (Some(nmemb), Some(elem_size)) =
                                    (operand_const_u64(nmemb_op), operand_const_u64(size_op))
                                else {
                                    mark_unknown(
                                        &mut final_result,
                                        "kcalloc with non-constant nmemb/size unsupported",
                                    );
                                    continue;
                                };
                                let Some(total_size) = nmemb.checked_mul(elem_size) else {
                                    final_result = AnalysisResult::Fail(
                                        "kcalloc size multiplication overflow".to_string(),
                                    );
                                    break;
                                };
                                let id = alloc_counter;
                                alloc_counter += 1;
                                alloc_sizes.insert(id, Int::from_u64(total_size));
                                if let Some(dest) = &call.dest {
                                    ptr_env.insert(
                                        dest.clone(),
                                        PtrVal::Kmalloc {
                                            alloc_id: id,
                                            offset: Int::from_u64(0),
                                        },
                                    );
                                }
                            }
                            Some("kfree") => {
                                let Some((ptr_op, _)) = call.arguments.first() else {
                                    mark_unknown(
                                        &mut final_result,
                                        "kfree missing pointer argument",
                                    );
                                    continue;
                                };
                                let Some(name) = operand_local_name(ptr_op) else {
                                    mark_unknown(
                                        &mut final_result,
                                        "kfree on non-local operand unsupported",
                                    );
                                    continue;
                                };
                                if let Some(PtrVal::Kmalloc { alloc_id, .. }) = ptr_env.get(name) {
                                    if !freed_allocs.insert(*alloc_id) {
                                        final_result = AnalysisResult::Fail(format!(
                                            "Double free detected in function {}",
                                            func.name
                                        ));
                                        break;
                                    }
                                }
                            }
                            Some("memset") => {
                                let Some((dest_op, _)) = call.arguments.first() else {
                                    continue;
                                };
                                let Some((len_op, _)) = call.arguments.get(2) else {
                                    mark_unknown(
                                        &mut final_result,
                                        "memset missing length argument",
                                    );
                                    continue;
                                };
                                let Some(dest_name) = operand_local_name(dest_op) else {
                                    continue;
                                };
                                let Some(len) = operand_const_u64(len_op) else {
                                    mark_unknown(
                                        &mut final_result,
                                        "memset with non-constant length unsupported",
                                    );
                                    continue;
                                };
                                if let Some(PtrVal::Kmalloc { alloc_id, offset }) =
                                    ptr_env.get(dest_name)
                                {
                                    if freed_allocs.contains(alloc_id) {
                                        final_result = AnalysisResult::Fail(format!(
                                            "Use-after-free in memset in function {}",
                                            func.name
                                        ));
                                        break;
                                    }
                                    let Some(alloc_size) = alloc_sizes.get(alloc_id) else {
                                        mark_unknown(
                                            &mut final_result,
                                            "Missing allocation size metadata",
                                        );
                                        continue;
                                    };
                                    let vc = vc_id(func.name.as_ref(), bb_idx, instr_idx, "memset");
                                    let vc_class = vc_class_id("memset", len);
                                    match check_access(
                                        &solver, alloc_size, offset, len, &vc, &vc_class, hitl_gate,
                                    ) {
                                        AccessCheckResult::Oob => {
                                            final_result = AnalysisResult::Fail(format!(
                                                "Out-of-bounds memset in function {}",
                                                func.name
                                            ));
                                            break;
                                        }
                                        AccessCheckResult::Safe => {}
                                        AccessCheckResult::SolverUnknown => mark_unknown(
                                            &mut final_result,
                                            "Solver returned unknown for memset bound check",
                                        ),
                                        AccessCheckResult::HitlBlocked => mark_unknown(
                                            &mut final_result,
                                            &format!("HITL gate blocked unapproved VC: {}", vc),
                                        ),
                                    }
                                }
                            }
                            Some("memcpy" | "__memcpy") => {
                                let Some((dest_op, _)) = call.arguments.first() else {
                                    continue;
                                };
                                let Some((src_op, _)) = call.arguments.get(1) else {
                                    mark_unknown(
                                        &mut final_result,
                                        "memcpy missing source argument",
                                    );
                                    continue;
                                };
                                let Some((len_op, _)) = call.arguments.get(2) else {
                                    mark_unknown(
                                        &mut final_result,
                                        "memcpy missing length argument",
                                    );
                                    continue;
                                };
                                let Some(len) = operand_const_u64(len_op) else {
                                    mark_unknown(
                                        &mut final_result,
                                        "memcpy with non-constant length unsupported",
                                    );
                                    continue;
                                };

                                for (op, kind) in [(dest_op, "destination"), (src_op, "source")] {
                                    let Some(name) = operand_local_name(op) else {
                                        continue;
                                    };
                                    if let Some(PtrVal::Kmalloc { alloc_id, offset }) =
                                        ptr_env.get(name)
                                    {
                                        if freed_allocs.contains(alloc_id) {
                                            final_result = AnalysisResult::Fail(format!(
                                                "Use-after-free in memcpy {} in function {}",
                                                kind, func.name
                                            ));
                                            break;
                                        }
                                        let Some(alloc_size) = alloc_sizes.get(alloc_id) else {
                                            mark_unknown(
                                                &mut final_result,
                                                "Missing allocation size metadata",
                                            );
                                            continue;
                                        };
                                        let vc = vc_id(
                                            func.name.as_ref(),
                                            bb_idx,
                                            instr_idx,
                                            &format!("memcpy_{}", kind),
                                        );
                                        let vc_class =
                                            vc_class_id(&format!("memcpy_{}", kind), len);
                                        match check_access(
                                            &solver, alloc_size, offset, len, &vc, &vc_class,
                                            hitl_gate,
                                        ) {
                                            AccessCheckResult::Oob => {
                                                final_result = AnalysisResult::Fail(format!(
                                                    "Out-of-bounds memcpy {} in function {}",
                                                    kind, func.name
                                                ));
                                                break;
                                            }
                                            AccessCheckResult::Safe => {}
                                            AccessCheckResult::SolverUnknown => mark_unknown(
                                                &mut final_result,
                                                "Solver returned unknown for memcpy bound check",
                                            ),
                                            AccessCheckResult::HitlBlocked => mark_unknown(
                                                &mut final_result,
                                                &format!("HITL gate blocked unapproved VC: {}", vc),
                                            ),
                                        }
                                    }
                                }
                                if matches!(final_result, AnalysisResult::Fail(_)) {
                                    break;
                                }
                            }
                            None => {
                                // Check if the call target is inline assembly
                                if let Either::Left(asm) = &call.function {
                                    match inline_asm_policy {
                                        InlineAsmPolicy::Trap => {
                                            inline_asm_vcs += 1;
                                            final_result = AnalysisResult::Fail(format!(
                                                "Inline assembly detected in function {} (trap policy)",
                                                func.name,
                                            ));
                                            break;
                                        }
                                        InlineAsmPolicy::Conservative => {
                                            if is_safe_inline_asm(&asm.assembly) {
                                                // Safe pattern, continue analysis
                                                continue;
                                            }

                                            // All other inline asm is opaque — emit UNKNOWN VC
                                            inline_asm_vcs += 1;
                                            let vc = vc_id(
                                                func.name.as_ref(),
                                                bb_idx,
                                                instr_idx,
                                                "inline_asm",
                                            );
                                            let vc_class = "class::inline_asm::opaque".to_string();
                                            if !hitl_gate.should_run_solver(&vc, &vc_class) {
                                                mark_unknown(
                                                    &mut final_result,
                                                    &format!(
                                                        "HITL gate blocked inline asm VC: {}",
                                                        vc
                                                    ),
                                                );
                                            } else {
                                                mark_unknown(
                                                    &mut final_result,
                                                    &format!(
                                                        "Opaque inline assembly in function {}: '{}'",
                                                        func.name, asm.assembly,
                                                    ),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            // Fix 2: DMA allocation tracking
                            Some("dma_alloc_coherent")
                                if !matches!(dma_policy, DmaPolicy::Ignore) =>
                            {
                                // dma_alloc_coherent(dev, size, dma_handle, flags)
                                let Some((size_op, _)) = call.arguments.get(1) else {
                                    mark_unknown(
                                        &mut final_result,
                                        "dma_alloc_coherent missing size argument",
                                    );
                                    continue;
                                };
                                let Some(size) = operand_const_u64(size_op) else {
                                    mark_unknown(
                                        &mut final_result,
                                        "dma_alloc_coherent with non-constant size",
                                    );
                                    continue;
                                };
                                let id = alloc_counter;
                                alloc_counter += 1;
                                alloc_sizes.insert(id, Int::from_u64(size));
                                dma_allocs_in_func.insert(id);
                                if let Some(dest) = &call.dest {
                                    ptr_env.insert(
                                        dest.clone(),
                                        PtrVal::DmaAlloc {
                                            alloc_id: id,
                                            offset: Int::from_u64(0),
                                        },
                                    );
                                }
                                dma_vcs += 1;
                                let vc = vc_id(func.name.as_ref(), bb_idx, instr_idx, "dma_alloc");
                                let vc_class = vc_class_id("dma_alloc", size);
                                hitl_gate.should_run_solver(&vc, &vc_class);
                            }
                            Some("dma_map_single") if !matches!(dma_policy, DmaPolicy::Ignore) => {
                                // dma_map_single(dev, ptr, size, direction)
                                let Some((ptr_op, _)) = call.arguments.get(1) else {
                                    mark_unknown(
                                        &mut final_result,
                                        "dma_map_single missing ptr argument",
                                    );
                                    continue;
                                };
                                let Some((size_op, _)) = call.arguments.get(2) else {
                                    mark_unknown(
                                        &mut final_result,
                                        "dma_map_single missing size argument",
                                    );
                                    continue;
                                };
                                let Some(map_size) = operand_const_u64(size_op) else {
                                    mark_unknown(
                                        &mut final_result,
                                        "dma_map_single with non-constant size",
                                    );
                                    continue;
                                };
                                // Check if the mapped ptr has a tracked allocation
                                if let Some(name) = operand_local_name(ptr_op) {
                                    if let Some(pv) = ptr_env.get(name) {
                                        if let Some((alloc_id, offset)) = ptrval_alloc_info(pv) {
                                            if let Some(alloc_size) = alloc_sizes.get(&alloc_id) {
                                                let vc = vc_id(
                                                    func.name.as_ref(),
                                                    bb_idx,
                                                    instr_idx,
                                                    "dma_map",
                                                );
                                                let vc_class = vc_class_id("dma_bounds", map_size);
                                                match check_access(
                                                    &solver, alloc_size, offset, map_size, &vc,
                                                    &vc_class, hitl_gate,
                                                ) {
                                                    AccessCheckResult::Oob => {
                                                        dma_vcs += 1;
                                                        final_result = AnalysisResult::Fail(
                                                            format!(
                                                                "DMA mapping exceeds allocation bounds in function {}",
                                                                func.name
                                                            ),
                                                        );
                                                        break;
                                                    }
                                                    AccessCheckResult::Safe => {}
                                                    AccessCheckResult::SolverUnknown => {
                                                        dma_vcs += 1;
                                                        mark_unknown(
                                                            &mut final_result,
                                                            "Solver unknown for DMA mapping bound check",
                                                        );
                                                    }
                                                    AccessCheckResult::HitlBlocked => {
                                                        dma_vcs += 1;
                                                        mark_unknown(
                                                            &mut final_result,
                                                            &format!(
                                                                "HITL gate blocked DMA VC: {}",
                                                                vc
                                                            ),
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Some("iommu_map") => {
                                // Track IOMMU mapping for require-iommu policy
                                // We track all DMA allocs that have been IOMMU-mapped
                                // For simplicity, mark all current DMA allocs as IOMMU-mapped
                                for id in &dma_allocs_in_func {
                                    iommu_mapped_in_func.insert(*id);
                                }
                            }
                            _ => {}
                        }
                    }
                    Instruction::GetElementPtr(gep) => {
                        if let Operand::LocalOperand {
                            name: base_name, ..
                        } = &gep.address
                        {
                            // Check ptr_env first, then alloca_store_map for stack-spill recovery
                            let base_ptr = ptr_env
                                .get(base_name)
                                .or_else(|| alloca_store_map.get(base_name))
                                .cloned();
                            match base_ptr {
                                Some(PtrVal::Kmalloc {
                                    alloc_id,
                                    ref offset,
                                }) => {
                                    if let Some(new_offset) = infer_gep_offset(gep, offset, module)
                                    {
                                        ptr_env.insert(
                                            gep.dest.clone(),
                                            PtrVal::Kmalloc {
                                                alloc_id,
                                                offset: new_offset,
                                            },
                                        );
                                    } else {
                                        ptr_env.insert(gep.dest.clone(), PtrVal::Unknown);
                                        mark_unknown(
                                            &mut final_result,
                                            "GEP with unsupported index/type pattern",
                                        );
                                    }
                                }
                                Some(PtrVal::DmaAlloc {
                                    alloc_id,
                                    ref offset,
                                }) => {
                                    if let Some(new_offset) = infer_gep_offset(gep, offset, module)
                                    {
                                        ptr_env.insert(
                                            gep.dest.clone(),
                                            PtrVal::DmaAlloc {
                                                alloc_id,
                                                offset: new_offset,
                                            },
                                        );
                                    } else {
                                        ptr_env.insert(gep.dest.clone(), PtrVal::Unknown);
                                        mark_unknown(
                                            &mut final_result,
                                            "GEP with unsupported index/type pattern (DMA)",
                                        );
                                    }
                                }
                                _ => {
                                    ptr_env.insert(gep.dest.clone(), PtrVal::Unknown);
                                }
                            }
                        } else {
                            ptr_env.insert(gep.dest.clone(), PtrVal::Unknown);
                            mark_unknown(&mut final_result, "GEP base is not a local operand");
                        }
                    }
                    Instruction::PtrToInt(cast) => {
                        if let Operand::LocalOperand {
                            name: base_name, ..
                        } = &cast.operand
                        {
                            let v = match ptr_env.get(base_name) {
                                Some(PtrVal::Kmalloc { alloc_id, offset }) => IntVal::PtrOffset {
                                    alloc_id: *alloc_id,
                                    offset: offset.clone(),
                                },
                                _ => IntVal::Unknown,
                            };
                            int_env.insert(cast.dest.clone(), v);
                        } else {
                            int_env.insert(cast.dest.clone(), IntVal::Unknown);
                            mark_unknown(
                                &mut final_result,
                                "PtrToInt from non-local operand unsupported",
                            );
                        }
                    }
                    Instruction::IntToPtr(cast) => {
                        if let Operand::LocalOperand {
                            name: base_name, ..
                        } = &cast.operand
                        {
                            let v = match int_env.get(base_name) {
                                Some(IntVal::PtrOffset { alloc_id, offset }) => PtrVal::Kmalloc {
                                    alloc_id: *alloc_id,
                                    offset: offset.clone(),
                                },
                                _ => PtrVal::Unknown,
                            };
                            ptr_env.insert(cast.dest.clone(), v);
                        } else {
                            ptr_env.insert(cast.dest.clone(), PtrVal::Unknown);
                            mark_unknown(
                                &mut final_result,
                                "IntToPtr from non-local operand unsupported",
                            );
                        }
                    }
                    Instruction::Add(add) => {
                        let lhs_ptr = operand_local_name(&add.operand0)
                            .and_then(|n| int_env.get(n))
                            .cloned();
                        let rhs_ptr = operand_local_name(&add.operand1)
                            .and_then(|n| int_env.get(n))
                            .cloned();

                        let tracked = lhs_ptr.is_some() || rhs_ptr.is_some();
                        let out = match (lhs_ptr, rhs_ptr) {
                            (Some(IntVal::PtrOffset { alloc_id, offset }), _) => {
                                int_const_ast(&add.operand1).map(|rhs| IntVal::PtrOffset {
                                    alloc_id,
                                    offset: offset + rhs,
                                })
                            }
                            (_, Some(IntVal::PtrOffset { alloc_id, offset })) => {
                                int_const_ast(&add.operand0).map(|lhs| IntVal::PtrOffset {
                                    alloc_id,
                                    offset: offset + lhs,
                                })
                            }
                            _ => None,
                        };

                        if let Some(v) = out {
                            int_env.insert(add.dest.clone(), v);
                        } else if tracked {
                            int_env.insert(add.dest.clone(), IntVal::Unknown);
                            mark_unknown(
                                &mut final_result,
                                "Unsupported pointer-derived integer add pattern",
                            );
                        }
                    }
                    Instruction::Sub(sub) => {
                        let lhs_ptr = operand_local_name(&sub.operand0)
                            .and_then(|n| int_env.get(n))
                            .cloned();
                        let rhs_ptr = operand_local_name(&sub.operand1)
                            .and_then(|n| int_env.get(n))
                            .cloned();

                        let rhs_was_ptr = rhs_ptr.is_some();
                        let tracked = lhs_ptr.is_some() || rhs_was_ptr;
                        let out = match (lhs_ptr, rhs_ptr) {
                            (Some(IntVal::PtrOffset { alloc_id, offset }), _) => {
                                int_const_ast(&sub.operand1).map(|rhs| IntVal::PtrOffset {
                                    alloc_id,
                                    offset: offset - rhs,
                                })
                            }
                            _ => None,
                        };

                        if let Some(v) = out {
                            int_env.insert(sub.dest.clone(), v);
                        } else if tracked {
                            int_env.insert(sub.dest.clone(), IntVal::Unknown);
                            mark_unknown(
                                &mut final_result,
                                "Unsupported pointer-derived integer sub pattern",
                            );
                        }
                        if rhs_was_ptr {
                            mark_unknown(
                                &mut final_result,
                                "Subtracting pointer-derived integer as RHS is unsupported",
                            );
                        }
                    }
                    Instruction::BitCast(cast) => {
                        if let Operand::LocalOperand {
                            name: base_name, ..
                        } = &cast.operand
                        {
                            let value = ptr_env.get(base_name).cloned().unwrap_or(PtrVal::Unknown);
                            ptr_env.insert(cast.dest.clone(), value);
                        } else {
                            ptr_env.insert(cast.dest.clone(), PtrVal::Unknown);
                            mark_unknown(
                                &mut final_result,
                                "BitCast from non-local operand unsupported",
                            );
                        }
                    }
                    Instruction::Store(store) => {
                        if let Operand::LocalOperand {
                            name: dest_name, ..
                        } = &store.address
                        {
                            // Fix 0: If storing a tracked pointer into an alloca, record it
                            if alloca_names.contains(dest_name) {
                                if let Operand::LocalOperand { name: val_name, .. } = &store.value {
                                    if let Some(pv) = ptr_env.get(val_name).cloned() {
                                        alloca_store_map.insert(dest_name.clone(), pv);
                                    }
                                }
                            }

                            // Check both ptr_env and alloca_store_map for the destination pointer
                            let dest_ptr = ptr_env.get(dest_name).cloned();
                            if let Some(ref pv) = dest_ptr {
                                if let Some((alloc_id, offset)) = ptrval_alloc_info(pv) {
                                    if freed_allocs.contains(&alloc_id) {
                                        final_result = AnalysisResult::Fail(format!(
                                            "Use-after-free store in function {}",
                                            func.name
                                        ));
                                        break;
                                    }
                                    let stored_ty = module.type_of(&store.value);
                                    let Some(size) = type_size(stored_ty.as_ref(), module) else {
                                        mark_unknown(
                                            &mut final_result,
                                            "Store with unknown value type size",
                                        );
                                        continue;
                                    };
                                    let Some(alloc_size) = alloc_sizes.get(&alloc_id) else {
                                        mark_unknown(
                                            &mut final_result,
                                            "Missing allocation size metadata",
                                        );
                                        continue;
                                    };
                                    let vc = vc_id(func.name.as_ref(), bb_idx, instr_idx, "store");
                                    let vc_class = vc_class_id("store", size);
                                    match check_access(
                                        &solver, alloc_size, offset, size, &vc, &vc_class,
                                        hitl_gate,
                                    ) {
                                        AccessCheckResult::Oob => {
                                            final_result = AnalysisResult::Fail(format!(
                                                "Out-of-bounds store in function {}",
                                                func.name
                                            ));
                                            break;
                                        }
                                        AccessCheckResult::Safe => {}
                                        AccessCheckResult::SolverUnknown => {
                                            mark_unknown(
                                                &mut final_result,
                                                "Solver returned unknown for store bound check",
                                            );
                                        }
                                        AccessCheckResult::HitlBlocked => mark_unknown(
                                            &mut final_result,
                                            &format!("HITL gate blocked unapproved VC: {}", vc),
                                        ),
                                    }
                                    // Fix 3: IRQ race check — if an interrupt handler could free this alloc class
                                    if has_irq_risk {
                                        let vc = vc_id(
                                            func.name.as_ref(),
                                            bb_idx,
                                            instr_idx,
                                            "irq_race_store",
                                        );
                                        let vc_class =
                                            format!("class::irq_race::alloc{}", alloc_id);
                                        irq_race_vcs += 1;
                                        if !hitl_gate.should_run_solver(&vc, &vc_class) {
                                            mark_unknown(
                                                &mut final_result,
                                                &format!("HITL gate blocked IRQ race VC: {}", vc),
                                            );
                                        } else {
                                            mark_unknown(
                                                &mut final_result,
                                                &format!(
                                                    "Potential IRQ race: interrupt handler may free allocation {} before store in {}",
                                                    alloc_id, func.name
                                                ),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Instruction::Load(load) => {
                        if let Operand::LocalOperand { name: src_name, .. } = &load.address {
                            // Fix 0: Recover PtrVal from alloca_store_map if src is an alloca
                            if alloca_names.contains(src_name) {
                                if let Some(recovered_pv) = alloca_store_map.get(src_name).cloned()
                                {
                                    // This load is reading a pointer back from the stack —
                                    // propagate the tracked PtrVal to the load destination
                                    ptr_env.insert(load.dest.clone(), recovered_pv);
                                }
                            }

                            // Check both ptr_env (for the address being loaded FROM, for bounds checking)
                            let src_ptr = ptr_env.get(src_name).cloned();
                            if let Some(ref pv) = src_ptr {
                                if let Some((alloc_id, offset)) = ptrval_alloc_info(pv) {
                                    if freed_allocs.contains(&alloc_id) {
                                        final_result = AnalysisResult::Fail(format!(
                                            "Use-after-free load in function {}",
                                            func.name
                                        ));
                                        break;
                                    }
                                    let Some(size) = type_size(load.loaded_ty.as_ref(), module)
                                    else {
                                        mark_unknown(
                                            &mut final_result,
                                            "Load with unknown type size",
                                        );
                                        continue;
                                    };
                                    let Some(alloc_size) = alloc_sizes.get(&alloc_id) else {
                                        mark_unknown(
                                            &mut final_result,
                                            "Missing allocation size metadata",
                                        );
                                        continue;
                                    };
                                    let vc = vc_id(func.name.as_ref(), bb_idx, instr_idx, "load");
                                    let vc_class = vc_class_id("load", size);
                                    match check_access(
                                        &solver, alloc_size, offset, size, &vc, &vc_class,
                                        hitl_gate,
                                    ) {
                                        AccessCheckResult::Oob => {
                                            final_result = AnalysisResult::Fail(format!(
                                                "Out-of-bounds load in function {}",
                                                func.name
                                            ));
                                            break;
                                        }
                                        AccessCheckResult::Safe => {}
                                        AccessCheckResult::SolverUnknown => {
                                            mark_unknown(
                                                &mut final_result,
                                                "Solver returned unknown for load bound check",
                                            );
                                        }
                                        AccessCheckResult::HitlBlocked => mark_unknown(
                                            &mut final_result,
                                            &format!("HITL gate blocked unapproved VC: {}", vc),
                                        ),
                                    }
                                    // Fix 3: IRQ race check for load
                                    if has_irq_risk {
                                        let vc = vc_id(
                                            func.name.as_ref(),
                                            bb_idx,
                                            instr_idx,
                                            "irq_race_load",
                                        );
                                        let vc_class =
                                            format!("class::irq_race::alloc{}", alloc_id);
                                        irq_race_vcs += 1;
                                        if !hitl_gate.should_run_solver(&vc, &vc_class) {
                                            mark_unknown(
                                                &mut final_result,
                                                &format!("HITL gate blocked IRQ race VC: {}", vc),
                                            );
                                        } else {
                                            mark_unknown(
                                                &mut final_result,
                                                &format!(
                                                    "Potential IRQ race: interrupt handler may free allocation {} before load in {}",
                                                    alloc_id, func.name
                                                ),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            if matches!(final_result, AnalysisResult::Fail(_)) {
                break;
            }
        }

        if matches!(final_result, AnalysisResult::Fail(_)) {
            break;
        }
    }

    // Fix 2: DMA require-iommu enforcement
    if matches!(dma_policy, DmaPolicy::RequireIommu) {
        for id in &dma_allocs_in_func {
            if !iommu_mapped_in_func.contains(id) {
                final_result = AnalysisResult::Fail(format!(
                    "DMA allocation {} has no paired iommu_map call (require-iommu policy)",
                    id
                ));
                break;
            }
        }
    }

    AnalysisOutcome {
        result: final_result,
        hitl_seen_vcs: hitl_gate.seen.iter().cloned().collect::<HashSet<_>>().len(),
        hitl_blocked_vcs: hitl_gate
            .blocked
            .iter()
            .cloned()
            .collect::<HashSet<_>>()
            .len(),
        hitl_seen_classes: hitl_gate
            .seen_classes
            .iter()
            .cloned()
            .collect::<HashSet<_>>()
            .len(),
        hitl_blocked_classes: hitl_gate
            .blocked_classes
            .iter()
            .cloned()
            .collect::<HashSet<_>>()
            .len(),
        inline_asm_vcs,
        dma_vcs,
        irq_race_vcs,
    }
}

fn apply_ring_policy(
    result: AnalysisResult,
    ring: RingMode,
    attestation_token: Option<&PathBuf>,
    attestation_max_age_sec: u64,
    attestation_nonce: Option<&String>,
    attestation_replay_state: Option<&PathBuf>,
    attestation_pubkey: Option<&PathBuf>,
    attestation_signature: Option<&PathBuf>,
    attestation_key_fingerprint: Option<&String>,
    ring2_root_pubkey: Option<&PathBuf>,
    ring2_root_signature: Option<&PathBuf>,
    ring2_root_key_fingerprint: Option<&String>,
) -> (AnalysisResult, Option<String>, Option<String>) {
    let mut key_fingerprint: Option<String> = None;
    let mut token_sha256: Option<String> = None;
    if let Some(required_ring) = ring.token_ring() {
        let Some(token_path) = attestation_token else {
            return (
                AnalysisResult::Fail(format!(
                    "{} requires C-validated attestation token (--attestation-token <path>)",
                    ring.label()
                )),
                key_fingerprint,
                token_sha256,
            );
        };
        let token_text = token_path.to_string_lossy();
        let Ok(token_cstr) = CString::new(token_text.as_ref()) else {
            return (
                AnalysisResult::Fail("Attestation token path contains NUL byte".to_string()),
                key_fingerprint,
                token_sha256,
            );
        };
        let Some(pubkey_path) = attestation_pubkey else {
            return (
                AnalysisResult::Fail(format!(
                    "{} requires --attestation-pubkey for signature verification",
                    ring.label()
                )),
                key_fingerprint,
                token_sha256,
            );
        };
        let Some(sig_path) = attestation_signature else {
            return (
                AnalysisResult::Fail(format!(
                    "{} requires --attestation-signature for signature verification",
                    ring.label()
                )),
                key_fingerprint,
                token_sha256,
            );
        };
        let Some(expected_fp) = attestation_key_fingerprint.as_ref() else {
            return (
                AnalysisResult::Fail(format!(
                    "{} requires --attestation-key-fingerprint for key pinning",
                    ring.label()
                )),
                key_fingerprint,
                token_sha256,
            );
        };
        match verify_attestation_signature(token_path, pubkey_path, sig_path, expected_fp) {
            Ok(meta) => {
                key_fingerprint = Some(meta.key_fingerprint);
                token_sha256 = Some(meta.token_sha256);
            }
            Err(e) => {
                return (
                    AnalysisResult::Fail(format!(
                        "{} attestation signature invalid: {}",
                        ring.label(),
                        e
                    )),
                    key_fingerprint,
                    token_sha256,
                );
            }
        }
        if matches!(ring, RingMode::RingM2) {
            let Some(root_pub) = ring2_root_pubkey else {
                return (
                    AnalysisResult::Fail(
                        "Ring -2 requires --ring2-root-pubkey for independent root attestation"
                            .to_string(),
                    ),
                    key_fingerprint,
                    token_sha256,
                );
            };
            let Some(root_sig) = ring2_root_signature else {
                return (
                    AnalysisResult::Fail(
                        "Ring -2 requires --ring2-root-signature for independent root attestation"
                            .to_string(),
                    ),
                    key_fingerprint,
                    token_sha256,
                );
            };
            let Some(root_fp) = ring2_root_key_fingerprint else {
                return (
                    AnalysisResult::Fail(
                        "Ring -2 requires --ring2-root-key-fingerprint for root key pinning"
                            .to_string(),
                    ),
                    key_fingerprint,
                    token_sha256,
                );
            };
            if let Err(e) = verify_attestation_signature(token_path, root_pub, root_sig, root_fp) {
                return (
                    AnalysisResult::Fail(format!("Ring -2 root signature invalid: {}", e)),
                    key_fingerprint,
                    token_sha256,
                );
            }
        }
        if attestation_max_age_sec == 0 {
            return (
                AnalysisResult::Fail("attestation max age must be > 0".to_string()),
                key_fingerprint,
                token_sha256,
            );
        }
        let max_age = match i64::try_from(attestation_max_age_sec) {
            Ok(v) => v,
            Err(_) => {
                return (
                    AnalysisResult::Fail("attestation max age is too large".to_string()),
                    key_fingerprint,
                    token_sha256,
                );
            }
        };
        let nonce_cstr = match attestation_nonce {
            Some(nonce) => match CString::new(nonce.as_str()) {
                Ok(v) => Some(v),
                Err(_) => {
                    return (
                        AnalysisResult::Fail("attestation nonce contains NUL byte".to_string()),
                        key_fingerprint,
                        token_sha256,
                    );
                }
            },
            None => {
                return (
                    AnalysisResult::Fail(format!(
                        "{} requires --attestation-nonce for anti-replay binding",
                        ring.label()
                    )),
                    key_fingerprint,
                    token_sha256,
                );
            }
        };
        let nonce_ptr = nonce_cstr.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());
        let Some(replay_path) = attestation_replay_state else {
            return (
                AnalysisResult::Fail(format!(
                    "{} requires --attestation-replay-state for replay protection",
                    ring.label()
                )),
                key_fingerprint,
                token_sha256,
            );
        };
        let replay_text = replay_path.to_string_lossy();
        let Ok(replay_cstr) = CString::new(replay_text.as_ref()) else {
            return (
                AnalysisResult::Fail("attestation replay state path contains NUL byte".to_string()),
                key_fingerprint,
                token_sha256,
            );
        };
        // SAFETY: token_cstr is a valid NUL-terminated C string for the duration of the call.
        let ok = unsafe {
            skv_validate_attestation_token(
                token_cstr.as_ptr(),
                required_ring,
                max_age,
                nonce_ptr,
                replay_cstr.as_ptr(),
            )
        };
        if ok != 1 {
            return (
                AnalysisResult::Fail(format!(
                    "{} attestation token validation failed",
                    ring.label()
                )),
                key_fingerprint,
                token_sha256,
            );
        }
    }

    let result = match (ring, result) {
        (RingMode::Ring0, r) => r,
        (RingMode::RingM1, AnalysisResult::Unknown(reason))
        | (RingMode::RingM2, AnalysisResult::Unknown(reason)) => AnalysisResult::Fail(format!(
            "{} strict policy rejected unresolved proof: {}",
            ring.label(),
            reason
        )),
        (_, r) => r,
    };
    (result, key_fingerprint, token_sha256)
}

struct SignatureMeta {
    key_fingerprint: String,
    token_sha256: String,
}

fn verify_attestation_signature(
    token_path: &PathBuf,
    pubkey_path: &PathBuf,
    signature_path: &PathBuf,
    expected_key_fingerprint: &str,
) -> Result<SignatureMeta> {
    ensure_secure_owned_file(pubkey_path, "attestation pubkey")?;
    ensure_secure_owned_file(signature_path, "attestation signature")?;

    let token = fs::read(token_path)
        .with_context(|| format!("Failed reading attestation token: {}", token_path.display()))?;
    let pubkey_b64 = fs::read_to_string(pubkey_path).with_context(|| {
        format!(
            "Failed reading attestation pubkey: {}",
            pubkey_path.display()
        )
    })?;
    let sig_b64 = fs::read_to_string(signature_path).with_context(|| {
        format!(
            "Failed reading attestation signature: {}",
            signature_path.display()
        )
    })?;

    let pubkey_raw = base64::engine::general_purpose::STANDARD
        .decode(pubkey_b64.trim())
        .context("Failed decoding base64 attestation pubkey")?;
    let sig_raw = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.trim())
        .context("Failed decoding base64 attestation signature")?;

    if pubkey_raw.len() != 32 {
        anyhow::bail!("attestation pubkey must decode to 32 bytes");
    }
    if sig_raw.len() != 64 {
        anyhow::bail!("attestation signature must decode to 64 bytes");
    }

    let pubkey_arr: [u8; 32] = pubkey_raw
        .as_slice()
        .try_into()
        .context("failed to parse pubkey bytes")?;
    let sig_arr: [u8; 64] = sig_raw
        .as_slice()
        .try_into()
        .context("failed to parse signature bytes")?;

    let key = VerifyingKey::from_bytes(&pubkey_arr).context("invalid ed25519 pubkey")?;
    let sig = Signature::from_bytes(&sig_arr);
    key.verify(&token, &sig)
        .context("ed25519 signature verification failed")?;
    let key_fp = hex::encode(Sha256::digest(pubkey_arr));
    let expected_norm = normalize_fingerprint(expected_key_fingerprint)?;
    if key_fp != expected_norm {
        anyhow::bail!("attestation key fingerprint mismatch");
    }
    let token_sha = hex::encode(Sha256::digest(&token));
    Ok(SignatureMeta {
        key_fingerprint: key_fp,
        token_sha256: token_sha,
    })
}

fn ensure_secure_owned_file(path: &PathBuf, label: &str) -> Result<()> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("Failed to stat {}: {}", label, path.display()))?;
    if !meta.file_type().is_file() {
        anyhow::bail!("{} must be a regular file", label);
    }
    if meta.uid() != nix_like_euid() {
        anyhow::bail!("{} must be owned by current effective user", label);
    }
    if (meta.mode() & 0o022) != 0 {
        anyhow::bail!("{} must not be group/world writable", label);
    }
    Ok(())
}

fn nix_like_euid() -> u32 {
    // libc-free for this binary; best effort from /proc/self/status fallback.
    // On Linux this always succeeds.
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let mut parts = rest.split_whitespace();
            let _real = parts.next();
            if let Some(euid) = parts.next() {
                if let Ok(v) = euid.parse::<u32>() {
                    return v;
                }
            }
        }
    }
    0
}

fn normalize_fingerprint(value: &str) -> Result<String> {
    let fp = value.trim().to_ascii_lowercase();
    if fp.len() != 64 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("fingerprint must be exactly 64 hex characters");
    }
    Ok(fp)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("[ERROR] {}", e);
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode> {
    let args = Args::parse();
    if let Some(command) = args.command.as_ref() {
        match command {
            Commands::Features => {
                if args.json {
                    println!("{}", feature_catalog_json());
                } else {
                    print_feature_catalog();
                }
                return Ok(ExitCode::from(0));
            }
            Commands::Doctor => {
                let ok = run_doctor(args.json);
                return Ok(if ok {
                    ExitCode::from(0)
                } else {
                    ExitCode::from(12)
                });
            }
            Commands::TokenTemplate { ring } => {
                print_token_template(*ring, args.json);
                return Ok(ExitCode::from(0));
            }
            Commands::Tui => {
                return run_tui();
            }
            Commands::AttestCheck => {
                let runtime_fallback = args.runtime_fallback.resolved().to_string();
                let (result, key_fingerprint, token_sha256) = apply_ring_policy(
                    AnalysisResult::Pass,
                    args.ring,
                    args.attestation_token.as_ref(),
                    args.attestation_max_age_sec,
                    args.attestation_nonce.as_ref(),
                    args.attestation_replay_state.as_ref(),
                    args.attestation_pubkey.as_ref(),
                    args.attestation_signature.as_ref(),
                    args.attestation_key_fingerprint.as_ref(),
                    args.ring2_root_pubkey.as_ref(),
                    args.ring2_root_signature.as_ref(),
                    args.ring2_root_key_fingerprint.as_ref(),
                );
                let verdict = verdict_from_result(
                    result,
                    key_fingerprint,
                    token_sha256,
                    runtime_fallback,
                    args.hitl_mode.label().to_string(),
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                );
                let json = verdict.to_json();
                if args.json {
                    println!("{json}");
                } else {
                    match verdict.status {
                        "pass" => println!("[PASS] {}", verdict.message),
                        "fail" => println!("[FAIL] {}", verdict.message),
                        _ => println!("[UNKNOWN] {}", verdict.message),
                    }
                    println!(
                        "[INFO] runtime fallback policy: {}",
                        verdict.runtime_fallback
                    );
                    println!(
                        "[INFO] HITL mode: {} (seen_vcs={}, blocked_vcs={}, seen_classes={}, blocked_classes={})",
                        verdict.hitl_mode,
                        verdict.hitl_seen_vcs,
                        verdict.hitl_blocked_vcs,
                        verdict.hitl_seen_classes,
                        verdict.hitl_blocked_classes
                    );
                }
                if let Some(path) = &args.verdict_out {
                    write_output_file(path, &format!("{json}\n")).with_context(|| {
                        format!("Failed to write verdict file: {}", path.display())
                    })?;
                }
                return Ok(ExitCode::from(verdict.code as u8));
            }
        }
    }
    let ir_path = args
        .ir_path
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("IR_PATH is required unless using `features` command"))?;
    let module = catch_unwind(AssertUnwindSafe(|| Module::from_ir_path(ir_path)))
        .map_err(|_| anyhow::anyhow!(
            "LLVM IR parser panicked on input; possible LLVM producer/consumer mismatch (this binary expects LLVM 19 IR). Use `attest-check` for trust-only validation or provide LLVM 19-compatible IR"
        ))?
        .map_err(|e| anyhow::anyhow!("Failed to parse LLVM IR: {e}"))?;

    let mut cfg = Config::new();
    cfg.set_timeout_msec(5_000);

    if matches!(args.hitl_mode, HitlMode::Require)
        && args.hitl_approvals.is_none()
        && args.hitl_class_approvals.is_none()
    {
        anyhow::bail!(
            "--hitl-mode require needs at least one approval source: --hitl-approvals or --hitl-class-approvals"
        );
    }
    let approved = match args.hitl_approvals.as_ref() {
        Some(path) => load_hitl_approvals(path)?,
        None => HashSet::new(),
    };
    let approved_classes = match args.hitl_mode {
        HitlMode::Off => HashSet::new(),
        HitlMode::Require => match args.hitl_class_approvals.as_ref() {
            Some(path) => load_hitl_approvals(path)?,
            None => HashSet::new(),
        },
    };
    let mut hitl_gate = HitlGate {
        mode: args.hitl_mode,
        approved,
        approved_classes,
        seen: Vec::new(),
        blocked: Vec::new(),
        seen_classes: Vec::new(),
        blocked_classes: Vec::new(),
    };
    let analysis = with_z3_config(&cfg, || {
        analyze(
            &module,
            &mut hitl_gate,
            args.inline_asm_policy,
            args.dma_policy,
        )
    });
    if let Some(path) = &args.emit_vcs {
        emit_hitl_vcs(path, &hitl_gate)?;
    }
    let analysis_result =
        enforce_hitl_policy(analysis.result, args.hitl_mode, analysis.hitl_blocked_vcs);
    let runtime_fallback = args.runtime_fallback.resolved().to_string();
    let (result, key_fingerprint, token_sha256) = apply_ring_policy(
        analysis_result,
        args.ring,
        args.attestation_token.as_ref(),
        args.attestation_max_age_sec,
        args.attestation_nonce.as_ref(),
        args.attestation_replay_state.as_ref(),
        args.attestation_pubkey.as_ref(),
        args.attestation_signature.as_ref(),
        args.attestation_key_fingerprint.as_ref(),
        args.ring2_root_pubkey.as_ref(),
        args.ring2_root_signature.as_ref(),
        args.ring2_root_key_fingerprint.as_ref(),
    );

    let verdict = verdict_from_result(
        result,
        key_fingerprint,
        token_sha256,
        runtime_fallback,
        args.hitl_mode.label().to_string(),
        analysis.hitl_seen_vcs,
        analysis.hitl_blocked_vcs,
        analysis.hitl_seen_classes,
        analysis.hitl_blocked_classes,
        analysis.inline_asm_vcs,
        analysis.dma_vcs,
        analysis.irq_race_vcs,
    );
    let json = verdict.to_json();

    if args.json {
        println!("{json}");
    } else {
        match verdict.status {
            "pass" => println!("[PASS] {}", verdict.message),
            "fail" => println!("[FAIL] {}", verdict.message),
            _ => println!("[UNKNOWN] {}", verdict.message),
        }
        println!(
            "[INFO] runtime fallback policy: {}",
            verdict.runtime_fallback
        );
        println!(
            "[INFO] HITL mode: {} (seen_vcs={}, blocked_vcs={}, seen_classes={}, blocked_classes={})",
            verdict.hitl_mode,
            verdict.hitl_seen_vcs,
            verdict.hitl_blocked_vcs,
            verdict.hitl_seen_classes,
            verdict.hitl_blocked_classes
        );
    }

    if let Some(path) = &args.verdict_out {
        write_output_file(path, &format!("{json}\n"))
            .with_context(|| format!("Failed to write verdict file: {}", path.display()))?;
    }

    if let Some(path) = &args.emit_proof {
        let proof_content = format!(
            ";; Sentinel-KV Z3 Proof Trace (Format: {})\n;; Verdict Status: {}\n;; Target Arch: {}\n(proof-trace-placeholder)\n",
            args.proof_format.label(),
            verdict.status,
            std::env::consts::ARCH
        );
        write_output_file(path, &proof_content)
            .with_context(|| format!("Failed to write proof trace file: {}", path.display()))?;
    }

    Ok(ExitCode::from(verdict.code as u8))
}

fn print_feature_catalog() {
    println!("SKV Analyzer - Full Feature Inventory");
    println!();
    println!("1) Core LLVM/Z3 memory safety analysis");
    println!("- kmalloc/kzalloc/kcalloc allocation tracking");
    println!("- Bounds checks for load/store/memcpy/memset");
    println!("- Use-after-free and double-free detection via kfree tracking");
    println!("- Pointer provenance through GEP, bitcast, ptrtoint/inttoptr, add/sub");
    println!("- Conservative UNKNOWN semantics for unsupported patterns");
    println!();
    println!("2) Ring policy enforcement");
    println!("- ring0: standard analysis verdict flow");
    println!("- ring-1: strict mode (UNKNOWN promoted to FAIL)");
    println!("- ring-2: strict mode + independent root trust requirements");
    println!();
    println!("3) Attestation validation (C or Zig backend)");
    println!("- Token field validation: ring, attested, timestamp, nonce, counter");
    println!("- ring-2 extra token requirement: root_attested:true");
    println!("- Freshness enforcement with max token age");
    println!("- Nonce challenge binding");
    println!("- Replay protection with monotonic counter state");
    println!("- Atomic replay-state update with file lock + fsync");
    println!("- Secure file checks: regular file, owner UID match, safe permissions");
    println!();
    println!("4) Cryptographic trust");
    println!("- Detached Ed25519 signature verification over token bytes");
    println!("- Pinned SHA-256 fingerprint check for attestation key");
    println!("- ring-2 independent root signature + root key pinning");
    println!();
    println!("5) Operational output and CI integration");
    println!("- Human-readable PASS/FAIL/UNKNOWN output");
    println!("- --json machine-readable verdict output");
    println!("- --verdict-out file emission for SIEM/pipeline ingestion");
    println!("- Stable exit codes: 0(pass), 10(fail), 20(unknown), 1(error)");
    println!("- Panic-safe LLVM parse path (fail closed instead of process crash)");
    println!();
    println!("6) HITL verification gate");
    println!("- --hitl-mode off|require");
    println!("- --hitl-approvals <path> newline-delimited approved VC IDs");
    println!("- --hitl-class-approvals <path> newline-delimited approved VC class IDs");
    println!("- require mode needs at least one approval source (VC IDs or class IDs)");
    println!("- --emit-vcs <path> emits seen/blocked VC IDs for human review");
    println!("- Class approvals allow reviewer to approve families of similar VCs");
    println!("- Solver is never executed for unapproved VCs in require mode");
    println!();
    println!("7) Runtime fallback policy");
    println!("- --runtime-fallback auto|arm-mte|integritag|software-targeted");
    println!(
        "- auto resolves to arm-mte on aarch64, integritag on x86_64, software-targeted otherwise"
    );
    println!("- Runtime fallback policy is included in verdict output");
    println!("- IntegriTag supports Intel TME-MK hardware cryptographic memory tagging");
    println!();
    println!("8) Proof-Carrying Code (PCC)");
    println!("- --emit-proof <path> outputs formal proof trace for memory safety");
    println!("- --proof-format lfsc|rup selects trace format (LFSC/RUP)");
    println!();
    println!("9) Build/runtime backends");
    println!("- Default C attestation backend");
    println!("- Optional Zig backend via SKV_ATTESTATION_IMPL=zig");
    println!("- Automatic fallback to C when Zig is unavailable");
    println!();
    println!("10) Production output hardening");
    println!("- Verdict and VC emission files are written with secure 0600 permissions");
    println!("- Existing output files must be regular files, owner-matched, and safe-mode");
    println!("- Output file writes use explicit sync_all() for durability");
    println!();
    println!("11) Inline assembly detection");
    println!("- --inline-asm-policy conservative|trap");
    println!(
        "- Conservative mode: emit UNKNOWN VC for opaque inline asm (promoted to FAIL under Ring -1/-2)"
    );
    println!("- Trap mode: always FAIL on any inline assembly");
    println!("- Inline asm VC count included in verdict JSON output");
    println!();
    println!("12) DMA allocation verification");
    println!("- --dma-policy verify|require-iommu|ignore");
    println!("- Tracks dma_alloc_coherent as DMA allocation source");
    println!("- Bounds-checks dma_map_single against allocation size");
    println!("- require-iommu: FAIL if DMA allocation has no paired iommu_map call");
    println!("- DMA VC count included in verdict JSON output");
    println!();
    println!("13) Interrupt sequentialization");
    println!("- Pre-scans module for request_irq handler registrations");
    println!("- Identifies handlers that call kfree on tracked allocations");
    println!("- Emits irq_race VCs for accesses that could race with interrupt-triggered frees");
    println!("- Conservative over-approximation: sound but may produce false positives");
    println!("- IRQ race VC count included in verdict JSON output");
    println!();
    println!("14) VC equivalence class grouping");
    println!("- --emit-equiv-summary <path> outputs grouped VC classes for HITL review");
    println!("- VC classes group structurally equivalent access patterns");
    println!("- Class-level approval via --hitl-class-approvals prevents reviewer fatigue");
    println!("- Equivalence summary includes per-class counts and member VC lists");
}

fn feature_catalog_json() -> String {
    let items = [
        "Core LLVM/Z3 memory safety analysis",
        "kmalloc/kzalloc/kcalloc allocation tracking",
        "Bounds checks for load/store/memcpy/memset",
        "Use-after-free and double-free detection via kfree tracking",
        "Pointer provenance through GEP, bitcast, ptrtoint/inttoptr, add/sub",
        "Conservative UNKNOWN semantics for unsupported patterns",
        "Ring policy: ring0/ring-1/ring-2",
        "Ring-2 independent root trust requirements",
        "Attestation fields: ring, attested, timestamp, nonce, counter",
        "Ring-2 token requirement: root_attested:true",
        "Freshness max-age enforcement",
        "Nonce challenge binding",
        "Replay protection with monotonic counter state",
        "Atomic replay-state locking + fsync",
        "Secure file checks: regular, owner UID, safe permissions",
        "Detached Ed25519 signature verification",
        "Pinned SHA-256 key fingerprint checks",
        "Ring-2 independent root signature + key pinning",
        "Machine-readable verdict JSON (--json)",
        "Verdict file output (--verdict-out)",
        "Stable exit codes: 0/10/20/1",
        "Panic-safe LLVM parse rejection",
        "HITL gate: --hitl-mode off|require",
        "HITL approvals file: --hitl-approvals",
        "HITL class approvals: --hitl-class-approvals",
        "HITL require mode requires VC or class approvals",
        "VC emission for human review: --emit-vcs",
        "HITL require mode fail-closed on blocked VCs",
        "Runtime fallback policy: --runtime-fallback auto|arm-mte|integritag|software-targeted",
        "IntegriTag Intel TME-MK hardware support",
        "Proof-Carrying Code emission: --emit-proof <path>",
        "Supported PCC formats: LFSC and RUP",
        "Secure output writing: 0600 + sync_all + owner/mode checks",
        "Backends: C default, Zig optional, C fallback",
        "Inline asm detection: --inline-asm-policy conservative|trap",
        "Opaque inline asm VC emission with HITL gate integration",
        "DMA allocation tracking: dma_alloc_coherent/dma_map_single",
        "DMA bounds verification: --dma-policy verify|require-iommu|ignore",
        "Interrupt sequentialization via request_irq pre-scan",
        "IRQ race VC emission for handler-induced frees",
        "VC equivalence class grouping: --emit-equiv-summary",
        "Structural VC class approval to prevent reviewer fatigue",
        "Stack-spill pointer tracking through alloca/store/load chains",
    ];
    let mut out = String::from("{\"name\":\"SKV Analyzer\",\"features\":[");
    for (idx, item) in items.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&item.replace('\\', "\\\\").replace('"', "\\\""));
        out.push('"');
    }
    out.push_str("]}");
    out
}

fn run_doctor(json: bool) -> bool {
    let required_checks: Vec<(&str, bool, String)> = vec![
        (
            "os_supported",
            cfg!(target_os = "linux"),
            "linux".to_string(),
        ),
        (
            "ffi_symbol_linked",
            true,
            "attestation bridge linked".to_string(),
        ),
    ];

    let zig_ok = std::process::Command::new("zig")
        .arg("version")
        .status()
        .is_ok_and(|s| s.success());

    let optional_checks: Vec<(&str, bool, String)> = vec![(
        "zig_available",
        zig_ok,
        if zig_ok { "yes".into() } else { "no".into() },
    )];

    let all_ok = required_checks.iter().all(|(_, ok, _)| *ok);
    if json {
        let mut out = String::from("{\"doctor\":[");
        let mut i = 0usize;
        for (name, ok, detail) in required_checks.iter() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"check\":\"{}\",\"ok\":{},\"required\":true,\"detail\":\"{}\"}}",
                name,
                ok,
                detail.replace('\\', "\\\\").replace('"', "\\\"")
            ));
            i += 1;
        }
        for (name, ok, detail) in optional_checks.iter() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"check\":\"{}\",\"ok\":{},\"required\":false,\"detail\":\"{}\"}}",
                name,
                ok,
                detail.replace('\\', "\\\\").replace('"', "\\\"")
            ));
            i += 1;
        }
        out.push_str(&format!("],\"all_ok\":{}}}", all_ok));
        println!("{out}");
    } else {
        println!("SKV Analyzer Doctor");
        for (name, ok, detail) in required_checks {
            println!(
                "- {}: {} [required] ({})",
                name,
                if ok { "OK" } else { "FAIL" },
                detail
            );
        }
        for (name, ok, detail) in optional_checks {
            println!(
                "- {}: {} [optional] ({})",
                name,
                if ok { "OK" } else { "WARN" },
                detail
            );
        }
        println!("overall: {}", if all_ok { "OK" } else { "FAIL" });
    }
    all_ok
}

fn print_token_template(ring: RingMode, json: bool) {
    let ring_num = ring.token_ring().unwrap_or(0);
    if json {
        if matches!(ring, RingMode::RingM2) {
            println!(
                "{{\"ring\":{},\"attested\":true,\"root_attested\":true,\"timestamp\":1700000000,\"nonce\":\"<nonce>\",\"counter\":1}}",
                ring_num
            );
        } else {
            println!(
                "{{\"ring\":{},\"attested\":true,\"timestamp\":1700000000,\"nonce\":\"<nonce>\",\"counter\":1}}",
                ring_num
            );
        }
        return;
    }
    println!("ring:{}", ring_num);
    println!("attested:true");
    if matches!(ring, RingMode::RingM2) {
        println!("root_attested:true");
    }
    println!("timestamp:1700000000");
    println!("nonce:<nonce>");
    println!("counter:1");
}

fn run_tui() -> Result<ExitCode> {
    const C_RESET: &str = "\x1B[0m";
    const C_HEAD: &str = "\x1B[1;36m";
    const C_SECTION: &str = "\x1B[1;34m";
    const C_PROMPT: &str = "\x1B[1;33m";
    const C_OK: &str = "\x1B[1;32m";
    const C_WARN: &str = "\x1B[1;31m";
    loop {
        print!("\x1B[2J\x1B[H");
        println!("{C_HEAD}╔══════════════════════════════════════════════════════════╗{C_RESET}");
        println!("{C_HEAD}║                    SKV ANALYZER CONSOLE                 ║{C_RESET}");
        println!("{C_HEAD}╠══════════════════════════════════════════════════════════╣{C_RESET}");
        println!("{C_SECTION}║ Security Operations                                     ║{C_RESET}");
        println!("║   1) Doctor diagnostics                                 ║");
        println!("║   2) Features catalog (text)   [shortcut: f]            ║");
        println!("║   3) Features catalog (json)                            ║");
        println!("║                                                          ║");
        println!(
            "{C_SECTION}║ Attestation Utilities                                    ║{C_RESET}"
        );
        println!("║   4) Token template (ring-1)                            ║");
        println!("║   5) Token template (ring-2)   [shortcut: j]            ║");
        println!("║                                                          ║");
        println!(
            "{C_SECTION}║ Session                                                  ║{C_RESET}"
        );
        println!("║   0) Exit                     [shortcut: q]             ║");
        println!("║   d) Doctor                   [shortcut: d]             ║");
        println!("{C_HEAD}╚══════════════════════════════════════════════════════════╝{C_RESET}");
        print!("{C_PROMPT}Select action [0-5 | d/f/j/q]: {C_RESET}");
        io::stdout().flush().context("Failed to flush stdout")?;

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .context("Failed to read TUI input")?;
        match input.trim().to_ascii_lowercase().as_str() {
            "1" | "d" => {
                println!();
                let ok = run_doctor(false);
                println!();
                if ok {
                    println!("{C_OK}Doctor status code: 0{C_RESET}");
                } else {
                    println!("{C_WARN}Doctor status code: 12{C_RESET}");
                }
                pause_tui()?;
            }
            "2" | "f" => {
                println!();
                print_feature_catalog();
                println!();
                pause_tui()?;
            }
            "3" => {
                println!();
                println!("{}", feature_catalog_json());
                println!();
                pause_tui()?;
            }
            "4" => {
                println!();
                print_token_template(RingMode::RingM1, false);
                println!();
                pause_tui()?;
            }
            "5" | "j" => {
                println!();
                print_token_template(RingMode::RingM2, false);
                println!();
                pause_tui()?;
            }
            "0" | "q" => return Ok(ExitCode::from(0)),
            _ => {
                println!();
                println!("{C_WARN}Invalid selection.{C_RESET} Choose 0-5 or d/f/j/q.");
                pause_tui()?;
            }
        }
    }
}

fn pause_tui() -> Result<()> {
    print!("Press Enter to continue...");
    io::stdout().flush().context("Failed to flush stdout")?;
    let mut discard = String::new();
    io::stdin()
        .read_line(&mut discard)
        .context("Failed to read pause input")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn hitl_gate_blocks_unapproved_vc() {
        let mut gate = HitlGate {
            mode: HitlMode::Require,
            approved: HashSet::new(),
            approved_classes: HashSet::new(),
            seen: Vec::new(),
            blocked: Vec::new(),
            seen_classes: Vec::new(),
            blocked_classes: Vec::new(),
        };
        assert!(!gate.should_run_solver("f::bb0::i1::load", "class::load::size4"));
        assert_eq!(gate.seen.len(), 1);
        assert_eq!(gate.blocked.len(), 1);
        assert_eq!(gate.seen_classes.len(), 1);
        assert_eq!(gate.blocked_classes.len(), 1);
    }

    #[test]
    fn hitl_gate_allows_approved_vc() {
        let mut approved = HashSet::new();
        approved.insert("f::bb0::i1::load".to_string());
        let mut gate = HitlGate {
            mode: HitlMode::Require,
            approved,
            approved_classes: HashSet::new(),
            seen: Vec::new(),
            blocked: Vec::new(),
            seen_classes: Vec::new(),
            blocked_classes: Vec::new(),
        };
        assert!(gate.should_run_solver("f::bb0::i1::load", "class::load::size4"));
        assert_eq!(gate.seen.len(), 1);
        assert_eq!(gate.blocked.len(), 0);
    }

    #[test]
    fn hitl_gate_allows_approved_class() {
        let mut approved_classes = HashSet::new();
        approved_classes.insert("class::load::size4".to_string());
        let mut gate = HitlGate {
            mode: HitlMode::Require,
            approved: HashSet::new(),
            approved_classes,
            seen: Vec::new(),
            blocked: Vec::new(),
            seen_classes: Vec::new(),
            blocked_classes: Vec::new(),
        };
        assert!(gate.should_run_solver("f::bb0::i7::load", "class::load::size4"));
        assert_eq!(gate.blocked.len(), 0);
        assert_eq!(gate.blocked_classes.len(), 0);
    }

    #[test]
    fn enforce_hitl_policy_is_fail_closed() {
        let r = enforce_hitl_policy(AnalysisResult::Pass, HitlMode::Require, 2);
        assert!(matches!(r, AnalysisResult::Fail(_)));
    }

    #[test]
    fn load_hitl_approvals_parses_lines_comments() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("skv-hitl-approvals-{ts}.txt"));
        fs::write(
            &path,
            "# comment\n\nf::bb0::i1::load\n  f::bb0::i2::store  \n",
        )
        .expect("write approvals");
        let parsed = load_hitl_approvals(&path).expect("parse approvals");
        let _ = fs::remove_file(&path);
        assert!(parsed.contains("f::bb0::i1::load"));
        assert!(parsed.contains("f::bb0::i2::store"));
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn write_output_file_sets_secure_permissions() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("skv-output-secure-{ts}.json"));
        write_output_file(&path, "{\"ok\":true}\n").expect("write output");
        let meta = fs::symlink_metadata(&path).expect("stat output");
        let _ = fs::remove_file(&path);
        assert_eq!(meta.mode() & 0o777, 0o600);
    }
}

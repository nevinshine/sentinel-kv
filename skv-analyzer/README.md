# sentinel-skv

`sentinel-skv` is a security-focused LLVM IR analyzer with strict attestation and ring policy enforcement.

Project name: `sentinel-skv`  
CLI binary: `skv-analyzer`

It combines:

- static memory-safety checks over LLVM IR
- signed attestation validation (including replay/freshness controls)
- ring-aware fail-closed trust policy (`ring0`, `ring-1`, `ring-2`)
- machine-readable outputs for CI/SIEM
- an interactive terminal UI

## Current Command Surface

```bash
skv-analyzer [OPTIONS] [IR_PATH] [COMMAND]
```

Commands:

- `features` — full feature inventory
- `doctor` — runtime/backend diagnostics
- `token-template` — attestation token template generation
- `tui` — interactive terminal menu
- `attest-check` — attestation + ring policy validation without IR parsing

## Build & Run

Requirements:

- Rust toolchain
- C compiler (for default attestation bridge)
- system libraries needed by `z3`/`llvm-ir` dependencies

Build:

```bash
cargo build
```

Run help:

```bash
cargo run -- --help
```

## Backends (C / Zig)

Attestation bridge backend selection:

- default: C backend (`src/c/attestation_bridge.c`)
- optional Zig backend (`src/zig/attestation_bridge.zig`)

Select Zig backend:

```bash
SKV_ATTESTATION_IMPL=zig cargo build
```

If Zig is requested but unavailable, build falls back to C backend with a warning.

## Security Model (High Level)

### 1) LLVM/Z3 Analysis Layer

Analyzes LLVM IR for memory-safety relevant behavior:

- allocation provenance (`kmalloc`, `kzalloc`, `kcalloc`)
- bounds checks for `load`, `store`, `memcpy`, `memset`
- use-after-free / double-free checks via `kfree`
- pointer tracking through `GEP`, `bitcast`, `ptrtoint`/`inttoptr`, integer `add/sub`

Unsupported patterns become `UNKNOWN` (never silently treated as safe).

### 2) Ring Policy Layer

- `ring0`: normal verdict behavior
- `ring-1`: strict mode (`UNKNOWN` promoted to `FAIL`)
- `ring-2`: strict mode + independent root trust requirements

### 3) Attestation Trust Layer

For `ring-1`/`ring-2`, policy requires signed token validation:

- detached Ed25519 signature over token
- key fingerprint pinning (SHA-256 hex)
- freshness (`timestamp` + max age)
- nonce binding
- replay counter with atomic update and lock
- secure file checks (regular file, owner UID match, no group/world write)

For `ring-2`, additional hard requirements:

- `root_attested:true` token field
- separate independent root signature/key/fingerprint path

## Architectural Determinism (HITL + SMT)

Sentinel-KV follows a deterministic proof pipeline where AI is explicitly **untrusted**:

- Tier 1 — Untrusted AI assistant:
  - proposes candidate invariants/ownership hints only
  - never auto-commits proof obligations
- Tier 2 — Human security gate:
  - accepts/modifies/rejects AI candidates
  - only human-approved verification conditions (VCs) proceed
- Tier 3 — Absolute verifier:
  - Z3 checks approved VCs and emits proof artifacts
  - load-time checker validates proofs deterministically

Result: AI accelerates invariant discovery, but cannot create trusted security guarantees by itself.

## Runtime Fallback Policy

For the unverifiable edge cases, Sentinel-KV uses minimal targeted runtime checks:

- preferred hardware path: ARM MTE (where available)
- otherwise: narrow software checks on only unverifiable operations

This avoids broad always-on instrumentation while preserving fail-closed behavior. The architecture does **not** rely on Intel TME-MK key management in the kernel trust path.

## Attestation Token Format

Text token (line-based fields). Required fields:

- `ring:-1` or `ring:-2` (or `ring:0` template mode)
- `attested:true`
- `timestamp:<unix-seconds>`
- `nonce:<challenge>`
- `counter:<monotonic-integer>`

Additional required for ring-2:

- `root_attested:true`

Example (`ring-2`):

```text
ring:-2
attested:true
root_attested:true
timestamp:1700000000
nonce:example-nonce
counter:42
```

## Main CLI Options

- `--ring ring0|ring-1|ring-2`
- `--attestation-token <path>`
- `--attestation-max-age-sec <n>`
- `--attestation-nonce <value>`
- `--attestation-replay-state <path>`
- `--attestation-pubkey <path>` (base64, 32 raw bytes)
- `--attestation-signature <path>` (base64, 64 raw bytes)
- `--attestation-key-fingerprint <64-hex>`
- `--ring2-root-pubkey <path>`
- `--ring2-root-signature <path>`
- `--ring2-root-key-fingerprint <64-hex>`
- `--hitl-mode off|require`
- `--hitl-approvals <path>` (newline-delimited VC IDs)
- `--hitl-class-approvals <path>` (newline-delimited VC class IDs)
- `--emit-vcs <path>` (writes seen/blocked VC IDs for review)
- `--runtime-fallback auto|arm-mte|software-targeted`
- `--json`
- `--verdict-out <path>`

When `--hitl-mode require` is used, at least one approval source must be provided:
`--hitl-approvals` or `--hitl-class-approvals`.

## Output & Exit Codes

Verdict statuses:

- `pass`
- `fail`
- `unknown`

Stable exit codes:

- `0` — pass
- `10` — fail
- `20` — unknown
- `1` — runtime/internal error
- `12` — doctor command failed required checks

JSON verdict includes:

- `status`
- `code`
- `message`
- `key_fingerprint` (when applicable)
- `token_sha256` (when applicable)
- `runtime_fallback`
- `hitl_mode`
- `hitl_seen_vcs`
- `hitl_blocked_vcs`
- `hitl_seen_classes`
- `hitl_blocked_classes`

Output hardening:

- `--verdict-out` and `--emit-vcs` write with `0600` permissions
- existing output file targets must be regular files, owner-matched, and not group/world writable
- output writes are synced to disk (`sync_all`) before completion

## A–Z Feature + Code Review Index (Single-Page Audit Map)

This section is the one-stop review map so you do not need to open every file blindly.

### A — Analyzer core (LLVM + Z3)

- What: memory safety analysis over LLVM IR (allocations, access bounds, UAF/double-free, pointer provenance)
- Code:
  - `src/main.rs`:
    - `analyze(...)`
    - `check_access(...)`
    - `infer_gep_offset(...)`
    - allocation/call handlers (`kmalloc`, `kzalloc`, `kcalloc`, `kfree`, `memset`, `memcpy`)

### B — Build backend selection (C/Zig)

- What: choose attestation backend at build time
- Code:
  - `build.rs`
    - `main()`
    - `has_zig()`
    - `compile_c()`
    - `compile_zig()`

### C — Command surface

- What: CLI commands and options
- Code:
  - `src/main.rs`
    - `struct Args`
    - `enum Commands`
    - `run()`

### D — Doctor diagnostics

- What: runtime health checks
- Code:
  - `src/main.rs`
    - `run_doctor(...)`

### E — Exit codes + verdict model

- What: stable exit semantics and machine-readable verdicts
- Code:
  - `src/main.rs`
    - `struct Verdict`
    - `verdict_from_result(...)`

### F — Feature catalog output

- What: full feature printouts in text/JSON
- Code:
  - `src/main.rs`
    - `print_feature_catalog()`
    - `feature_catalog_json()`

### G — Guarded parser path

- What: catches LLVM parser panics and returns explicit error guidance
- Code:
  - `src/main.rs`
    - `run()` around `Module::from_ir_path(...)` + `catch_unwind(...)`

### H — HITL verification gate (fail-closed in require mode)

- What:
  - solver runs only for approved verification conditions (VCs) in `require` mode
  - solver can also run when VC class is approved (equivalence-class approval)
- blocked VCs are tracked and can be emitted
- blocked VC classes are tracked and can be emitted
- final result is forced to `FAIL` when blocked VCs exist in `require` mode
- `require` mode needs at least one approval source (VC IDs or class IDs)
- Code:
  - `src/main.rs`
    - `enum HitlMode`
    - `struct HitlGate`
    - `load_hitl_approvals(...)`
    - `emit_hitl_vcs(...)`
    - `vc_class_id(...)`
    - `enforce_hitl_policy(...)`
    - `analyze(...)` + `check_access(...)`
- Tests:
  - `src/main.rs` (unit tests module)
    - `hitl_gate_blocks_unapproved_vc`
    - `hitl_gate_allows_approved_vc`
    - `hitl_gate_allows_approved_class`
    - `enforce_hitl_policy_is_fail_closed`
    - `load_hitl_approvals_parses_lines_comments`

### I — Integrity of attestation signatures

- What: detached Ed25519 signature verification + key fingerprint pinning
- Code:
  - `src/main.rs`
    - `verify_attestation_signature(...)`
    - `normalize_fingerprint(...)`

### J — JSON outputs for automation

- What: `--json` + `--verdict-out` for CI/SIEM pipelines
- Code:
  - `src/main.rs`
    - `Verdict::to_json(...)`
    - `run()` output/write paths

### K — Key and file security checks

- What: regular file, owner match, safe permission enforcement for key/signature files
- Code:
  - `src/main.rs`
    - `ensure_secure_owned_file(...)`

### L — Load-time attestation gate (FFI bridge)

- What: C/Zig validator enforces ring, freshness, nonce, replay
- Code:
  - `src/main.rs`
    - `unsafe extern "C" { skv_validate_attestation_token(...) }`
    - `apply_ring_policy(...)`
  - `src/c/attestation_bridge.h`

### M — Monotonic replay protection

- What: replay counter must strictly increase; atomic state update with lock/fsync (C backend)
- Code:
  - `src/c/attestation_bridge.c`
    - replay-state open/lock/read/compare/write/fsync logic

### N — Nonce binding

- What: required nonce equality check for ring-1/ring-2 attestation
- Code:
  - `src/main.rs`
    - `apply_ring_policy(...)`
  - `src/c/attestation_bridge.c`
    - expected nonce vs token nonce check

### O — Operational TUI

- What: interactive console with shortcuts and formatted sections
- Code:
  - `src/main.rs`
    - `run_tui()`
    - `pause_tui()`

### P — Pointer provenance tracking

- What: pointer flow through `GEP`, `bitcast`, `ptrtoint`, `inttoptr`, integer `add/sub`
- Code:
  - `src/main.rs`
    - `enum PtrVal`
    - `enum IntVal`
    - instruction handlers in `analyze(...)`

### Q — Quick token generation

- What: ring-specific token templates
- Code:
  - `src/main.rs`
    - `print_token_template(...)`

### R — Ring policy enforcement

- What: strict ring behavior (`UNKNOWN` -> `FAIL` for ring-1/ring-2), ring-2 independent root trust
- Code:
  - `src/main.rs`
    - `enum RingMode`
    - `apply_ring_policy(...)`

### S — Secure token/replay file validation

- What: token/replay files must be secure regular files, owned by effective user, not group/world writable
- Code:
  - `src/c/attestation_bridge.c`
    - `lstat`/`fstat` and mode/uid checks

### T — Timestamp freshness checks

- What: token timestamp must be current and within max-age window
- Code:
  - `src/main.rs`
    - `apply_ring_policy(...)`
  - `src/c/attestation_bridge.c`
    - `time(...)` + age checks

### U — UNKNOWN safety semantics

- What: unsupported analysis patterns are `UNKNOWN`, never silently treated as safe
- Code:
  - `src/main.rs`
    - `mark_unknown(...)`
    - unknown-marking branches in `analyze(...)`

### V — VC emission for review workflows

- What: emit seen/blocked VC IDs to a JSON file for human review pipelines
- Code:
  - `src/main.rs`
    - `emit_hitl_vcs(...)`

### W — Wire-up for runtime fallback policy

- What: explicit fallback policy in verdict (`auto|arm-mte|software-targeted`)
- Code:
  - `src/main.rs`
    - `enum RuntimeFallbackPolicy`
    - `RuntimeFallbackPolicy::resolved(...)`
    - verdict population in `run()`

### X — eXternal C ABI contract

- What: fixed C ABI between Rust and C/Zig validators
- Code:
  - `src/c/attestation_bridge.h`
  - `src/main.rs` `extern "C"` declaration

### Y — “You can automate this” hooks

- What: stable status codes + JSON + file output suitable for policy engines
- Code:
  - `src/main.rs`
    - `verdict_from_result(...)`
    - `run()` output/exit handling

### Z — Zig backend parity (optional)

- What: optional attestation validator in Zig, with build fallback to C
- Code:
  - `src/zig/attestation_bridge.zig`
  - `build.rs`

## File-by-File Review Order (Recommended)

1. `src/main.rs` (core logic, policy, CLI, HITL, verdicts)
2. `src/c/attestation_bridge.c` (authoritative token/replay validator)
3. `src/c/attestation_bridge.h` (ABI)
4. `build.rs` (backend select + fallback)
5. `src/zig/attestation_bridge.zig` (optional backend parity)
6. `Cargo.toml` (dependencies and build script registration)

## Copy/Paste Verification Commands (Fast Audit)

Build/tests:

```bash
cargo check --quiet
cargo test --quiet
```

Feature visibility:

```bash
cargo run --quiet -- --help
cargo run --quiet -- features
cargo run --quiet -- --json features
```

Doctor + command checks:

```bash
cargo run --quiet -- doctor
cargo run --quiet -- token-template --ring ring-1
cargo run --quiet -- token-template --ring ring-2
```

HITL flags present:

```bash
cargo run --quiet -- --help | rg "hitl|emit-vcs|runtime-fallback"
```

HITL unit tests:

```bash
cargo test --quiet hitl_gate_blocks_unapproved_vc
cargo test --quiet hitl_gate_allows_approved_vc
cargo test --quiet hitl_gate_allows_approved_class
cargo test --quiet enforce_hitl_policy_is_fail_closed
cargo test --quiet load_hitl_approvals_parses_lines_comments
cargo test --quiet write_output_file_sets_secure_permissions
```

Attestation-only trust path:

```bash
skv-analyzer --ring ring-2 \
  --attestation-token token.txt \
  --attestation-max-age-sec 300 \
  --attestation-nonce "$NONCE" \
  --attestation-replay-state replay.state \
  --attestation-pubkey attest.pub.b64 \
  --attestation-signature attest.sig.b64 \
  --attestation-key-fingerprint "$ATTEST_FP" \
  --ring2-root-pubkey root.pub.b64 \
  --ring2-root-signature root.sig.b64 \
  --ring2-root-key-fingerprint "$ROOT_FP" \
  --json attest-check
```

## Commands in Practice

### Features catalog

```bash
skv-analyzer features
skv-analyzer --json features
```

### Doctor

```bash
skv-analyzer doctor
skv-analyzer --json doctor
```

### Token templates

```bash
skv-analyzer token-template --ring ring-1
skv-analyzer --json token-template --ring ring-2
```

### Attestation-only validation (no IR parsing)

Use this when validating trust pipeline independently:

```bash
skv-analyzer --ring ring-2 \
  --attestation-token token.txt \
  --attestation-max-age-sec 300 \
  --attestation-nonce "$NONCE" \
  --attestation-replay-state replay.state \
  --attestation-pubkey attest.pub.b64 \
  --attestation-signature attest.sig.b64 \
  --attestation-key-fingerprint "$ATTEST_FP" \
  --ring2-root-pubkey root.pub.b64 \
  --ring2-root-signature root.sig.b64 \
  --ring2-root-key-fingerprint "$ROOT_FP" \
  --json \
  attest-check
```

### Full analysis run (IR + policy)

```bash
skv-analyzer path/to/module.ll --ring ring0
```

If your host LLVM producer is incompatible with this build’s parser expectations, use `attest-check` for trust-only path validation and provide LLVM-compatible IR for analysis mode.

### TUI

```bash
skv-analyzer tui
```

TUI supports numeric and shortcut keys:

- `d` doctor
- `f` features text
- `j` ring-2 token template
- `q` quit

## Notes

- This tool is fail-closed by default in high-assurance paths.
- Parser panics from third-party IR parser are trapped and surfaced as explicit errors.
- Replay protection uses locked, atomic state update semantics in C backend.

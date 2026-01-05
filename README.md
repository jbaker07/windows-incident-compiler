# git-glue

EDR (Endpoint Detection and Response) incident compiler pipeline with cross-platform telemetry capture.

## Quick Start (3 OS)

### Prerequisites
- Rust toolchain (`rustup`)
- macOS: Xcode Command Line Tools
- Linux: `build-essential`, `pkg-config`, `libssl-dev`, kernel headers (for eBPF)
- Windows: Visual Studio Build Tools with C++ workload

### Build

```bash
cargo build --release --bins
```

### Run Stack

**macOS** (requires sudo for capture):
```bash
./scripts/run_stack_macos.sh
```

**Linux** (requires sudo for eBPF):
```bash
./scripts/run_stack_linux.sh
```

**Windows** (PowerShell, may need admin for capture):
```powershell
.\scripts\run_stack_windows.ps1
```

### Verify

```bash
# macOS/Linux
./scripts/smoke_stack.sh

# Windows
.\scripts\smoke_stack.ps1
```

### UI

Once the stack is running, open: **http://localhost:3000**

## Architecture

```
capture_*_rotating → segments/*.jsonl → edr-locald → incidents → edr-server (API)
```

| Component | Description |
|-----------|-------------|
| `capture_*_rotating` | Per-OS telemetry capture (BSM/eBPF/ETW) |
| `edr-locald` | Incident compiler (slot matching, hypothesis promotion) |
| `edr-server` | HTTP API + UI server |
| `proof_run` | Integration verification harness |

## Documentation

- [docs/VM_BRINGUP.md](docs/VM_BRINGUP.md) - VM deployment guide
- [docs/PUSH_CHECKLIST.md](docs/PUSH_CHECKLIST.md) - Pre-push verification
- [BASELINE_SYSTEM_DESIGN.md](BASELINE_SYSTEM_DESIGN.md) - System architecture

## License

MIT - see [LICENSE](LICENSE)

# Test Import Fixtures

This directory contains minimal test fixtures for validating the import pipeline.

## Contents

- `nmap_sample.xml` - Minimal nmap XML output
- `yara_sample.json` - YARA match results
- `atomic_sample.json` - Atomic Red Team output
- `osquery_sample.json` - osquery results
- `plaintext_sample.txt` - Plain text file for testing

## Usage

Run the import_bundle CLI on this directory:

```bash
cargo run --bin import_bundle -- --input testdata/imports --out ./test_out
```

Then verify the outputs in `./test_out/imports/<bundle_id>/`.

# API Parity Snapshots

This folder contains frozen snapshots of the API contract and route registry.
These are used by automated tests to detect accidental API drift after refactoring.

## Files

- **routes_snapshot.json** - Complete list of all registered API routes
  - Generated from `services::meta::get_registered_routes()`
  - Contains: method, path, description, mutates flag for each endpoint

- **contract_snapshot.json** - API contract specification
  - Generated from `services::meta::get_api_contract()`
  - Contains: wrapper schema, endpoint schemas, error codes

## How It Works

The parity tests in `crates/server/tests/parity_routes_contract.rs` compare
the current build's routes and contract against these snapshots. If there's
any difference, the test fails with a diff showing what changed.

## Updating Snapshots

If you need to change the API (add/modify/remove endpoints), you must:

1. **Bump the version** in `crates/server/src/services/meta.rs`:
   - Update `CONTRACT_VERSION` (semver format)
   - Update `CONTRACT_HASH` (v{major}-{scope}-{YYYYMM} format)

2. **Update the snapshots**:
   - Regenerate `routes_snapshot.json` from `get_registered_routes()`
   - Regenerate `contract_snapshot.json` from `get_api_contract()`

3. **Document the change** in CHANGELOG.md

## Escape Hatch (Dev Only)

For local development, you can bypass parity failures:

```bash
LOCINT_ALLOW_CONTRACT_DRIFT=1 cargo test -p edr-server parity
```

This will print mismatches but not fail the test. **Never use this in CI.**

## Why This Exists

After the locint.rs → thin router refactor (12k LOC → ~2.7k LOC), we needed
to ensure zero behavior drift. These snapshots serve as a regression guard
to catch any accidental changes to the public API surface.

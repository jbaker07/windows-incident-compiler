# Team Case Store (v1)

## Overview

The Team Case Store enables collaboration between analysts in the Team tier by sharing cases, notes, and runs via a shared network folder (SMB/NAS). No cloud services, no database server - just a shared folder that all team members can access.

## Requirements

- **Tier**: Team or Dev
- **Shared Storage**: A network folder accessible to all team members (read/write)
  - Windows: UNC path like `\\server\share\locint_cases`
  - Linux/Mac: Mount path like `/mnt/shared/locint_cases`

## Configuration

### Environment Variable (Recommended)

Set `LOCINT_CASE_STORE_DIR` to your shared folder path:

```powershell
# PowerShell
$env:LOCINT_CASE_STORE_DIR = "\\server\share\locint_cases"

# Or in system environment variables for persistence
```

```bash
# Linux/Mac
export LOCINT_CASE_STORE_DIR="/mnt/shared/locint_cases"
```

### UI Configuration

1. Go to the **Team** tab
2. Click **Configure** on the Store Status card
3. Enter your shared folder path
4. Click **Save & Connect**

The path is saved to `team_config.json` in your local data directory.

## Store Structure

```
/locint_case_store/
├── store.json                    # Store metadata (schema_version, store_id, created_at)
├── cases/
│   └── case_<id>/
│       ├── case.json             # Case metadata (title, tags, runs list)
│       ├── notes.jsonl           # Append-only notes log
│       └── runs/
│           └── run_<id>.zip      # Immutable run bundles
├── locks/
│   └── case_<id>.lock            # Lock files for concurrent access
└── audit/
    └── events.jsonl              # Audit trail (planned)
```

## API Endpoints

All endpoints require Team tier. Attempting to access without Team tier returns:

```json
{
  "success": false,
  "error": {
    "code": "FEATURE_LOCKED",
    "feature": "Team Case Store",
    "required_tier": "Team",
    "upgrade_url": "https://locint.io/upgrade"
  }
}
```

### Store Management

#### GET /api/team/store/status

Check store configuration and availability.

**Response:**
```json
{
  "success": true,
  "data": {
    "configured": true,
    "store_dir": "\\\\server\\share\\locint_cases",
    "available": true,
    "writable": true,
    "reason": null
  }
}
```

#### POST /api/team/store/configure

Save store path to local configuration.

**Request:**
```json
{
  "case_store_dir": "\\\\server\\share\\locint_cases"
}
```

### Case Operations

#### GET /api/team/cases

List all cases in the store.

**Response:**
```json
{
  "success": true,
  "data": {
    "cases": [
      {
        "case_id": "case_1736500000_abc123",
        "title": "Suspicious PowerShell Activity",
        "description": "Investigation of encoded PowerShell commands",
        "tags": ["investigation", "powershell"],
        "run_count": 2,
        "notes_count": 5,
        "created_at": "2025-01-10T12:00:00Z",
        "updated_at": "2025-01-10T15:30:00Z"
      }
    ]
  }
}
```

#### POST /api/team/cases

Create a new case.

**Request:**
```json
{
  "title": "Suspicious Activity Investigation",
  "description": "Optional description",
  "tags": ["tag1", "tag2"]
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "case_id": "case_1736500000_abc123"
  }
}
```

#### GET /api/team/cases/:case_id

Get case details including recent notes.

**Response:**
```json
{
  "success": true,
  "data": {
    "case_id": "case_1736500000_abc123",
    "title": "Investigation",
    "description": "Description text",
    "tags": ["tag1"],
    "runs": [
      {
        "run_id": "run_1736500000",
        "published_at": "2025-01-10T12:00:00Z",
        "published_by": "ANALYST-PC"
      }
    ],
    "recent_notes": [
      {
        "ts": "2025-01-10T14:00:00Z",
        "author": "ANALYST-PC",
        "content": "Found evidence of lateral movement"
      }
    ],
    "created_at": "2025-01-10T12:00:00Z"
  }
}
```

#### POST /api/team/cases/:case_id/tags

Add or remove tags.

**Request:**
```json
{
  "add": ["new-tag"],
  "remove": ["old-tag"]
}
```

### Notes

#### POST /api/team/cases/:case_id/notes

Add a note to the case. Notes are append-only (JSONL format).

**Request:**
```json
{
  "content": "Found evidence of credential dumping using Mimikatz"
}
```

### Runs

#### POST /api/team/cases/:case_id/runs

Publish a local run to the case store. Creates an immutable ZIP bundle.

**Request:**
```json
{
  "run_id": "run_1736500000"
}
```

#### POST /api/team/cases/:case_id/runs/:run_id/import

Import a run from the case store to local storage.

**Response:**
```json
{
  "success": true,
  "data": {
    "local_run_id": "run_1736500000_imported"
  }
}
```

## Concurrency & Locking

The store uses file-based locking for operations that modify case metadata:

- **Lock acquisition**: Creates `locks/case_<id>.lock` with exclusive access
- **Lock timeout**: 30 seconds (stale locks are automatically cleaned up)
- **Lock contents**: JSON with `pid`, `host`, `created_at`

Operations that require locks:
- Creating cases
- Updating tags
- Publishing runs

Operations that don't require locks (append-only):
- Adding notes (JSONL append is atomic on most filesystems)

## Atomic Writes

All JSON file updates use the atomic write pattern:
1. Write to `<file>.tmp`
2. Rename to `<file>` (atomic on POSIX, usually atomic on Windows)

This prevents corruption if the operation is interrupted.

## Path Safety

All case IDs and run IDs are validated to prevent path traversal attacks:
- Must match pattern: `case_` or `run_` prefix + alphanumeric + underscores
- No `..`, `/`, or `\` allowed in IDs
- Absolute paths are rejected

## UI Features

The Team tab provides:

1. **Store Status Card**
   - Connection status badge (Connected/Read-Only/Unavailable/Not Configured)
   - Store path display
   - Case count
   - Configure and Refresh buttons

2. **Create Case Form**
   - Title, description, and tags input
   - One-click case creation

3. **Case List**
   - Searchable list of all cases
   - Shows run count, notes count, and tags
   - Click to select and view details

4. **Case Detail View**
   - Case metadata and description
   - Tag management (add/remove)
   - Published runs list with Import button
   - Notes timeline with Add Note form
   - Publish Run button (opens modal to select local run)

## Troubleshooting

### "Store unavailable" Error

1. Check that the path exists and is accessible
2. Verify network connectivity to the share
3. Check file permissions (need read/write access)
4. Try accessing the path in Explorer/Finder

### "Lock held by another process" Error

Another team member is currently modifying the case. Wait a moment and try again.
Locks automatically expire after 30 seconds if the holding process crashes.

### Import/Export Failures

- Ensure the run exists locally before publishing
- Check that the store has sufficient disk space
- Verify write permissions on the store

## Limitations (v1)

- No real-time sync (refresh manually to see changes)
- No conflict resolution for simultaneous edits
- No audit log viewer in UI (events.jsonl exists but not displayed)
- No case deletion (by design - cases are append-only)
- Maximum ~100 cases recommended per store (no pagination yet)

## Security Considerations

- Store access is controlled by filesystem permissions
- No authentication beyond filesystem ACLs
- Case IDs and run IDs are validated to prevent path traversal
- All writes are atomic to prevent corruption
- Lock files include host/PID for debugging

## Future Enhancements (Planned)

- Real-time sync via file watching
- Audit log viewer
- Case archival/deletion (soft delete)
- Pagination for large stores
- Cross-case search
- Case templates

# Team Case Store Workflow (V1)

> Last Updated: 2025-01-08
> Version: 1.1.0

## Overview

The Team Case Store enables analysts to share investigation runs across machines via a shared SMB folder. This document describes the end-to-end workflow for using the Team tab effectively.

## Prerequisites

1. **Team Tier License** — The Team tab requires `tier: Team` or `tier: Dev` plus `features.case_store: true`.
2. **Shared SMB Folder** — A network share accessible by all team members (e.g., `\\fileserver\incident_cases`).
3. **Write Permissions** — Users need read/write access to the shared folder.

## 5-Step Analyst Workflow

### Step 1: Configure the Team Store

1. Navigate to the **Team** tab.
2. If unconfigured, click **⚙️ Configure Store**.
3. Enter the UNC path to your shared folder (e.g., `\\server\share\cases`).
4. Click **Save**. The status should show "Connected" with a green badge.

**Troubleshooting:**
- If "Disconnected" appears, check network connectivity.
- Click the 📋 **Copy Diagnostics** button to capture diagnostic JSON for support.
- Common reason codes: `STORE_NOT_FOUND`, `ACCESS_DENIED`, `NETWORK_ERROR`.

### Step 2: Create or Find a Case

**Creating a New Case:**
1. Click the **Create Case** header to expand the form.
2. Enter a **Title** (required) and optional **Description** and **Tags**.
3. Click **Create Case**.

**Finding an Existing Case:**
1. Use the **Search** box to filter by case title.
2. Use the **Tag Filter** dropdown to filter by specific tags.
3. Use **Sort By** to order by: Updated, Created, # Runs, or # Notes.
4. Check **Has Runs Only** to hide empty cases.

**Provenance Chips:**
Each case shows a small 🖥️ chip indicating the host that created or last updated it.

### Step 3: Publish a Run to the Case

1. Select a case from the list.
2. In the **Runs** sub-tab, click **+ Publish Run**.
3. Select a run from the dropdown (shows all local runs).
4. Click **Publish**. The run bundle is copied to the shared store with:
   - Two-phase atomic write (temp → verify → move)
   - SHA256 integrity verification
   - Provenance metadata (your hostname, username hint)

### Step 4: Review Shared Runs and Import

**Viewing Runs:**
1. Select a case to see its published runs.
2. Each run shows: Run ID, timestamp, event/signal counts, publisher host.
3. Click **Copy Path** to copy the bundle's network path.

**Importing Runs:**
- **Single Import:** Click **Import** on any run to import it to your local instance.
- **Bulk Import:** Check multiple runs → click **Import Selected (N)**. A progress bar shows import status.

After import, switch to the **Runs** tab in the main UI to view imported runs.

### Step 5: Collaborate with Notes and Tags

**Adding Notes:**
1. Go to the **Notes** sub-tab.
2. Type your note in the text area and click **Add Note**.
3. Notes show: content, timestamp, author (host + user hint).
4. Click **📋 Copy** on any note to copy its text.

Notes are grouped by day for easy timeline navigation.

**Managing Tags:**
1. Go to the **Tags** sub-tab to see all tags.
2. Add new tags using the input field + **Add Tag** button.
3. Click **×** on any tag to remove it.

## UX Features Summary

| Feature | Description |
|---------|-------------|
| **Auto-Refresh** | Store status refreshes every 10 seconds when Team tab is open |
| **Search Debounce** | 300ms debounce on search to avoid excessive filtering |
| **Copy Diagnostics** | Copies JSON diagnostics when store is disconnected |
| **Provenance Chips** | Shows creator/updater host on cases and runs |
| **Multi-Select Import** | Checkbox selection for bulk run import |
| **Progress Bar** | Visual progress during bulk import operations |
| **Toast Notifications** | Non-blocking success/error messages |
| **Empty State Messages** | Clear guidance when no cases or runs exist |

## Store Health Indicators

| Badge | Meaning |
|-------|---------|
| 🟢 Connected | Store is available and writable |
| 🟡 Read-Only | Store exists but you lack write permissions |
| 🔴 Disconnected | Store path is unreachable |

## Lock & Publish Flow (Technical)

```
1. Lock Acquisition
   - Request lock with 5-minute heartbeat timeout
   - Lock file contains: timestamp, hostname, user_hint, pid

2. Two-Phase Publish
   a. Write to temp file: case_id.tmp
   b. Compute SHA256 hash
   c. Verify hash matches expected
   d. Atomic rename: case_id.tmp → case_id.json

3. Lock Release
   - Remove lock file
   - Auto-expires after 5 minutes if orphaned
```

## Sub-tabs Reference

| Tab | Contents |
|-----|----------|
| **📊 Runs** | Published run bundles, import/export actions |
| **📝 Notes** | Investigation notes timeline with copy buttons |
| **🏷️ Tags** | Tag management (add/remove) |
| **📈 Overview** | [V2] Aggregate view across all runs (coming soon) |

## Error Handling

| Error | Resolution |
|-------|------------|
| `Failed to load cases` | Check store connectivity; refresh manually |
| `This case is unreadable` | Case JSON is corrupt; restore from backup |
| `Lock held by another user` | Wait for 5-minute timeout or contact lock holder |
| `Import failed` | Check disk space; verify bundle integrity |

## Related Documentation

- [UI_VERIFICATION_CHECKLIST.md](UI_VERIFICATION_CHECKLIST.md) — Full UI test matrix
- [ENDPOINT_CONTRACTS.md](ENDPOINT_CONTRACTS.md) — API contracts for Team endpoints
- [TRUTH_CONTRACT.md](../TRUTH_CONTRACT.md) — Data isolation guarantees

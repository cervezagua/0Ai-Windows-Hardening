# 0AI v2.3 Architecture

This document describes the layered, manifest-driven architecture that replaces
the monolithic `.bat` files in v2.2. v2.2 remains available under `legacy/`
for reference.

## 1. Goals

- **User-intent-aligned categories** instead of the v2.2 A/B/C grouping.
- **Declarative policies** stored as data (`.psd1`) separated from the code
  that applies them.
- **Parallel execution** of safe policies (registry writes, service toggles)
  with explicit concurrency caps for unsafe ones (Defender, Appx, mitigations).
- **Symmetric revert** that reads a run manifest (`run.json`) and walks each
  action backwards through the same dispatcher.
- **PowerShell-first** so we can actually test the code. Windows PowerShell
  5.1 is the minimum baseline.
- **No regressions**: every v2.2 policy is preserved as a `.psd1` record,
  except `DisableSettingsAgenticSearch`, which v2.13.0 removed because it
  never existed (the real control is `DisableSettingsAgent`). Revert can
  still undo it via `src/retired/retired.psd1`.

## 2. The 5-category model

| Code      | Name                               | Run by default |
|-----------|------------------------------------|----------------|
| `AI`      | Disable AI across the OS           | yes            |
| `PRIV`    | Privacy & telemetry                | yes            |
| `HARD`    | Security hardening                 | yes            |
| `DEBLOAT` | Remove bundled apps (destructive)  | **no**         |
| `AUDIT`   | Read-only state report             | yes            |

`Apply.ps1` with no arguments runs `AI,PRIV,HARD,AUDIT`. `DEBLOAT` must be
requested explicitly via `-Categories AI,PRIV,HARD,DEBLOAT,AUDIT` because its
Appx removals are not reinstalled by `Revert.ps1`.

## 3. Policy schema

Each change is represented by a hashtable record in a `.psd1` file under
`src/manifest/`. Common fields:

| Field         | Required | Meaning                                                      |
|---------------|----------|--------------------------------------------------------------|
| `Id`          | yes      | Dotted unique id, e.g. `AI.WindowsAI.AllowRecallEnablement`  |
| `Category`    | yes      | One of `AI PRIV HARD DEBLOAT AUDIT`                          |
| `Group`       | yes      | Exec group (see below)                                       |
| `Description` | yes      | Human-readable one-liner                                     |
| `Kind`        | yes      | Dispatcher key (see below)                                   |
| `MinBuild`    | no       | Minimum Windows build; `0` = any                             |
| `DocUrl`      | no       | Microsoft Learn / reference URL                              |
| `Confidence`  | no       | `Documented` / `Community` / `BestEffort`                    |
| `Reversible`  | no       | `$true` / `$false`                                           |
| `Destructive` | no       | `$true` for DEBLOAT + Recall purge                           |

Kind-specific fields:

- **Registry** – `Hive` (`HKLM`/`HKCU`), `Key`, `Value`, `Type`, `Data`
  - optional `RequiresService`: apply only where that service is installed
    (otherwise Apply skips and Verify reports `n/a`)
  - optional `UcpdProtected = $true` + `GroupPolicy`: Windows' UCPD driver
    blocks scripted writes to the value; Apply skips with the Group Policy
    route while UCPD runs and the value isn't set, Verify reports `n/a`
- **Service** – `Name`, `State='Stopped'`, `StartupType='Disabled'`
  - a service that isn't installed is skipped (Apply) and `n/a` (Verify)
- **AppxRemove** – `NamePattern` (regex), `AllUsers`, `Provisioned`
- **DefenderPref** – `Preference` (e.g. `PUAProtection`), `Value`
- **DefenderAsr** – `RuleId` (GUID), `Action` (`Enabled`/`Disabled`)
- **Mitigation** – `Enable` (array), `Disable` (array)
- **FolderPurge** – `Path` (env-var expandable, destructive)
- **Report** – `Script` (scriptblock-as-string)

Schema tests live in `tests/Manifest.Tests.ps1` and run on pwsh anywhere.

## 4. Exec groups and parallelism

| Group        | Max concurrent | Why                                         |
|--------------|----------------|---------------------------------------------|
| `reg-safe`   | 16             | registry writes are independent             |
| `sc-safe`    | 8              | `sc.exe` / `Set-Service` are fine parallel  |
| `appx`       | 1              | DISM serializes anyway                      |
| `defender`   | 1              | `Set-MpPreference` hates concurrency        |
| `mitigation` | 1              | `Set-ProcessMitigation -System` is global   |
| `folder`     | 1              | destructive                                 |
| `report`     | 4              | read-only CIM/Appx queries                  |

Groups **themselves run concurrently**. The runner spawns one `ThreadJob`
per exec group; each group runner then parallelises its own policies up to
its cap. A slow `appx` removal in DEBLOAT never blocks fast reg writes in
PRIV/HARD.

Fallback strategy:

1. If `Start-ThreadJob` is available (Windows PS 5.1 with `ThreadJob` module,
   or PS7), use it.
2. Otherwise run sequentially and emit a warning.

PS 7-only features (`ForEach-Object -Parallel`, null-coalescing, etc.) are
guarded by `$PSVersionTable.PSVersion.Major -ge 7` checks. None are required.

## 5. File layout

```
/
+-- 0AI_Apply.cmd         launcher: self-elevate + PS Apply.ps1
+-- 0AI_Revert.cmd        launcher: self-elevate + PS Revert.ps1
+-- 0AI_Verify.cmd        launcher: read-only state check
+-- src/
|   +-- Apply.ps1         entry point: load manifest, plan, run
|   +-- Revert.ps1        entry point: read run.json, undo
|   +-- Verify.ps1        entry point: compare expected vs current
|   +-- manifest/
|   |   +-- ai.psd1
|   |   +-- priv.psd1
|   |   +-- hard.psd1
|   |   +-- debloat.psd1
|   |   +-- audit.psd1
|   +-- retired/
|   |   +-- retired.psd1  Ids older versions applied; Revert can still undo them
|   +-- module/
|       +-- OAi.Manifest.psm1     shared manifest + retired-list loader, -Select check
|       +-- OAi.BackupAcl.psm1    lock backup folders admin-only; Revert's check
|       +-- OAi.BackupHistory.psm1 pick snapshots from older backups for skipped policies
|       +-- OAi.Engine.psm1       primitives (Invoke/Test/Backup/Undo)
|       +-- OAi.Runner.psm1       orchestration + parallelism
|       +-- OAi.UI.Console.psm1   live progress display
|       +-- OAi.UI.Plan.psm1      dry-run plan viewer
+-- tests/
|   +-- Manifest.Tests.ps1        Pester v5 schema tests
+-- docs/
|   +-- ARCHITECTURE.md           (this file)
+-- legacy/
|   +-- 0AI_Apply_v2_2.bat
|   +-- 0AI_Revert_v2_2.bat
+-- README.md
+-- LICENSE
```

## 6. Layers

### Layer 1 — Manifest (data)

One `.psd1` per category. Each file is a hashtable array. See section 3.

### Layer 2 — Engine (`OAi.Engine.psm1`)

Pure, stateless primitives:

- `Test-Precondition -Policy $p` — checks MinBuild, current state, skip
  conditions. Returns `$false` if the policy is already applied.
- `Backup-PolicyState -Policy $p -BackupDir $dir` — writes a snapshot
  appropriate to the Kind (reg export, service JSON, Defender prefs JSON,
  mitigation XML, etc.). Returns the backup file path.
- `Invoke-PolicyAction -Policy $p -BackupDir $dir` — dispatches on `Kind`,
  returns a `PolicyResult` record.
- `Undo-PolicyAction -Policy $p -BackupDir $dir -BackupFile $bf` — reverses
  a previously-applied policy using its backup snapshot.

`PolicyResult`: `Id`, `Status` (ok/warn/error/skipped), `DurationMs`,
`Message`, `BackupFile`.

All primitives catch exceptions and return structured results. The engine
never crashes the runner.

### Layer 3 — Runner (`OAi.Runner.psm1`)

- `New-Plan -Manifest $m -Categories @(...) -Selected @(...)` — filters the
  manifest and produces a plan object.
- `Invoke-Plan -Plan $plan -BackupDir $dir -EventQueue $q` — groups by
  `Group`, spawns one ThreadJob per group, processes each group up to its
  cap, collects a `PlanResult`.

Progress events are written to a
`System.Collections.Concurrent.ConcurrentQueue` that the UI drains.

### Layer 4 — UI

- `OAi.UI.Console.psm1` — drain the event queue, emit `[OK]`/`[WARN]`/
  `[ERROR]`/`[SKIP]` lines. ANSI coloring if `SupportsVirtualTerminal`.
- `OAi.UI.Plan.psm1` — render plan grouped by `Confidence`; non-interactive
  print when the host lacks ReadKey.

### Layer 5 — Entry points

- `Apply.ps1` — admin check, backup dir, restore point, load manifest, plan,
  console UI, `Invoke-Plan`, write `run.json` + `verification.txt` +
  `apply.log`.
- `Revert.ps1` — find newest backup, read `run.json`, walk actions through
  `Undo-PolicyAction`, write `revert.log`.
- `Verify.ps1` — read-only diff of manifest vs current state.

### Layer 6 — Launchers

Tiny `.cmd` files that self-elevate via
`Start-Process -Verb RunAs` and invoke `powershell -NoProfile
-ExecutionPolicy Bypass -File <ps>`. Same execution-policy posture as v2.2.

### Layer 7 — Tests

Pester v5 schema tests in `tests/Manifest.Tests.ps1`. Runnable on pwsh on
Linux because they only touch `.psd1` data.

## 7. Adding a new policy

1. Pick the right category file in `src/manifest/`.
2. Append a hashtable record with a unique `Id`, correct `Category`,
   `Group`, `Kind`, and Kind-specific fields.
3. Run the Pester tests:
   ```
   pwsh -NoProfile -Command "Invoke-Pester ./tests/Manifest.Tests.ps1"
   ```
4. Verify with `Verify.ps1` on a test machine.

No module code needs to change for a new Registry, Service, Appx, Defender
or Mitigation policy — the dispatcher already handles them.

## 8. How Revert works

At Apply time, every `Invoke-PolicyAction` call writes a `PolicyResult`
with a `BackupFile` pointing at the per-Kind snapshot. The full run is
serialized to `run.json`.

`Revert.ps1` then:

1. Finds the newest backup with a `run.json`: first under
   `%ProgramData%\0AI_Backups\<account SID>` (v2.14.2+, where Apply creates
   each folder admin-only in one step via `OAi.BackupAcl.psm1`), then the old
   `%USERPROFILE%\0AI_Backups`, preferring trusted ones.
2. Trusts a backup only if the folder, its files and every folder above it
   are safe from changes, renames and replacement by non-admin accounts.
   Otherwise (v2.14.1-or-earlier backups) it asks for a typed `YES` or
   `-AllowUnlockedBackup` and works from an admin-only copy; a backup that is
   or contains a junction or symlink is refused. Then reads `run.json`.
3. For each Registry/Service result with no snapshot in this backup (Apply
   skipped it because it was already in place), finds the newest older
   backup that recorded one, stopping at an older run whose own Revert
   already restored that Id. Untrusted older backups need one `YES` and are
   read from admin-only copies.
4. For each result, looks up the matching policy record in the current
   manifest, or else in `src/retired/retired.psd1`. An Id in neither is
   skipped with a `[warn]` on the console and in `revert.log`.
5. Calls `Undo-PolicyAction`, which dispatches by `Kind`:
   - Registry → restore the one value from its per-value JSON snapshot
     (value did not exist before → delete it). Legacy `.reg` backups
     (v2.9.3 and earlier) are read in memory for that one value only;
     `reg import` is never run. The location always comes from the manifest
     or retired list, never from the backup, which Revert reads with admin
     rights
   - Service → restore startup type from JSON snapshot
   - DefenderPref → restore preference from run-snapshot JSON
   - DefenderAsr → `Remove-MpPreference`
   - Mitigation → delete the system `MitigationOptions` override (reset to
     Windows defaults; reboot required)
   - AppxRemove → **no-op** (matches v2.2 by design)
   - FolderPurge → **no-op** (destructive, documented)
   - Report → no-op

## 9. Non-goals

- Forcing Firewall or Defender Real-Time on.
- Reinstalling removed Appx packages.
- Enforcing Smart App Control (report-only).
- Any undocumented app-private data hacking.
- Network calls of any kind. The script is fully offline.

## 10. Execution policy

Same posture as v2.2: the launchers invoke PowerShell with
`-ExecutionPolicy Bypass`. This is a deliberate choice — signing the
scripts is out of scope for a community hardening kit. Users who prefer a
signed pipeline can import the modules directly from an elevated prompt.

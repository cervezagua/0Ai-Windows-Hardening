# 0AI - Windows Hardening Kit

### Windows 11 Privacy, AI Disablement & Security Hardening
**Version:** `v2.3`

**Supported baselines:** Windows 11 24H2 (OS Build **26100.8246+**) and 25H2
(OS Build **26200.8246+**), through the **April 2026 cumulative KB5083769**.
Earlier builds still work but the 25H2-specific switches (e.g. File Explorer
AI Actions) are no-ops.

> **v2.2 users**: the legacy `.bat` scripts are preserved under `legacy/` and
> still work. v2.3 is a PowerShell-first rewrite with the same effective
> policies — see `docs/ARCHITECTURE.md`.

---

## Quick Start (v2.3)

### Apply
1. **Right-click** `0AI_Apply.cmd`
2. Select **Run as Administrator**
3. Wait for the console progress to finish
4. **Reboot** when done

By default this runs categories `AI`, `PRIV`, `HARD`, and `AUDIT`. It does
**not** run `DEBLOAT` (destructive Appx removal) unless you explicitly ask
for it.

```cmd
REM Include Widgets + Phone Link removal (not reinstallable via revert):
0AI_Apply.cmd -Categories AI,PRIV,HARD,DEBLOAT,AUDIT

REM Dry-run: show the plan and exit without changes:
0AI_Apply.cmd -WhatIf

REM Run only specific policies by ID:
0AI_Apply.cmd -Select AI.WindowsAI.AllowRecallEnablement,HARD.Defender.PUAProtection
```

### Revert
1. **Right-click** `0AI_Revert.cmd`
2. Select **Run as Administrator**
3. **Reboot**

Revert finds the most recent backup folder under
`%USERPROFILE%\0AI_Backups`, reads `run.json`, and walks each action
backwards through the same dispatcher. It does **not** reinstall removed
Appx packages (matches v2.2 behaviour).

### Verify (read-only)
```cmd
0AI_Verify.cmd
```
Prints a table of `Id | Expected | Current | Status` for every policy in
the manifest. No changes.

---

## The 5 categories

| Code      | Name                               | Default? | What it does                                                                 |
|-----------|------------------------------------|----------|------------------------------------------------------------------------------|
| `AI`      | Disable AI across the OS           | yes      | Copilot, Recall, Click-to-Do, Paint AI, Notepad AI, Edge AI, `systemAIModels=Deny` |
| `PRIV`    | Privacy & telemetry                | yes      | DiagTrack/dmwappush off, AllowTelemetry, Advertising ID, WER, Activity History, sync banners |
| `HARD`    | Security hardening                 | yes      | RDP off, Restricted Admin, Defender PUA + ASR subset, Exploit Protection     |
| `DEBLOAT` | Remove bundled apps (destructive)  | **no**   | Widgets / WebExperience, Phone Link / YourPhone / CrossDevice                |
| `AUDIT`   | Read-only state report             | yes      | OS build, AI component snapshot, Smart App Control state, effective telemetry |

`DEBLOAT` is excluded by default because removed Appx packages are **not**
reinstalled by `Revert.ps1`. Opt in only if you're comfortable with that.

---

## What's new in v2.3

- **New architecture** — layered, manifest-driven, PowerShell-first. Each
  policy is a data record in `src/manifest/*.psd1`, dispatched by
  `src/module/OAi.Engine.psm1`, orchestrated with real parallelism by
  `src/module/OAi.Runner.psm1`. See `docs/ARCHITECTURE.md`.
- **5-category model** replaces the v2.2 A/B/C menu.
- **Parallel execution** — registry writes and service toggles run in
  parallel with per-group caps (reg-safe=16, sc-safe=8, appx=1, defender=1,
  mitigation=1, report=4). Slow Appx removals in `DEBLOAT` no longer block
  fast reg writes in `PRIV`/`HARD`.
- **Symmetric revert** via `run.json` — every action recorded at apply time
  is reversed through the same dispatcher, not a hand-maintained list.
- **`-WhatIf` dry-run** prints the plan grouped by Confidence and exits
  without making changes.
- **`Verify.ps1`** is a first-class read-only command that diffs expected
  vs current state for every policy.
- **Pester schema tests** in `tests/Manifest.Tests.ps1` run anywhere with
  `pwsh` installed (no Windows cmdlets required).

No v2.2 policy was dropped. The `HideAIActionsMenu` entry is labelled
`Community` and the Narrator `ImageDescriptionsEnabled` entry is labelled
`BestEffort`, matching the v2.2 caveats.

---

## What this script does NOT do

- Does **not** force the Windows Firewall on.
- Does **not** force Defender Real-Time Protection on.
- Does **not** force Smart App Control on (report-only).
- Does **not** reinstall removed Appx packages on revert.
- Does **not** make any network calls.
- Does **not** touch app-private storage or undocumented registry keys.

These are intentional design choices.

---

## Execution policy

The launchers invoke PowerShell with `-ExecutionPolicy Bypass` — the same
posture as v2.2. The scripts are not code-signed. If your environment
requires signed scripts, import the modules directly from an elevated
prompt or sign them yourself.

---

## File layout

```
/
|-- 0AI_Apply.cmd            launcher
|-- 0AI_Revert.cmd           launcher
|-- 0AI_Verify.cmd           launcher
|-- src/
|   |-- Apply.ps1
|   |-- Revert.ps1
|   |-- Verify.ps1
|   |-- manifest/            data: one .psd1 per category
|   `-- module/              engine + runner + UI
|-- tests/Manifest.Tests.ps1
|-- docs/ARCHITECTURE.md
|-- legacy/                  v2.2 .bat scripts, preserved for reference
`-- README.md                (this file)
```

---

## Legacy v2.2

The v2.2 `.bat` scripts are still in the repo under `legacy/`:

- `legacy/0AI_Apply_v2_2.bat`
- `legacy/0AI_Revert_v2_2.bat`

They are unchanged from the `823d2da` commit on `main` and continue to work
on any Windows 11 build. Use v2.2 if you prefer a single self-contained
batch script; use v2.3 if you want the manifest-driven design, parallel
execution, `-WhatIf`, structured revert, and Pester schema tests.

---

## Safety & reversibility

Before making changes, Apply:
- Creates a best-effort **System Restore Point**
- Writes per-policy backup snapshots to
  `%USERPROFILE%\0AI_Backups\<timestamp>\`
- Saves `apply.log`, `run.json`, and `verification.txt`

Revert:
- Reads the newest `run.json`
- Restores registry snapshots with `reg import`
- Restores Defender preferences from the pre-run snapshot
- Removes the ASR rules it added
- Disables the process mitigations it enabled
- Does **not** reinstall removed Appx packages (by design)

---

## Threat model

Designed to:
- Prevent silent background AI activity
- Reduce data collection and agentic behaviour
- Preserve system stability and update compatibility

> Security correctness is prioritized over cosmetic enforcement. Aggressive
> or undocumented techniques are intentionally excluded.

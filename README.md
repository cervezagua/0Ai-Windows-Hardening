# 0AI - Windows Hardening Kit

### Windows 11 Privacy, AI Disablement & Security Hardening
**Version:** `v2.9.4`

**Supported baselines:** Windows 11 24H2 (OS Build **26100.8894+**) and 25H2
(OS Build **26200.8894+**), through the **July 18 2026 out-of-band KB5121767**
(which builds on the July Patch Tuesday KB5101650). Earlier builds still work
but the 25H2-specific switches (e.g. File Explorer AI Actions, IsoEnvBroker,
RemoveMicrosoftCopilotApp) are no-ops.

**Runs correctly on every Windows display language.** All string matching is
pinned to the invariant culture — see *Localization* below for why that
matters.

> **v2.2 users**: the legacy `.bat` scripts are preserved under `legacy/` and
> still work. v2.3 is a PowerShell-first rewrite with the same effective
> policies — see `docs/ARCHITECTURE.md`.

---

## Quick Start (v2.5)

### Apply
1. **Right-click** `0AI_Apply.cmd`
2. Select **Run as Administrator**
3. An interactive picker appears — use `Up/Down` to move, `SPACE` to
   toggle a category, `D` to toggle dry-run, `ENTER` to run, `Q` to quit
4. Wait for the console progress to finish
5. **Reboot** when done

By default the picker pre-selects `AI`, `PRIV`, `HARD`, and `AUDIT`. It
leaves `DEBLOAT` (destructive Appx removal) **off** — toggle it on with
`SPACE` if you want it.

The picker is skipped if you pass any parameters on the command line, so
automation and CI still work unchanged:

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
| `AI`      | Disable AI across the OS           | yes      | Copilot (disable + remove app), Recall, Click-to-Do, IsoEnvBroker (agentic framework), Paint AI (incl. Remove Background / Generative Erase), Photos AI (Blur / Erase Objects), Notepad AI, Edge AI, `systemAIModels=Deny` |
| `PRIV`    | Privacy & telemetry                | yes      | DiagTrack/dmwappush off, AllowTelemetry, Advertising ID, WER, Activity History, sync banners, online speech recognition, Cloud Content / Spotlight / consumer features, Tailored Experiences, online tips, Find My Device, feedback notifications |
| `HARD`    | Security hardening                 | yes      | RDP off, Restricted Admin, Defender PUA + ASR subset, Exploit Protection, batch file locking |
| `DEBLOAT` | Remove bundled apps (destructive)  | **no**   | Widgets / WebExperience, Phone Link / YourPhone / CrossDevice                |
| `AUDIT`   | Read-only state report             | yes      | OS build, SKU, AI component snapshot, effective telemetry level              |

`DEBLOAT` is excluded by default because removed Appx packages are **not**
reinstalled by `Revert.ps1`. Opt in only if you're comfortable with that.

---

## What's new in v2.9.4

**Root cause of the Bitdefender block, found and removed.** A user's log
plus Bitdefender's own report pinned it exactly:

```
Antivirus            The item ...\0AI_Backups\...\HKLM_SOFTWARE_Policies_Microsoft_Dsh.reg
                     was deleted at user request.
Advanced Threat      Bitdefender detected potentially malicious behavior and
Defense              blocked all applications involved.
```

The file Bitdefender killed was **our own backup**, not a Windows key. The
chain was:

1. Policies already applied are **skipped**, and skipped policies are never
   backed up — so `DEBLOAT.Dsh.AllowNewsAndInterests`, the only registry
   policy still needing work, was the *only* one to reach the backup step.
2. Backup ran `reg.exe export` and wrote
   `HKLM_SOFTWARE_Policies_Microsoft_Dsh.reg`.
3. Bitdefender deleted that `.reg` file and ATD "blocked all applications
   involved".
4. The registry write that followed therefore failed with *"Attempted to
   perform an unauthorized operation"* — surfacing as the `[WARN]` added in
   v2.9.1. It was never an ACL problem or a value-type problem.

**Fix: registry backups are now per-value JSON snapshots, not `.reg`
exports.** No `.reg` files are written and `reg.exe` is no longer spawned.
This is also strictly more correct:

- `reg export`/`import` round-trips the **whole key**, so a revert could
  resurrect unrelated values or clobber changes made after apply. A
  per-value snapshot reverts exactly what the kit touched.
- It can represent *"this value did not exist before"* (revert = delete it),
  which `reg import` cannot express at all.
- It matches the JSON format already used for service, Appx and Defender
  backups.

Backup folders written by v2.9.3 and earlier still contain `.reg` files;
`Revert.ps1` detects those and keeps using `reg import` for them, so old
backups remain restorable.

> This removes the one trigger Bitdefender named a file for. Advanced Threat
> Defense may still score the process on its other behaviour (changing
> Defender settings, disabling services, bulk policy writes) — the exclusion
> guidance under *Antivirus false positives* still applies.

## What's new in v2.9.3

- **Universal locale fix.** v2.9.2 patched the two *known* Turkish-locale
  failures individually. That was whack-a-mole: the same trap exists at
  every `-match` / `-replace` / `-like` in the codebase (Appx name matching
  in `Verify.ps1` and `OAi.Engine.psm1`, the `-like` filters in
  `audit.psd1`), and at every one added in future. All four entry points now
  pin the thread to **`InvariantCulture`** before doing any work, so string
  handling is identical on every Windows display language. See
  *Localization*. The targeted `-creplace` / `CultureInvariant` fixes from
  v2.9.2 are kept as defence in depth for anyone importing the modules
  directly.
- **Baseline bumped to KB5121767** (July 18 2026 out-of-band, builds
  26100.8894 / 26200.8894). Out-of-band fix for an Intel Innovation Platform
  Framework driver issue; it also unblocks Dell devices that were held back
  from KB5101650. **No new AI or privacy surfaces**, so no new policies.
- **Antivirus behaviour documented honestly.** New *Antivirus false
  positives* section explains why behaviour-based AV flags this kit (unsigned
  script + Defender changes + service disabling + bulk policy writes is
  indistinguishable from system-tampering malware to a heuristic), what was
  already removed in v2.9.1 to reduce it, and how to add a Bitdefender
  exclusion that covers **Advanced Threat Defense** and not just the
  on-access scanner. The kit will not add evasion techniques to dodge
  detection.

## What's new in v2.9.2 (hotfix)

Found by reading a real apply log from a Turkish-locale machine.

- **Report filenames were mangled on Turkish/Azeri locales.**
  `AUDIT.AI.ComponentSnapshot` was written out as
  `report_AUD_T.A_.ComponentSnapshot.json` — every capital **I** became `_`.
  Cause: PowerShell's `-replace` is case-**insensitive** and folds case using
  the *current culture*. Under Turkish rules `I` (U+0049) folds to dotless
  `ı` (U+0131), which falls outside the `a-z` range, so the "invalid
  character" class `[^A-Za-z0-9._-]` matched every `I`. Fixed by using the
  case-**sensitive** `-creplace`, which does no case folding at all.
- **The same bug class silently weakened the diagnostic.**
  `Snapshot-AIShellVerbs.ps1` flagged AI candidates with `-match '(?i)ai|…'`;
  on a Turkish locale that fails to match a key literally named **AI** — the
  exact thing it exists to find. All its matches now go through a
  `CultureInvariant` helper so results are identical on every locale.
- **Seven scary `WARNING:` lines on every run, gone.** `Start-ThreadJob`
  ships with PowerShell 7+, not stock 5.1, so the sequential path is the
  *normal* case on Windows 11 — but the runner warned once per exec group.
  Now it prints a single `[i]` informational line, and the README no longer
  overpromises parallelism (see v2.3 notes).
- **Registry writes retry once on a type mismatch.** `-Force` can't always
  overwrite a value that already exists with a different registry type. The
  engine now deletes the stale value and retries; if that fails too it
  rethrows the *original* error, so a genuine ACL / AV-tamper denial is
  still reported as the `[WARN]` added in v2.9.1.
- **The tool no longer calls itself v2.3.** Version lived hardcoded in eight
  places, so logs said `0AI v2.3 Apply starting` while running v2.9.1
  policies. New `src/module/OAi.Version.psm1` is the single source of truth
  for every banner, log header and restore-point name.

## What's new in v2.9.1 (hotfix)

- **Backed out the machine-wide "Ask Copilot" block that tripped
  antivirus.** v2.9 wrote the Copilot shell-extension CLSID into
  `HKLM\...\Shell Extensions\Blocked`. Writing a CLSID into the
  *machine-wide* Blocked list is a recognized defense-evasion technique
  (MITRE T1112 — disabling shell/security extensions), so Bitdefender's
  tamper/registry-guard module intercepted it: the HKLM write was denied
  ("unauthorized operation") **and the whole apply run was flagged as
  malware**. The kit now keeps **only the per-user HKCU block**, which is
  not guarded that way, still hides "Ask Copilot" for the signed-in user,
  and matches the kit's threat model (no aggressive/undocumented
  machine-wide techniques). `RemoveMicrosoftCopilotApp` (v2.8) remains the
  documented path that removes Copilot at its source.
- **Access-denied writes now report as `[WARN]`, not `[ERROR]`.** When a
  third-party AV tamper-guard or a TrustedInstaller-protected key denies
  an otherwise-valid elevated write (e.g. the `DEBLOAT.Dsh.*` Widgets/News
  policies under some Bitdefender configs), the engine now classifies it
  as a warning with a clear cause — *"access denied (AV tamper-protection
  or protected key)"* — instead of a hard error that looks like a kit bug.
  Genuine failures still surface as errors.

## What's new in v2.9

- **Baseline bumped to KB5101650** (July 14 2026 Patch Tuesday, builds
  26100.8875 / 26200.8875) — Microsoft's largest security release to
  date (570 CVEs fixed).
- **Block the "Ask Copilot" File Explorer shell extension** (2 new AI
  policies). KB5101650 surfaced "Ask Copilot" as a File Explorer Home
  **hover action**; the same Copilot packaged-COM handler also owns the
  right-click "Ask Copilot" verb. The kit now adds the extension's
  CLSID `{CB3B0003-8088-4EDE-8769-8B354AB2FF8C}` to the Shell Extensions
  **Blocked** list (HKLM + HKCU), removing the entry without uninstalling
  Copilot. Community-identified CLSID (confirmed across multiple
  independent sources), fully reversible.
- **Reviewed, no action needed**: KB5101650's other changes (Point-in-Time
  Restore, Bluetooth/AirPods fixes, faster File Explorer, Secure Boot
  cert rollout) are not AI/privacy surfaces. The File Explorer Home hover
  action is Copilot-app driven, so `RemoveMicrosoftCopilotApp` (v2.8) plus
  this CLSID block cover it.

## What's new in v2.8

- **Baseline bumped to June 2026** — KB5094126 (June 9 Patch Tuesday)
  and KB5095093 (June 23 preview), builds 26100.8737 / 26200.8737.
- **`RemoveMicrosoftCopilotApp` scope fix**. v2.7 wrote this policy to
  HKLM only, but Microsoft defined it as a **User Configuration** policy
  that reads from `HKCU\Software\Policies\Microsoft\Windows\WindowsAI` —
  so it likely never took effect. v2.8 adds the documented HKCU entry
  and keeps the HKLM twin as a best-effort mirror. This policy also
  blocks the **dockable Copilot sidebar** Microsoft started rolling out
  in late May 2026 (the sidebar ships inside the Copilot app; removing
  the app removes the sidebar).
- **Reviewed, no action needed**: KB5095093's NPU standby profile lets
  AI tasks (Studio Effects, Live Captions, on-device Copilot) keep
  running during Modern Standby. Microsoft ships **no dedicated policy**
  to disable NPU-standby processing; the kit's existing
  `systemAIModels=Deny` + Copilot disables are the effective mitigation.
  Similarly, `AgentConnectorMinimumPolicy` (agent connectors CSP) still
  has no documented allowed values, so it stays out of the manifest —
  the kit only ships registry values Microsoft actually documents.

## What's new in v2.7

- **Baseline bumped to KB5089549** (May 12 2026 Patch Tuesday, builds
  26100.8457 / 26200.8457). This is the mandatory security update that
  rolls up KB5083631's preview features into GA.
- **`RemoveMicrosoftCopilotApp`** (1 new AI policy). Official Microsoft
  GP/CSP that uninstalls the Copilot app binary from the device if it
  hasn't been launched in 28 days. Stronger than `TurnOffWindowsCopilot`
  which only hides the UI. Works on 25H2 Pro/Enterprise/Education.
- **`LockBatchFilesWhenInUse`** (1 new HARD policy). Enables batch file
  secure mode: the command processor locks `.bat`/`.cmd` files during
  execution, preventing runtime tampering or command-substitution
  attacks. No reboot required.

## What's new in v2.6

- **Baseline bumped to KB5083631** (April 30 2026 preview, builds
  26100.8328 / 26200.8328).
- **IsoEnvBroker disabled** (2 new policies). KB5083631 introduces
  taskbar-based AI agent monitoring and a system-level "experimental
  agentic features" broker service (`IsoEnvBroker`). The kit now
  disables the broker via its `Enabled` registry value **and**
  stops + disables the service, preventing background AI agents
  (including third-party ones) from running through the Windows
  agentic framework.
- **Mandatory ASLR removed** from `HARD.Mitigation.System`.
  `ForceRelocateImages` broke Cygwin/MSYS2-based tools (Git for
  Windows, etc.) by randomizing DLL load addresses that `fork()`
  requires to be fixed. The remaining mitigations (DEP, BottomUp,
  HighEntropy, SEHOP) are unaffected.

## What's new in v2.5

- **Honest labelling of the AI actions menu gap**. The
  `HideAIActionsMenu=1` policy that was supposed to hide the
  right-click "AI actions" submenu on images is confirmed **not
  effective on build 26200**. Microsoft only wired it starting at
  build 26220.7344+. There is **no working registry fix** on 26200 —
  the menu and its actions (Generative erase, Remove background, Blur
  background, Erase objects) remain functional. The existing
  `HideAIActionsMenu` entries are retained (they'll work once your
  build updates to 26220+) and re-labelled to say "best-effort;
  bypassed on 26200+".
- **New diagnostic `src/Snapshot-AIShellVerbs.ps1`**. Read-only.
  Enumerates the shell verbs registered under
  `HKLM\SOFTWARE\Classes\SystemFileAssociations\image\Shell` (and
  related), plus the current state of the kit-managed AI-action keys,
  so we can target specific shell registrations if a workaround is
  found. Run it with
  `powershell -NoProfile -File src\Snapshot-AIShellVerbs.ps1`.

## What's new in v2.4

- **Interactive launcher picker**. Double-clicking `0AI_Apply.cmd` no
  longer runs straight to the engine — it opens an arrow-key / SPACE
  checkbox picker so you can choose which categories to apply without
  typing a command line. `DEBLOAT` is still off by default and flagged
  in red. Passing any CLI parameter (`-Categories`, `-Select`,
  `-WhatIf`) skips the picker, so automation is unaffected. Defined in
  `src/module/OAi.UI.Launcher.psm1`.
- **Codepage fix in the launcher**: `0AI_Apply.cmd` now sets
  `chcp 65001` before spawning PowerShell so the box-drawing characters
  in the picker render cleanly on default conhost.

## What's new in v2.3

- **New architecture** — layered, manifest-driven, PowerShell-first. Each
  policy is a data record in `src/manifest/*.psd1`, dispatched by
  `src/module/OAi.Engine.psm1`, orchestrated with real parallelism by
  `src/module/OAi.Runner.psm1`. See `docs/ARCHITECTURE.md`.
- **5-category model** replaces the v2.2 A/B/C menu.
- **Parallel execution** — registry writes and service toggles run in
  parallel with per-group caps (reg-safe=16, sc-safe=8, appx=1, defender=1,
  mitigation=1, report=4). Slow Appx removals in `DEBLOAT` no longer block
  fast reg writes in `PRIV`/`HARD`. **Requires PowerShell 7+** (or the
  `ThreadJob` module installed on 5.1). Stock Windows 11 ships Windows
  PowerShell 5.1 *without* `ThreadJob`, so the launchers normally take the
  **sequential** path and print one `[i]` note saying so — that is the
  expected case, and a full run still finishes in a few seconds.
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

### v2.3 hotfixes (post-release)

- **Manifest loader fix**: `Import-PowerShellDataFile` silently returns only
  the first element of a top-level `@(...)` on Windows PowerShell 5.1, which
  was dropping ~93% of policies. All four entry points now use an AST-based
  loader (`Parser::ParseFile` + `SafeGetValue` + flatten).
- **ANSI escape fix**: PS 5.1 doesn't recognize `` `e ``; switched to
  `[char]27` so the colored console UI renders correctly on 5.1.
- **Empty report fix**: `_Apply-Report` now coerces `$null` to `@()` so
  report files always write valid JSON instead of zero-byte files.
- **Broader AI component snapshot**: `AUDIT.AI.ComponentSnapshot` now also
  surfaces `MicrosoftWindows.Client.AI*`, Copilot, Recall, and
  SemanticAnalysis/ContentExtraction/ImageSearch packages so the report is
  useful on regular Win11 Pro boxes, not just Copilot+ PCs.
- **Smart App Control audit dropped**: removed `AUDIT.SmartAppControl.State`.
- **+12 PRIV policies**: online speech recognition, Cloud Content / consumer
  features, Tailored Experiences with Diagnostic Data, online tips, Find My
  Device, feedback notifications.

---

## What this script does NOT do

- Does **not** force the Windows Firewall on.
- Does **not** force Defender Real-Time Protection on.
- Does **not** probe or report Smart App Control state.
- Does **not** reinstall removed Appx packages on revert.
- Does **not** make any network calls.
- Does **not** touch app-private storage or undocumented registry keys.
- Does **not** hide the "AI actions" submenu from the image right-click
  on Win11 25H2 build 26200. Microsoft did not wire the
  `HideAIActionsMenu` policy on that build — there is no registry fix
  until build 26220+. Once your OS updates to 26220+, the existing
  `HideAIActionsMenu` entries will take effect.

These are intentional design choices.

---

## Execution policy

The launchers invoke PowerShell with `-ExecutionPolicy Bypass` — the same
posture as v2.2. The scripts are not code-signed. If your environment
requires signed scripts, import the modules directly from an elevated
prompt or sign them yourself.

---

## Antivirus false positives

**Third-party AV will likely flag this kit. That is expected, and it is not
a bug we can fully engineer away.** Behaviour-based engines (Bitdefender
Advanced Threat Defense, Norton SONAR, etc.) score an *unsigned PowerShell
script launched with `-ExecutionPolicy Bypass`* that also:

- changes Microsoft Defender settings (`Set-MpPreference`, ASR rules),
- stops and disables services (DiagTrack, WerSvc, TermService),
- bulk-writes `HKLM\SOFTWARE\Policies\...` keys, and
- removes Appx packages,

…and that combination is a near-perfect match for the behavioural signature
of real system-tampering malware. The irony is that most of what the kit
does *strengthens* Defender — the heuristic cannot tell the difference
between "hardens the machine" and "tampers with security settings".

**What we have already done about it:**

- **v2.9.1** removed the one genuinely malware-shaped *technique* in the kit
  — a machine-wide write into `HKLM\...\Shell Extensions\Blocked` (MITRE
  **T1112**, disabling shell / security extensions).
- **v2.9.4** removed the one malware-shaped *artifact*: the kit no longer
  spawns `reg.exe` or writes `.reg` files. Bitdefender was deleting our own
  exported `.reg` backup and blocking the process as a result (see the
  v2.9.4 notes). Registry backups are per-value JSON snapshots now.

Everything remaining targets documented Microsoft policy keys. The kit will
not adopt evasion techniques to dodge AV detection; that would be exactly
the wrong trade for a security tool.

**What to do:** if you trust the source, add a folder exclusion for the kit
before running it.

- *Bitdefender*: **Protection → Antivirus → Settings → Manage exceptions →
  Add an exception** → the kit's folder, and tick **Advanced Threat
  Defense** as well as On-Access scanning. An Antivirus-only exclusion is
  not enough — the behavioural module is usually what fires.
- Re-enable protection afterwards. Do not leave AV disabled.

If a scanner reports a *specific detection name* (e.g. `Gen:Variant...`,
`Heur.BZC...`, `ATD:...`) rather than a generic behaviour block, that is
worth reporting as an issue — a named signature hit may indicate something
we should look at, whereas a generic behavioural block is inherent to what
the tool does.

---

## Localization

The kit pins its thread to **`InvariantCulture`** at every entry point
(`Apply.ps1`, `Revert.ps1`, `Verify.ps1`, `Snapshot-AIShellVerbs.ps1`).

This is not cosmetic. PowerShell's `-match`, `-replace` and `-like` are
case-insensitive **and fold case using the current culture**. On Turkish and
Azeri locales, uppercase `I` (U+0049) folds to dotless `ı` (U+0131) — which
is outside the `a-z` range. Real consequences observed on a Turkish machine
before v2.9.3:

- report filenames were corrupted (`AUDIT.AI...` → `AUD_T.A_...`), because
  the "invalid filename character" class `[^A-Za-z0-9._-]` matched every `I`;
- the AI-candidate scanner in `Snapshot-AIShellVerbs.ps1` failed to match a
  registry key literally named **`AI`** — the exact thing it looks for.

Pinning the culture fixes every present *and future* call site at once,
rather than patching them one at a time. Pinning `CurrentUICulture` as well
means framework and OS error messages come back in English, so the
access-denied detection in `OAi.Engine.psm1` also works on non-English
Windows installs.

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
|   `-- module/              engine + runner + UI + launcher picker + version
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
- Restores registry values from per-value JSON snapshots (legacy `.reg`
  backups from v2.9.3 and earlier are still imported)
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

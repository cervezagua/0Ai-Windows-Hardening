# 🛡️ 0AI – Windows Hardening Script

### One-Click Windows 11 Privacy, AI Disablement & Security Hardening  
**Version:** `v2.2` ✅

**Supported baselines:** Windows 11 24H2 (OS Build **26100.8246+**) and 25H2 (OS Build **26200.8246+**), through the **April 2026 cumulative KB5083769**. Earlier builds still work but the 25H2-specific switches (e.g. File Explorer AI Actions) are no-ops.

---

## 🚀 Quick Start

### ▶ Apply Hardening
1. **Right-click** `0AI_Apply_v2_2.bat`
2. Select **Run as Administrator**
3. Press **`P`** → *Run everything (recommended)*
4. **Reboot** when finished

### ↩️ Revert Changes
1. **Right-click** `0AI_Revert_v2_2.bat`
2. Select **Run as Administrator**
3. **Reboot**

---

## 🆕 What's new in v2.2

- **File Explorer "AI Actions" menu** hidden via `HideAIActionsMenu` (Win11 25H2+).
- **WindowsAI hive** now also receives the 25H2 Intune Settings-Catalog names (`DisableCocreator`, `DisableGenerativeFill`, `DisableImageCreator`, `TurnOffWindowsCopilot`) for forward-compat.
- **Copilot** disabled at both `HKCU` *and* `HKLM` (Pro SKUs after 24H2 often ignore the user-hive key alone).
- **.rdp client hardening** (April 2026 phishing mitigation): saved credentials blocked, RDGClientTransport forced off. Complements the existing `TermService` shutdown.
- **Narrator rich image descriptions** (cloud-assisted, expanded to all PCs in KB5083769) disabled.
- **Notepad** policy also written at HKCU (`Software\Policies\Microsoft\Windows\WindowsNotepad`) — recent Store builds read user scope first.
- **Telemetry mirror** at `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection`, and a note in `verification.txt` that Pro/Home SKUs silently clamp `AllowTelemetry=0` to `1`.
- **Smart App Control** state is now surfaced in the verification report (KB5083769 removed the "clean reinstall only" requirement). The script **does not** force SAC on — report-only.
- **Audit snapshot** of `Microsoft.Windows.AI.*` component versions (Image Search / Content Extraction / Semantic Analysis / Settings Model) now saved to `AI_Components.txt`.
- **[A12] removed**: `AllowLockScreenCamera` is deprecated on 24H2+ (no-op).
- **[C3] Exploit Protection** no longer explicitly sets `CFG` — it has been a system default since KB5066835 and the explicit toggle occasionally triggers EDR false positives. DEP / SEHOP / BottomUp / HighEntropy / ForceRelocateImages remain.

---

## 🧠 Overview

**0AI v2.2 SAFE** is a conservative, policy-based Windows 11 hygiene script focused on:

- 🔒 Privacy hardening  
- 🤖 Reducing Windows AI surface area  
- 🚫 Disabling background AI features  
  - Recall  
  - Click-to-Do  
  - Agentic / AI search  
- 🧹 Removing select consumer features  
  - Widgets  
  - Phone Link  
- 🛠️ Applying supported security hardening  

This release **avoids undocumented hacks**, private app data manipulation, and fragile assumptions.  
Everything is **supported, reversible, and stable**.

---

## 🧩 Design Principles

- **Policy-First**  
  Uses documented Windows policies and supported registry paths only.
- **Fail-Safe**  
  If a setting cannot be enforced, the script exits cleanly.
- **Fully Reversible**  
  Registry snapshots and a dedicated revert script are included.
- **Distribution-Safe**  
  Safe to share with non-technical users.
- **Honest by Design**  
  Does not claim control over what Windows does not allow.

---

## 🛠️ What This Script Does

### 🔐 A) Core Privacy & AI Surface Reduction

Disables Windows AI platform features:
- ❌ Recall  
- ❌ Click-to-Do  
- ❌ Agentic Settings Search  
- ❌ AI data analysis  

Other actions:
- 🔍 Forces **classic local-only Windows Search** (no Bing / web results)
- 🧱 Removes & blocks **Widgets (WebExperience)**
- 📉 Minimizes telemetry:
  - DiagTrack  
  - dmwappush  

Disables:
- Windows Error Reporting  
- Advertising ID  
- Activity History  
- Cross-device Clipboard  
- Remote Desktop service  

Keeps:
- ✅ OneDrive (including autostart)

Removes:
- ❌ Phone Link / Cross-Device Experience  
  *(installed + provisioned)*

---

### 🎨 B) AI in Apps (Safe, Supported Controls Only)

**Paint**
- Cocreator disabled  
- Generative Fill disabled  
- Image Creator disabled  

**Notepad**
- Writes supported policy keys under:
```

HKLM\SOFTWARE\Policies\Microsoft\Notepad
HKLM\SOFTWARE\Policies\WindowsNotepad

```
- Reduces backend AI capability

⚠ **Important limitation (by Microsoft design):**  
On some Windows 11 / Notepad builds, the Copilot / Rewrite button may still appear even when policy keys exist.  
This script **does not** manipulate Notepad’s private app storage to force UI removal.

**System-Wide**
- `systemAIModels` capability set to **Deny** (HKLM + HKCU)  
- Reduces generative AI access across the OS

---

### 🧯 C) Security Hardening (Dev-Friendly)

**Microsoft Defender**
- PUA Protection → **Block** *(best-effort)*  
- ASR rules enabled *(compatibility subset)*  

**Exploit Protection**
- System defaults enabled:
- DEP  
- ASLR  
- SEHOP  
- CFG  

🚫 **Does NOT**
- Force Firewall ON  
- Force Defender Real-Time Protection ON  

> Defender settings may be blocked by Tamper Protection or MDM.  
> Attempts are logged but not forced.

---

## 🔄 Safety & Reversibility

Before making changes, the script:
- 🧩 Attempts to create a **System Restore Point**
- 📦 Exports registry keys to:
```

%USERPROFILE%\0AI_Backups<timestamp>\

```

Creates:
- `apply.log`
- `verification.txt`

### 🔁 Revert Script
- Restores registry snapshots  
- Resets `systemAIModels` to default (**Prompt**)  
- Best-effort reverts Defender and exploit mitigations  
- ❌ Does **not** reinstall removed apps *(by design)*

---

## 🚫 What This Script Does NOT Do

- Does **not** uninstall core Windows components  
- Does **not** hack Store app internal data  
- Does **not** guarantee removal of all AI UI elements  
- Does **not** block Windows Update or Store updates  

➡️ This behavior is **intentional**.

---

## 🎯 Threat Model Summary

Designed to:
- Prevent silent background AI activity  
- Reduce data collection and agentic behavior  
- Preserve system stability and update compatibility  

> Security correctness is prioritized over cosmetic enforcement.
> Aggressive or undocumented techniques are **intentionally excluded**.
```

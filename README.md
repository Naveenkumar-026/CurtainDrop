# CurtainDrop
**Panic-mode privacy lock for Windows. One command. Immediate silence. Immediate blackout. Clean restore.**

CurtainDrop is a PowerShell 5.1–safe incident-response “curtain drop” script designed to quickly reduce exposure during a suspected compromise or high-risk situation by:

- Muting system audio output (CoreAudio, no external modules)
- Disabling targeted **camera + microphone** devices (PnP strict-class targeting)
- Disabling active network adapters (with skip patterns for tunnels/virtual adapters)
- Optionally freezing **user-owned, session-scoped, non-critical** processes via Sysinternals **PsSuspend**
- Producing a **forensic-grade local HTML report** and a `state.json` snapshot so Restore is deterministic

This repository is intentionally simple: a single script plus PsSuspend.

---

## What it does (exactly as implemented)

### Panic
Runs, in order:

1) Preflight admin check  
2) Snapshot audio state  
3) Mute speakers (default render endpoint)  
4) Disable camera + mic targets found via strict device-class filtering  
5) Disable active network adapters (except those matching skip patterns)  
6) Verification (trust-but-verify) *(disabled automatically in DryRun)*  
7) Freeze (optional) user-safe processes using PsSuspend (only when `FreezeMode=UserSafe`)  
8) Capture event logs (best-effort)  
9) Write `state.json` (only what CurtainDrop changed)  
10) Generate `report.html` and open it  

### Restore
Restores only what was changed in the associated `state.json`, in order:

1) Resume suspended PIDs (if any)  
2) Re-enable adapters that were disabled  
3) Re-enable devices that were disabled  
4) Restore audio mute + volume snapshot (best-effort)  
5) Verification (optional, non-DryRun)  
6) Regenerate and open the report  

---

## Quick start (recommended workflow)

Open **PowerShell as Administrator** in the project directory:

```powershell
cd "C:\Users\Silencio\Desktop\CurtainDrop"
```

### 1) Safe report check (no changes)
```powershell
.\CurtainDrop.ps1 -Mode Panic -FreezeMode UserSafe -DryRun
```

### 2) Real test without freezing processes (low risk)
```powershell
.\CurtainDrop.ps1 -Mode Panic -FreezeMode Off
.\CurtainDrop.ps1 -Mode Restore
```

### 3) Full operational mode
```powershell
.\CurtainDrop.ps1 -Mode Panic -FreezeMode UserSafe
.\CurtainDrop.ps1 -Mode Restore
```

---

## Parameters

| Parameter | Values | Default | Meaning |
|---|---|---:|---|
| `-Mode` | `Panic`, `Restore` | `Panic` | Execute lockdown or restore |
| `-DryRun` | switch | Off | Simulates actions, writes logs/report, no system changes |
| `-RunId` | string | (auto) | Restore a specific run folder under `./runs/<RunId>` |
| `-FreezeMode` | `UserSafe`, `Off` | `UserSafe` | Freeze user-safe processes with PsSuspend, or skip freezing |

---

## Files produced per run

Each run creates a folder under:

```
./runs/<RunId>/
```

Inside:

- `actions.jsonl` — append-only JSON Lines log of all actions and verification checks  
- `state.json` — the authoritative “what CurtainDrop changed” snapshot used for Restore  
- `report.html` — layered, searchable report (Actions + Summary + State + Event logs)

Restore reuses the same `<RunId>` folder and regenerates `report.html` after restoration so the timeline stays connected.

---

## Report: what each tile means

- **Cam/Mic Targets**  
  Count of `disabled_devices` in `state.json` (camera + microphone targets combined)

- **Network Targets**  
  Count of `disabled_adapters` in `state.json`

- **Audio Actions**  
  Count of *audio step actions* in `actions.jsonl` (e.g., snapshot + mute + restore + verify)

- **Processes Frozen**  
  Count of `suspended_pids` in `state.json`  
  - Stored as `[]` (never `null`) so counts remain accurate

---

## Device targeting logic (strict and intentional)

CurtainDrop targets only devices whose **PnP Class** matches:

- Cameras: `Camera`, `Image`  
- Mics: `AudioEndpoint`  

…and whose FriendlyName matches patterns in the config:

- `CameraNamePatterns`: `Camera`, `Webcam`, `UVC`, `Integrated Camera`, `IR UVC`, `USB Video`, `Windows Studio Effects Camera`
- `MicNamePatterns`: `Microphone`, `Microphone Array`, `Mic Array`

This conservative approach is intended to reduce collateral disabling.

---

## Network targeting logic

CurtainDrop disables adapters whose **AdminStatus is Up**, excluding names matching:

- `Loopback`, `Teredo`, `isatap`, `VirtualBox Host-Only`, `VMware Network Adapter`, `Npcap`, `Tailscale`

Extend this list if your machine uses other virtual interfaces you never want touched.

---

## Process freezing (UserSafe)

When `-FreezeMode UserSafe`, CurtainDrop will:

- Freeze only processes **in your session**
- Prefer processes with a **window**
- Always include “priority apps” when present, subject to `MaxSuspendCount`
- Never suspend critical Windows processes or terminals via a hard allow-list + deny-list
- Run PsSuspend with `-accepteula -nobanner` to prevent first-run EULA blocking

If you want zero risk of UI impact, run Panic with `-FreezeMode Off`.

---

## Requirements

- Windows 10/11
- PowerShell 5.1 (script is PS 5.1 compatible)
- Administrator privileges for real Panic/Restore actions
- PsSuspend present in either:
  - `./pssuspend.exe` *(root)* or
  - `./tools/pssuspend.exe`

Your current layout:

```
C:.
|   CurtainDrop.ps1
|   pssuspend.exe
|
\---runs
```

---

## Operational notes

- Always test `FreezeMode Off` first on a new machine profile.
- Keep `runs/` local. It contains instance IDs and operational logs.
- If `pssuspend.exe` is missing, freezing is skipped and logged as WARN (script continues safely).

---

## Troubleshooting

- **WARNs for event logs** are common (empty results or permission constraints) and do not imply failure.
- If a mic/cam is not disabled, it may not match `AudioEndpoint` or the friendly-name patterns—extend carefully.
- Restore reverts only what is recorded in `state.json` for that run.

---

## License / third-party notice

PsSuspend is a Sysinternals tool (Microsoft). Review redistribution/licensing constraints before publishing it in a public repository.

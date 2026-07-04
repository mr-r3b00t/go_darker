# Windows Telemetry & Browser Privacy Tools

Two single-file, dependency-free PowerShell 5.1 scripts:

| Script | Scope |
|---|---|
| `Manage-WindowsTelemetry.ps1` | Windows 11 telemetry / diagnostic-data settings, services and scheduled tasks |
| `Manage-BrowserPrivacy.ps1` | Privacy / telemetry policies for Edge, Chrome, Firefox and Brave |

Both share the same UX: a color-coded status view (**Enabled** = collecting,
**Disabled** = hardened), interactive per-item toggling, one-shot
`-DisableAll` / `-EnableAll`, `-Report`, and CSV export. Both are ASCII-only,
BOM-free, module-free, and run in stock `powershell.exe` on Windows 11.

> **Disclaimer:** Changing telemetry, service, task and browser-policy
> settings alters system behaviour. Review the scripts before running them,
> test on a non-production machine first, and consider a restore point.
> No warranty.

---

# 1. Manage-WindowsTelemetry.ps1

Views and controls **Windows 11 telemetry / diagnostic-data settings,
services and scheduled tasks** from one place.

## Quick start

```powershell
# View status only (read-only, safe anywhere)
.\Manage-WindowsTelemetry.ps1 -Report

# Interactive menu (run from an ELEVATED PowerShell to change HKLM/services/tasks)
.\Manage-WindowsTelemetry.ps1

# One-shot hardening: turn all telemetry OFF (keeps [SEC] SmartScreen ON)
.\Manage-WindowsTelemetry.ps1 -DisableAll

# ... also disable the SmartScreen reputation checks (see [SEC] note below)
.\Manage-WindowsTelemetry.ps1 -DisableAll -IncludeSecurity

# Restore Windows default behaviour: turn everything back ON
.\Manage-WindowsTelemetry.ps1 -EnableAll

# Export current status to CSV (exits after export)
.\Manage-WindowsTelemetry.ps1 -Csv .\telemetry-status.csv

# Report to screen AND CSV
.\Manage-WindowsTelemetry.ps1 -Report -Csv .\telemetry-status.csv
```

If script execution is blocked on your machine:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsTelemetry.ps1 -Report
```

## Semantics

| Term | Meaning |
|---|---|
| **Enabled** (yellow) | The telemetry / data-collection behaviour is ON |
| **Enabled (default)** | No override present; Windows out-of-box behaviour (ON) |
| **Disabled** (green) | The behaviour is OFF / hardened |
| **Not present** (gray) | Service or task does not exist on this system |
| `*` suffix | Requires Administrator to change (run elevated) |

Two design rules worth knowing:

1. **"Enable" restores the true Windows default.** For policy-style registry
   values (where the Windows default is *no value at all*), enabling
   **removes** the policy value instead of writing one. This avoids leaving
   the machine in a "Some settings are managed by your organization" state
   after an enable/disable round trip.
2. **Services are restored to their real default start types** (`DiagTrack`
   = Automatic, `dmwappushservice` / `WerSvc` = Manual), not blanket
   Automatic.

## Interactive menu commands

| Command | Action |
|---|---|
| `<n>` | Toggle item *n* (Enabled <-> Disabled) |
| `e <n>` / `d <n>` | Enable / disable item *n* |
| `E` / `D` (uppercase) | Enable / disable **ALL** items (asks for `YES` confirmation; `D` keeps `[SEC]` items ON) |
| `S` | Disable the `[SEC]` SmartScreen features (requires typing `DISABLE-SECURITY`) |
| `r` | Refresh the view |
| `c <path>` | Export status to CSV |
| `q` | Quit |

The menu is case-sensitive where it matters: a bare lowercase `d`/`e` will
**not** trigger the ALL branches.

### `[SEC]` items: Windows SmartScreen

Three controls check apps, files and URLs against Microsoft's cloud
reputation service: **SmartScreen for apps and files** (shell), **SmartScreen
for Store apps**, and **Enhanced Phishing Protection**. They are marked
`[SEC]` because disabling them *reduces protection* against malware and
phishing. The same guard rails as the browser tool apply: `-DisableAll` and
menu `D` leave them ON; disabling requires `-IncludeSecurity`, the menu `S`
command, or an individual item toggle. A red WARNING line appears in the
status view whenever any `[SEC]` item is OFF.

## What is covered

### Registry (policy and per-user)

| Area | Items |
|---|---|
| Core telemetry | `AllowTelemetry` (policy + non-policy), feedback notifications, `LimitDiagnosticLogCollection`, `DisableOneSettingsDownloads` |
| App compatibility | Appraiser telemetry (`AITEnable`), Inventory Collector |
| Error Reporting (the modern successor to Dr. Watson) | WER on/off (non-policy + policy), `DontSendAdditionalData`, consent level (`DefaultConsent`) |
| CEIP | `CEIPEnable` (SQM Client) |
| Cloud content | Consumer Features, Tailored Experiences (policy) |
| Activity history | Publish / Upload User Activities |
| Per-user privacy (no admin needed) | Advertising ID, Tailored Experiences, Feedback frequency (SIUF), implicit ink/text collection, Typing Insights (TIPC), online speech recognition, linguistic data collection, Search box web suggestions (Win11) + legacy `BingSearchEnabled` |
| SmartScreen `[SEC]` | Apps-and-files check (`EnableSmartScreen` policy), Store apps URL check (`EnableWebContentEvaluation`), Enhanced Phishing Protection (`WTDS ServiceEnabled`) |

### Services

| Service | Default start | Note |
|---|---|---|
| `DiagTrack` (Connected User Experiences and Telemetry) | Automatic | Primary telemetry service |
| `dmwappushservice` | Manual | Disabling can break provisioning-package / MDM enrolment |
| `WerSvc` (Windows Error Reporting) | Manual | Runs WER report submission |

### Scheduled tasks

- Application Experience: Compatibility Appraiser, ProgramDataUpdater, StartupAppTask
- CEIP: Consolidator, UsbCeip, Autochk\Proxy (kernel CEIP)
- Feedback (SIUF): DmClient, DmClientOnScenarioDownload
- Windows Error Reporting: QueueReporting
- DiskDiagnostic: DiskDiagnosticDataCollector

## Known limitations

- **Home/Pro diagnostic-data floor:** `AllowTelemetry = 0` (Security) is only
  fully honoured on Enterprise/Education/IoT SKUs. On Home/Pro, Windows
  treats 0 as 1 (Required), so a small baseline of required diagnostic data
  may still flow even when everything here shows Disabled.
- Some items are refreshed by Windows Update or feature updates; re-run
  `-Report` after major updates to verify state.
- `BingSearchEnabled` is a Windows 10-era value kept for completeness; the
  effective Windows 11 control is `DisableSearchBoxSuggestions` (also
  included).
- Changing WER/crash-reporting settings affects local crash-dump collection
  behaviour, which you may want during debugging.

## CSV output columns

`Name, Category, Type (Reg/Service/Task), State, AdminReq, Note`

---

# 2. Manage-BrowserPrivacy.ps1

Views and hardens **privacy / telemetry-related policy settings** for the
browsers installed on the machine. Browsers are auto-detected (via App Paths
registration); only installed ones are shown unless you pass `-IncludeAll`.

## Quick start

```powershell
# View status only (read-only)
.\Manage-BrowserPrivacy.ps1 -Report

# Interactive menu (ELEVATED PowerShell required to change anything)
.\Manage-BrowserPrivacy.ps1

# One-shot: harden every detected browser
.\Manage-BrowserPrivacy.ps1 -DisableAll

# Restore all browser defaults (removes the policy values)
.\Manage-BrowserPrivacy.ps1 -EnableAll

# Export status to CSV / include browsers that are not installed
.\Manage-BrowserPrivacy.ps1 -Csv .\browser-status.csv
.\Manage-BrowserPrivacy.ps1 -Report -IncludeAll

# Harden everything AND turn off the malicious-URL checks (see warning below)
.\Manage-BrowserPrivacy.ps1 -DisableAll -IncludeSecurity
```

The menu supports the same commands as the Windows tool, plus
`b <browser>` to harden a single browser, `B <browser>` to restore a single
browser's defaults (e.g. `b Edge` / `B Edge`), and `S` to disable the
malicious-URL checks (see below).

## Safe Browsing / SmartScreen (URL reputation) - read this

Some controls check the **domain / IP / URL** you visit against a cloud
reputation service (Microsoft SmartScreen for Edge, Google Safe Browsing for
Chrome/Brave). These are **security** features - they warn you off phishing
and malware sites - but they work by sending URL/host data off the machine,
so they are also a privacy consideration. They are marked **`[SEC]`** in the
status view.

Because turning them off *reduces protection*, they are handled separately:

- **`-DisableAll` and the menu `D` command leave `[SEC]` items ON.** Bulk
  hardening will not silently disable your malware protection.
- To disable them you must be explicit:
  - CLI: `-DisableAll -IncludeSecurity`
  - Menu: the dedicated **`S`** command (requires typing
    `DISABLE-SECURITY` to confirm)
  - Or toggle the individual numbered item (that is always a deliberate act)
- The status view prints a red **WARNING** line whenever any `[SEC]` feature
  is currently OFF, so a hardened-too-far machine is obvious at a glance.

`[SEC]` controls covered: Edge SmartScreen (site/URL check, PUA blocking, DNS
reputation lookups, typosquatting checker); Chrome & Brave Safe Browsing
protection level (`0` = off, disables URL reputation checks entirely).

> Recommendation: leave these ON unless you have a specific reason (e.g. you
> route all traffic through a separate filtering DNS/proxy that already does
> this). They are the browser's main defence against phishing and drive-by
> malware.

## How it works

All controls are **policy DWORD values** under `HKLM\SOFTWARE\Policies\...`
(the official enterprise policy locations each vendor documents). Because a
browser's true default is *no policy value at all*, **Enable always removes
the value** rather than writing one - so an enable/disable round trip leaves
no permanent "managed" residue.

Two things to expect:

- Policies apply on the **next browser start** - restart the browser after
  changes.
- While hardened, browsers display a **"Managed by your organization"**
  notice on their settings pages. That is Chromium/Firefox correctly
  reporting that policies are active, not a malfunction; `-EnableAll`
  removes it again.

## What is covered

| Browser | Policies |
|---|---|
| **Edge** | Diagnostic data, personalization reporting, user feedback, search suggestions, Bing address-bar provider, Shopping Assistant, Rewards, Web Widget, Spotlight recommendations, Do Not Track, navigation-error web service, alternate error pages, network prediction (prefetch) |
| **Chrome** | Metrics reporting (UMA), search suggestions, Safe Browsing extended reporting, URL-keyed data collection, cloud spell check, alternate error pages, network prediction, feedback surveys, Privacy Sandbox (prompt, Ad Topics, site-suggested ads, ad measurement) |
| **Firefox** | Telemetry, Firefox Studies (Shield), Default Browser Agent (daily Mozilla ping), Pocket |
| **Brave** | Rewards, Wallet, VPN, Tor windows, search suggestions (Chromium policy) |
| **`[SEC]` URL checks** | Edge SmartScreen (site/URL, PUA, DNS lookups, typosquatting); Chrome & Brave Safe Browsing protection level |

Notes:

- Under `-DisableAll`, Safe Browsing / SmartScreen stay ON; only the
  *extended reporting* (extra data to Google) is hardened by default. Full
  URL-check disabling requires `-IncludeSecurity` or the menu `S` command.
- The three Chrome Privacy Sandbox ad policies require the Privacy Sandbox
  prompt policy to be Disabled as well - the tool includes it.
- Brave sends comparatively little telemetry by default; its entries harden
  the bundled feature surface (Rewards/Wallet/VPN/Tor), each of which
  contacts Brave services.
- DNS-over-HTTPS policies are intentionally not touched - DoH is a privacy
  *gain* in most settings and is better configured deliberately per network.

## CSV output columns

`Name, Browser, Installed, Policy, State, Note` ([SEC] items are named as
such in the `Name` column).

---

# Files

| File | Purpose |
|---|---|
| `Manage-WindowsTelemetry.ps1` | Windows telemetry view + control |
| `Manage-BrowserPrivacy.ps1` | Browser privacy view + hardening |
| `README.md` | This file |

Both CSV exports are useful for fleet auditing: run with `-Csv` on multiple
machines and diff or aggregate the results.

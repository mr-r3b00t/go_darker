# Windows Telemetry & Browser Privacy Tools

Two single-file, dependency-free PowerShell 5.1 scripts:

| Script | Scope |
|---|---|
| `Manage-WindowsTelemetry.ps1` | Windows 11 telemetry / diagnostic-data settings, services and scheduled tasks |
| `Manage-BrowserPrivacy.ps1` | Privacy / telemetry policies for Edge, Chrome, Firefox and Brave |
| `Manage-DefenderAntivirus.ps1` | Microsoft Defender Antivirus health, protection settings, scans and updates |

All three share the same UX: a color-coded status view, interactive per-item
toggling, `-Report`, and CSV export. They are ASCII-only, BOM-free, and run
in stock `powershell.exe` on Windows 11.

**Intended audience:** this is a privacy-enabling / telemetry-disabling
toolkit for **advanced users and administrators** who understand the
tradeoffs. It is **not** aimed at general users and it deliberately exposes
switches that reduce data sharing *and* switches that reduce security
protection. Know what each item does before you flip it.

**Important difference in orientation:** in the telemetry and browser tools,
**Disabled = hardened** (you turn data collection *off*). In the Defender
tool the polarity is **reversed** - **On/Enabled = protected/recommended**,
and turning a protection *off* reduces security. Each tool's status view is
labelled accordingly.

> **Disclaimer - USE AT YOUR OWN RISK.** These scripts modify registry
> values, service startup types and scheduled tasks. They are provided as-is,
> with **no warranty of any kind**; you are solely responsible for what they
> do to your systems. Review the code before running it, test on a
> non-production machine first, and create a System Restore point (or
> equivalent backup) before applying changes.

## Key risks

Read this before running either script with `-DisableAll` or the menu
`D`/`S` commands:

| Risk | Detail | Mitigation |
|---|---|---|
| **Reduced malware/phishing protection** | Disabling the `[SEC]` items (Windows SmartScreen, Edge SmartScreen, Chrome/Brave Safe Browsing) removes URL, download and app reputation warnings. Likewise the **Defender** tool's `-DisableAll` / menu `D` turns off real-time monitoring, cloud protection, network protection and controlled folder access - a direct antivirus downgrade that leaves the machine without Defender coverage. | Browser `[SEC]` items are excluded from bulk disable by default; the Defender bulk disable requires an explicit switch/confirmation. Only disable deliberately, and only if other controls (DNS/proxy/EDR) cover the gap. |
| **Managed / corporate machines** | On a domain-joined or Intune/MDM-managed device, these settings may be owned by your organisation. Changing them can conflict with GPO/MDM (which will usually re-apply), break compliance posture, or violate your IT policy. | Only run on machines you own or are authorised to change. Expect GPO/MDM to win any conflict. |
| **MDM / provisioning breakage** | Disabling `dmwappushservice` can break provisioning-package installation (`Add-ProvisioningPackage`) and some MDM enrolment flows. | Skip that item (or re-enable it) on devices that will be enrolled. |
| **Lost crash reporting** | Disabling Windows Error Reporting stops crash reports to Microsoft, and WER-based *local* workflows too (e.g. LocalDumps collection for debugging). | Re-enable WER while troubleshooting crashes. |
| **Feature loss** | Some features depend on the data flows being disabled: Find My Device, Windows Insider Program (requires Optional diagnostic data), inking/typing personalisation, cross-device Timeline/resume, cloud speech recognition, live search suggestions, Cortana, cross-device clipboard paste, settings sync across devices, location-aware apps (maps/weather/timezone), Windows Copilot and Recall. | Review the per-setting tables below and keep the items you use enabled. |
| **"Managed by your organization" notices** | While hardened, Windows Settings and browser settings pages show a managed/policy notice. This is expected policy behaviour, not malware - but it can alarm users and support desks. | `-EnableAll` removes all values written by the tools and clears the notice. |
| **Updates can revert changes** | Windows feature updates, cumulative updates and browser updates can re-enable items or re-create scheduled tasks. | Re-run `-Report` after major updates; re-apply as needed. |
| **Upgrade readiness data** | Disabling the Compatibility Appraiser stops the inventory Microsoft uses to assess upgrade compatibility for your device. | Low impact for most; re-enable before a major feature upgrade if you want Microsoft's compatibility safeguards. |
| **Partial effect on Home/Pro** | `AllowTelemetry=0` is only fully honoured on Enterprise/Education SKUs; Home/Pro still send Required diagnostic data. | Understand "hardened" is not "zero data" on consumer SKUs. |

If any of these matter for your environment and you are unsure: run
`-Report` (read-only) first, and change items one at a time instead of using
the bulk commands.

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

### Registry settings reference

All values are `REG_DWORD`. "Hardened" is the value the tool writes when you
disable an item. "Default" is Windows out-of-box behaviour: for most policy
values that means **the value is absent** - which is why enabling an item
usually *removes* the value rather than writing one.

#### Core telemetry
Key: `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection`

| Value | Hardened | Explanation |
|---|---|---|
| `AllowTelemetry` | `0` | The master diagnostic-data level sent by the DiagTrack service. `0` = Security (honoured only on Enterprise/Education), `1` = Required, `3` = Optional (full). Default: absent = user's Settings choice applies. |
| `DoNotShowFeedbackNotifications` | `1` | Stops Windows asking for feedback via notifications ("How is your experience?"). Collection-adjacent rather than collection itself. |
| `LimitDiagnosticLogCollection` | `1` | Blocks the upload of *additional* diagnostic logs Microsoft can request on top of the normal telemetry stream. |
| `DisableOneSettingsDownloads` | `1` | Stops Windows fetching remote telemetry configuration ("OneSettings"). With this off, Microsoft cannot remotely adjust what diagnostic data is sampled. |

Key: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection`

| Value | Hardened | Explanation |
|---|---|---|
| `AllowTelemetry` | `0` | Older, non-Group-Policy location for the same setting; some components read this path, so the tool sets both. |

#### Application compatibility (appraiser)
Key: `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat`

| Value | Hardened | Explanation |
|---|---|---|
| `AITEnable` | `0` | Application Impact Telemetry: usage/launch data about installed programs, gathered by the Compatibility Appraiser and sent to Microsoft to assess upgrade compatibility. |
| `DisableInventory` | `1` | Stops the Inventory Collector uploading a list of installed applications, devices and drivers. |

#### Windows Error Reporting (successor to Dr. Watson)

| Key / Value | Hardened | Explanation |
|---|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting` -> `Disabled` | `1` | Turns off crash/hang report generation and submission machine-wide (non-policy location, same one the old `serverweroptin` flow used). |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting` -> `Disabled` | `1` | Group Policy variant of the same switch; wins over the non-policy flag if both are set. |
| `...Policies...\Windows Error Reporting` -> `DontSendAdditionalData` | `1` | Blocks the *second stage* of WER: after the initial crash signature, Microsoft can request extra payloads (memory dumps, files). This stops those. |
| `HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent` -> `DefaultConsent` | `1` | How much WER may send without asking: `1` = always ask first, `2` = send parameters only, `3` = parameters + safe data, `4` = send everything automatically. Hardened = always ask. |

#### Customer Experience Improvement Program
Key: `HKLM\SOFTWARE\Microsoft\SQMClient\Windows`

| Value | Hardened | Explanation |
|---|---|---|
| `CEIPEnable` | `0` | Opts the machine out of CEIP/SQM ("Software Quality Metrics") - anonymous usage statistics collected by older Windows components and the CEIP scheduled tasks. |

#### Cloud content and suggestions
Key: `HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent`

| Value | Hardened | Explanation |
|---|---|---|
| `DisableWindowsConsumerFeatures` | `1` | Stops "consumer experiences": auto-installed sponsored/suggested Store apps, promotional tiles and app suggestions in Start. |
| `DisableTailoredExperiencesWithDiagnosticData` | `1` | Stops Microsoft using your diagnostic data to personalise tips, ads and recommendations shown inside Windows. |

#### Activity history (Timeline)
Key: `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`

| Value | Hardened | Explanation |
|---|---|---|
| `PublishUserActivities` | `0` | Stops apps recording "activities" (documents opened, sites visited) into the local activity feed. |
| `UploadUserActivities` | `0` | Stops the activity feed being synced to the Microsoft cloud (cross-device timeline/resume). |

#### Per-user privacy (HKCU - changeable without admin)

| Key / Value | Hardened | Explanation |
|---|---|---|
| `HKCU\...\CurrentVersion\AdvertisingInfo` -> `Enabled` | `0` | Disables the per-user Advertising ID that apps use to correlate you across apps for ad targeting. |
| `HKCU\...\CurrentVersion\Privacy` -> `TailoredExperiencesWithDiagnosticDataEnabled` | `0` | User-level counterpart of Tailored Experiences: no diagnostic-data-driven tips/ads for this account. |
| `HKCU\SOFTWARE\Microsoft\Siuf\Rules` -> `NumberOfSIUFInPeriod` | `0` | Feedback frequency ("System Initiated User Feedback"). `0` = Windows never asks for feedback. Default: absent = automatic. |
| `HKCU\SOFTWARE\Microsoft\InputPersonalization` -> `RestrictImplicitInkCollection` | `1` | Blocks collection of handwriting/ink samples used to build your personal dictionary. |
| `HKCU\SOFTWARE\Microsoft\InputPersonalization` -> `RestrictImplicitTextCollection` | `1` | Same for typed text - stops typing history feeding personalization. |
| `HKCU\SOFTWARE\Microsoft\Input\TIPC` -> `Enabled` | `0` | The "Improve inking and typing" telemetry channel - samples of what you type/ink sent as diagnostic data. |
| `HKCU\...\Speech_OneCore\Settings\OnlineSpeechPrivacy` -> `HasAccepted` | `0` | Consent flag for cloud (online) speech recognition; `0` = voice audio is not sent to Microsoft speech services. Default is off until a user consents. |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\TextInput` -> `AllowLinguisticDataCollection` | `0` | Machine-wide policy blocking typing/inking samples (the policy behind TIPC). Requires admin, listed here as it belongs to the same feature. |
| `HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer` -> `DisableSearchBoxSuggestions` | `1` | Removes Bing web search/suggestions from the Start menu and taskbar Search on Windows 11 - queries stay local. |
| `HKCU\...\CurrentVersion\Search` -> `BingSearchEnabled` | `0` | The Windows 10-era equivalent of the above; largely ignored by Windows 11 but kept for completeness. |

#### Search / Cortana cloud
Key: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search`

| Value | Hardened | Explanation |
|---|---|---|
| `AllowCortana` | `0` | Disables Cortana, which sends voice/text queries and context to Microsoft. |
| `ConnectedSearchUseWeb` | `0` | Stops Start/Search sending typed queries to Bing for web results. |
| `AllowCloudSearch` | `0` | Disables searching your OneDrive/Outlook/SharePoint content from the local search box (each query hits Microsoft cloud). |
| `AllowSearchToUseLocation` | `0` | Stops the search/Cortana stack using your device location. |

#### Cloud sync (clipboard / settings)
Keys: `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` and `...\SettingSync`

| Value | Hardened | Explanation |
|---|---|---|
| `AllowClipboardHistory` | `0` | Disables local clipboard history (Win+V). Local only, but a data-retention surface. |
| `AllowCrossDeviceClipboard` | `0` | Disables syncing clipboard **contents** to the Microsoft cloud for cross-device paste - potentially very sensitive data. |
| `DisableSettingSync` (SettingSync key) | `2` | Stops Windows settings/credentials/preferences syncing across devices via your Microsoft account. |

#### Suggestions / ads (Content Delivery Manager - per-user, HKCU)
Key: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager`

| Value | Hardened | Explanation |
|---|---|---|
| `SilentInstalledAppsEnabled` | `0` | Stops Windows silently installing sponsored/suggested apps. |
| `SystemPaneSuggestionsEnabled` | `0` | Removes app/content suggestions in the Start menu. |
| `SubscribedContent-338393Enabled` | `0` | Removes suggested content in the Settings app. |
| `SubscribedContent-338389Enabled` | `0` | Disables Windows tips/suggestion notifications. |
| `RotatingLockScreenOverlayEnabled` | `0` | Disables Spotlight ads/"fun facts" overlaid on the lock screen. |

#### Location
Key: `HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors`

| Value | Hardened | Explanation |
|---|---|---|
| `DisableLocation` | `1` | Turns off the system-wide location platform for all apps and services. |

#### Find My Device
Key: `HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice`

| Value | Hardened | Explanation |
|---|---|---|
| `AllowFindMyDevice` | `0` | Stops Windows periodically reporting device location to your Microsoft account. |

#### AI features (Copilot / Recall)

| Key / Value | Hardened | Explanation |
|---|---|---|
| `HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot` -> `TurnOffWindowsCopilot` | `1` | Disables the Windows Copilot assistant (prompts and context leave the device to Microsoft/OpenAI services). |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI` -> `DisableAIDataAnalysis` | `1` | Disables **Recall** screen-snapshot capture and analysis. Local-first, but a large capture surface; only present on Copilot+ PCs (24H2+). |

#### Network
Key: `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization`

| Value | Hardened | Explanation |
|---|---|---|
| `DODownloadMode` | `0` | Delivery Optimization peer sharing: `0` = HTTP only (no peers), `1` = LAN peers, `3` = internet peers. Hardened = your PC neither pulls from nor advertises update chunks to other machines. |

#### Windows SmartScreen `[SEC]` - reputation checks

| Key / Value | Hardened | Explanation |
|---|---|---|
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` -> `EnableSmartScreen` | `0` | The shell "Check apps and files" feature: hashes/metadata of downloaded executables are checked against Microsoft's reputation service before they run. |
| `HKCU\...\CurrentVersion\AppHost` -> `EnableWebContentEvaluation` | `0` | SmartScreen URL checking for web content loaded inside Microsoft Store apps. |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components` -> `ServiceEnabled` | `0` | Enhanced Phishing Protection (Windows 11): warns when you type your Windows password into a suspicious site or store it insecurely. |

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

## Registry settings reference

All values are `REG_DWORD` policies. "Hardened" is what the tool writes when
you disable an item; enabling always *removes* the value (browser default =
absent). Browsers pick up changes on next start.

### Microsoft Edge
Key: `HKLM\SOFTWARE\Policies\Microsoft\Edge`

| Value | Hardened | Explanation |
|---|---|---|
| `DiagnosticData` | `0` | Edge's own usage/crash telemetry level: `0` = off, `1` = required, `2` = optional (full). Separate from the Windows AllowTelemetry setting. |
| `PersonalizationReportingEnabled` | `0` | Stops Edge sending browsing history to Microsoft to personalise ads, news, search and shopping. |
| `UserFeedbackAllowed` | `0` | Removes the Send Feedback feature and its data uploads (screenshots, diagnostics attached to feedback). |
| `SearchSuggestEnabled` | `0` | Stops the address bar sending every keystroke to the search provider for live suggestions. Typed text stays local until you press Enter. |
| `AddressBarMicrosoftSearchInBingProviderEnabled` | `0` | Stops address-bar queries being sent to Microsoft Search in Bing (work/school results). |
| `EdgeShoppingAssistantEnabled` | `0` | Disables the shopping assistant (coupons, price comparison, cashback), which shares the pages you shop on with Microsoft. |
| `ShowMicrosoftRewards` | `0` | Hides Microsoft Rewards, which tracks Bing searches/purchases for points. |
| `WebWidgetAllowed` | `0` | Disables the Edge search bar widget (a persistent background process with web access). |
| `SpotlightExperiencesAndRecommendationsEnabled` | `0` | Disables Spotlight tips/recommendations delivered from Microsoft services. |
| `ConfigureDoNotTrack` | `1` | Hardened = Edge sends the "Do Not Track" (DNT) request header with all traffic. (Advisory only - sites may ignore it.) |
| `ResolveNavigationErrorsUseWebService` | `0` | Stops Edge using a Microsoft web service to diagnose connection problems (which reports the failing address). |
| `AlternateErrorPagesEnabled` | `0` | Stops Edge sending details of not-found/error pages to Microsoft to fetch suggestion pages. |
| `NetworkPredictionOptions` | `2` | Disables DNS prefetching / preconnecting to links the browser *predicts* you may visit (`0` = predict always, `2` = never). Prediction leaks hostnames you never actually clicked. |
| `SmartScreenEnabled` `[SEC]` | `0` | Microsoft Defender SmartScreen: checks visited sites and downloads against Microsoft's reputation service. Disabling removes phishing/malware warnings. |
| `SmartScreenPuaEnabled` `[SEC]` | `0` | SmartScreen blocking of potentially unwanted applications (PUA) in downloads. |
| `SmartScreenDnsRequestsEnabled` `[SEC]` | `0` | Stops the DNS requests SmartScreen makes for site reputation lookups. |
| `TyposquattingCheckerEnabled` `[SEC]` | `0` | Disables warnings when you mistype a domain and land on a lookalike (typosquatted) site. |

### Google Chrome
Key: `HKLM\SOFTWARE\Policies\Google\Chrome`

| Value | Hardened | Explanation |
|---|---|---|
| `MetricsReportingEnabled` | `0` | UMA metrics: anonymised usage statistics and crash reports sent to Google. |
| `SearchSuggestEnabled` | `0` | Stops the omnibox sending keystrokes to the search provider for live suggestions. |
| `SafeBrowsingExtendedReportingEnabled` | `0` | Stops the *extra* Safe Browsing reports (page contents, system info) sent to Google. Safe Browsing protection itself stays on. |
| `SafeBrowsingProtectionLevel` `[SEC]` | `0` | The Safe Browsing URL check itself: `0` = off (no URL reputation checks at all), `1` = standard, `2` = enhanced (more data to Google, more protection). |
| `UrlKeyedAnonymizedDataCollectionEnabled` | `0` | Stops URL-keyed data collection - the URLs of pages you visit sent to Google to improve services. |
| `SpellCheckServiceEnabled` | `0` | Disables the *cloud* spell checker, which sends typed text to Google. Local spell check keeps working. |
| `AlternateErrorPagesEnabled` | `0` | Stops error-page details being sent to Google for "did you mean" suggestions. |
| `NetworkPredictionOptions` | `2` | Same as Edge: disables predictive DNS prefetch/preconnect (`0` = always, `2` = never). |
| `FeedbackSurveysEnabled` | `0` | Disables Google's in-browser Happiness Tracking Surveys. |
| `PrivacySandboxPromptEnabled` | `0` | Suppresses the Privacy Sandbox consent prompt; required for the three policies below to take effect. |
| `PrivacySandboxAdTopicsEnabled` | `0` | Disables the Topics API - Chrome deriving advertising interest categories from your browsing history. |
| `PrivacySandboxSiteEnabledAdsEnabled` | `0` | Disables site-suggested ads (Protected Audience / remarketing without third-party cookies). |
| `PrivacySandboxAdMeasurementEnabled` | `0` | Disables the Attribution Reporting API (ad click/conversion measurement). |

### Mozilla Firefox
Key: `HKLM\SOFTWARE\Policies\Mozilla\Firefox`

Firefox policies are inverted ("Disable..."), so hardened = `1`.

| Value | Hardened | Explanation |
|---|---|---|
| `DisableTelemetry` | `1` | Stops Firefox usage, performance and technical telemetry to Mozilla. |
| `DisableFirefoxStudies` | `1` | Stops Shield/Nimbus studies - remote experiments and preference rollouts Mozilla can push to your browser. |
| `DisableDefaultBrowserAgent` | `1` | Removes the Default Browser Agent - a scheduled task that pings Mozilla daily with default-browser and OS info, even when Firefox is closed. |
| `DisablePocket` | `1` | Disables Pocket integration and its sponsored/recommended stories on the new-tab page. |

Note: Firefox's Safe Browsing cannot be toggled from the registry (it lives
in `browser.safebrowsing.*` preferences / `policies.json`), so it is
deliberately not included here.

### Brave
Key: `HKLM\SOFTWARE\Policies\BraveSoftware\Brave`

Brave sends comparatively little telemetry by default; these harden its
bundled feature surface, each of which contacts Brave services.

| Value | Hardened | Explanation |
|---|---|---|
| `BraveRewardsDisabled` | `1` | Disables Brave Rewards (BAT ads/attention tracking). |
| `BraveWalletDisabled` | `1` | Disables the built-in crypto wallet. |
| `BraveVPNDisabled` | `1` | Disables the Brave VPN feature and its account checks. |
| `TorDisabled` | `1` | Disables "Private window with Tor". (Feature-surface reduction; Tor itself is a privacy feature - leave enabled if you use it.) |
| `SearchSuggestEnabled` | `0` | Chromium policy honoured by Brave: stops keystroke-by-keystroke search suggestions. |
| `SafeBrowsingProtectionLevel` `[SEC]` | `0` | Same as Chrome: `0` disables URL reputation checks entirely. |

### General notes

- Under `-DisableAll`, Safe Browsing / SmartScreen (`[SEC]`) stay ON; full
  URL-check disabling requires `-IncludeSecurity` or the menu `S` command.
- DNS-over-HTTPS policies are intentionally not touched - DoH is a privacy
  *gain* in most settings and is better configured deliberately per network.

## CSV output columns

`Name, Browser, Installed, Policy, State, Note` ([SEC] items are named as
such in the `Name` column).

---

# 3. Manage-DefenderAntivirus.ps1

Views the **health of Microsoft Defender Antivirus** and lets you view/toggle
its protection settings, plus run common actions (update signatures,
quick/full scan, view threats and exclusions).

Unlike the other two tools this is a **security** tool, so the polarity is
reversed: **On = protected (good, green)**, **Off = reduced protection (red)**.
It uses the built-in Defender PowerShell module (`Get-MpComputerStatus`,
`Get-MpPreference`, `Set-MpPreference`, `Update-MpSignature`, `Start-MpScan`)
- **not** the registry, because Tamper Protection and policy layering make
direct registry edits to Defender unreliable.

## Quick start

```powershell
# View health + protection status (read-only, works as standard user)
.\Manage-DefenderAntivirus.ps1 -Report

# Interactive menu (run ELEVATED to change settings, scan or update)
.\Manage-DefenderAntivirus.ps1

# Set every protection to its recommended (ON) state
.\Manage-DefenderAntivirus.ps1 -EnableRecommended

# Turn ALL protections OFF (reduces security; also stops Defender cloud
# lookups and sample submission to Microsoft)
.\Manage-DefenderAntivirus.ps1 -DisableAll

# Update signatures / run a scan and exit
.\Manage-DefenderAntivirus.ps1 -Update
.\Manage-DefenderAntivirus.ps1 -QuickScan
.\Manage-DefenderAntivirus.ps1 -FullScan

# Export health + config to CSV
.\Manage-DefenderAntivirus.ps1 -Csv .\defender-status.csv
```

## Tamper Protection

On Windows 11, **Tamper Protection** is on by default and deliberately
**blocks programmatic changes** to core protection (real-time monitoring,
etc.). When it is on, `Set-MpPreference` calls for those items will fail -
the tool detects this, shows a NOTE, and reports the failure clearly rather
than pretending the change succeeded. To change guarded items you must first
turn Tamper Protection off in the **Windows Security app** (Virus & threat
protection -> Manage settings) or via Intune. The tool intentionally cannot
disable Tamper Protection for you - that is by design.

## Health summary (read-only)

From `Get-MpComputerStatus`: running mode (Normal / Passive / EDR Block -
passive means another AV is primary and Defender settings are inactive),
AntiMalware service, real-time protection, behaviour monitor, on-access
(IOAV), network inspection (NIS), Tamper Protection state, signature version
and **age in days** (green <=2, yellow <=7, red older), engine version, and
last quick/full scan times.

## Configurable protections

Each maps to one `Set-MpPreference` parameter. "Recommended" is always **On**.

| Protection | Preference | Recommended | Explanation |
|---|---|---|---|
| Real-time Monitoring | `DisableRealtimeMonitoring` | On (`$false`) | Core on-access scanning. Guarded by Tamper Protection. |
| Behavior Monitoring | `DisableBehaviorMonitoring` | On (`$false`) | Detects malicious behaviour patterns at runtime. |
| Downloads/Attachment Scan | `DisableIOAVProtection` | On (`$false`) | Scans files downloaded from internet/email. |
| Script Scanning | `DisableScriptScanning` | On (`$false`) | Scans scripts before they execute. |
| Archive Scanning | `DisableArchiveScanning` | On (`$false`) | Scans inside .zip/.rar/etc. |
| Email Scanning | `DisableEmailScanning` | On (`$false`) | Parses mailbox/email files during scans. |
| Removable Drive Scanning | `DisableRemovableDriveScanning` | On (`$false`) | Includes USB media in full scans. |
| Cloud-delivered Protection | `MAPSReporting` | Advanced (`2`) | Real-time cloud lookups (`0` off, `1` basic, `2` advanced). |
| Automatic Sample Submission `[PRIV]` | `SubmitSamplesConsent` | SendSafeSamples (`1`) | Needed for full cloud protection; **sends files to Microsoft**. `2` = Never (privacy). |
| Cloud Block Level | `CloudBlockLevel` | High (`2`) | Aggressiveness of cloud blocking; higher = safer but more false positives. |
| PUA Protection | `PUAProtection` | Enabled (`1`) | Blocks potentially unwanted apps (adware/bundleware); `2` = audit. |
| Network Protection | `EnableNetworkProtection` | Enabled (`1`) | Blocks connections to malicious domains/IPs; `2` = audit. |
| Controlled Folder Access | `EnableControlledFolderAccess` | Enabled (`1`) | Anti-ransomware; blocks untrusted apps writing to protected folders. May need app allow-listing. |

`[PRIV]` marks the one setting that improves protection but also sends data
to Microsoft, so you can make an informed choice. **Audit mode** (for PUA /
Network Protection / Controlled Folder Access) shows as `Other (AuditMode)` -
it logs but does not block, useful for testing before enforcing.

## Menu commands

| Command | Action |
|---|---|
| `<n>` | Toggle protection *n* (disabling asks for `YES` confirmation) |
| `e <n>` / `d <n>` | Enable / disable item *n* (`d` warns and confirms) |
| `E` | Enable **all** recommended protections |
| `D` | Disable **all** protections (requires typing `DISABLE-ALL`) |
| `u` | Update signatures (`Update-MpSignature`) |
| `s` / `f` | Run quick / full scan (`Start-MpScan`) |
| `t` | Show recent threat detections |
| `x` | Show configured exclusions (paths/extensions/processes) |
| `r` / `c <path>` / `q` | Refresh / export CSV / quit |

### Bulk disable

This is a privacy/telemetry-hardening toolkit for advanced users, so a bulk
disable is provided to match the other scripts:

- **CLI:** `-DisableAll` runs immediately (scriptable), then reprints status.
- **Menu:** `D` requires typing `DISABLE-ALL` to confirm.

Disabling here doubles as privacy hardening: it sets `MAPSReporting` to
Disabled and `SubmitSamplesConsent` to Never, which **stops Defender's cloud
lookups and file/sample uploads to Microsoft**. Note that with **Tamper
Protection on**, core items (real-time monitoring, etc.) stay ON regardless -
turn Tamper Protection off in the Windows Security app first if you need
those off too. Individual protections can still be re-enabled with `e <n>`
or restored wholesale with `E` / `-EnableRecommended`.

## Requirements and caveats

- Needs the built-in **Defender module**; the tool exits cleanly if the
  cmdlets are absent (e.g. Defender removed, or a Server SKU without the
  feature).
- Viewing works as a standard user; **changing settings, scanning and
  updating require Administrator**.
- If a **third-party AV** is installed, Defender runs in **passive mode** and
  most of these settings will not take effect until Defender is primary
  again. The running-mode line makes this visible.
- Exclusions are shown (`x`) but not edited here - review them, as each
  exclusion is a gap in coverage that malware can hide behind.

## CSV output columns

`Group (Health/Protection), Name, State, Note`

---

# Files

| File | Purpose |
|---|---|
| `Manage-WindowsTelemetry.ps1` | Windows telemetry view + control |
| `Manage-BrowserPrivacy.ps1` | Browser privacy view + hardening |
| `Manage-DefenderAntivirus.ps1` | Defender health + protection management |
| `README.md` | This file |

All CSV exports are useful for fleet auditing: run with `-Csv` on multiple
machines and diff or aggregate the results.

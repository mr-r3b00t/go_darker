#Requires -Version 5.1
<#
    Manage-BrowserPrivacy.ps1

    Purpose : View and control privacy / telemetry-related policy settings for
              browsers installed on this Windows 11 machine:
              Microsoft Edge, Google Chrome, Mozilla Firefox, Brave.

    How     : Uses each browser's supported policy registry keys under
              HKLM\SOFTWARE\Policies\... . Browsers apply these on next start.
              Only detected (installed) browsers are shown, unless -IncludeAll.

    Notes   : - Windows PowerShell 5.1 compatible. ASCII-only source.
              - HKLM policy changes require Administrator.
              - "Enabled"  = the data-collection / suggestion feature is ON.
                "Disabled" = hardened / OFF.
              - "Enable" REMOVES the policy value (true browser default =
                value absent), so browsers are not left permanently showing
                "Managed by your organization" after a round trip.
              - While policies are applied (hardened), browsers WILL show a
                "managed" notice on their settings pages. That is how
                Chromium/Firefox indicate active policies and is expected.

    Usage   :
        .\Manage-BrowserPrivacy.ps1                 # interactive menu
        .\Manage-BrowserPrivacy.ps1 -Report         # print status and exit
        .\Manage-BrowserPrivacy.ps1 -DisableAll     # harden all browsers
        .\Manage-BrowserPrivacy.ps1 -EnableAll      # restore browser defaults
        .\Manage-BrowserPrivacy.ps1 -Csv .\out.csv  # export status and exit
        .\Manage-BrowserPrivacy.ps1 -Report -IncludeAll   # show non-installed too

    DISCLAIMER: Review before use. Test on a non-production machine first.
    No warranty.
#>

[CmdletBinding()]
param(
    [switch]$Report,
    [switch]$DisableAll,
    [switch]$EnableAll,
    [switch]$IncludeAll,
    [switch]$IncludeSecurity,   # also disable [SEC] URL-check features in bulk actions
    [string]$Csv
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Elevation helpers
# ---------------------------------------------------------------------------
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$Script:IsAdmin = Test-IsAdmin

# ---------------------------------------------------------------------------
# Browser detection
# ---------------------------------------------------------------------------
function Get-BrowserInfo {
    param([string]$Exe)
    foreach ($hive in 'HKLM', 'HKCU') {
        $key = ('{0}:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{1}' -f $hive, $Exe)
        if (Test-Path -LiteralPath $key) {
            $ver = ''
            try {
                $path = (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).'(default)'
                if ($path -and (Test-Path -LiteralPath $path)) {
                    $ver = (Get-Item -LiteralPath $path).VersionInfo.ProductVersion
                }
            } catch { $ver = '' }
            return [pscustomobject]@{ Installed = $true; Version = $ver }
        }
    }
    return [pscustomobject]@{ Installed = $false; Version = '' }
}

$Script:Browsers = @{
    'Edge'    = Get-BrowserInfo -Exe 'msedge.exe'
    'Chrome'  = Get-BrowserInfo -Exe 'chrome.exe'
    'Firefox' = Get-BrowserInfo -Exe 'firefox.exe'
    'Brave'   = Get-BrowserInfo -Exe 'brave.exe'
}

# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------
function Get-RegValue {
    param([string]$FullPath, [string]$Name)
    try {
        if (-not (Test-Path -LiteralPath $FullPath)) { return $null }
        $item = Get-ItemProperty -LiteralPath $FullPath -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch {
        return $null
    }
}

function Set-RegValue {
    param([string]$FullPath, [string]$Name, $Value, [string]$Type = 'DWord')
    if (-not (Test-Path -LiteralPath $FullPath)) {
        New-Item -Path $FullPath -Force | Out-Null
    }
    New-ItemProperty -LiteralPath $FullPath -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

function Remove-RegValue {
    param([string]$FullPath, [string]$Name)
    if (Test-Path -LiteralPath $FullPath) {
        Remove-ItemProperty -LiteralPath $FullPath -Name $Name -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Control model (policy DWORD values under HKLM\SOFTWARE\Policies\...)
#   All browser policies default to ABSENT, so every control is
#   remove-on-enable: Enable deletes the value, Disable writes OffValue.
# ---------------------------------------------------------------------------
function New-PolicyControl {
    param(
        [string]$Name, [string]$Browser, [string]$PolicyPath,
        [string]$ValueName, [int]$OnValue, [int]$OffValue,
        [string]$Note = '',
        [switch]$Security   # marks a control whose "Disabled" state REDUCES protection
    )
    [pscustomobject]@{
        Type      = 'Reg'
        Name      = $Name
        Category  = $Browser
        Note      = $Note
        FullPath  = ('HKLM:\{0}' -f $PolicyPath)
        ValueName = $ValueName
        OnValue   = $OnValue
        OffValue  = $OffValue
        Security  = [bool]$Security
        AdminReq  = $true
    }
}

function Get-ControlState {
    param($Ctrl)
    $cur = Get-RegValue -FullPath $Ctrl.FullPath -Name $Ctrl.ValueName
    if ($null -eq $cur) { return 'Enabled (default)' }
    $curInt = $null
    try { $curInt = [int]$cur } catch {
        return ('Enabled (value={0})' -f $cur)
    }
    if ($curInt -eq $Ctrl.OffValue) { return 'Disabled' }
    if ($curInt -eq $Ctrl.OnValue)  { return 'Enabled' }
    return ('Enabled (value={0})' -f $curInt)
}

function Set-ControlEnabled {
    param($Ctrl)   # restore browser default: remove the policy value
    Remove-RegValue -FullPath $Ctrl.FullPath -Name $Ctrl.ValueName
}

function Set-ControlDisabled {
    param($Ctrl)   # harden: write the policy value
    Set-RegValue -FullPath $Ctrl.FullPath -Name $Ctrl.ValueName -Value $Ctrl.OffValue -Type 'DWord'
}

# ---------------------------------------------------------------------------
# Control catalog
# ---------------------------------------------------------------------------
function Get-Controls {
    $c    = New-Object System.Collections.ArrayList
    $edge = 'SOFTWARE\Policies\Microsoft\Edge'
    $chr  = 'SOFTWARE\Policies\Google\Chrome'
    $ffx  = 'SOFTWARE\Policies\Mozilla\Firefox'
    $brv  = 'SOFTWARE\Policies\BraveSoftware\Brave'

    # =========================== Microsoft Edge ===========================
    [void]$c.Add( (New-PolicyControl -Name 'Diagnostic Data' -Browser Edge -PolicyPath $edge `
        -ValueName 'DiagnosticData' -OnValue 2 -OffValue 0 `
        -Note '0=off 1=required 2=optional') )

    [void]$c.Add( (New-PolicyControl -Name 'Personalization Reporting' -Browser Edge -PolicyPath $edge `
        -ValueName 'PersonalizationReportingEnabled' -OnValue 1 -OffValue 0 `
        -Note 'Browsing history used for ads/news personalization') )

    [void]$c.Add( (New-PolicyControl -Name 'User Feedback' -Browser Edge -PolicyPath $edge `
        -ValueName 'UserFeedbackAllowed' -OnValue 1 -OffValue 0) )

    [void]$c.Add( (New-PolicyControl -Name 'Search Suggestions' -Browser Edge -PolicyPath $edge `
        -ValueName 'SearchSuggestEnabled' -OnValue 1 -OffValue 0 `
        -Note 'Sends keystrokes to search provider') )

    [void]$c.Add( (New-PolicyControl -Name 'Bing Provider in Address Bar' -Browser Edge -PolicyPath $edge `
        -ValueName 'AddressBarMicrosoftSearchInBingProviderEnabled' -OnValue 1 -OffValue 0) )

    [void]$c.Add( (New-PolicyControl -Name 'Shopping Assistant' -Browser Edge -PolicyPath $edge `
        -ValueName 'EdgeShoppingAssistantEnabled' -OnValue 1 -OffValue 0 `
        -Note 'Coupons/price comparison; shares browsing data') )

    [void]$c.Add( (New-PolicyControl -Name 'Microsoft Rewards' -Browser Edge -PolicyPath $edge `
        -ValueName 'ShowMicrosoftRewards' -OnValue 1 -OffValue 0) )

    [void]$c.Add( (New-PolicyControl -Name 'Web Widget (search bar)' -Browser Edge -PolicyPath $edge `
        -ValueName 'WebWidgetAllowed' -OnValue 1 -OffValue 0) )

    [void]$c.Add( (New-PolicyControl -Name 'Spotlight Recommendations' -Browser Edge -PolicyPath $edge `
        -ValueName 'SpotlightExperiencesAndRecommendationsEnabled' -OnValue 1 -OffValue 0) )

    [void]$c.Add( (New-PolicyControl -Name 'Do Not Track OFF' -Browser Edge -PolicyPath $edge `
        -ValueName 'ConfigureDoNotTrack' -OnValue 0 -OffValue 1 `
        -Note 'Disabled = DNT header IS sent (hardened)') )

    [void]$c.Add( (New-PolicyControl -Name 'Nav Error Web Service' -Browser Edge -PolicyPath $edge `
        -ValueName 'ResolveNavigationErrorsUseWebService' -OnValue 1 -OffValue 0) )

    [void]$c.Add( (New-PolicyControl -Name 'Alternate Error Pages' -Browser Edge -PolicyPath $edge `
        -ValueName 'AlternateErrorPagesEnabled' -OnValue 1 -OffValue 0) )

    [void]$c.Add( (New-PolicyControl -Name 'Network Prediction (prefetch)' -Browser Edge -PolicyPath $edge `
        -ValueName 'NetworkPredictionOptions' -OnValue 0 -OffValue 2 `
        -Note '0=predict always 2=never') )

    # --- Edge SmartScreen: URL / site / download reputation (SECURITY) ---
    [void]$c.Add( (New-PolicyControl -Name 'SmartScreen (URL/site check)' -Browser Edge -PolicyPath $edge `
        -ValueName 'SmartScreenEnabled' -OnValue 1 -OffValue 0 -Security `
        -Note 'SECURITY: checks visited URLs/downloads against Microsoft reputation') )

    [void]$c.Add( (New-PolicyControl -Name 'SmartScreen PUA blocking' -Browser Edge -PolicyPath $edge `
        -ValueName 'SmartScreenPuaEnabled' -OnValue 1 -OffValue 0 -Security `
        -Note 'SECURITY: blocks potentially unwanted apps') )

    [void]$c.Add( (New-PolicyControl -Name 'SmartScreen DNS lookups' -Browser Edge -PolicyPath $edge `
        -ValueName 'SmartScreenDnsRequestsEnabled' -OnValue 1 -OffValue 0 -Security `
        -Note 'SECURITY: DNS-based site reputation lookups') )

    [void]$c.Add( (New-PolicyControl -Name 'Typosquatting Checker' -Browser Edge -PolicyPath $edge `
        -ValueName 'TyposquattingCheckerEnabled' -OnValue 1 -OffValue 0 -Security `
        -Note 'SECURITY: warns on lookalike/typo domains') )

    # =========================== Google Chrome ============================
    [void]$c.Add( (New-PolicyControl -Name 'Metrics Reporting (UMA)' -Browser Chrome -PolicyPath $chr `
        -ValueName 'MetricsReportingEnabled' -OnValue 1 -OffValue 0 `
        -Note 'Usage statistics and crash reports to Google') )

    [void]$c.Add( (New-PolicyControl -Name 'Search Suggestions' -Browser Chrome -PolicyPath $chr `
        -ValueName 'SearchSuggestEnabled' -OnValue 1 -OffValue 0 `
        -Note 'Sends keystrokes to search provider') )

    [void]$c.Add( (New-PolicyControl -Name 'Safe Browsing Ext. Reporting' -Browser Chrome -PolicyPath $chr `
        -ValueName 'SafeBrowsingExtendedReportingEnabled' -OnValue 1 -OffValue 0 `
        -Note 'Extra page/system data to Google; SB itself stays on') )

    [void]$c.Add( (New-PolicyControl -Name 'Safe Browsing (URL check)' -Browser Chrome -PolicyPath $chr `
        -ValueName 'SafeBrowsingProtectionLevel' -OnValue 1 -OffValue 0 -Security `
        -Note 'SECURITY: 0=off 1=standard 2=enhanced. Off stops URL reputation checks') )

    [void]$c.Add( (New-PolicyControl -Name 'URL-keyed Data Collection' -Browser Chrome -PolicyPath $chr `
        -ValueName 'UrlKeyedAnonymizedDataCollectionEnabled' -OnValue 1 -OffValue 0 `
        -Note 'URLs of visited pages sent to Google') )

    [void]$c.Add( (New-PolicyControl -Name 'Cloud Spell Check' -Browser Chrome -PolicyPath $chr `
        -ValueName 'SpellCheckServiceEnabled' -OnValue 1 -OffValue 0 `
        -Note 'Typed text sent to Google web service') )

    [void]$c.Add( (New-PolicyControl -Name 'Alternate Error Pages' -Browser Chrome -PolicyPath $chr `
        -ValueName 'AlternateErrorPagesEnabled' -OnValue 1 -OffValue 0) )

    [void]$c.Add( (New-PolicyControl -Name 'Network Prediction (prefetch)' -Browser Chrome -PolicyPath $chr `
        -ValueName 'NetworkPredictionOptions' -OnValue 0 -OffValue 2 `
        -Note '0=predict always 2=never') )

    [void]$c.Add( (New-PolicyControl -Name 'Feedback Surveys' -Browser Chrome -PolicyPath $chr `
        -ValueName 'FeedbackSurveysEnabled' -OnValue 1 -OffValue 0) )

    [void]$c.Add( (New-PolicyControl -Name 'Privacy Sandbox Prompt' -Browser Chrome -PolicyPath $chr `
        -ValueName 'PrivacySandboxPromptEnabled' -OnValue 1 -OffValue 0 `
        -Note 'Must be Disabled for the three policies below') )

    [void]$c.Add( (New-PolicyControl -Name 'Privacy Sandbox: Ad Topics' -Browser Chrome -PolicyPath $chr `
        -ValueName 'PrivacySandboxAdTopicsEnabled' -OnValue 1 -OffValue 0 `
        -Note 'Interest-based advertising (Topics API)') )

    [void]$c.Add( (New-PolicyControl -Name 'Privacy Sandbox: Site Ads' -Browser Chrome -PolicyPath $chr `
        -ValueName 'PrivacySandboxSiteEnabledAdsEnabled' -OnValue 1 -OffValue 0 `
        -Note 'Site-suggested ads (Protected Audience)') )

    [void]$c.Add( (New-PolicyControl -Name 'Privacy Sandbox: Ad Measure' -Browser Chrome -PolicyPath $chr `
        -ValueName 'PrivacySandboxAdMeasurementEnabled' -OnValue 1 -OffValue 0 `
        -Note 'Attribution / ad measurement API') )

    # =========================== Mozilla Firefox ==========================
    [void]$c.Add( (New-PolicyControl -Name 'Telemetry' -Browser Firefox -PolicyPath $ffx `
        -ValueName 'DisableTelemetry' -OnValue 0 -OffValue 1 `
        -Note 'Usage and technical data to Mozilla') )

    [void]$c.Add( (New-PolicyControl -Name 'Firefox Studies (Shield)' -Browser Firefox -PolicyPath $ffx `
        -ValueName 'DisableFirefoxStudies' -OnValue 0 -OffValue 1 `
        -Note 'Remote experiments / preference rollouts') )

    [void]$c.Add( (New-PolicyControl -Name 'Default Browser Agent' -Browser Firefox -PolicyPath $ffx `
        -ValueName 'DisableDefaultBrowserAgent' -OnValue 0 -OffValue 1 `
        -Note 'Scheduled task that pings Mozilla daily') )

    [void]$c.Add( (New-PolicyControl -Name 'Pocket Integration' -Browser Firefox -PolicyPath $ffx `
        -ValueName 'DisablePocket' -OnValue 0 -OffValue 1 `
        -Note 'Sponsored stories / recommendations') )

    # =============================== Brave ================================
    # Brave sends little telemetry by default; these harden its bundled
    # feature surface area (each phones home to Brave services).
    [void]$c.Add( (New-PolicyControl -Name 'Brave Rewards' -Browser Brave -PolicyPath $brv `
        -ValueName 'BraveRewardsDisabled' -OnValue 0 -OffValue 1) )

    [void]$c.Add( (New-PolicyControl -Name 'Brave Wallet' -Browser Brave -PolicyPath $brv `
        -ValueName 'BraveWalletDisabled' -OnValue 0 -OffValue 1) )

    [void]$c.Add( (New-PolicyControl -Name 'Brave VPN' -Browser Brave -PolicyPath $brv `
        -ValueName 'BraveVPNDisabled' -OnValue 0 -OffValue 1) )

    [void]$c.Add( (New-PolicyControl -Name 'Tor Windows' -Browser Brave -PolicyPath $brv `
        -ValueName 'TorDisabled' -OnValue 0 -OffValue 1 `
        -Note 'Private windows with Tor') )

    [void]$c.Add( (New-PolicyControl -Name 'Search Suggestions' -Browser Brave -PolicyPath $brv `
        -ValueName 'SearchSuggestEnabled' -OnValue 1 -OffValue 0 `
        -Note 'Chromium policy honoured by Brave') )

    [void]$c.Add( (New-PolicyControl -Name 'Safe Browsing (URL check)' -Browser Brave -PolicyPath $brv `
        -ValueName 'SafeBrowsingProtectionLevel' -OnValue 1 -OffValue 0 -Security `
        -Note 'SECURITY: 0=off 1=standard 2=enhanced. Off stops URL reputation checks') )

    # Filter to installed browsers unless -IncludeAll
    if ($IncludeAll) { return $c }
    $filtered = New-Object System.Collections.ArrayList
    foreach ($ctrl in $c) {
        if ($Script:Browsers[$ctrl.Category].Installed) { [void]$filtered.Add($ctrl) }
    }
    return $filtered
}

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------
function Get-StateColor {
    param([string]$State)
    if ($State -like 'Disabled*') { return 'Green' }
    if ($State -like 'Enabled*')  { return 'Yellow' }
    return 'Gray'
}

function Show-Status {
    param($Controls)

    Write-Host ''
    Write-Host '==================================================================' -ForegroundColor Cyan
    Write-Host '  Browser Privacy / Telemetry Status' -ForegroundColor Cyan
    Write-Host ('  Host: {0}   Admin: {1}   {2}' -f $env:COMPUTERNAME, $Script:IsAdmin, (Get-Date)) -ForegroundColor DarkCyan
    $det = @()
    foreach ($b in @('Edge','Chrome','Firefox','Brave')) {
        $info = $Script:Browsers[$b]
        if ($info.Installed) {
            if ($info.Version) { $det += ('{0} {1}' -f $b, $info.Version) }
            else               { $det += $b }
        }
    }
    if ($det.Count -eq 0) { $det = @('none detected') }
    Write-Host ('  Browsers: {0}' -f ($det -join ', ')) -ForegroundColor DarkCyan
    Write-Host '  Enabled = collecting/on    Disabled = hardened/off' -ForegroundColor DarkCyan
    Write-Host '==================================================================' -ForegroundColor Cyan
    Write-Host ('{0,-4}{1,-36}{2,-10}{3}' -f '#', 'Setting', 'Browser', 'State') -ForegroundColor White
    Write-Host ('{0,-4}{1,-36}{2,-10}{3}' -f '---', '-------', '-------', '-----') -ForegroundColor DarkGray

    $i = 0
    $nEnabled = 0; $nDisabled = 0; $nSecOff = 0
    foreach ($ctrl in $Controls) {
        $i++
        $state = Get-ControlState -Ctrl $ctrl
        if     ($state -like 'Enabled*')  { $nEnabled++ }
        elseif ($state -like 'Disabled*') { $nDisabled++ }
        $sec = ''
        if ($ctrl.Security) {
            $sec = ' [SEC]'
            if ($state -like 'Disabled*') { $nSecOff++ }
        }
        $lock = ''
        if ($ctrl.AdminReq -and -not $Script:IsAdmin) { $lock = ' *' }
        $flag = ''
        if (-not $Script:Browsers[$ctrl.Category].Installed) { $flag = ' (not installed)' }
        $line = ('{0,-4}{1,-36}{2,-10}' -f $i, ($ctrl.Name + $sec), $ctrl.Category)
        Write-Host $line -NoNewline
        Write-Host ($state + $lock + $flag) -ForegroundColor (Get-StateColor $state)
    }
    Write-Host ('{0,-4}{1,-36}{2,-10}{3}' -f '---', '-------', '-------', '-----') -ForegroundColor DarkGray
    Write-Host ('  Summary: {0} enabled, {1} disabled' -f $nEnabled, $nDisabled) -ForegroundColor White
    Write-Host '  [SEC] = anti-malware URL/site check. Disabling REDUCES protection' -ForegroundColor DarkYellow
    if ($nSecOff -gt 0) {
        Write-Host ('  WARNING: {0} security URL-check feature(s) are currently OFF' -f $nSecOff) -ForegroundColor Red
    }
    Write-Host '  Policies apply on next browser start. While hardened, browsers' -ForegroundColor DarkCyan
    Write-Host '  show a "managed" notice on settings pages - that is expected.' -ForegroundColor DarkCyan
    if (-not $Script:IsAdmin) {
        Write-Host '  * requires Administrator to change (run elevated)' -ForegroundColor DarkYellow
    }
    Write-Host ''
}

function Export-StatusCsv {
    param($Controls, [string]$Path)
    $rows = foreach ($ctrl in $Controls) {
        [pscustomobject]@{
            Name      = $ctrl.Name
            Browser   = $ctrl.Category
            Installed = $Script:Browsers[$ctrl.Category].Installed
            Policy    = $ctrl.ValueName
            State     = (Get-ControlState -Ctrl $ctrl)
            Note      = $ctrl.Note
        }
    }
    $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding ASCII
    Write-Host ("Status written to {0}" -f $Path) -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Apply helpers with guard rails
# ---------------------------------------------------------------------------
function Invoke-ControlAction {
    param($Ctrl, [ValidateSet('Enable','Disable')][string]$Action)

    if ($Ctrl.AdminReq -and -not $Script:IsAdmin) {
        Write-Host ("  SKIP  {0}/{1} (needs Administrator)" -f $Ctrl.Category, $Ctrl.Name) -ForegroundColor DarkYellow
        return
    }
    try {
        if ($Action -eq 'Enable') { Set-ControlEnabled -Ctrl $Ctrl }
        else                      { Set-ControlDisabled -Ctrl $Ctrl }
        $new = Get-ControlState -Ctrl $Ctrl
        Write-Host ("  OK    {0}/{1} -> {2}" -f $Ctrl.Category, $Ctrl.Name, $new) -ForegroundColor Green
    } catch {
        Write-Host ("  FAIL  {0}/{1}: {2}" -f $Ctrl.Category, $Ctrl.Name, $_.Exception.Message) -ForegroundColor Red
    }
}

function Invoke-AllAction {
    param(
        $Controls,
        [ValidateSet('Enable','Disable')][string]$Action,
        [switch]$WithSecurity   # when disabling, also include [SEC] URL-check features
    )
    $verb = if ($Action -eq 'Enable') { 'ENABLE (restore browser defaults)' } else { 'DISABLE (harden)' }
    Write-Host ''
    Write-Host ("Applying {0} to ALL items..." -f $verb) -ForegroundColor Cyan
    $skippedSec = 0
    foreach ($ctrl in $Controls) {
        # Never auto-disable anti-malware URL checks in bulk unless explicitly requested.
        if ($Action -eq 'Disable' -and $ctrl.Security -and -not $WithSecurity) {
            $skippedSec++
            continue
        }
        Invoke-ControlAction -Ctrl $ctrl -Action $Action
    }
    if ($skippedSec -gt 0) {
        Write-Host ('  Kept {0} [SEC] URL-check feature(s) ON (use -IncludeSecurity / menu "S" to disable).' -f $skippedSec) -ForegroundColor DarkYellow
    }
    Write-Host ''
    Write-Host 'Restart the affected browsers for policies to take effect.' -ForegroundColor Cyan
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------
function Start-Menu {
    param($Controls)
    while ($true) {
        Show-Status -Controls $Controls
        Write-Host 'Commands:' -ForegroundColor White
        Write-Host '  <n>          toggle item n (Enable<->Disable)'
        Write-Host '  e <n>        enable item n'
        Write-Host '  d <n>        disable item n'
        Write-Host '  D            disable ALL (harden; keeps [SEC] URL checks ON)'
        Write-Host '  E            enable ALL (restore browser defaults)'
        Write-Host '  S            disable ALL [SEC] URL-check features (reduces security)'
        Write-Host '  b <name>     apply D to one browser (e.g. b Edge)'
        Write-Host '  r            refresh view'
        Write-Host '  c <path>     export status to CSV'
        Write-Host '  q            quit'
        Write-Host ''
        $inp = Read-Host 'Select'
        if ([string]::IsNullOrWhiteSpace($inp)) { continue }
        $inp = $inp.Trim()

        # -CaseSensitive so bare "d"/"e" do NOT match the ALL branches below
        switch -Regex -CaseSensitive ($inp) {
            '^[Qq]$'      { return }
            '^[Rr]$'      { continue }
            '^D$'         {
                if ((Read-Host 'Harden ALL browser settings? type YES') -ceq 'YES') {
                    Invoke-AllAction -Controls $Controls -Action Disable
                }
                Read-Host 'Press Enter'; continue
            }
            '^E$'         {
                if ((Read-Host 'Restore ALL browser defaults? type YES') -ceq 'YES') {
                    Invoke-AllAction -Controls $Controls -Action Enable
                }
                Read-Host 'Press Enter'; continue
            }
            '^S$'         {
                $secList = @($Controls | Where-Object { $_.Security })
                Write-Host ''
                Write-Host 'WARNING: This turns OFF anti-malware URL/site reputation checks' -ForegroundColor Red
                Write-Host ('(SmartScreen / Safe Browsing) for {0} item(s). Your browser will' -f $secList.Count) -ForegroundColor Red
                Write-Host 'no longer warn about known malicious or phishing sites.' -ForegroundColor Red
                if ((Read-Host 'Proceed? type DISABLE-SECURITY') -ceq 'DISABLE-SECURITY') {
                    Invoke-AllAction -Controls $secList -Action Disable -WithSecurity
                }
                Read-Host 'Press Enter'; continue
            }
            '^[Bb]\s+(\w+)$' {
                $target = $Matches[1]
                $subset = @($Controls | Where-Object { $_.Category -eq $target })
                if ($subset.Count -eq 0) {
                    Write-Host ('No controls for browser "{0}" (use Edge/Chrome/Firefox/Brave)' -f $target) -ForegroundColor Red
                } elseif ((Read-Host ('Harden all {0} settings? type YES' -f $target)) -ceq 'YES') {
                    Invoke-AllAction -Controls $subset -Action Disable
                }
                Read-Host 'Press Enter'; continue
            }
            '^[Cc]\s+(.+)$' {
                Export-StatusCsv -Controls $Controls -Path $Matches[1].Trim('"')
                Read-Host 'Press Enter'; continue
            }
            '^[Ee]\s+(\d+)$' {
                $n = [int]$Matches[1]
                if ($n -ge 1 -and $n -le $Controls.Count) { Invoke-ControlAction -Ctrl $Controls[$n-1] -Action Enable }
                else { Write-Host 'Out of range' -ForegroundColor Red }
                Read-Host 'Press Enter'; continue
            }
            '^[Dd]\s+(\d+)$' {
                $n = [int]$Matches[1]
                if ($n -ge 1 -and $n -le $Controls.Count) { Invoke-ControlAction -Ctrl $Controls[$n-1] -Action Disable }
                else { Write-Host 'Out of range' -ForegroundColor Red }
                Read-Host 'Press Enter'; continue
            }
            '^\d+$' {
                $n = [int]$inp
                if ($n -ge 1 -and $n -le $Controls.Count) {
                    $ctrl  = $Controls[$n-1]
                    $state = Get-ControlState -Ctrl $ctrl
                    if ($state -like 'Enabled*') { Invoke-ControlAction -Ctrl $ctrl -Action Disable }
                    else                         { Invoke-ControlAction -Ctrl $ctrl -Action Enable }
                } else { Write-Host 'Out of range' -ForegroundColor Red }
                Read-Host 'Press Enter'; continue
            }
            default { Write-Host 'Unknown command (d/e need an item number; D/E alone mean ALL)' -ForegroundColor Red; Start-Sleep -Milliseconds 600 }
        }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$controls = Get-Controls

if (@($controls).Count -eq 0) {
    Write-Host 'No supported browsers detected (Edge/Chrome/Firefox/Brave).' -ForegroundColor Red
    Write-Host 'Use -IncludeAll to manage policies for browsers not yet installed.' -ForegroundColor DarkYellow
    return
}

if ($DisableAll) {
    Invoke-AllAction -Controls $controls -Action Disable -WithSecurity:$IncludeSecurity
    Show-Status -Controls $controls
    if ($Csv) { Export-StatusCsv -Controls $controls -Path $Csv }
    return
}
if ($EnableAll) {
    Invoke-AllAction -Controls $controls -Action Enable
    Show-Status -Controls $controls
    if ($Csv) { Export-StatusCsv -Controls $controls -Path $Csv }
    return
}
if ($Report -or $Csv) {
    if ($Report) { Show-Status -Controls $controls }
    if ($Csv)    { Export-StatusCsv -Controls $controls -Path $Csv }
    return
}

if (-not $Script:IsAdmin) {
    Write-Host ''
    Write-Host 'NOTE: Not running as Administrator. Policy values live in HKLM,' -ForegroundColor DarkYellow
    Write-Host '      so nothing can be changed until you relaunch this script' -ForegroundColor DarkYellow
    Write-Host '      in an elevated PowerShell window. Viewing works fine.' -ForegroundColor DarkYellow
}

Start-Menu -Controls $controls

#Requires -Version 5.1
<#
    Manage-DefenderAntivirus.ps1

    Purpose : View the health of Microsoft Defender Antivirus and view/toggle
              its protection settings, plus run common actions (update
              signatures, quick/full scan, view threats and exclusions).

    IMPORTANT: This is a SECURITY tool. Unlike the telemetry/privacy scripts,
              here "Enabled / On" is the DESIRED (protected) state and
              "Off" REDUCES protection. Turning protections off is guarded
              and should only be done deliberately (e.g. troubleshooting).

    How     : Uses the built-in Defender PowerShell module (Get-MpComputerStatus,
              Get-MpPreference, Set-MpPreference, Update-MpSignature, Start-MpScan).
              Registry is intentionally NOT used - Tamper Protection and policy
              layering make direct registry edits to Defender unreliable.

    Notes   : - Windows PowerShell 5.1 compatible. ASCII-only source.
              - Viewing works as a standard user; changing settings and running
                scans require Administrator.
              - TAMPER PROTECTION: when on (default on Windows 11), Windows
                blocks programmatic changes to core protection. Such changes
                will fail here by design - turn Tamper Protection off in the
                Windows Security app first if you really need to change them.

    Usage   :
        .\Manage-DefenderAntivirus.ps1                 # interactive menu
        .\Manage-DefenderAntivirus.ps1 -Report         # print status and exit
        .\Manage-DefenderAntivirus.ps1 -EnableRecommended  # set all to protected
        .\Manage-DefenderAntivirus.ps1 -DisableAll     # turn all protections OFF
        .\Manage-DefenderAntivirus.ps1 -Update         # update signatures and exit
        .\Manage-DefenderAntivirus.ps1 -QuickScan      # run a quick scan and exit
        .\Manage-DefenderAntivirus.ps1 -Csv .\def.csv  # export status and exit

    DISCLAIMER: USE AT YOUR OWN RISK. Provided as-is with no warranty. Disabling
    antivirus protection exposes the system to malware. Review before use.
#>

[CmdletBinding()]
param(
    [switch]$Report,
    [switch]$EnableRecommended,
    [switch]$DisableAll,
    [switch]$Update,
    [switch]$QuickScan,
    [switch]$FullScan,
    [string]$Csv
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Elevation / availability
# ---------------------------------------------------------------------------
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$Script:IsAdmin = Test-IsAdmin

if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
    Write-Host 'Microsoft Defender PowerShell module not found on this system.' -ForegroundColor Red
    Write-Host 'This tool requires the built-in Defender cmdlets (Windows client / Server' -ForegroundColor DarkYellow
    Write-Host 'with the Defender feature installed). Nothing to do.' -ForegroundColor DarkYellow
    return
}

# ---------------------------------------------------------------------------
# Cached preference / status reads
# ---------------------------------------------------------------------------
$Script:Mp     = $null
$Script:Status = $null

function Get-MpPref {
    if ($null -eq $Script:Mp) { $Script:Mp = Get-MpPreference }
    return $Script:Mp
}
function Get-MpStatus {
    if ($null -eq $Script:Status) { $Script:Status = Get-MpComputerStatus }
    return $Script:Status
}
function Reset-MpCache {
    $Script:Mp     = $null
    $Script:Status = $null
}

# ---------------------------------------------------------------------------
# Control model
#   Pref controls map to a single Set-MpPreference parameter.
#   Kind:
#     Bool - the parameter is a Disable* boolean; ProtectOn = $false.
#     Enum - integer-backed; ProtectOn/ProtectOff are ints, Map gives labels.
#   "On" (protected) is always the recommended state.
# ---------------------------------------------------------------------------
function New-PrefControl {
    param(
        [string]$Name,
        [string]$PrefName,
        [ValidateSet('Bool','Enum')][string]$Kind,
        $ProtectOn, $ProtectOff,
        [hashtable]$Map = $null,
        [string]$Note = '',
        [switch]$PrivacyTradeoff   # feature that also sends data to Microsoft
    )
    [pscustomobject]@{
        Type            = 'Pref'
        Name            = $Name
        PrefName        = $PrefName
        Kind            = $Kind
        ProtectOn       = $ProtectOn
        ProtectOff      = $ProtectOff
        Map             = $Map
        Note            = $Note
        PrivacyTradeoff = [bool]$PrivacyTradeoff
        AdminReq        = $true
    }
}

function Get-PrefRaw {
    param($Ctrl)
    $mp = Get-MpPref
    try   { return $mp.$($Ctrl.PrefName) }
    catch { return $null }
}

function Get-ControlState {
    param($Ctrl)
    $cur = Get-PrefRaw -Ctrl $Ctrl
    if ($null -eq $cur) { return 'Unknown' }

    if ($Ctrl.Kind -eq 'Bool') {
        if ([bool]$cur -eq [bool]$Ctrl.ProtectOn)  { return 'On' }
        if ([bool]$cur -eq [bool]$Ctrl.ProtectOff) { return 'Off' }
        return ('? ({0})' -f $cur)
    } else {
        $curInt = $null
        try { $curInt = [int]$cur } catch { return ('? ({0})' -f $cur) }
        $label = $curInt
        if ($Ctrl.Map -and $Ctrl.Map.ContainsKey($curInt)) { $label = $Ctrl.Map[$curInt] }
        if ($curInt -eq [int]$Ctrl.ProtectOn)  { return ('On ({0})' -f $label) }
        if ($curInt -eq [int]$Ctrl.ProtectOff) { return ('Off ({0})' -f $label) }
        return ('Other ({0})' -f $label)   # e.g. Audit mode
    }
}

function Set-ControlValue {
    param($Ctrl, [ValidateSet('Enable','Disable')][string]$Action)
    $val = if ($Action -eq 'Enable') { $Ctrl.ProtectOn } else { $Ctrl.ProtectOff }
    $splat = @{ $Ctrl.PrefName = $val }
    Set-MpPreference @splat -ErrorAction Stop
}

# ---------------------------------------------------------------------------
# Control catalog
# ---------------------------------------------------------------------------
function Get-Controls {
    $c = New-Object System.Collections.ArrayList

    # --- Core real-time engine (Tamper Protection usually guards these) ---
    [void]$c.Add( (New-PrefControl -Name 'Real-time Monitoring' -PrefName 'DisableRealtimeMonitoring' `
        -Kind Bool -ProtectOn $false -ProtectOff $true `
        -Note 'Core on-access scanning. Guarded by Tamper Protection.') )

    [void]$c.Add( (New-PrefControl -Name 'Behavior Monitoring' -PrefName 'DisableBehaviorMonitoring' `
        -Kind Bool -ProtectOn $false -ProtectOff $true `
        -Note 'Detects malicious behaviour patterns at runtime.') )

    [void]$c.Add( (New-PrefControl -Name 'Downloads/Attachment Scan (IOAV)' -PrefName 'DisableIOAVProtection' `
        -Kind Bool -ProtectOn $false -ProtectOff $true `
        -Note 'Scans files downloaded from the internet / email.') )

    [void]$c.Add( (New-PrefControl -Name 'Script Scanning' -PrefName 'DisableScriptScanning' `
        -Kind Bool -ProtectOn $false -ProtectOff $true `
        -Note 'Scans scripts before they run.') )

    # --- Scan surface ---
    [void]$c.Add( (New-PrefControl -Name 'Archive Scanning' -PrefName 'DisableArchiveScanning' `
        -Kind Bool -ProtectOn $false -ProtectOff $true `
        -Note 'Scans inside .zip/.rar/etc during scans.') )

    [void]$c.Add( (New-PrefControl -Name 'Email Scanning' -PrefName 'DisableEmailScanning' `
        -Kind Bool -ProtectOn $false -ProtectOff $true `
        -Note 'Parses mailbox/email files during scans.') )

    [void]$c.Add( (New-PrefControl -Name 'Removable Drive Scanning' -PrefName 'DisableRemovableDriveScanning' `
        -Kind Bool -ProtectOn $false -ProtectOff $true `
        -Note 'Includes USB/removable media in full scans.') )

    # --- Cloud protection ---
    [void]$c.Add( (New-PrefControl -Name 'Cloud-delivered Protection (MAPS)' -PrefName 'MAPSReporting' `
        -Kind Enum -ProtectOn 2 -ProtectOff 0 `
        -Map @{ 0='Disabled'; 1='Basic'; 2='Advanced' } `
        -Note 'Real-time cloud lookups. Recommended: Advanced.') )

    [void]$c.Add( (New-PrefControl -Name 'Automatic Sample Submission' -PrefName 'SubmitSamplesConsent' `
        -Kind Enum -ProtectOn 1 -ProtectOff 2 `
        -Map @{ 0='AlwaysPrompt'; 1='SendSafeSamples'; 2='NeverSend'; 3='SendAllSamples' } `
        -PrivacyTradeoff `
        -Note 'Needed for full cloud protection; sends files to Microsoft. 2=Never for privacy.') )

    [void]$c.Add( (New-PrefControl -Name 'Cloud Block Level' -PrefName 'CloudBlockLevel' `
        -Kind Enum -ProtectOn 2 -ProtectOff 0 `
        -Map @{ 0='Default'; 1='Moderate'; 2='High'; 4='HighPlus'; 6='ZeroTolerance' } `
        -Note 'How aggressively cloud blocks suspicious files. Higher = safer, more false positives.') )

    # --- Advanced protections ---
    [void]$c.Add( (New-PrefControl -Name 'PUA Protection' -PrefName 'PUAProtection' `
        -Kind Enum -ProtectOn 1 -ProtectOff 0 `
        -Map @{ 0='Disabled'; 1='Enabled'; 2='AuditMode' } `
        -Note 'Blocks potentially unwanted apps (adware, bundleware).') )

    [void]$c.Add( (New-PrefControl -Name 'Network Protection' -PrefName 'EnableNetworkProtection' `
        -Kind Enum -ProtectOn 1 -ProtectOff 0 `
        -Map @{ 0='Disabled'; 1='Enabled'; 2='AuditMode' } `
        -Note 'Blocks connections to malicious domains/IPs (SmartScreen for any app).') )

    [void]$c.Add( (New-PrefControl -Name 'Controlled Folder Access' -PrefName 'EnableControlledFolderAccess' `
        -Kind Enum -ProtectOn 1 -ProtectOff 0 `
        -Map @{ 0='Disabled'; 1='Enabled'; 2='AuditMode' } `
        -Note 'Anti-ransomware: blocks untrusted apps writing to protected folders. May need app allow-listing.') )

    return $c
}

# ---------------------------------------------------------------------------
# Display: health summary
# ---------------------------------------------------------------------------
function Format-Bool {
    param([bool]$Value, [bool]$GoodIsTrue = $true)
    if ($Value) { return 'Yes' } else { return 'No' }
}

# Safe property read - property names on MpComputerStatus vary by Windows build,
# and Set-StrictMode makes a missing property throw. Try each candidate name.
function Get-Prop {
    param($Obj, [string[]]$Names, $Default = $null)
    foreach ($n in $Names) {
        if ($Obj.PSObject.Properties.Match($n).Count -gt 0) {
            $v = $Obj.$n
            if ($null -ne $v) { return $v }
        }
    }
    return $Default
}

function Show-Health {
    $s = Get-MpStatus

    Write-Host ''
    Write-Host '==================================================================' -ForegroundColor Cyan
    Write-Host '  Microsoft Defender Antivirus - Health' -ForegroundColor Cyan
    Write-Host ('  Host: {0}   Admin: {1}   {2}' -f $env:COMPUTERNAME, $Script:IsAdmin, (Get-Date)) -ForegroundColor DarkCyan
    Write-Host '==================================================================' -ForegroundColor Cyan

    function Line {
        param([string]$Label, $Value, [string]$Color = 'Gray')
        Write-Host ('  {0,-32}' -f $Label) -NoNewline
        Write-Host $Value -ForegroundColor $Color
    }

    # Running mode (Normal / Passive / EDR Block / etc.)
    $mode = Get-Prop $s @('AMRunningMode') 'Unknown'
    $modeColor = if ($mode -eq 'Normal') { 'Green' } else { 'Yellow' }
    Line 'Running mode' $mode $modeColor
    if ($mode -ne 'Normal' -and $mode -ne 'Unknown') {
        Write-Host '    (Passive/other mode: another AV may be primary; some settings inactive)' -ForegroundColor DarkYellow
    }

    Line 'AntiMalware service' (Format-Bool $s.AMServiceEnabled) ($(if ($s.AMServiceEnabled) {'Green'} else {'Red'}))
    Line 'Real-time protection' (Format-Bool $s.RealTimeProtectionEnabled) ($(if ($s.RealTimeProtectionEnabled) {'Green'} else {'Red'}))
    Line 'Behavior monitor' (Format-Bool $s.BehaviorMonitorEnabled) ($(if ($s.BehaviorMonitorEnabled) {'Green'} else {'Yellow'}))
    Line 'On-access (IOAV) protection' (Format-Bool $s.IoavProtectionEnabled) ($(if ($s.IoavProtectionEnabled) {'Green'} else {'Yellow'}))
    Line 'Network inspection (NIS)' (Format-Bool $s.NISEnabled) ($(if ($s.NISEnabled) {'Green'} else {'Yellow'}))
    Line 'Tamper Protection' (Format-Bool $s.IsTamperProtected) ($(if ($s.IsTamperProtected) {'Green'} else {'Yellow'}))

    # Signature freshness
    $age = [int](Get-Prop $s @('AntivirusSignatureAge') 0)
    $ageColor = if ($age -le 2) { 'Green' } elseif ($age -le 7) { 'Yellow' } else { 'Red' }
    Line 'Signature version' (Get-Prop $s @('AntivirusSignatureVersion') 'n/a') 'Gray'
    Line 'Signature age (days)' $age $ageColor
    Line 'Engine version' (Get-Prop $s @('AMEngineVersion') 'n/a') 'Gray'

    # Last scans (property names differ across builds)
    $lastQuick = Get-Prop $s @('QuickScanEndTime','LastQuickScanEndTime') 'never'
    $lastFull  = Get-Prop $s @('FullScanEndTime','LastFullScanEndTime')   'never'
    Line 'Last quick scan' $lastQuick 'Gray'
    Line 'Last full scan'  $lastFull 'Gray'
}

# ---------------------------------------------------------------------------
# Display: configurable protections
# ---------------------------------------------------------------------------
function Get-StateColor {
    param([string]$State)
    if ($State -like 'On*')    { return 'Green' }
    if ($State -like 'Off*')   { return 'Red' }
    if ($State -like 'Other*') { return 'Yellow' }   # audit mode etc.
    return 'DarkGray'
}

function Show-Controls {
    param($Controls)

    Write-Host ''
    Write-Host '  Configurable protections (On = protected / recommended)' -ForegroundColor White
    Write-Host ('  {0,-3}{1,-36}{2}' -f '#', 'Protection', 'State') -ForegroundColor White
    Write-Host ('  {0,-3}{1,-36}{2}' -f '---', '----------', '-----') -ForegroundColor DarkGray

    $i = 0
    $nOff = 0
    foreach ($ctrl in $Controls) {
        $i++
        $state = Get-ControlState -Ctrl $ctrl
        if ($state -like 'Off*') { $nOff++ }
        $tag  = ''
        if ($ctrl.PrivacyTradeoff) { $tag = ' [PRIV]' }
        $lock = ''
        if ($ctrl.AdminReq -and -not $Script:IsAdmin) { $lock = ' *' }
        Write-Host ('  {0,-3}{1,-36}' -f $i, ($ctrl.Name + $tag)) -NoNewline
        Write-Host ($state + $lock) -ForegroundColor (Get-StateColor $state)
    }
    Write-Host ('  {0,-3}{1,-36}{2}' -f '---', '----------', '-----') -ForegroundColor DarkGray
    if ($nOff -gt 0) {
        Write-Host ('  WARNING: {0} protection(s) are currently OFF (reduced security)' -f $nOff) -ForegroundColor Red
    } else {
        Write-Host '  All listed protections are ON.' -ForegroundColor Green
    }
    Write-Host '  [PRIV] = also sends data to Microsoft (privacy tradeoff)' -ForegroundColor DarkCyan
    if (-not $Script:IsAdmin) {
        Write-Host '  * requires Administrator to change (run elevated)' -ForegroundColor DarkYellow
    }
    if ((Get-MpStatus).IsTamperProtected) {
        Write-Host '  NOTE: Tamper Protection is ON - changes to core items may be blocked.' -ForegroundColor DarkYellow
    }
    Write-Host ''
}

function Show-Status {
    param($Controls)
    Show-Health
    Show-Controls -Controls $Controls
}

function Export-StatusCsv {
    param($Controls, [string]$Path)
    $s = Get-MpStatus
    $rows = New-Object System.Collections.ArrayList

    # Health rows
    [void]$rows.Add([pscustomobject]@{ Group='Health'; Name='RealTimeProtection'; State=$s.RealTimeProtectionEnabled; Note='' })
    [void]$rows.Add([pscustomobject]@{ Group='Health'; Name='TamperProtection';   State=$s.IsTamperProtected;         Note='' })
    [void]$rows.Add([pscustomobject]@{ Group='Health'; Name='SignatureAgeDays';   State=[int](Get-Prop $s @('AntivirusSignatureAge') 0); Note=(Get-Prop $s @('AntivirusSignatureVersion') 'n/a') })
    # Config rows
    foreach ($ctrl in $Controls) {
        [void]$rows.Add([pscustomobject]@{
            Group = 'Protection'
            Name  = $ctrl.Name
            State = (Get-ControlState -Ctrl $ctrl)
            Note  = $ctrl.Note
        })
    }
    $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding ASCII
    Write-Host ("Status written to {0}" -f $Path) -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Apply helpers
# ---------------------------------------------------------------------------
function Invoke-ControlAction {
    param($Ctrl, [ValidateSet('Enable','Disable')][string]$Action)

    if ($Ctrl.AdminReq -and -not $Script:IsAdmin) {
        Write-Host ("  SKIP  {0} (needs Administrator)" -f $Ctrl.Name) -ForegroundColor DarkYellow
        return
    }
    try {
        Set-ControlValue -Ctrl $Ctrl -Action $Action
        Reset-MpCache
        $new = Get-ControlState -Ctrl $Ctrl
        Write-Host ("  OK    {0} -> {1}" -f $Ctrl.Name, $new) -ForegroundColor Green
    } catch {
        Write-Host ("  FAIL  {0}: {1}" -f $Ctrl.Name, $_.Exception.Message) -ForegroundColor Red
        Write-Host '        (If Tamper Protection is on, this change is blocked by design.)' -ForegroundColor DarkYellow
    }
}

function Invoke-EnableRecommended {
    param($Controls)
    Write-Host ''
    Write-Host 'Setting all protections to recommended (ON)...' -ForegroundColor Cyan
    foreach ($ctrl in $Controls) {
        $state = Get-ControlState -Ctrl $ctrl
        if ($state -like 'On*') {
            Write-Host ("  --    {0} already On" -f $ctrl.Name) -ForegroundColor DarkGray
            continue
        }
        Invoke-ControlAction -Ctrl $ctrl -Action Enable
    }
    Write-Host ''
}

function Invoke-DisableAll {
    param($Controls)
    Write-Host ''
    Write-Host 'Disabling ALL Defender protections (REDUCES SECURITY)...' -ForegroundColor Red
    foreach ($ctrl in $Controls) {
        $state = Get-ControlState -Ctrl $ctrl
        if ($state -like 'Off*') {
            Write-Host ("  --    {0} already Off" -f $ctrl.Name) -ForegroundColor DarkGray
            continue
        }
        Invoke-ControlAction -Ctrl $ctrl -Action Disable
    }
    Write-Host ''
    if ((Get-MpStatus).IsTamperProtected) {
        Write-Host 'Note: core items stay ON while Tamper Protection is enabled - turn it' -ForegroundColor DarkYellow
        Write-Host '      off in the Windows Security app first if you need them off too.' -ForegroundColor DarkYellow
    }
    Write-Host 'This also stops Defender cloud lookups and sample submission to Microsoft.' -ForegroundColor DarkCyan
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Actions: update / scan / threats / exclusions
# ---------------------------------------------------------------------------
function Invoke-Update {
    if (-not $Script:IsAdmin) { Write-Host 'Signature update requires Administrator.' -ForegroundColor DarkYellow; return }
    Write-Host 'Updating Defender signatures...' -ForegroundColor Cyan
    try {
        Update-MpSignature -ErrorAction Stop
        Reset-MpCache
        $s = Get-MpStatus
        Write-Host ('Done. Signature version {0} (age {1} day(s)).' -f $s.AntivirusSignatureVersion, [int]$s.AntivirusSignatureAge) -ForegroundColor Green
    } catch {
        Write-Host ('Update failed: {0}' -f $_.Exception.Message) -ForegroundColor Red
    }
}

function Invoke-Scan {
    param([ValidateSet('Quick','Full')][string]$Kind)
    if (-not $Script:IsAdmin) { Write-Host 'Scanning requires Administrator.' -ForegroundColor DarkYellow; return }
    Write-Host ("Starting {0} scan (this may take a while)..." -f $Kind) -ForegroundColor Cyan
    try {
        Start-MpScan -ScanType ($Kind + 'Scan') -ErrorAction Stop
        Reset-MpCache
        Write-Host 'Scan complete.' -ForegroundColor Green
    } catch {
        Write-Host ('Scan failed: {0}' -f $_.Exception.Message) -ForegroundColor Red
    }
}

function Show-Threats {
    Write-Host ''
    Write-Host 'Recent threat detections:' -ForegroundColor White
    try {
        $threats = @(Get-MpThreatDetection -ErrorAction Stop | Sort-Object InitialDetectionTime -Descending | Select-Object -First 15)
        if ($threats.Count -eq 0) {
            Write-Host '  None recorded.' -ForegroundColor Green
        } else {
            foreach ($t in $threats) {
                $name = try { (Get-MpThreat -ThreatID $t.ThreatID -ErrorAction SilentlyContinue).ThreatName } catch { $t.ThreatID }
                if (-not $name) { $name = $t.ThreatID }
                Write-Host ('  {0}  {1}  (action: {2})' -f $t.InitialDetectionTime, $name, $t.ThreatStatusID) -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host ('  Could not read threat history: {0}' -f $_.Exception.Message) -ForegroundColor Red
    }
    Write-Host ''
}

function Show-Exclusions {
    $mp = Get-MpPref
    Write-Host ''
    Write-Host 'Configured exclusions (attack surface - review carefully):' -ForegroundColor White
    function Dump {
        param([string]$Label, $Items)
        $arr = @($Items)
        if ($arr.Count -eq 0) { Write-Host ('  {0}: none' -f $Label) -ForegroundColor DarkGray; return }
        Write-Host ('  {0}:' -f $Label) -ForegroundColor Yellow
        foreach ($x in $arr) { Write-Host ('    {0}' -f $x) -ForegroundColor Gray }
    }
    Dump 'Paths'      $mp.ExclusionPath
    Dump 'Extensions' $mp.ExclusionExtension
    Dump 'Processes'  $mp.ExclusionProcess
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------
function Start-Menu {
    param($Controls)
    while ($true) {
        Reset-MpCache
        Show-Status -Controls $Controls
        Write-Host 'Commands:' -ForegroundColor White
        Write-Host '  <n>          toggle protection n (On<->Off)'
        Write-Host '  e <n>        enable (protect) item n'
        Write-Host '  d <n>        disable item n (REDUCES security)'
        Write-Host '  E            enable ALL recommended protections'
        Write-Host '  D            disable ALL protections (reduces security)'
        Write-Host '  u            update signatures'
        Write-Host '  s            run quick scan'
        Write-Host '  f            run full scan'
        Write-Host '  t            show recent threat detections'
        Write-Host '  x            show exclusions'
        Write-Host '  r            refresh view'
        Write-Host '  c <path>     export status to CSV'
        Write-Host '  q            quit'
        Write-Host ''
        $inp = Read-Host 'Select'
        if ([string]::IsNullOrWhiteSpace($inp)) { continue }
        $inp = $inp.Trim()

        switch -Regex -CaseSensitive ($inp) {
            '^[Qq]$'      { return }
            '^[Rr]$'      { continue }
            '^E$'         {
                Invoke-EnableRecommended -Controls $Controls
                Read-Host 'Press Enter'; continue
            }
            '^D$'         {
                Write-Host ''
                Write-Host 'WARNING: This disables ALL Defender protections listed above.' -ForegroundColor Red
                Write-Host 'The system will be left without Defender antivirus coverage.' -ForegroundColor Red
                if ((Read-Host 'Proceed? type DISABLE-ALL') -ceq 'DISABLE-ALL') {
                    Invoke-DisableAll -Controls $Controls
                }
                Read-Host 'Press Enter'; continue
            }
            '^[Uu]$'      { Invoke-Update;            Read-Host 'Press Enter'; continue }
            '^[Ss]$'      { Invoke-Scan -Kind Quick;  Read-Host 'Press Enter'; continue }
            '^[Ff]$'      { Invoke-Scan -Kind Full;   Read-Host 'Press Enter'; continue }
            '^[Tt]$'      { Show-Threats;             Read-Host 'Press Enter'; continue }
            '^[Xx]$'      { Show-Exclusions;          Read-Host 'Press Enter'; continue }
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
                if ($n -ge 1 -and $n -le $Controls.Count) {
                    $ctrl = $Controls[$n-1]
                    Write-Host ''
                    Write-Host ('WARNING: Disabling "{0}" reduces protection.' -f $ctrl.Name) -ForegroundColor Red
                    if ((Read-Host 'Proceed? type YES') -ceq 'YES') {
                        Invoke-ControlAction -Ctrl $ctrl -Action Disable
                    }
                } else { Write-Host 'Out of range' -ForegroundColor Red }
                Read-Host 'Press Enter'; continue
            }
            '^\d+$' {
                $n = [int]$inp
                if ($n -ge 1 -and $n -le $Controls.Count) {
                    $ctrl  = $Controls[$n-1]
                    $state = Get-ControlState -Ctrl $ctrl
                    if ($state -like 'On*') {
                        Write-Host ''
                        Write-Host ('WARNING: Disabling "{0}" reduces protection.' -f $ctrl.Name) -ForegroundColor Red
                        if ((Read-Host 'Proceed? type YES') -ceq 'YES') {
                            Invoke-ControlAction -Ctrl $ctrl -Action Disable
                        }
                    } else {
                        Invoke-ControlAction -Ctrl $ctrl -Action Enable
                    }
                } else { Write-Host 'Out of range' -ForegroundColor Red }
                Read-Host 'Press Enter'; continue
            }
            default { Write-Host 'Unknown command' -ForegroundColor Red; Start-Sleep -Milliseconds 600 }
        }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$controls = Get-Controls

if ($Update)            { Invoke-Update; return }
if ($QuickScan)         { Invoke-Scan -Kind Quick; return }
if ($FullScan)          { Invoke-Scan -Kind Full; return }
if ($EnableRecommended) { Invoke-EnableRecommended -Controls $controls; Show-Status -Controls $controls; if ($Csv) { Export-StatusCsv -Controls $controls -Path $Csv }; return }
if ($DisableAll)        { Invoke-DisableAll -Controls $controls; Show-Status -Controls $controls; if ($Csv) { Export-StatusCsv -Controls $controls -Path $Csv }; return }
if ($Report -or $Csv) {
    if ($Report) { Show-Status -Controls $controls }
    if ($Csv)    { Export-StatusCsv -Controls $controls -Path $Csv }
    return
}

if (-not $Script:IsAdmin) {
    Write-Host ''
    Write-Host 'NOTE: Not running as Administrator. You can VIEW status, but changing' -ForegroundColor DarkYellow
    Write-Host '      protections, updating signatures and scanning need an elevated' -ForegroundColor DarkYellow
    Write-Host '      PowerShell window.' -ForegroundColor DarkYellow
}

Start-Menu -Controls $controls

#Requires -Version 5.1
<#
    Manage-WindowsTelemetry.ps1

    Purpose : View and control common Windows 11 telemetry / diagnostic-data
              settings, services and scheduled tasks.

    Scope   : Shows what is currently ENABLED (data collecting) vs DISABLED,
              and lets the user turn individual items - or everything - on/off.

    Areas   : Core diagnostic data (AllowTelemetry), diagnostic log limits,
              Windows Error Reporting (full stack: flags, consent, service,
              task - the modern successor to Dr. Watson), CEIP/SQM, AppCompat
              appraiser, Cloud Content / Tailored Experiences, Activity
              History, Advertising ID, Feedback (SIUF), inking/typing and
              speech data, search suggestions, DiagTrack + related services,
              and telemetry scheduled tasks.

    Notes   : - Windows PowerShell 5.1 compatible. ASCII-only source.
              - Registry (HKLM) and service changes require Administrator.
              - "Enabled"  = the telemetry / data-collection behaviour is ON.
                "Disabled" = the telemetry / data-collection behaviour is OFF.
              - For policy-type values, "Enable" REMOVES the policy value to
                restore the true Windows default (absent), so the Settings UI
                is not left in a "managed by your organization" state.

    Usage   :
        .\Manage-WindowsTelemetry.ps1                 # interactive menu
        .\Manage-WindowsTelemetry.ps1 -Report         # print status and exit
        .\Manage-WindowsTelemetry.ps1 -DisableAll     # turn telemetry OFF
        .\Manage-WindowsTelemetry.ps1 -EnableAll      # restore Windows default ON
        .\Manage-WindowsTelemetry.ps1 -Csv .\out.csv  # export status and exit
        .\Manage-WindowsTelemetry.ps1 -Report -Csv .\status.csv

    DISCLAIMER: Review before use. Changing telemetry / service settings alters
    system behaviour. Run in a test environment first. No warranty.
#>

[CmdletBinding()]
param(
    [switch]$Report,
    [switch]$DisableAll,
    [switch]$EnableAll,
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
# Registry helpers
# ---------------------------------------------------------------------------
function Resolve-RegPath {
    param([string]$Hive, [string]$Path)
    return ('{0}:\{1}' -f $Hive, $Path)
}

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
# Control model
#   Each control is a PSCustomObject with a Type that drives Get/Enable/Disable.
#   Types: Reg, Service, Task
#
#   RemoveOnEnable: for policy-style values whose Windows default is ABSENT.
#   Enabling such a control deletes the value instead of writing OnValue, so
#   the machine is not left policy-managed after an "enable".
# ---------------------------------------------------------------------------
function New-RegControl {
    param(
        [string]$Name, [string]$Category, [string]$Hive, [string]$Path,
        [string]$ValueName, [int]$OnValue, [int]$OffValue,
        [ValidateSet('On','Off')][string]$Default = 'On',
        [string]$RegType = 'DWord', [string]$Note = '',
        [switch]$RemoveOnEnable
    )
    [pscustomobject]@{
        Type           = 'Reg'
        Name           = $Name
        Category       = $Category
        Note           = $Note
        FullPath       = (Resolve-RegPath -Hive $Hive -Path $Path)
        ValueName      = $ValueName
        OnValue        = $OnValue
        OffValue       = $OffValue
        Default        = $Default
        RegType        = $RegType
        RemoveOnEnable = [bool]$RemoveOnEnable
        AdminReq       = ($Hive -eq 'HKLM')
    }
}

function New-ServiceControl {
    param(
        [string]$Name, [string]$ServiceName,
        [ValidateSet('Automatic','Manual')][string]$DefaultStartupType = 'Automatic',
        [string]$Note = ''
    )
    [pscustomobject]@{
        Type               = 'Service'
        Name               = $Name
        Category           = 'Service'
        Note               = $Note
        ServiceName        = $ServiceName
        DefaultStartupType = $DefaultStartupType
        AdminReq           = $true
    }
}

function New-TaskControl {
    param([string]$Name, [string[]]$Tasks, [string]$Note = '')
    # $Tasks entries are full task paths, e.g. \Microsoft\Windows\Application Experience\ProgramDataUpdater
    [pscustomobject]@{
        Type     = 'Task'
        Name     = $Name
        Category = 'Scheduled Task'
        Note     = $Note
        Tasks    = $Tasks
        AdminReq = $true
    }
}

# ---------------------------------------------------------------------------
# State + actions
# ---------------------------------------------------------------------------
function Get-ControlState {
    param($Ctrl)
    switch ($Ctrl.Type) {
        'Reg' {
            $cur = Get-RegValue -FullPath $Ctrl.FullPath -Name $Ctrl.ValueName
            if ($null -eq $cur) {
                if ($Ctrl.Default -eq 'On') { return 'Enabled (default)' }
                else                        { return 'Disabled (default)' }
            }
            $curInt = $null
            try { $curInt = [int]$cur } catch {
                return ('Enabled (value={0})' -f $cur)   # non-numeric data: report, do not throw
            }
            if ($curInt -eq $Ctrl.OffValue) { return 'Disabled' }
            if ($curInt -eq $Ctrl.OnValue)  { return 'Enabled' }
            return ('Enabled (value={0})' -f $curInt)
        }
        'Service' {
            $svc = Get-Service -Name $Ctrl.ServiceName -ErrorAction SilentlyContinue
            if ($null -eq $svc) { return 'Not present' }
            if ($svc.StartType -eq 'Disabled') { return 'Disabled' }
            return ('Enabled ({0}, {1})' -f $svc.StartType, $svc.Status)
        }
        'Task' {
            $states = @()
            foreach ($t in $Ctrl.Tasks) {
                $leaf = Split-Path $t -Leaf
                $path = (Split-Path $t -Parent) + '\'
                $task = Get-ScheduledTask -TaskName $leaf -TaskPath $path -ErrorAction SilentlyContinue
                if ($task) { $states += $task.State }
            }
            if ($states.Count -eq 0) { return 'Not present' }
            if ($states -contains 'Ready' -or $states -contains 'Running') { return 'Enabled' }
            return 'Disabled'
        }
    }
    return 'Unknown'
}

function Set-ControlEnabled {
    param($Ctrl)   # Enable telemetry (restore Windows default behaviour)
    switch ($Ctrl.Type) {
        'Reg' {
            if ($Ctrl.RemoveOnEnable) {
                Remove-RegValue -FullPath $Ctrl.FullPath -Name $Ctrl.ValueName
            } else {
                Set-RegValue -FullPath $Ctrl.FullPath -Name $Ctrl.ValueName -Value $Ctrl.OnValue -Type $Ctrl.RegType
            }
        }
        'Service' {
            Set-Service -Name $Ctrl.ServiceName -StartupType $Ctrl.DefaultStartupType -ErrorAction Stop
            if ($Ctrl.DefaultStartupType -eq 'Automatic') {
                Start-Service -Name $Ctrl.ServiceName -ErrorAction SilentlyContinue
            }
        }
        'Task' {
            foreach ($t in $Ctrl.Tasks) {
                $leaf = Split-Path $t -Leaf
                $path = (Split-Path $t -Parent) + '\'
                Enable-ScheduledTask -TaskName $leaf -TaskPath $path -ErrorAction SilentlyContinue | Out-Null
            }
        }
    }
}

function Set-ControlDisabled {
    param($Ctrl)   # Disable telemetry (privacy hardened)
    switch ($Ctrl.Type) {
        'Reg' {
            Set-RegValue -FullPath $Ctrl.FullPath -Name $Ctrl.ValueName -Value $Ctrl.OffValue -Type $Ctrl.RegType
        }
        'Service' {
            Stop-Service -Name $Ctrl.ServiceName -Force -ErrorAction SilentlyContinue
            Set-Service -Name $Ctrl.ServiceName -StartupType Disabled -ErrorAction Stop
        }
        'Task' {
            foreach ($t in $Ctrl.Tasks) {
                $leaf = Split-Path $t -Leaf
                $path = (Split-Path $t -Parent) + '\'
                Disable-ScheduledTask -TaskName $leaf -TaskPath $path -ErrorAction SilentlyContinue | Out-Null
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Control catalog
# ---------------------------------------------------------------------------
function Get-Controls {
    $c = New-Object System.Collections.ArrayList

    # --- Core telemetry policy ---
    [void]$c.Add( (New-RegControl -Name 'Diagnostic data (AllowTelemetry)' -Category 'Telemetry' `
        -Hive HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
        -ValueName 'AllowTelemetry' -OnValue 3 -OffValue 0 -Default On -RemoveOnEnable `
        -Note '0=Off/Security 1=Required 3=Optional. Home/Pro treat 0 as 1.') )

    [void]$c.Add( (New-RegControl -Name 'Diagnostic data (non-policy)' -Category 'Telemetry' `
        -Hive HKLM -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' `
        -ValueName 'AllowTelemetry' -OnValue 3 -OffValue 0 -Default On -RemoveOnEnable) )

    [void]$c.Add( (New-RegControl -Name 'Feedback Notifications' -Category 'Telemetry' `
        -Hive HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
        -ValueName 'DoNotShowFeedbackNotifications' -OnValue 0 -OffValue 1 -Default On -RemoveOnEnable `
        -Note 'Disabled hides feedback prompts') )

    [void]$c.Add( (New-RegControl -Name 'Diagnostic Log Collection' -Category 'Telemetry' `
        -Hive HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
        -ValueName 'LimitDiagnosticLogCollection' -OnValue 0 -OffValue 1 -Default On -RemoveOnEnable `
        -Note 'Disabled blocks extra diagnostic log upload') )

    [void]$c.Add( (New-RegControl -Name 'OneSettings Downloads' -Category 'Telemetry' `
        -Hive HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
        -ValueName 'DisableOneSettingsDownloads' -OnValue 0 -OffValue 1 -Default On -RemoveOnEnable `
        -Note 'Remote telemetry configuration channel') )

    # --- Application compatibility / appraiser telemetry ---
    [void]$c.Add( (New-RegControl -Name 'App Impact Telemetry (AITEnable)' -Category 'AppCompat' `
        -Hive HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\AppCompat' `
        -ValueName 'AITEnable' -OnValue 1 -OffValue 0 -Default On -RemoveOnEnable) )

    [void]$c.Add( (New-RegControl -Name 'Inventory Collector' -Category 'AppCompat' `
        -Hive HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\AppCompat' `
        -ValueName 'DisableInventory' -OnValue 0 -OffValue 1 -Default On -RemoveOnEnable) )

    # --- Windows Error Reporting (successor to Dr. Watson) ---
    [void]$c.Add( (New-RegControl -Name 'Windows Error Reporting' -Category 'Error Reporting' `
        -Hive HKLM -Path 'SOFTWARE\Microsoft\Windows\Windows Error Reporting' `
        -ValueName 'Disabled' -OnValue 0 -OffValue 1 -Default On -RemoveOnEnable) )

    [void]$c.Add( (New-RegControl -Name 'Error Reporting (policy)' -Category 'Error Reporting' `
        -Hive HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' `
        -ValueName 'Disabled' -OnValue 0 -OffValue 1 -Default On -RemoveOnEnable `
        -Note 'Group Policy variant; overrides the non-policy flag') )

    [void]$c.Add( (New-RegControl -Name 'WER Additional Data' -Category 'Error Reporting' `
        -Hive HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' `
        -ValueName 'DontSendAdditionalData' -OnValue 0 -OffValue 1 -Default On -RemoveOnEnable `
        -Note 'Disabled stops second-stage crash data upload') )

    [void]$c.Add( (New-RegControl -Name 'WER Consent Level' -Category 'Error Reporting' `
        -Hive HKLM -Path 'SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent' `
        -ValueName 'DefaultConsent' -OnValue 4 -OffValue 1 -Default On -RemoveOnEnable `
        -Note '1=always ask 2=params 3=params+safe 4=send all') )

    # --- Customer Experience Improvement Program ---
    [void]$c.Add( (New-RegControl -Name 'CEIP (SQM Client)' -Category 'CEIP' `
        -Hive HKLM -Path 'SOFTWARE\Microsoft\SQMClient\Windows' `
        -ValueName 'CEIPEnable' -OnValue 1 -OffValue 0 -Default On) )

    # --- Cloud content / consumer features / ads ---
    [void]$c.Add( (New-RegControl -Name 'Windows Consumer Features' -Category 'Cloud Content' `
        -Hive HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\CloudContent' `
        -ValueName 'DisableWindowsConsumerFeatures' -OnValue 0 -OffValue 1 -Default On -RemoveOnEnable) )

    [void]$c.Add( (New-RegControl -Name 'Tailored Experiences (policy)' -Category 'Cloud Content' `
        -Hive HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\CloudContent' `
        -ValueName 'DisableTailoredExperiencesWithDiagnosticData' -OnValue 0 -OffValue 1 -Default On -RemoveOnEnable) )

    # --- Activity history / timeline ---
    [void]$c.Add( (New-RegControl -Name 'Publish User Activities' -Category 'Activity History' `
        -Hive HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\System' `
        -ValueName 'PublishUserActivities' -OnValue 1 -OffValue 0 -Default On -RemoveOnEnable) )

    [void]$c.Add( (New-RegControl -Name 'Upload User Activities' -Category 'Activity History' `
        -Hive HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\System' `
        -ValueName 'UploadUserActivities' -OnValue 1 -OffValue 0 -Default On -RemoveOnEnable) )

    # --- Per-user privacy (HKCU, no admin needed) ---
    [void]$c.Add( (New-RegControl -Name 'Advertising ID' -Category 'Privacy (User)' `
        -Hive HKCU -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' `
        -ValueName 'Enabled' -OnValue 1 -OffValue 0 -Default On) )

    [void]$c.Add( (New-RegControl -Name 'Tailored Experiences (user)' -Category 'Privacy (User)' `
        -Hive HKCU -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy' `
        -ValueName 'TailoredExperiencesWithDiagnosticDataEnabled' -OnValue 1 -OffValue 0 -Default On) )

    [void]$c.Add( (New-RegControl -Name 'Feedback Frequency (SIUF)' -Category 'Privacy (User)' `
        -Hive HKCU -Path 'SOFTWARE\Microsoft\Siuf\Rules' `
        -ValueName 'NumberOfSIUFInPeriod' -OnValue 1 -OffValue 0 -Default On -RemoveOnEnable `
        -Note 'Disabled = never asked for feedback') )

    [void]$c.Add( (New-RegControl -Name 'Implicit Ink Collection' -Category 'Privacy (User)' `
        -Hive HKCU -Path 'SOFTWARE\Microsoft\InputPersonalization' `
        -ValueName 'RestrictImplicitInkCollection' -OnValue 0 -OffValue 1 -Default On `
        -Note 'Inking personalization data') )

    [void]$c.Add( (New-RegControl -Name 'Implicit Text Collection' -Category 'Privacy (User)' `
        -Hive HKCU -Path 'SOFTWARE\Microsoft\InputPersonalization' `
        -ValueName 'RestrictImplicitTextCollection' -OnValue 0 -OffValue 1 -Default On `
        -Note 'Typing personalization data') )

    [void]$c.Add( (New-RegControl -Name 'Typing Insights (TIPC)' -Category 'Privacy (User)' `
        -Hive HKCU -Path 'SOFTWARE\Microsoft\Input\TIPC' `
        -ValueName 'Enabled' -OnValue 1 -OffValue 0 -Default On `
        -Note 'Typing/ink telemetry channel') )

    [void]$c.Add( (New-RegControl -Name 'Online Speech Recognition' -Category 'Privacy (User)' `
        -Hive HKCU -Path 'SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy' `
        -ValueName 'HasAccepted' -OnValue 1 -OffValue 0 -Default Off `
        -Note 'Cloud speech; default off until user consents') )

    [void]$c.Add( (New-RegControl -Name 'Linguistic Data Collection' -Category 'Privacy (User)' `
        -Hive HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\TextInput' `
        -ValueName 'AllowLinguisticDataCollection' -OnValue 1 -OffValue 0 -Default On -RemoveOnEnable) )

    [void]$c.Add( (New-RegControl -Name 'Search Box Web Suggestions' -Category 'Privacy (User)' `
        -Hive HKCU -Path 'SOFTWARE\Policies\Microsoft\Windows\Explorer' `
        -ValueName 'DisableSearchBoxSuggestions' -OnValue 0 -OffValue 1 -Default On -RemoveOnEnable `
        -Note 'Win11 control for web results in Search') )

    [void]$c.Add( (New-RegControl -Name 'Bing Search (legacy)' -Category 'Privacy (User)' `
        -Hive HKCU -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Search' `
        -ValueName 'BingSearchEnabled' -OnValue 1 -OffValue 0 -Default On -RemoveOnEnable `
        -Note 'Win10-era value; largely ignored on Win11') )

    # --- Services ---
    [void]$c.Add( (New-ServiceControl -Name 'Connected User Experiences' `
        -ServiceName 'DiagTrack' -DefaultStartupType Automatic `
        -Note 'DiagTrack - primary telemetry service') )

    [void]$c.Add( (New-ServiceControl -Name 'WAP Push Routing (dmwappush)' `
        -ServiceName 'dmwappushservice' -DefaultStartupType Manual `
        -Note 'Disabling can break provisioning package / MDM enrolment') )

    [void]$c.Add( (New-ServiceControl -Name 'Error Reporting Svc (WerSvc)' `
        -ServiceName 'WerSvc' -DefaultStartupType Manual `
        -Note 'Runs WER report submission') )

    # --- Scheduled tasks ---
    [void]$c.Add( (New-TaskControl -Name 'Compatibility Appraiser tasks' -Tasks @(
        '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
        '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
        '\Microsoft\Windows\Application Experience\StartupAppTask'
    )) )

    [void]$c.Add( (New-TaskControl -Name 'CEIP tasks' -Tasks @(
        '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
        '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
        '\Microsoft\Windows\Autochk\Proxy'
    ) -Note 'Includes Autochk\Proxy (kernel CEIP)') )

    [void]$c.Add( (New-TaskControl -Name 'Feedback (SIUF) tasks' -Tasks @(
        '\Microsoft\Windows\Feedback\Siuf\DmClient',
        '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload'
    )) )

    [void]$c.Add( (New-TaskControl -Name 'Error Reporting task' -Tasks @(
        '\Microsoft\Windows\Windows Error Reporting\QueueReporting'
    )) )

    [void]$c.Add( (New-TaskControl -Name 'Disk Diagnostic collector' -Tasks @(
        '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector'
    )) )

    return $c
}

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------
function Get-StateColor {
    param([string]$State)
    if ($State -like 'Disabled*')   { return 'Green' }
    if ($State -like 'Enabled*')    { return 'Yellow' }
    if ($State -like 'Not present*'){ return 'DarkGray' }
    return 'Gray'
}

function Show-Status {
    param($Controls)

    Write-Host ''
    Write-Host '==================================================================' -ForegroundColor Cyan
    Write-Host '  Windows 11 Telemetry / Diagnostic Data Status' -ForegroundColor Cyan
    Write-Host ('  Host: {0}   Admin: {1}   {2}' -f $env:COMPUTERNAME, $Script:IsAdmin, (Get-Date)) -ForegroundColor DarkCyan
    Write-Host '  Enabled = collecting/on    Disabled = hardened/off' -ForegroundColor DarkCyan
    Write-Host '==================================================================' -ForegroundColor Cyan
    Write-Host ('{0,-4}{1,-34}{2,-18}{3}' -f '#', 'Setting', 'Category', 'State') -ForegroundColor White
    Write-Host ('{0,-4}{1,-34}{2,-18}{3}' -f '---', '-------', '--------', '-----') -ForegroundColor DarkGray

    $i = 0
    $nEnabled = 0; $nDisabled = 0; $nAbsent = 0
    foreach ($ctrl in $Controls) {
        $i++
        $state = Get-ControlState -Ctrl $ctrl
        if     ($state -like 'Enabled*')     { $nEnabled++ }
        elseif ($state -like 'Disabled*')    { $nDisabled++ }
        elseif ($state -like 'Not present*') { $nAbsent++ }
        $lock  = ''
        if ($ctrl.AdminReq -and -not $Script:IsAdmin) { $lock = ' *' }
        $line = ('{0,-4}{1,-34}{2,-18}' -f $i, $ctrl.Name, $ctrl.Category)
        Write-Host $line -NoNewline
        Write-Host ($state + $lock) -ForegroundColor (Get-StateColor $state)
    }
    Write-Host ('{0,-4}{1,-34}{2,-18}{3}' -f '---', '-------', '--------', '-----') -ForegroundColor DarkGray
    Write-Host ('  Summary: {0} enabled, {1} disabled, {2} not present' -f $nEnabled, $nDisabled, $nAbsent) -ForegroundColor White
    if (-not $Script:IsAdmin) {
        Write-Host '  * requires Administrator to change (run elevated)' -ForegroundColor DarkYellow
    }
    Write-Host ''
}

function Export-StatusCsv {
    param($Controls, [string]$Path)
    $rows = foreach ($ctrl in $Controls) {
        [pscustomobject]@{
            Name     = $ctrl.Name
            Category = $ctrl.Category
            Type     = $ctrl.Type
            State    = (Get-ControlState -Ctrl $ctrl)
            AdminReq = $ctrl.AdminReq
            Note     = $ctrl.Note
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
        Write-Host ("  SKIP  {0} (needs Administrator)" -f $Ctrl.Name) -ForegroundColor DarkYellow
        return
    }
    if ((Get-ControlState -Ctrl $Ctrl) -eq 'Not present') {
        Write-Host ("  SKIP  {0} (not present on this system)" -f $Ctrl.Name) -ForegroundColor DarkGray
        return
    }
    try {
        if ($Action -eq 'Enable') { Set-ControlEnabled -Ctrl $Ctrl }
        else                      { Set-ControlDisabled -Ctrl $Ctrl }
        $new = Get-ControlState -Ctrl $Ctrl
        Write-Host ("  OK    {0} -> {1}" -f $Ctrl.Name, $new) -ForegroundColor Green
    } catch {
        Write-Host ("  FAIL  {0}: {1}" -f $Ctrl.Name, $_.Exception.Message) -ForegroundColor Red
    }
}

function Invoke-AllAction {
    param($Controls, [ValidateSet('Enable','Disable')][string]$Action)
    $verb = if ($Action -eq 'Enable') { 'ENABLE (restore Windows default)' } else { 'DISABLE (harden)' }
    Write-Host ''
    Write-Host ("Applying {0} to ALL items..." -f $verb) -ForegroundColor Cyan
    foreach ($ctrl in $Controls) { Invoke-ControlAction -Ctrl $ctrl -Action $Action }
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
        Write-Host '  D            disable ALL (harden)'
        Write-Host '  E            enable ALL (restore Windows default)'
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
                if ((Read-Host 'Disable ALL telemetry? type YES') -ceq 'YES') {
                    Invoke-AllAction -Controls $Controls -Action Disable
                }
                Read-Host 'Press Enter'; continue
            }
            '^E$'         {
                if ((Read-Host 'Enable ALL (Windows default)? type YES') -ceq 'YES') {
                    Invoke-AllAction -Controls $Controls -Action Enable
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

if ($DisableAll) {
    Invoke-AllAction -Controls $controls -Action Disable
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
    Write-Host 'NOTE: Not running as Administrator. HKLM / service / task items' -ForegroundColor DarkYellow
    Write-Host '      will show as read-only (*) and cannot be changed until you' -ForegroundColor DarkYellow
    Write-Host '      relaunch this script in an elevated PowerShell window.' -ForegroundColor DarkYellow
}

Start-Menu -Controls $controls

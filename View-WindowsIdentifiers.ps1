#Requires -Version 5.1
<#
    View-WindowsIdentifiers.ps1

    Purpose : READ-ONLY privacy audit. Enumerates the unique identifiers that
              Windows and the hardware expose about this machine and user -
              the values that can be used to fingerprint or correlate the
              device. Nothing is changed; this only reports.

    Shows   : Machine identifiers (MachineGuid, Product ID / "PUID",
              install ID, SQM/telemetry client IDs), Windows activation /
              licensing (edition, status, partial + full product key,
              OEM firmware key), advertising / user identifiers (Advertising
              ID, user SID, MSA), and hardware identifiers (SMBIOS UUID, BIOS
              / baseboard / disk serials, MAC addresses, TPM, CPU).

    Privacy : Output contains SENSITIVE data. By default, sensitive values are
              MASKED so the report is safe to share/screenshot. Use -Reveal to
              print full values (e.g. to back up your own product key).

    Notes   : - Windows PowerShell 5.1 compatible. ASCII-only source.
              - Read-only: makes NO changes to the system.
              - Some values (OEM product key, certain WMI/TPM data) require
                Administrator; without it they show "(needs admin)".

    Usage   :
        .\View-WindowsIdentifiers.ps1                 # masked report
        .\View-WindowsIdentifiers.ps1 -Reveal         # full values (sensitive!)
        .\View-WindowsIdentifiers.ps1 -Csv .\ids.csv  # export (respects masking)
        .\View-WindowsIdentifiers.ps1 -Reveal -Csv .\ids.csv
        .\View-WindowsIdentifiers.ps1 -Json .\ids.json

    DISCLAIMER: USE AT YOUR OWN RISK. Provided as-is, no warranty. This tool
    only reports identifiers already present on YOUR machine. Handle the
    output (especially with -Reveal) as confidential.
#>

[CmdletBinding()]
param(
    [switch]$Reveal,
    [string]$Csv,
    [string]$Json
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Elevation
# ---------------------------------------------------------------------------
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
$Script:IsAdmin = Test-IsAdmin

# ---------------------------------------------------------------------------
# Safe getters
# ---------------------------------------------------------------------------
function Get-RegVal {
    param([string]$Path, [string]$Name)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $p = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $p.$Name
    } catch { return $null }
}

function Get-Cim {
    param([string]$Class, [string]$Namespace = 'root\cimv2', [string]$Filter = $null)
    try {
        if ($Filter) { return Get-CimInstance -ClassName $Class -Namespace $Namespace -Filter $Filter -ErrorAction Stop }
        return Get-CimInstance -ClassName $Class -Namespace $Namespace -ErrorAction Stop
    } catch { return $null }
}

# ---------------------------------------------------------------------------
# Product key decoder (classic DigitalProductId base-24 decode)
#   Decodes the product key stored in the registry. Legitimate: reads YOUR
#   machine's own installed key so you can record it before a reinstall.
# ---------------------------------------------------------------------------
function ConvertFrom-DigitalProductId {
    param([byte[]]$Id)
    if ($null -eq $Id -or $Id.Count -lt 67) { return $null }
    try {
        $chars   = 'BCDFGHJKMPQRTVWXY2346789'
        $offset  = 52
        $isWin8  = [int](([math]::Floor($Id[66] / 6)) -band 1)
        $Id[66]  = [byte](($Id[66] -band 0xF7) -bor (($isWin8 -band 2) * 4))
        $key = ''
        for ($i = 24; $i -ge 0; $i--) {
            $cur = 0
            for ($j = 14; $j -ge 0; $j--) {
                $cur = ($cur * 256) + [int]$Id[$offset + $j]
                $Id[$offset + $j] = [byte][math]::Floor($cur / 24)
                $cur = $cur % 24
            }
            $key = $chars[$cur] + $key
        }
        if ($isWin8 -eq 1) {
            $last  = $key.Substring(1, 1)
            $key   = $key.Remove(1, 1)
            $insAt = [int]$last
            $key   = $key.Insert($insAt, 'N')
        }
        # group into 5x5
        $groups = @()
        for ($g = 0; $g -lt 25; $g += 5) { $groups += $key.Substring($g, 5) }
        return ($groups -join '-')
    } catch { return $null }
}

# ---------------------------------------------------------------------------
# Masking
# ---------------------------------------------------------------------------
function Format-Masked {
    param($Value, [switch]$Sensitive)
    if ($null -eq $Value -or "$Value" -eq '') { return '(not set)' }
    $s = "$Value"
    # Never mask status placeholders like (needs admin) / (not set) / (unavailable)
    if ($s -match '^\(.*\)$') { return $s }
    if (-not $Sensitive -or $Reveal) { return $s }

    # Product-key style AAAAA-BBBBB-... : keep first and last group
    if ($s -match '^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$') {
        $parts = $s.Split('-')
        return ('{0}-XXXXX-XXXXX-XXXXX-{1}' -f $parts[0], $parts[4])
    }
    # GUID-ish / long strings: show first 6 chars
    $keep = [math]::Min(6, $s.Length)
    return ($s.Substring(0, $keep) + ('*' * [math]::Max(0, ($s.Length - $keep))))
}

# ---------------------------------------------------------------------------
# Identifier collection
# ---------------------------------------------------------------------------
function New-Id {
    param([string]$Category, [string]$Name, $Value, [switch]$Sensitive, [string]$Source = '')
    [pscustomobject]@{
        Category  = $Category
        Name      = $Name
        Raw       = $Value
        Sensitive = [bool]$Sensitive
        Source    = $Source
    }
}

function Get-Identifiers {
    $ids = New-Object System.Collections.ArrayList
    $cvNt   = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $crypto = 'HKLM:\SOFTWARE\Microsoft\Cryptography'
    $sqm    = 'HKLM:\SOFTWARE\Microsoft\SQMClient'
    $adv    = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'

    $os   = Get-Cim 'Win32_OperatingSystem'
    $cs   = Get-Cim 'Win32_ComputerSystem'
    $csp  = Get-Cim 'Win32_ComputerSystemProduct'
    $bios = Get-Cim 'Win32_BIOS'
    $base = Get-Cim 'Win32_BaseBoard'
    $cpu  = Get-Cim 'Win32_Processor'

    # ---- Machine ----
    [void]$ids.Add( (New-Id 'Machine' 'Computer name' $env:COMPUTERNAME -Source 'env') )
    [void]$ids.Add( (New-Id 'Machine' 'MachineGuid' (Get-RegVal $crypto 'MachineGuid') -Sensitive -Source 'Cryptography\MachineGuid') )
    [void]$ids.Add( (New-Id 'Machine' 'Product ID (PUID)' (Get-RegVal $cvNt 'ProductId') -Sensitive -Source 'CurrentVersion\ProductId') )
    [void]$ids.Add( (New-Id 'Machine' 'Build GUID' (Get-RegVal $cvNt 'BuildGUID') -Source 'CurrentVersion\BuildGUID') )
    [void]$ids.Add( (New-Id 'Machine' 'Install date' $(if ($os) { $os.InstallDate } else { $null }) -Source 'Win32_OperatingSystem') )
    if ($csp) {
        [void]$ids.Add( (New-Id 'Machine' 'SMBIOS UUID' $csp.UUID -Sensitive -Source 'Win32_ComputerSystemProduct') )
        [void]$ids.Add( (New-Id 'Machine' 'System SKU/IdentifyingNumber' $csp.IdentifyingNumber -Sensitive -Source 'Win32_ComputerSystemProduct') )
    }

    # ---- Telemetry client IDs ----
    [void]$ids.Add( (New-Id 'Telemetry' 'SQM Machine ID' (Get-RegVal $sqm 'MachineId') -Sensitive -Source 'SQMClient\MachineId') )
    [void]$ids.Add( (New-Id 'Telemetry' 'SQM User ID' (Get-RegVal "$sqm\Windows" 'UserId') -Sensitive -Source 'SQMClient\Windows\UserId') )
    # Diagnostics / Universal Telemetry Client ID (if present)
    $utcClientId = Get-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\SettingsRequests' 'ClientId'
    [void]$ids.Add( (New-Id 'Telemetry' 'DiagTrack Client ID' $utcClientId -Sensitive -Source 'DiagTrack\SettingsRequests\ClientId') )

    # ---- Activation / licensing ----
    if ($os) {
        [void]$ids.Add( (New-Id 'Activation' 'Windows edition' $os.Caption -Source 'Win32_OperatingSystem') )
    }
    $partial = $null; $licStatus = $null; $licDesc = $null; $chan = $null
    $lic = Get-Cim 'SoftwareLicensingProduct' -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL"
    if ($lic) {
        $lic = @($lic)[0]
        $partial = $lic.PartialProductKey
        $chan    = $lic.ProductKeyChannel
        $map = @{ 0='Unlicensed'; 1='Licensed'; 2='OOB Grace'; 3='OOT Grace'; 4='Non-Genuine Grace'; 5='Notification'; 6='Extended Grace' }
        $licStatus = if ($map.ContainsKey([int]$lic.LicenseStatus)) { $map[[int]$lic.LicenseStatus] } else { $lic.LicenseStatus }
        $licDesc = $lic.Description
    }
    [void]$ids.Add( (New-Id 'Activation' 'License status' $licStatus -Source 'SoftwareLicensingProduct') )
    [void]$ids.Add( (New-Id 'Activation' 'License channel' $chan -Source 'SoftwareLicensingProduct') )
    [void]$ids.Add( (New-Id 'Activation' 'License description' $licDesc -Source 'SoftwareLicensingProduct') )
    [void]$ids.Add( (New-Id 'Activation' 'Partial product key' $partial -Sensitive -Source 'SoftwareLicensingProduct') )

    # OEM firmware key (needs admin)
    $oemKey = $null
    if ($Script:IsAdmin) {
        $sls = Get-Cim 'SoftwareLicensingService'
        if ($sls) { $oemKey = $sls.OA3xOriginalProductKey }
        if ([string]::IsNullOrEmpty($oemKey)) { $oemKey = '(none in firmware)' }
    } else {
        $oemKey = '(needs admin)'
    }
    [void]$ids.Add( (New-Id 'Activation' 'OEM firmware key (OA3)' $oemKey -Sensitive -Source 'SoftwareLicensingService.OA3xOriginalProductKey') )

    # Decoded installed product key from DigitalProductId
    $decoded = $null
    $dpi = Get-RegVal $cvNt 'DigitalProductId'
    if ($dpi) {
        try { $decoded = ConvertFrom-DigitalProductId -Id ([byte[]]$dpi) } catch { $decoded = $null }
    }
    if ([string]::IsNullOrEmpty($decoded)) {
        $decoded = '(unavailable)'
    } else {
        # Volume (MAK/KMS) channels do not store a recoverable key: decode is garbage
        # (typically a single repeated character). Detect and report honestly.
        $clean    = $decoded -replace '-', ''
        $distinct = @($clean.ToCharArray() | Select-Object -Unique).Count
        if ($distinct -le 3) { $decoded = '(unavailable - volume/MAK license)' }
    }
    [void]$ids.Add( (New-Id 'Activation' 'Installed product key (decoded)' $decoded -Sensitive -Source 'CurrentVersion\DigitalProductId') )

    # ---- Advertising / user ----
    [void]$ids.Add( (New-Id 'User' 'User name' ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME) -Source 'env') )
    try {
        $sid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
        [void]$ids.Add( (New-Id 'User' 'User SID' $sid -Sensitive -Source 'WindowsIdentity') )
    } catch { }
    $advId = Get-RegVal $adv 'Id'
    [void]$ids.Add( (New-Id 'User' 'Advertising ID' $advId -Sensitive -Source 'AdvertisingInfo\Id') )
    $advOn = Get-RegVal $adv 'Enabled'
    [void]$ids.Add( (New-Id 'User' 'Advertising ID enabled' $advOn -Source 'AdvertisingInfo\Enabled') )

    # ---- Hardware ----
    if ($bios) {
        [void]$ids.Add( (New-Id 'Hardware' 'BIOS serial number' $bios.SerialNumber -Sensitive -Source 'Win32_BIOS') )
    }
    if ($base) {
        [void]$ids.Add( (New-Id 'Hardware' 'Baseboard serial' $base.SerialNumber -Sensitive -Source 'Win32_BaseBoard') )
    }
    if ($cpu) {
        $cpu1 = @($cpu)[0]
        [void]$ids.Add( (New-Id 'Hardware' 'CPU ProcessorId' $cpu1.ProcessorId -Sensitive -Source 'Win32_Processor') )
    }
    # Disk serials
    $disks = Get-Cim 'Win32_DiskDrive'
    if ($disks) {
        $n = 0
        foreach ($d in @($disks)) {
            $n++
            $ser = if ($d.SerialNumber) { ($d.SerialNumber).Trim() } else { '(none)' }
            [void]$ids.Add( (New-Id 'Hardware' ("Disk {0} serial" -f $n) $ser -Sensitive -Source 'Win32_DiskDrive') )
        }
    }
    # MAC addresses (physical adapters with a MAC)
    $nics = Get-Cim 'Win32_NetworkAdapter' -Filter 'PhysicalAdapter=TRUE AND MACAddress IS NOT NULL'
    if ($nics) {
        foreach ($nic in @($nics)) {
            [void]$ids.Add( (New-Id 'Network' ("MAC - {0}" -f $nic.NetConnectionID) $nic.MACAddress -Sensitive -Source 'Win32_NetworkAdapter') )
        }
    }
    # TPM (needs admin; separate namespace)
    $tpm = Get-Cim 'Win32_Tpm' -Namespace 'root\cimv2\Security\MicrosoftTpm'
    if ($tpm) {
        $tpm1 = @($tpm)[0]
        [void]$ids.Add( (New-Id 'Hardware' 'TPM present' $tpm1.IsEnabled_InitialValue -Source 'Win32_Tpm') )
        [void]$ids.Add( (New-Id 'Hardware' 'TPM manufacturer ID' $tpm1.ManufacturerId -Source 'Win32_Tpm') )
    } elseif (-not $Script:IsAdmin) {
        [void]$ids.Add( (New-Id 'Hardware' 'TPM info' '(needs admin)' -Source 'Win32_Tpm') )
    }

    return $ids
}

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------
function Show-Report {
    param($Ids)

    Write-Host ''
    Write-Host '==================================================================' -ForegroundColor Cyan
    Write-Host '  Windows Identifier Privacy Audit (READ-ONLY)' -ForegroundColor Cyan
    Write-Host ('  Host: {0}   Admin: {1}   {2}' -f $env:COMPUTERNAME, $Script:IsAdmin, (Get-Date)) -ForegroundColor DarkCyan
    if ($Reveal) {
        Write-Host '  MODE: REVEAL - full sensitive values shown. Handle as confidential.' -ForegroundColor Red
    } else {
        Write-Host '  MODE: MASKED - sensitive values redacted. Use -Reveal for full values.' -ForegroundColor Magenta
    }
    Write-Host '==================================================================' -ForegroundColor Cyan

    $categories = @('Machine','Activation','Telemetry','User','Hardware','Network')
    foreach ($cat in $categories) {
        $group = @($Ids | Where-Object { $_.Category -eq $cat })
        if ($group.Count -eq 0) { continue }
        Write-Host ''
        Write-Host ("  [{0}]" -f $cat) -ForegroundColor White
        foreach ($id in $group) {
            $disp  = Format-Masked -Value $id.Raw -Sensitive:$id.Sensitive
            $color = if ($id.Sensitive) { 'Yellow' } else { 'Gray' }
            $tag   = if ($id.Sensitive) { '!' } else { ' ' }
            Write-Host ('  {0} {1,-32}' -f $tag, $id.Name) -NoNewline
            Write-Host $disp -ForegroundColor $color
        }
    }
    Write-Host ''
    Write-Host '  ! = sensitive identifier (masked unless -Reveal).' -ForegroundColor DarkYellow
    if (-not $Script:IsAdmin) {
        Write-Host '  Some values need Administrator (OEM key, TPM) - shown as (needs admin).' -ForegroundColor DarkYellow
    }
    Write-Host ''
}

function Export-Rows {
    param($Ids)
    foreach ($id in $Ids) {
        [pscustomobject]@{
            Category = $id.Category
            Name     = $id.Name
            Value    = (Format-Masked -Value $id.Raw -Sensitive:$id.Sensitive)
            Sensitive = $id.Sensitive
            Source   = $id.Source
        }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$ids = Get-Identifiers

Show-Report -Ids $ids

if ($Csv) {
    Export-Rows -Ids $ids | Export-Csv -Path $Csv -NoTypeInformation -Encoding ASCII
    Write-Host ("CSV written to {0}{1}" -f $Csv, $(if (-not $Reveal) { ' (masked)' } else { ' (REVEALED - confidential)' })) -ForegroundColor Green
}
if ($Json) {
    Export-Rows -Ids $ids | ConvertTo-Json -Depth 3 | Out-File -FilePath $Json -Encoding ASCII
    Write-Host ("JSON written to {0}{1}" -f $Json, $(if (-not $Reveal) { ' (masked)' } else { ' (REVEALED - confidential)' })) -ForegroundColor Green
}
